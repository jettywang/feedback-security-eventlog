"""Regression tests for BinXML template reuse in EVTX.

The EVTX parser caches template *definitions* per chunk. A definition only holds the element tree and the
substitution placeholders; the substitution values belong to a single record. These tests use real records
from ``TestLogX.evtx`` (relocated, but never mocked) to verify the ownership split:

* keeping the first event object alive while later records are parsed does not change its values,
* an already filled instance is not affected by filling another instance from the same definition,
* substitution values that contain a child template are isolated as well,
* regular template reuse inside a chunk keeps working,
* the same template offset in a different chunk is not treated as the same template,
* reading chunk A then B and chunk B then A gives independent results.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.util.ts import wintimestamp

from dissect.eventlog.bxml import Bxml, BxmlSub, EvtxNameReader, Template
from dissect.eventlog.evtx import Evtx
from dissect.eventlog.evtx.evtx import ElfChnk

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

FILETIME_ORIGIN = datetime(1601, 1, 1, tzinfo=timezone.utc)
CHUNK_SIZE = 0x10000
FILE_HEADER_SIZE = 0x1000
FIRST_RECORD_OFFSET = 0x200
RECORD_HEADER_SIZE = 24

TEMPLATE_OFFSET = 0x226
NESTED_TEMPLATE_OFFSET = 0x764
TIMESTAMP_SUB_ID = 6
NESTED_SUB_ID = 19

# Byte locations of the ``TimeCreated_SystemTime`` value and the ``Data`` string inside the payload of the
# first two records of ``TestLogX.evtx``. Located by scanning for the parsed values and verifying them.
PAYLOAD_LAYOUT = {0: (0x525, 0x5EC), 1: (0x72, 0xA9)}
RECORD_TEXT = {0: "Test log message, information", 1: "Test log message, error"}

# The five real records of ``TestLogX.evtx``, in file order.
REAL_TIMESTAMPS = [
    datetime(2021, 7, 22, 15, 44, 21, 416718, tzinfo=timezone.utc),
    datetime(2021, 7, 22, 15, 45, 44, 663879, tzinfo=timezone.utc),
    datetime(2021, 7, 22, 15, 46, 15, 976278, tzinfo=timezone.utc),
    datetime(2021, 7, 22, 15, 50, 23, 212521, tzinfo=timezone.utc),
    datetime(2021, 7, 22, 15, 50, 23, 212521, tzinfo=timezone.utc),
]
REAL_DATA = [
    "Test log message, information",
    "Test log message, error",
    "Test log message, warning",
    "Test log message, failure audit",
    "Test log message, success audit",
]


def _filetime(value: datetime) -> int:
    delta = value - FILETIME_ORIGIN
    return delta.days * 86400 * 10_000_000 + delta.seconds * 10_000_000 + delta.microseconds * 10


def _decoded(value: datetime) -> datetime:
    """Return the timestamp exactly as the parser decodes the encoded filetime."""
    return wintimestamp(_filetime(value))


def _read_file(path: Path) -> bytes:
    return path.read_bytes()


def _chunk_bytes(data: bytes) -> bytes:
    return data[FILE_HEADER_SIZE : FILE_HEADER_SIZE + CHUNK_SIZE]


def _raw_records(chunk: bytes) -> list[tuple[int, bytes]]:
    """Return the ``(chunk offset, raw record)`` pairs of a chunk, exactly as stored."""
    records = []
    offset = FIRST_RECORD_OFFSET
    while True:
        signature, size = struct.unpack_from("<II", chunk, offset)
        if signature != 0x2A2A or size < 28:
            return records
        records.append((offset, chunk[offset : offset + size]))
        offset += size


def _payload(record: bytes) -> bytes:
    size = struct.unpack_from("<I", record, 4)[0]
    return record[RECORD_HEADER_SIZE : size - 4]


def _patch_record(record: bytes, source: int, timestamp: datetime, text: str, record_id: int) -> bytes:
    """Return a copy of a real record with new substitution values, keeping the substitution sizes."""
    assert len(text) == len(RECORD_TEXT[source]), "replacement must keep the substitution size"

    patched = bytearray(record)
    timestamp_offset, _ = PAYLOAD_LAYOUT[source]
    payload_offset = RECORD_HEADER_SIZE + timestamp_offset
    patched[payload_offset : payload_offset + 8] = struct.pack("<Q", _filetime(timestamp))

    old_text = RECORD_TEXT[source].encode("utf-16-le")
    assert record.count(old_text) == 1, "substitution value must be unique"
    text_offset = record.find(old_text)
    patched[text_offset : text_offset + len(old_text)] = text.encode("utf-16-le")

    patched[8:16] = struct.pack("<Q", record_id)
    return bytes(patched)


def _compose_chunk(base_chunk: bytes, records: list[tuple[int, bytes]]) -> bytes:
    """Compose a standalone chunk from real chunk header bytes and a list of real records."""
    chunk = bytearray(base_chunk)
    chunk[FIRST_RECORD_OFFSET:] = b"\x00" * (CHUNK_SIZE - FIRST_RECORD_OFFSET)

    end = FIRST_RECORD_OFFSET
    for offset, record in records:
        chunk[offset : offset + len(record)] = record
        end = max(end, offset + len(record))

    struct.pack_into("<I", chunk, 0x2C, end)  # last_record_offset
    struct.pack_into("<I", chunk, 0x30, end)  # free_space_offset
    return bytes(chunk)


def _compose_file(base_file: bytes, chunks: list[bytes]) -> bytes:
    """Compose an EVTX file from the real file header and a list of composed chunks."""
    header = bytearray(base_file[:FILE_HEADER_SIZE])
    struct.pack_into("<H", header, 0x2A, len(chunks))  # num_chunks
    return bytes(header) + b"".join(chunks)


def _parse_chunk(chunk: bytes) -> tuple[ElfChnk, list[dict]]:
    parser = ElfChnk(chunk)
    return parser, list(parser.read())


def _read_instance(parser: ElfChnk, record: bytes, record_offset: int) -> Template:
    """Fill a template instance from one real record, using the parser's chunk template cache."""
    bxml = Bxml(BytesIO(_payload(record)), parser.stream)
    bxml.data_offset = record_offset + RECORD_HEADER_SIZE
    bxml.templates = parser.templates
    bxml.set_name_reader(EvtxNameReader(bxml))
    bxml.bxml_stream.seek(5)  # first token is BXML_TEMPLATE_INSTANCE
    return bxml.read_template_instance()


def _snapshot(value: object) -> object:
    """Build a comparable snapshot, including live substitutions and child templates."""
    if isinstance(value, BxmlSub):
        return ("sub", value.sub_id, _snapshot(value.get()))
    if isinstance(value, Template):
        return (
            "template",
            tuple(sorted((key, _snapshot(sub.get())) for key, sub in value.subs.items())),
            tuple(_snapshot(child) for child in value.child_templates),
        )
    if isinstance(value, dict):
        return {key: _snapshot(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return tuple(_snapshot(item) for item in value)
    return value


def _definition_is_value_free(template: Template) -> bool:
    """A cached definition must never hold record values or per-record child templates."""
    return all(sub.get() is None for sub in template.subs.values()) and not template.child_templates


def test_first_event_is_not_mutated_by_later_records(get_absolute_path: Callable[[str], Path]) -> None:
    with get_absolute_path("_data/TestLogX.evtx").open("rb") as fh:
        events = iter(Evtx(fh))
        first = next(events)
        snapshot = _snapshot(first)
        remaining = list(events)

    # The object returned first must still describe its own record after all other records were parsed.
    assert _snapshot(first) == snapshot
    assert first["TimeCreated_SystemTime"].get() == REAL_TIMESTAMPS[0]
    assert first["Data"] == [REAL_DATA[0]]

    assert len(remaining) == 4
    assert [event["TimeCreated_SystemTime"].get() for event in [first, *remaining]] == REAL_TIMESTAMPS
    assert [event["Data"][0] for event in [first, *remaining]] == REAL_DATA

    # Each event owns its substitution objects; no object is reused between records.
    live = [sub for event in [first, *remaining] for sub in event.values() if isinstance(sub, BxmlSub)]
    assert len({id(sub) for sub in live}) == len(live)


def test_same_definition_instances_are_isolated(get_absolute_path: Callable[[str], Path]) -> None:
    chunk = _chunk_bytes(_read_file(get_absolute_path("_data/TestLogX.evtx")))
    records = _raw_records(chunk)

    # Record 0 carries both the outer definition (0x226) and the nested one (0x764).
    parser, _ = _parse_chunk(_compose_chunk(chunk, [records[0]]))
    first_instance = _read_instance(parser, records[0][1], records[0][0])
    first_snapshot = _snapshot(first_instance)

    definitions = dict(parser.templates)
    assert set(definitions) == {TEMPLATE_OFFSET, NESTED_TEMPLATE_OFFSET}
    assert _definition_is_value_free(definitions[TEMPLATE_OFFSET])
    assert _definition_is_value_free(definitions[NESTED_TEMPLATE_OFFSET])

    # Fill a second instance from the same cached definitions with a different record's values.
    second_instance = _read_instance(parser, records[1][1], records[1][0])

    assert _snapshot(first_instance) == first_snapshot
    assert first_instance is not second_instance
    assert {id(sub) for sub in first_instance.subs.values()}.isdisjoint(
        {id(sub) for sub in second_instance.subs.values()}
    )
    assert _definition_is_value_free(definitions[TEMPLATE_OFFSET])
    assert _definition_is_value_free(definitions[NESTED_TEMPLATE_OFFSET])


def test_child_template_values_are_isolated(get_absolute_path: Callable[[str], Path]) -> None:
    chunk = _chunk_bytes(_read_file(get_absolute_path("_data/TestLogX.evtx")))
    records = _raw_records(chunk)

    parser, _ = _parse_chunk(_compose_chunk(chunk, [records[0]]))
    first_instance = _read_instance(parser, records[0][1], records[0][0])
    first_child = first_instance.subs[NESTED_SUB_ID].get()
    assert isinstance(first_child, Template)
    first_child_snapshot = _snapshot(first_child)
    assert first_child.as_map() == {"Data": [REAL_DATA[0]], "Binary": None}

    # Record 4 has a Binary value in the same child template slot.
    record_index = len(records) - 1
    second_instance = _read_instance(parser, records[record_index][1], records[record_index][0])
    second_child = second_instance.subs[NESTED_SUB_ID].get()
    assert isinstance(second_child, Template)

    assert first_child is not second_child
    assert _snapshot(first_child) == first_child_snapshot
    assert second_child.as_map()["Binary"] is not None
    assert first_child.as_map()["Binary"] is None


def test_template_reuse_within_a_chunk_still_works(get_absolute_path: Callable[[str], Path]) -> None:
    chunk = _chunk_bytes(_read_file(get_absolute_path("_data/TestLogX.evtx")))
    parser, events = _parse_chunk(chunk)

    assert len(events) == 5
    assert [event["TimeCreated_SystemTime"].get() for event in events] == REAL_TIMESTAMPS
    assert [event["Data"][0] for event in events] == REAL_DATA
    assert [event["EventRecordID"] for event in events] == [1, 2, 3, 4, 5]
    assert events[3]["Binary"] is not None
    assert events[4]["Binary"] is not None

    # Two templates are defined once in this chunk and reused by every later record.
    assert set(parser.templates) == {TEMPLATE_OFFSET, NESTED_TEMPLATE_OFFSET}
    for definition in parser.templates.values():
        assert _definition_is_value_free(definition)


def _composed_chunks(get_absolute_path: Callable[[str], Path]) -> tuple[bytes, bytes]:
    """Build two chunks that share template offsets but carry different substitution values."""
    data = _read_file(get_absolute_path("_data/TestLogX.evtx"))
    chunk = _chunk_bytes(data)
    records = _raw_records(chunk)

    timestamp_a = datetime(2022, 1, 1, 0, 0, 1, 120300, tzinfo=timezone.utc)
    timestamp_b = datetime(2022, 1, 2, 0, 0, 2, 230000, tzinfo=timezone.utc)
    timestamp_c = datetime(2023, 2, 3, 0, 0, 3, 340000, tzinfo=timezone.utc)
    timestamp_d = datetime(2023, 2, 4, 0, 0, 4, 450300, tzinfo=timezone.utc)

    text_a = "A" * len(RECORD_TEXT[0])
    text_b = "B" * len(RECORD_TEXT[1])
    text_c = "C" * len(RECORD_TEXT[0])
    text_d = "D" * len(RECORD_TEXT[1])

    chunk_one = _compose_chunk(
        chunk,
        [
            (0x200, _patch_record(records[0][1], 0, timestamp_a, text_a, 11)),
            (0x850, _patch_record(records[1][1], 1, timestamp_b, text_b, 12)),
        ],
    )
    chunk_two = _compose_chunk(
        chunk,
        [
            (0x200, _patch_record(records[0][1], 0, timestamp_c, text_c, 21)),
            (0x850, _patch_record(records[1][1], 1, timestamp_d, text_d, 22)),
        ],
    )
    return chunk_one, chunk_two


def test_same_offset_in_different_chunks_is_independent(get_absolute_path: Callable[[str], Path]) -> None:
    chunk_one, chunk_two = _composed_chunks(get_absolute_path)

    # Each chunk defines its first template at the same offset (0x226), but in a separate cache entry.
    parser_one, events_one = _parse_chunk(chunk_one)
    first_snapshot = _snapshot(events_one[0])
    parser_two, events_two = _parse_chunk(chunk_two)

    assert parser_one.templates[TEMPLATE_OFFSET] is not parser_two.templates[TEMPLATE_OFFSET]
    assert parser_one.templates[TEMPLATE_OFFSET].mapping == parser_two.templates[TEMPLATE_OFFSET].mapping
    assert _definition_is_value_free(parser_one.templates[TEMPLATE_OFFSET])
    assert _definition_is_value_free(parser_two.templates[TEMPLATE_OFFSET])

    # Parsing the second chunk did not touch the events of the first chunk.
    assert _snapshot(events_one[0]) == first_snapshot
    assert [event["TimeCreated_SystemTime"].get() for event in events_one] == [
        _decoded(datetime(2022, 1, 1, 0, 0, 1, 120300, tzinfo=timezone.utc)),
        _decoded(datetime(2022, 1, 2, 0, 0, 2, 230000, tzinfo=timezone.utc)),
    ]
    assert [event["Data"][0] for event in events_one] == ["A" * len(RECORD_TEXT[0]), "B" * len(RECORD_TEXT[1])]
    assert [event["Data"][0] for event in events_two] == ["C" * len(RECORD_TEXT[0]), "D" * len(RECORD_TEXT[1])]


def test_chunk_order_does_not_change_results(get_absolute_path: Callable[[str], Path]) -> None:
    chunk_one, chunk_two = _composed_chunks(get_absolute_path)

    base_file = _read_file(get_absolute_path("_data/TestLogX.evtx"))
    file_ab = _compose_file(base_file, [chunk_one, chunk_two])
    file_ba = _compose_file(base_file, [chunk_two, chunk_one])

    events_ab = list(Evtx(BytesIO(file_ab)))
    events_ba = list(Evtx(BytesIO(file_ba)))

    assert len(events_ab) == len(events_ba) == 4
    text_a = "A" * len(RECORD_TEXT[0])
    text_b = "B" * len(RECORD_TEXT[1])
    text_c = "C" * len(RECORD_TEXT[0])
    text_d = "D" * len(RECORD_TEXT[1])
    assert [event["Data"][0] for event in events_ab] == [text_a, text_b, text_c, text_d]
    assert [event["Data"][0] for event in events_ba] == [text_c, text_d, text_a, text_b]
    timestamp_a = _decoded(datetime(2022, 1, 1, 0, 0, 1, 120300, tzinfo=timezone.utc))
    timestamp_b = _decoded(datetime(2022, 1, 2, 0, 0, 2, 230000, tzinfo=timezone.utc))
    timestamp_c = _decoded(datetime(2023, 2, 3, 0, 0, 3, 340000, tzinfo=timezone.utc))
    timestamp_d = _decoded(datetime(2023, 2, 4, 0, 0, 4, 450300, tzinfo=timezone.utc))

    assert [event["TimeCreated_SystemTime"].get() for event in events_ab] == [
        timestamp_a,
        timestamp_b,
        timestamp_c,
        timestamp_d,
    ]
    assert [event["TimeCreated_SystemTime"].get() for event in events_ba] == [
        timestamp_c,
        timestamp_d,
        timestamp_a,
        timestamp_b,
    ]


def test_create_instance_clones_placeholders(get_absolute_path: Callable[[str], Path]) -> None:
    chunk = _chunk_bytes(_read_file(get_absolute_path("_data/TestLogX.evtx")))
    records = _raw_records(chunk)
    parser, _ = _parse_chunk(_compose_chunk(chunk, [records[0]]))
    _read_instance(parser, records[0][1], records[0][0])

    definition = parser.templates[TEMPLATE_OFFSET]
    instance_one = definition.create_instance()
    instance_two = definition.create_instance()

    assert instance_one is not instance_two
    assert instance_one.mapping == definition.mapping == instance_two.mapping
    assert set(instance_one.subs) == set(definition.subs)
    assert {id(sub) for sub in instance_one.subs.values()}.isdisjoint({id(sub) for sub in instance_two.subs.values()})
    assert {id(sub) for sub in instance_one.subs.values()}.isdisjoint({id(sub) for sub in definition.subs.values()})

    instance_one.subs[TIMESTAMP_SUB_ID].set("first")
    assert instance_two.subs[TIMESTAMP_SUB_ID].get() is None
    assert definition.subs[TIMESTAMP_SUB_ID].get() is None

    instance_two.subs[TIMESTAMP_SUB_ID].set("second")
    assert instance_one.subs[TIMESTAMP_SUB_ID].get() == "first"
