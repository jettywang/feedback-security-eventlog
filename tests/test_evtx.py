from __future__ import annotations

import typing

from dissect.eventlog.evtx import Evtx
from dissect.eventlog.utils import KeyValueCollection, SourceKind

if typing.TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

# $rawData = [System.Text.Encoding]::Unicode.GetBytes("Test Binary Data")

# New-EventLog -Source TestAppX -LogName TestLogX

# Write-EventLog -Source TestAppX -LogName TestLogX -EntryType Information -EventId 1 -Message "Test log message, information"  # noqa
# Write-EventLog -Source TestAppX -LogName TestLogX -EntryType Error -EventId 2 -Message "Test log message, error"
# Write-EventLog -Source TestAppX -LogName TestLogX -EntryType Warning -EventId 3 -Message "Test log message, warning"
# Write-EventLog -Source TestAppX -LogName TestLogX -Category 99 -EntryType FailureAudit -EventId 65534 -Message "Test log message, failure audit" -RawData $rawData  # noqa
# Write-EventLog -Source TestAppX -LogName TestLogX -Category 1 -EntryType SuccessAudit -EventId 5 -Message "Test log message, success audit" -RawData $rawData  # noqa


def test_evtx_parsing(get_absolute_path: Callable[[str], Path]) -> None:
    log_file_path: Path = get_absolute_path("_data/TestLogX.evtx")

    with log_file_path.open("rb") as f:
        records = list(Evtx(f))

        assert len(records) == 5

        assert {r["Computer"] for r in records} == {"DESKTOP-PJOQLJS"}
        assert {r["Provider_Name"] for r in records} == {"TestAppX"}
        assert {r["Channel"] for r in records} == {"TestLogX"}

        # https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc#52-level
        event_levels = {
            "Information": 4,
            "Error": 2,
            "Warning": 3,
            "FailureAudit": 0,
            "SuccessAudit": 0,
        }
        assert [
            # EventType, EventID, EventCategory, Message
            (event_levels["Information"], 1, 1, "Test log message, information"),
            (event_levels["Error"], 2, 1, "Test log message, error"),
            (event_levels["Warning"], 3, 1, "Test log message, warning"),
            (event_levels["FailureAudit"], 65534, 99, "Test log message, failure audit"),
            (event_levels["SuccessAudit"], 5, 1, "Test log message, success audit"),
        ] == [(r["Level"], r["EventID"], r["Task"], r["Data"][0]) for r in records]

        events_with_data = records[-2:]

        # other records have no Data
        assert not records[0]["Binary"]

        assert events_with_data[0]["Binary"]
        data1 = events_with_data[0]["Binary"]
        assert bytearray.fromhex(data1.decode()).decode("utf-16") == "Test Binary Data"

        assert events_with_data[1]["Binary"]
        data2 = events_with_data[1]["Binary"]
        assert bytearray.fromhex(data2.decode()).decode("utf-16") == "Test Binary Data"


def _normalized(record: dict) -> dict:
    """Resolve BxmlSub wrappers so default and provenance records can be compared."""
    from dissect.eventlog.bxml import BxmlSub

    result = {}
    for key, value in record.items():
        if isinstance(value, BxmlSub):
            value = value.get()
        result[key] = value
    return result


def test_evtx_provenance_opt_out_is_unchanged(get_absolute_path: Callable[[str], Path]) -> None:
    log_file_path: Path = get_absolute_path("_data/TestLogX.evtx")

    with log_file_path.open("rb") as f:
        plain = list(Evtx(f))

    with log_file_path.open("rb") as f:
        sourced = list(Evtx(f).with_sources())

    assert len(plain) == len(sourced) == 5
    for plain_record, sourced_record in zip(plain, sourced, strict=True):
        assert list(plain_record.keys()) == list(sourced_record.keys())
        assert _normalized(plain_record) == _normalized(sourced_record)
        assert not hasattr(plain_record, "sources")


def test_evtx_provenance_template_constant_and_substitution(get_absolute_path: Callable[[str], Path]) -> None:
    log_file_path: Path = get_absolute_path("_data/TestLogX.evtx")
    data = log_file_path.read_bytes()

    with log_file_path.open("rb") as f:
        record = next(Evtx(f).with_sources())

    assert record.sources.record_offset > 0
    assert record.sources.record_id == 1

    # A template constant: the Channel name/value is stored in the chunk template area, not
    # the record. Its raw bytes are the inline string value token.
    channel = record.sources["Channel"]
    assert channel.detail["origin"] == "inline"
    inline = [r for r in channel.ranges if r.role == "inline_value"]
    assert len(inline) == 1
    assert inline[0].kind is SourceKind.TEMPLATE
    raw = inline[0].read(data)
    assert raw[:2] == b"\x05\x01"
    assert raw[4:].decode("utf-16-le").rstrip("\x00") == "TestLogX"
    assert all(r.kind is SourceKind.TEMPLATE for r in channel.ranges)

    # A substitution field: EventID value bytes come from the record's descriptor payload.
    event_id = record.sources["EventID"]
    assert event_id.sub_id == 3
    assert event_id.value_type == "win:UINT16"
    assert event_id.template_offset is not None
    value_ranges = [r for r in event_id.ranges if r.role == "substitution_value"]
    assert len(value_ranges) == 1
    assert value_ranges[0].kind is SourceKind.RECORD
    assert int.from_bytes(value_ranges[0].read(data), "little") == record["EventID"]

    # Template and name ranges must point at the chunk template region, which is reused by
    # every record in the chunk.
    template_ranges = [r for r in event_id.ranges if r.kind is SourceKind.TEMPLATE]
    assert template_ranges
    name_ranges = [r for r in event_id.ranges if r.role == "name"]
    assert name_ranges


def test_evtx_provenance_reused_template_is_stable(get_absolute_path: Callable[[str], Path]) -> None:
    log_file_path: Path = get_absolute_path("_data/TestLogX.evtx")
    data = log_file_path.read_bytes()

    with log_file_path.open("rb") as f:
        records = list(Evtx(f).with_sources())

    first = records[0].sources["EventID"]
    last = records[-1].sources["EventID"]
    template_first = [r for r in first.ranges if r.kind is SourceKind.TEMPLATE and r.role == "template"]
    template_last = [r for r in last.ranges if r.kind is SourceKind.TEMPLATE and r.role == "template"]
    assert template_first == template_last

    # Every record must resolve its own EventID value, not the first record's bytes.
    for index, record in enumerate(records, start=1):
        value_range = next(r for r in record.sources["EventID"].ranges if r.role == "substitution_value")
        expected = record["EventID"]
        if index == 4:
            expected = 65534
        assert int.from_bytes(value_range.read(data), "little") == expected


def test_evtx_provenance_reports_record_identity_and_copy(get_absolute_path: Callable[[str], Path]) -> None:
    log_file_path: Path = get_absolute_path("_data/TestLogX.evtx")
    data = log_file_path.read_bytes()

    with log_file_path.open("rb") as f:
        iterator = Evtx(f).with_sources()
        first = next(iterator)
        first_sources = dict(first.sources)

        # Copy the record before consuming more of the iterator.
        copied = first.copy()
        remaining = list(iterator)

    assert isinstance(copied, KeyValueCollection)
    assert hasattr(copied, "sources")
    assert copied.sources == first_sources
    assert copied.sources is not first.sources

    # The original and the copy must still resolve bytes exactly as reported.
    for record in (first, copied):
        assert record.sources.record_id == 1
        assert record.sources.record_offset > 0
        assert record.sources.chunk_offset is not None
        event_id = record.sources["EventID"]
        value_range = next(r for r in event_id.ranges if r.role == "substitution_value")
        assert int.from_bytes(value_range.read(data), "little") == record["EventID"]

    # Continuing iteration must not mutate any earlier source chain.
    assert dict(first.sources) == first_sources
    assert len(remaining) == 4
    for record in remaining:
        assert record.sources.record_id != first.sources.record_id


def test_evtx_provenance_template_definition_bytes(get_absolute_path: Callable[[str], Path]) -> None:
    log_file_path: Path = get_absolute_path("_data/TestLogX.evtx")
    data = log_file_path.read_bytes()

    with log_file_path.open("rb") as f:
        record = next(Evtx(f).with_sources())

    # The nested EventData template has its own definition range, and the outer template that
    # lexically contains it is also reported. Both must be readable and must contain the
    # corresponding template identifier bytes.
    data_source = record.sources["Data"]
    template_ranges = [r for r in data_source.ranges if r.kind is SourceKind.TEMPLATE and r.role == "template"]
    assert len(template_ranges) == 2

    nested, outer = template_ranges
    assert nested.start is not None and outer.start is not None
    assert nested.start < outer.start or outer.start < nested.start

    nested_bytes = nested.read(data)
    assert nested_bytes[:4] == b"\x00\x00\x00\x00"
    # The nested definition references EventData through the chunk name table.
    assert b"E\x00v\x00e\x00n\x00t\x00D\x00a\x00t\x00a\x00" in nested_bytes
    assert b"\x0f\x01\x01\x00" in nested_bytes

    # The template offset in the FieldSource matches the exact chunk-relative definition start.
    assert data_source.template_offset == nested.start - record.sources.chunk_offset


def test_evtx_provenance_constructor_flag(get_absolute_path: Callable[[str], Path]) -> None:
    log_file_path: Path = get_absolute_path("_data/TestLogX.evtx")

    with log_file_path.open("rb") as f:
        records = list(Evtx(f, include_sources=True))

    assert len(records) == 5
    assert all(hasattr(record, "sources") for record in records)

    with log_file_path.open("rb") as f:
        plain = list(Evtx(f))

    assert all(not hasattr(record, "sources") for record in plain)


def test_evtx_provenance_readback_acceptance(get_absolute_path: Callable[[str], Path]) -> None:
    """Acceptance: read a template constant and a substitution field back from raw bytes."""
    log_file_path: Path = get_absolute_path("_data/TestLogX.evtx")
    data = log_file_path.read_bytes()

    with log_file_path.open("rb") as f:
        iterator = Evtx(f).with_sources()
        record = next(iterator)
        copied = record.copy()
        original_chain = {key: source.ranges for key, source in record.sources.items()}

        # Keep iterating after the copy; earlier source chains must remain intact.
        remaining = list(iterator)

    # A template constant (Channel) is entirely chunk-resident and decodes to the field value.
    channel = record.sources["Channel"]
    inline = next(r for r in channel.ranges if r.role == "inline_value")
    raw = inline.read(data)
    assert raw[4:].decode("utf-16-le").rstrip("\x00") == record["Channel"]

    # A substitution field (EventID) resolves from the current record's value bytes.
    event_id = record.sources["EventID"]
    value_range = next(r for r in event_id.ranges if r.role == "substitution_value")
    assert int.from_bytes(value_range.read(data), "little") == record["EventID"]

    # The copied record still carries the same, independently readable source chain.
    assert {key: source.ranges for key, source in copied.sources.items()} == original_chain
    assert copied.sources["EventID"].ranges == event_id.ranges
    assert copied.sources["Channel"].ranges == channel.ranges

    # The original object was not mutated by the copy or by continued iteration.
    assert {key: source.ranges for key, source in record.sources.items()} == original_chain
    assert len(remaining) == 4
