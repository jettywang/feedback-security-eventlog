from __future__ import annotations

import hashlib
import importlib
import io
import json
import struct
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

from dissect.eventlog.evtx import Evtx
from dissect.eventlog.evtx.recovery import EVTX_FILE_HEADER_SIZE, SkippedRange

CHUNK_START = EVTX_FILE_HEADER_SIZE
CHUNK_SIZE = 0x10000
RECORD_OFFSETS = {
    1: 0x200,
    2: 0x850,
    3: 0x950,
    4: 0xA50,
    5: 0xB80,
}


def _record_identity(record: object) -> tuple[int, int, object, tuple[object, ...]]:
    timestamp = record.get("TimeCreated_SystemTime")
    if hasattr(timestamp, "get"):
        timestamp = timestamp.get()

    return (
        record["EventRecordID"],
        record["EventID"],
        timestamp,
        tuple(record.get("Data") or ()),
    )


def _strict_identities(path: Path) -> dict[int, tuple[int, int, object, tuple[object, ...]]]:
    # Capture values while iterating: the upstream parser reuses template substitution objects between records.
    identities = {}
    with path.open("rb") as fh:
        for record in Evtx(fh):
            identity = _record_identity(record)
            identities[identity[0]] = identity

    return identities


def _recover(data: bytes) -> object:
    evtx = Evtx(io.BytesIO(data))
    return evtx.recover()


def _copy_with_size_corruption(source: bytes, record_id: int, size: int) -> bytes:
    data = bytearray(source)
    offset = CHUNK_START + RECORD_OFFSETS[record_id]
    struct.pack_into("<I", data, offset + 4, size)
    return bytes(data)


def _fake_signature_in_payload(source: bytes) -> tuple[bytes, int]:
    """Embed a plain record signature inside record 4's `Binary` value bytes."""
    data = bytearray(source)
    # 8-byte aligned, in the middle of record 4's hex-encoded Binary value (still valid BinXML data).
    offset = CHUNK_START + 0xB58
    data[offset : offset + 4] = b"**\x00\x00"
    return bytes(data), offset


def _fake_signature_in_free_space(source: bytes) -> bytes:
    """Embed a record signature in the unused part of the chunk, with a plausible size."""
    data = bytearray(source)
    offset = CHUNK_START + 0xD00
    data[offset : offset + 4] = b"**\x00\x00"
    struct.pack_into("<I", data, offset + 4, 0x100)
    return bytes(data)


def test_strict_contract_is_unchanged(get_absolute_path: Callable[[str], Path], tmp_path: Path) -> None:
    source = get_absolute_path("_data/TestLogX.evtx")
    assert len(_strict_identities(source)) == 5

    damaged_path = tmp_path / "TestLogX-damaged-size.evtx"
    damaged_path.write_bytes(_copy_with_size_corruption(source.read_bytes(), 2, 9999))

    # Strict iteration still stops at the damaged record and does not silently recover later ones.
    assert list(_strict_identities(damaged_path)) == [1]


def test_recover_intact_file_matches_strict(get_absolute_path: Callable[[str], Path]) -> None:
    source = get_absolute_path("_data/TestLogX.evtx")
    report = _recover(source.read_bytes())

    assert [record.record_id for record in report.records] == [1, 2, 3, 4, 5]
    assert report.skipped_ranges == []

    assert [_record_identity(record) for record in report.records] == list(_strict_identities(source).values())


def test_recover_records_after_damaged_record(get_absolute_path: Callable[[str], Path]) -> None:
    source = get_absolute_path("_data/TestLogX.evtx")
    base = source.read_bytes()
    report = _recover(_copy_with_size_corruption(base, 2, 9999))

    assert [record.record_id for record in report.records] == [1, 3, 4, 5]

    assert len(report.skipped_ranges) == 1
    skipped = report.skipped_ranges[0]
    assert skipped.offset == CHUNK_START + RECORD_OFFSETS[2]
    assert skipped.size == 256
    assert skipped.reason == "record size 9999 extends past the chunk record region"

    pristine = _strict_identities(source)
    for record in report.records:
        assert _record_identity(record) == pristine[record.record_id]


def test_recover_adjacent_damaged_records(get_absolute_path: Callable[[str], Path]) -> None:
    source = get_absolute_path("_data/TestLogX.evtx")
    data = bytearray(source.read_bytes())

    for record_id in (2, 3):
        offset = CHUNK_START + RECORD_OFFSETS[record_id]
        data[offset : offset + 4] = b"XXXX"

    report = _recover(bytes(data))

    assert [record.record_id for record in report.records] == [1, 4, 5]
    assert len(report.skipped_ranges) == 1

    skipped = report.skipped_ranges[0]
    assert skipped.offset == CHUNK_START + RECORD_OFFSETS[2]
    assert skipped.size == RECORD_OFFSETS[4] - RECORD_OFFSETS[2]
    assert skipped.reason == "no structurally valid record signature in this range"

    pristine = _strict_identities(source)
    for record in report.records:
        assert _record_identity(record) == pristine[record.record_id]


def test_fake_signature_in_payload_does_not_create_event(get_absolute_path: Callable[[str], Path]) -> None:
    source = get_absolute_path("_data/TestLogX.evtx")
    pristine = _strict_identities(source)

    mutated, fake_offset = _fake_signature_in_payload(source.read_bytes())
    report = _recover(mutated)

    # The containing record still parses, and the embedded signature does not become a separate event.
    assert [record.record_id for record in report.records] == [1, 2, 3, 4, 5]
    assert all(record.file_offset != fake_offset for record in report.records)
    assert report.skipped_ranges == []

    for record in report.records:
        assert _record_identity(record) == pristine[record.record_id]


def test_fake_signature_in_free_space_does_not_create_event(get_absolute_path: Callable[[str], Path]) -> None:
    source = get_absolute_path("_data/TestLogX.evtx")
    report = _recover(_fake_signature_in_free_space(source.read_bytes()))

    assert [record.record_id for record in report.records] == [1, 2, 3, 4, 5]
    assert report.skipped_ranges == []


def test_truncated_tail_chunk(get_absolute_path: Callable[[str], Path]) -> None:
    source = get_absolute_path("_data/TestLogX.evtx")
    base = source.read_bytes()
    truncated = base[: CHUNK_START + RECORD_OFFSETS[5] + 100]

    report = _recover(truncated)

    assert [record.record_id for record in report.records] == [1, 2, 3, 4]
    assert len(report.skipped_ranges) == 1

    skipped = report.skipped_ranges[0]
    assert skipped.offset == CHUNK_START + RECORD_OFFSETS[5]
    assert skipped.size == 100
    assert "extends past the chunk record region" in skipped.reason
    assert report.chunks[0].complete is False
    assert any("truncated" in warning for warning in report.warnings)


def test_trailing_partial_chunk(get_absolute_path: Callable[[str], Path]) -> None:
    source = get_absolute_path("_data/TestLogX.evtx")
    base = source.read_bytes()
    report = _recover(base + base[CHUNK_START : CHUNK_START + 300])

    assert [record.record_id for record in report.records] == [1, 2, 3, 4, 5]
    assert report.skipped_ranges == [
        SkippedRange(
            offset=CHUNK_START + CHUNK_SIZE,
            size=300,
            reason="trailing partial chunk is smaller than a chunk header",
            chunk_index=1,
            chunk_offset=0,
        )
    ]


def test_recovery_never_modifies_source(get_absolute_path: Callable[[str], Path]) -> None:
    source = get_absolute_path("_data/TestLogX.evtx")
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    report = _recover(source.read_bytes())

    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert report.source_sha256 == before


def test_recovery_report_is_json_serializable(get_absolute_path: Callable[[str], Path]) -> None:
    source = get_absolute_path("_data/TestLogX.evtx")
    report = _recover(_copy_with_size_corruption(source.read_bytes(), 2, 9999))

    payload = json.loads(report.to_json())

    assert payload["mode"] == "recovery"
    assert payload["source_sha256"] == report.source_sha256
    assert [record["file_offset"] for record in payload["records"]] == [
        CHUNK_START + RECORD_OFFSETS[record_id] for record_id in (1, 3, 4, 5)
    ]
    assert payload["skipped_ranges"] == [
        {
            "offset": CHUNK_START + RECORD_OFFSETS[2],
            "size": 256,
            "end": CHUNK_START + RECORD_OFFSETS[2] + 256,
            "chunk_index": 0,
            "chunk_offset": RECORD_OFFSETS[2],
            "reason": "record size 9999 extends past the chunk record region",
            "details": [],
        }
    ]

    for record in payload["records"]:
        assert record["confidence"]
        assert "BinXML parsed successfully" in record["confidence"]


def test_recovery_cli_produces_reproducible_report(
    get_absolute_path: Callable[[str], Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = get_absolute_path("_data/TestLogX.evtx")
    damaged_path = tmp_path / "TestLogX-damaged.evtx"
    damaged_path.write_bytes(_copy_with_size_corruption(source.read_bytes(), 2, 9999))
    output_path = tmp_path / "skip-report.json"

    module = importlib.import_module("examples.recover_evtx")

    def run() -> str:
        with monkeypatch.context() as context:
            context.setattr(sys, "argv", ["recover_evtx", str(damaged_path), "--report", str(output_path)])
            module.main()

        return output_path.read_text()

    first = run()
    second = run()

    assert first == second

    payload = json.loads(second)

    assert [record["record_id"] for record in payload["records"]] == [1, 3, 4, 5]
    assert [skipped["offset"] for skipped in payload["skipped_ranges"]] == [CHUNK_START + RECORD_OFFSETS[2]]
    assert payload["summary"]["skipped_bytes"] == 256
    assert payload["summary"]["recovered_records"] == 4
