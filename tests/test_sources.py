from __future__ import annotations

from pathlib import Path

import pytest

from dissect.eventlog.utils import (
    ByteRange,
    FieldSource,
    KeyValueCollection,
    SourceCollection,
    SourceKind,
    attach_sources,
    source_for,
    unresolved,
)


def test_byte_range_read_bytes() -> None:
    data = b"0123456789"
    byte_range = ByteRange(SourceKind.RECORD, 2, 3, "value")
    assert byte_range.read(data) == b"234"


def test_byte_range_read_file_restores_position(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"0123456789")
    with path.open("rb") as fh:
        fh.seek(7)
        position = fh.tell()
        assert ByteRange(SourceKind.RECORD, 2, 3).read(fh) == b"234"
        assert fh.tell() == position


def test_byte_range_validates_bounds() -> None:
    with pytest.raises(ValueError):
        ByteRange(SourceKind.RECORD, 8, 4).read(b"0123456789")

    with pytest.raises(ValueError):
        unresolved("unknown template offset").read(b"0123456789")


def test_field_source_read_all_requires_full_chain() -> None:
    source = FieldSource(
        key="k",
        ranges=(
            ByteRange(SourceKind.RECORD, 0, 1),
            unresolved("missing template"),
        ),
    )
    assert not source.is_resolved
    with pytest.raises(ValueError, match="not fully resolved"):
        source.read_all(b"x")


def test_field_source_to_dict_roundtrip_shape() -> None:
    source = FieldSource(
        key="EventID",
        ranges=(ByteRange(SourceKind.RECORD, 0x10, 2, "substitution_value"),),
        path=("System", "EventID", "EventID", "#"),
        value_type="win:UINT16",
        sub_id=3,
        template_offset=0x226,
        record_offset=0x1200,
        record_id=1,
        detail={"origin": "substitution"},
    )
    payload = source.to_dict()
    assert payload["ranges"] == [
        {"kind": "record", "start": 0x10, "length": 2, "role": "substitution_value"},
    ]
    assert payload["path"] == ["System", "EventID", "EventID", "#"]
    assert payload["sub_id"] == 3
    assert payload["detail"] == {"origin": "substitution"}


def test_attach_sources_stages_record_identity() -> None:
    record = KeyValueCollection()
    record["EventID"] = 1
    sources = SourceCollection()
    sources.record_offset = 0x1200
    sources.record_id = 1
    sources["EventID"] = FieldSource(key="EventID", ranges=(ByteRange(SourceKind.RECORD, 0x10, 2),))

    attached = attach_sources(record, sources)
    assert attached.sources["EventID"].record_offset == 0x1200
    assert attached.sources["EventID"].record_id == 1
    assert source_for(attached, "EventID") == attached.sources["EventID"]

    plain = KeyValueCollection()
    assert source_for(plain, "EventID") is None


def test_key_value_copy_preserves_sources() -> None:
    record = KeyValueCollection()
    record["Data"] = "value"
    sources = SourceCollection()
    sources.record_offset = 0x1200
    sources.record_id = 1
    sources["Data"] = FieldSource(key="Data", ranges=(ByteRange(SourceKind.RECORD, 0x10, 2),))
    record.sources = sources

    copied = record.copy()
    assert isinstance(copied, KeyValueCollection)
    assert copied["Data"] == "value"
    assert copied.sources is not sources
    assert copied.sources.record_id == 1
    assert list(copied.keys()) == ["Data"]

    # Non-provenance records keep the original dict-copy behaviour.
    plain = KeyValueCollection()
    plain["Data"] = "value"
    assert isinstance(plain.copy(), dict)
    assert plain.copy() == {"Data": "value"}
