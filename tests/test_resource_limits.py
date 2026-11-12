"""Resource-boundary tests for safely processing untrusted EVTX/BinXML data.

These tests use only fixed, hand-crafted byte sequences and counting streams. There are no large
fixtures, no real malicious files and no long-running stress loops; every pathological input is a
small, fully determined sample that terminates within a bounded amount of work.

The boundaries under test are explicit and named:

* total bytes read from a record's BinXML stream,
* template expansion (nesting / cycle) depth,
* number of substitution values materialised per record,
* number of output fields produced per record.

Three distinct termination reasons are asserted separately: structural corruption
(:class:`BxmlException` / :class:`MalformedElfChnkException`), a crossed configuration limit
(:class:`ResourceLimitExceeded`) and a clean end of stream (:class:`EOFError`).
"""

from __future__ import annotations

import struct
import sys
from io import BytesIO
from pathlib import Path

import pytest

from dissect.eventlog.bxml import Bxml, EvtxNameReader, parse_bxml
from dissect.eventlog.bxml.c_bxml import c_bxml
from dissect.eventlog.evtx import ElfChnk, Evtx
from dissect.eventlog.exceptions import (
    BxmlException,
    MalformedElfChnkException,
    ResourceLimitExceeded,
)
from dissect.eventlog.limits import DEFAULT_MAX_FIELDS, DEFAULT_MAX_TEMPLATE_DEPTH, ResourceLimit
from tests._resource_bxml import (
    DATA_OFFSET,
    cyclic_templates,
    huge_descriptor_count,
    make_bxml,
    nested_chain,
)

EVTX_PATH = Path(__file__).parent / "_data" / "TestLogX.evtx"
CHUNK_SIZE = 0x10000
HEADER_SIZE = 0x1000
RECORD_HEADER_SIZE = 24


# ---------------------------------------------------------------------------------------------
# Bounded byte stream
# ---------------------------------------------------------------------------------------------


def test_bounded_stream_counts_bytes_and_allows_clean_eof() -> None:
    raw = BytesIO(b"\x01\x02\x03")
    bxml = Bxml(raw, BytesIO(b""), ResourceLimit(max_bytes=10))

    assert bxml.bxml_stream.read(2) == b"\x01\x02"
    assert bxml.bytes_read == 2
    # Reading past the real end returns the available bytes and then an empty result: a genuine
    # EOF condition, not a limit violation.
    assert bxml.bxml_stream.read(5) == b"\x03"
    assert bxml.bxml_stream.read(1) == b""
    assert bxml.bytes_read == 3


def test_bounded_stream_raises_limit_not_eof_when_budget_crossed() -> None:
    bxml = Bxml(BytesIO(b"\x00" * 8), BytesIO(b""), ResourceLimit(max_bytes=4))

    assert bxml.bxml_stream.read(4) == b"\x00" * 4
    with pytest.raises(ResourceLimitExceeded):
        bxml.bxml_stream.read(1)


def test_byte_budget_stops_a_deep_chain_within_bounded_reads() -> None:
    # A depth-16 chain is only ~1.5 KiB but would be read almost in full; a tiny budget stops it
    # after a small, asserted number of bytes.
    data = nested_chain(16)
    bxml = make_bxml(data, ResourceLimit(max_bytes=128))

    with pytest.raises(ResourceLimitExceeded):
        parse_bxml(bxml)
    assert bxml.bytes_read <= 128


# ---------------------------------------------------------------------------------------------
# Template expansion depth (deep sub-templates and cyclic references)
# ---------------------------------------------------------------------------------------------


def test_finite_nested_chain_parses_within_depth_boundary() -> None:
    # The deepest fixed chain stays well below the default depth limit.
    assert 16 < DEFAULT_MAX_TEMPLATE_DEPTH
    data = nested_chain(16)
    bxml = make_bxml(data)

    parse_bxml(bxml)  # must complete without raising
    assert bxml.depth_guard.depth == 0  # guard is always released after traversal


def test_deep_chain_is_stopped_by_a_tight_depth_limit() -> None:
    data = nested_chain(8)
    bxml = make_bxml(data, ResourceLimit(max_template_depth=3))

    with pytest.raises(ResourceLimitExceeded, match="depth"):
        parse_bxml(bxml)


def test_cyclic_template_reference_terminates_with_guard() -> None:
    # Without a guard this fixed ~4 KiB sample recurses until the Python stack dies; with the guard
    # it terminates deterministically at the configured depth.
    cyclic = cyclic_templates(300)
    # A fixed, small counting stream drives the cycle; no large or real malicious payload is used.
    assert len(cyclic) < 8000

    guarded = make_bxml(cyclic, ResourceLimit(max_template_depth=32))
    with pytest.raises(ResourceLimitExceeded, match="depth"):
        parse_bxml(guarded)


def test_cyclic_reference_is_unbounded_without_guard() -> None:
    # Evidence that the depth check is load-bearing: neutralising the guard lets the same fixed
    # sample run into the interpreter's own recursion ceiling instead of stopping cleanly.
    cyclic = cyclic_templates(400)
    bxml = make_bxml(cyclic, ResourceLimit(max_template_depth=10**9))
    bxml.depth_guard.__class__  # noqa: B018 - document the object being neutralised below

    class _Disabled:
        depth = 0

        def __enter__(self) -> _Disabled:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

    bxml.depth_guard = _Disabled()
    default_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(400)
    try:
        with pytest.raises(RecursionError):
            parse_bxml(bxml)
    finally:
        sys.setrecursionlimit(default_limit)


# ---------------------------------------------------------------------------------------------
# Substitution value count (counting stream, not a big payload)
# ---------------------------------------------------------------------------------------------


def test_huge_descriptor_count_is_rejected_before_looping() -> None:
    data = huge_descriptor_count()
    bxml = make_bxml(data, ResourceLimit(max_substitutions=1024))

    with pytest.raises(ResourceLimitExceeded, match="substitution"):
        parse_bxml(bxml)
    # The forged count never drove the descriptor loop: only a handful of bytes were consumed.
    assert bxml.bytes_read < len(data)


def test_descriptor_count_limit_distinguishes_clean_eof() -> None:
    # Same template, but the forged count field is followed by genuine end-of-stream. With a budget
    # larger than the forged count the parser reaches the real stream end and raises EOFError,
    # proving the limit exception and the EOF condition are not conflated.
    data = huge_descriptor_count()
    bxml = make_bxml(data, ResourceLimit(max_substitutions=10**10))

    with pytest.raises(EOFError):
        parse_bxml(bxml)


# ---------------------------------------------------------------------------------------------
# Output field count
# ---------------------------------------------------------------------------------------------


def test_field_limit_is_enforced_on_a_genuine_record(tmp_path: Path) -> None:
    target = tmp_path / "sample.evtx"
    target.write_bytes(EVTX_PATH.read_bytes())

    with target.open("rb") as fh:
        evtx = Evtx(fh, limits=ResourceLimit(max_fields=3))
        records = list(evtx)

    # The limit is crossed while expanding the first record; that chunk is marked limited and its
    # oversized record is dropped rather than emitted as a partial result.
    assert records == []
    assert evtx.limited_chunks == [0]
    assert evtx.malformed_chunks == []


def test_default_field_limit_accepts_genuine_records() -> None:
    with EVTX_PATH.open("rb") as fh:
        records = list(Evtx(fh))
    assert len(records) == 5
    assert all(len(record) <= DEFAULT_MAX_FIELDS for record in records)


# ---------------------------------------------------------------------------------------------
# Corruption vs limit vs clean EOF classification
# ---------------------------------------------------------------------------------------------


def test_unknown_bxml_token_is_corruption_not_a_limit() -> None:
    # Replace the template instance token of the depth-1 chain root with an unknown token (0x10).
    data = bytearray(nested_chain(1))
    template_token_index = data.index(c_bxml.uint8.dumps(0x0C))
    data[template_token_index] = 0x10
    bxml = make_bxml(bytes(data))

    with pytest.raises(BxmlException, match="Unknown BXML token"):
        parse_bxml(bxml)


def test_three_termination_reasons_are_distinct() -> None:
    # Corruption.
    corrupt = bytearray(nested_chain(1))
    corrupt[corrupt.index(c_bxml.uint8.dumps(0x0C))] = 0x10
    with pytest.raises(BxmlException):
        parse_bxml(make_bxml(bytes(corrupt)))

    # Configuration limit.
    with pytest.raises(ResourceLimitExceeded):
        parse_bxml(make_bxml(nested_chain(8), ResourceLimit(max_template_depth=2)))

    # Clean end of stream.
    with pytest.raises(EOFError):
        parse_bxml(make_bxml(huge_descriptor_count(), ResourceLimit(max_substitutions=10**10)))


# ---------------------------------------------------------------------------------------------
# Recovery: a marked bad chunk does not poison the next independent valid chunk
# ---------------------------------------------------------------------------------------------


def _good_chunk() -> bytes:
    return EVTX_PATH.read_bytes()[HEADER_SIZE : HEADER_SIZE + CHUNK_SIZE]


def _corrupt_chunk() -> bytes:
    chunk = bytearray(_good_chunk())
    # First record lives at offset 0x200; its BinXML starts 24 bytes later with a 4-byte fragment
    # header, immediately followed by the template instance token (0x0C) at 0x21C. Flip it to an
    # unknown token so the record is structurally invalid while the chunk magic stays intact.
    assert chunk[0x21C] == 0x0C
    chunk[0x21C] = 0x10
    return bytes(chunk)


def _evtx_with_chunks(header: bytes, chunks: list[bytes]) -> bytes:
    return header + b"".join(chunks)


def test_bad_chunk_is_marked_and_next_valid_chunk_still_parsed(tmp_path: Path) -> None:
    source = EVTX_PATH.read_bytes()
    header = source[:HEADER_SIZE]
    good = _good_chunk()
    assembled = _evtx_with_chunks(header, [good, _corrupt_chunk(), good])
    log_path = tmp_path / "good_bad_good.evtx"
    log_path.write_bytes(assembled)

    with log_path.open("rb") as fh:
        evtx = Evtx(fh)
        records = list(evtx)

    # Chunks 0 and 2 are independent and each contributes five records; the corrupt chunk is marked
    # and skipped rather than aborting the whole file.
    assert len(records) == 10
    assert evtx.malformed_chunks == [1]
    assert evtx.limited_chunks == []


def test_records_confirmed_before_a_limit_are_preserved(tmp_path: Path) -> None:
    source = EVTX_PATH.read_bytes()
    header = source[:HEADER_SIZE]
    good = _good_chunk()
    # A self-contained depth bomb positioned at the normal record offset, so its absolute BinXML
    # offsets match a genuine first record in a chunk.
    bomb_record = _record_from_bxml(nested_chain(40, absolute_base=0x218))
    bomb_chunk = _chunk_with_record(bomb_record)
    log_path = tmp_path / "limited.evtx"
    log_path.write_bytes(header + good + bomb_chunk)

    with log_path.open("rb") as fh:
        evtx = Evtx(fh, limits=ResourceLimit(max_template_depth=8))
        records = list(evtx)

    # The five fully validated records from the first chunk survive; only the limited chunk is lost.
    assert len(records) == 5
    assert evtx.limited_chunks == [1]
    assert evtx.malformed_chunks == []


def test_truncated_final_chunk_is_clean_eof(tmp_path: Path) -> None:
    source = EVTX_PATH.read_bytes()
    header = source[:HEADER_SIZE]
    good = _good_chunk()
    log_path = tmp_path / "truncated.evtx"
    # A trailing partial chunk (< 64 KiB) must simply stop iteration, not be marked malformed.
    log_path.write_bytes(header + good + good[:1000])

    with log_path.open("rb") as fh:
        evtx = Evtx(fh)
        records = list(evtx)

    assert len(records) == 5
    assert evtx.malformed_chunks == []
    assert evtx.limited_chunks == []


def test_half_parsed_event_is_never_yielded(tmp_path: Path) -> None:
    # ElfChnk.read must not swallow an exception and emit the partial record: it propagates after
    # only complete, timestamp-validated records have been yielded.
    chunk = _corrupt_chunk()
    elf = ElfChnk(chunk)
    yielded: list = []
    with pytest.raises(MalformedElfChnkException):
        for record in elf.read():
            yielded.append(record)
    # The first record is the corrupted one, so nothing partial is delivered from this chunk.
    assert yielded == []


# ---------------------------------------------------------------------------------------------
# Mutation evidence: removing a boundary check makes a test fail
# ---------------------------------------------------------------------------------------------


def test_removing_depth_guard_reopens_unbounded_recursion(monkeypatch: pytest.MonkeyPatch) -> None:
    cyclic = cyclic_templates(400)
    limit = ResourceLimit(max_template_depth=32)

    # With the boundary check in place the same fixed sample stops cleanly at depth 32.
    with pytest.raises(ResourceLimitExceeded, match="depth"):
        parse_bxml(make_bxml(cyclic, limit))

    # Neutralise the guard the production parser relies on for both read and expansion phases.
    class _Disabled:
        depth = 0

        def __enter__(self) -> _Disabled:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

    bxml = make_bxml(cyclic, limit)
    monkeypatch.setattr(bxml, "depth_guard", _Disabled())

    original = sys.getrecursionlimit()
    sys.setrecursionlimit(400)
    try:
        # With the check removed the configured depth=32 limit is ignored and the fixed sample runs
        # into RecursionError, which is the observable evidence that the check is load-bearing.
        with pytest.raises(RecursionError):
            parse_bxml(bxml)
    finally:
        sys.setrecursionlimit(original)


def test_removing_substitution_check_allows_forged_count(monkeypatch: pytest.MonkeyPatch) -> None:
    limit = ResourceLimit(max_substitutions=1024)

    # With the check in place the forged count is rejected before any descriptor loop runs.
    with pytest.raises(ResourceLimitExceeded, match="substitution"):
        parse_bxml(make_bxml(huge_descriptor_count(), limit))

    bxml = make_bxml(huge_descriptor_count(), limit)
    # Remove the accounting hook; the forged 0xFFFFFFFF count is then trusted and the parser walks
    # the (empty) stream until EOF instead of rejecting the configuration violation.
    monkeypatch.setattr(bxml, "account_substitutions", lambda count: None)

    with pytest.raises(EOFError):
        parse_bxml(bxml)


def test_removing_byte_check_allows_unbounded_reads() -> None:
    data = nested_chain(16)
    limit = ResourceLimit(max_bytes=8)

    # With the byte budget the bounded parse stops almost immediately.
    with pytest.raises(ResourceLimitExceeded):
        parse_bxml(make_bxml(data, limit))

    # The same bytes parse fully once the budget is lifted, proving the budget alone was stopping it.
    raw = BytesIO(data)
    unbounded = Bxml(raw, BytesIO(b""), ResourceLimit(max_bytes=10**9))
    unbounded.data_offset = DATA_OFFSET
    unbounded.templates = {}
    unbounded.set_name_reader(EvtxNameReader(unbounded))
    parse_bxml(unbounded)
    # It consumes a substantial, bounded portion of the stream (trailing bytes may be skipped by
    # seeks rather than reads); crucially it completes where the 8-byte budget could not.
    assert unbounded.bytes_read > len(data) // 2


# ---------------------------------------------------------------------------------------------
# Log file bytes are unchanged before and after processing
# ---------------------------------------------------------------------------------------------


def test_log_file_bytes_are_identical_after_processing(tmp_path: Path) -> None:
    log_path = tmp_path / "immutable.evtx"
    original = EVTX_PATH.read_bytes()
    log_path.write_bytes(original)
    digest_before = __import__("hashlib").sha256(original).digest()

    with log_path.open("rb") as fh:
        list(Evtx(fh))  # normal parse
    with log_path.open("rb") as fh:
        list(Evtx(fh, limits=ResourceLimit(max_fields=1)))  # limit-tripping parse
    with log_path.open("rb") as fh:
        list(ElfChnk(fh.read(CHUNK_SIZE)).read()) if False else None

    digest_after = __import__("hashlib").sha256(log_path.read_bytes()).digest()
    assert digest_after == digest_before
    assert log_path.read_bytes() == original


# ---------------------------------------------------------------------------------------------
# Helpers for wrapping BinXML samples into EVTX records / chunks
# ---------------------------------------------------------------------------------------------


def _record_from_bxml(bxml_data: bytes, record_id: int = 1) -> bytes:
    size = RECORD_HEADER_SIZE + len(bxml_data) + 4
    header = struct.pack("<IIQQ", 0x2A2A, size, record_id, 0)
    return header + bxml_data + struct.pack("<I", size)


def _chunk_with_record(record: bytes) -> bytes:
    chunk = bytearray(CHUNK_SIZE)
    chunk[0:8] = b"ElfChnk\x00"
    # free_space_offset must not equal 512, otherwise the chunk is treated as empty on errors.
    struct.pack_into("<I", chunk, 0x18, 512 + len(record))
    chunk[512 : 512 + len(record)] = record
    return bytes(chunk)
