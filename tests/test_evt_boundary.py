"""Boundary regression tests for forensic reads of legacy EVT ring logs.

The ground truth for every synthetic file below is derived from explicit record
numbers and byte positions recorded while the file is built. ``Evt`` output is
never used as the oracle: a separate Length-field chain walk recomputes which
records survive overwrite and in which logical order they must be presented.
When a file does not contain enough information to recover a unique order, the
parser is expected to raise an explanatory error instead of inventing a
continuous timeline.
"""
from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from dissect.eventlog.evt.c_evt import c_evt
from dissect.eventlog.evt.evt import DIRTY_NEEDLE, EVENTLOGRECORD_SIZE, Evt, find_needle
from dissect.eventlog.exceptions import AmbiguousEofRecordError, Error, MalformedEofRecordError

if TYPE_CHECKING:
    from collections.abc import Callable

HEADER_SIZE = 0x30
EOF_SIZE = len(c_evt.EVENTLOGEOF)
DIRTY_FLAG = c_evt.ELF_LOGFILE_HEADER_DIRTY
WRAP_FLAG = c_evt.ELF_LOGFILE_HEADER_WRAP

# Byte offsets within an EVENTLOGRECORD (54-byte header).
RECORD_NUMBER_OFFSET = 0x08
DATA_LENGTH_OFFSET = 0x30
DATA_OFFSET_FIELD = 0x34

# A deliberately generous bound used only to prove iterator termination; a
# correct file yields exactly len(expected_order) records.
TERMINATION_SLACK = 16


def pack_header(start: int, end: int, current: int, oldest: int, max_size: int, flags: int) -> bytes:
    return struct.pack(
        "<I4s10I",
        HEADER_SIZE,
        b"LfLe",
        1,
        1,
        start,
        end,
        current,
        oldest,
        max_size,
        flags,
        604800,
        HEADER_SIZE,
    )


def pack_eof(begin: int, end: int, current: int, oldest: int) -> bytearray:
    return bytearray(
        struct.pack(
            "<10I",
            EOF_SIZE,
            0x11111111,
            0x22222222,
            0x33333333,
            0x44444444,
            begin,
            end,
            current,
            oldest,
            EOF_SIZE,
        )
    )


def _load_template_blobs(sample_path: Path) -> dict[int, bytes]:
    data = sample_path.read_bytes()
    blobs = {}
    position = HEADER_SIZE
    while position < len(data) - EOF_SIZE:
        length, _, record_number = struct.unpack_from("<III", data, position)
        if length < EVENTLOGRECORD_SIZE:
            break
        blobs[record_number] = bytes(data[position : position + length])
        position += length
    return blobs


@dataclass(frozen=True)
class Placement:
    """Byte-level location of one record in the ring."""

    record_number: int
    intervals: tuple[tuple[int, int], ...]
    length: int
    token: int

    @property
    def is_split(self) -> bool:
        return len(self.intervals) > 1

    @property
    def first_offset(self) -> int:
        return self.intervals[0][0]


@dataclass
class GroundTruth:
    """Forensic oracle built from write history, not from Evt output."""

    capacity: int
    placements: list[Placement]
    eof_offset: int
    survivors: list[int]
    begin_offset: int

    @property
    def expected_order(self) -> list[int]:
        return list(self.survivors)

    def placement(self, record_number: int) -> Placement:
        return next(p for p in self.placements if p.record_number == record_number)


class EvtRingBuilder:
    """Synthesises EVT ring files while tracking exact byte ownership.

    Each write gets a monotonically increasing ownership token stamped over its
    bytes. A record survives overwrite only when every byte still carries its
    token. This yields ground truth independent of the parser under test.
    """

    def __init__(self, capacity: int, templates: dict[int, bytes]):
        self.capacity = capacity
        self.buffer = bytearray(capacity)
        self.buffer[0:HEADER_SIZE] = pack_header(HEADER_SIZE, HEADER_SIZE, 1, 0, capacity, 0)
        self.tokens = bytearray(capacity)
        self.next_token = 1
        self.write_position = HEADER_SIZE
        self.record_number = 0
        self.placements: list[Placement] = []
        self.templates = templates
        self.eof_offset: int | None = None

    def _stamp(self, data: bytes, position: int) -> list[tuple[int, int]]:
        intervals = []
        remaining = data
        cursor = position
        token = self.next_token
        while remaining:
            chunk_size = min(len(remaining), self.capacity - cursor)
            self.buffer[cursor : cursor + chunk_size] = remaining[:chunk_size]
            self.tokens[cursor : cursor + chunk_size] = bytes([token]) * chunk_size
            intervals.append((cursor, chunk_size))
            remaining = remaining[chunk_size:]
            cursor = HEADER_SIZE if cursor + chunk_size >= self.capacity else cursor + chunk_size
        self.next_token += 1
        self.write_position = cursor
        return intervals

    def add_record(self, blob: bytes | None = None) -> int:
        self.record_number += 1
        if blob is None:
            template = bytearray(self.templates[((self.record_number - 1) % len(self.templates)) + 1])
            struct.pack_into("<I", template, 8, self.record_number)
            blob = bytes(template)
        intervals = self._stamp(blob, self.write_position)
        self.placements.append(
            Placement(self.record_number, tuple(intervals), len(blob), self.next_token - 1)
        )
        return self.record_number

    def add_records(self, count: int) -> None:
        for _ in range(count):
            self.add_record()

    def write_eof(self, position: int | None = None) -> int:
        if position is None:
            position = self.write_position
            if self.capacity - position < EOF_SIZE:
                position = HEADER_SIZE
        self.buffer[position : position + EOF_SIZE] = pack_eof(0, 0, 0, 0)
        self.tokens[position : position + EOF_SIZE] = bytes([self.next_token]) * EOF_SIZE
        self.next_token += 1
        self.write_position = position + EOF_SIZE
        self.eof_offset = position
        return position

    def place_bytes(self, position: int, data: bytes) -> None:
        self.buffer[position : position + len(data)] = data

    def _surviving_placements(self) -> list[Placement]:
        alive = []
        for placement in self.placements:
            intact = all(
                all(self.tokens[offset + index] == placement.token for index in range(size))
                for offset, size in placement.intervals
            )
            if intact:
                alive.append(placement)
        return alive

    def ground_truth(self) -> GroundTruth:
        if self.eof_offset is None:
            raise ValueError("EOF record must be written before deriving ground truth")
        alive = self._surviving_placements()
        survivors = [placement.record_number for placement in alive]
        if survivors and survivors != list(range(survivors[0], survivors[-1] + 1)):
            raise AssertionError("Builder invariant violated: surviving record numbers must be contiguous")
        begin_offset = alive[0].first_offset if alive else self.eof_offset
        return GroundTruth(self.capacity, self.placements, self.eof_offset, survivors, begin_offset)

    def finalize(
        self,
        truth: GroundTruth,
        dirty: bool,
        header_mutator: Callable[[bytearray], bytearray] | None = None,
        eof_mutator: Callable[[bytearray], bytearray] | None = None,
        end_record_override: int | None = None,
    ) -> bytes:
        current = self.record_number + 1
        oldest = truth.survivors[0] if truth.survivors else current
        end_record = truth.eof_offset if end_record_override is None else end_record_override
        eof = pack_eof(truth.begin_offset, end_record, current, oldest)
        if eof_mutator is not None:
            eof = eof_mutator(bytearray(eof))
        self.buffer[truth.eof_offset : truth.eof_offset + EOF_SIZE] = eof

        if dirty:
            header = pack_header(HEADER_SIZE, HEADER_SIZE, 1, 0, self.capacity, DIRTY_FLAG)
        else:
            header = pack_header(truth.begin_offset, end_record, current, oldest, self.capacity, WRAP_FLAG)
        if header_mutator is not None:
            header = header_mutator(bytearray(header))
        self.buffer[0:HEADER_SIZE] = header
        return bytes(self.buffer)


def _resolve_record_relative_offset(placement: Placement, relative: int) -> int:
    """Map a record-relative offset to an absolute file offset, honouring splits."""
    remaining = relative
    for offset, size in placement.intervals:
        if remaining <= size:
            return offset + remaining
        remaining -= size
    raise AssertionError("relative offset falls outside the record placement")


def _read_wrapped_dword(image: bytes, position: int, capacity: int) -> int | None:
    available = capacity - position
    if available >= 4:
        return struct.unpack_from("<I", image, position)[0]
    if available <= 0 or HEADER_SIZE + (4 - available) > capacity:
        return None
    raw = image[position : position + available] + image[HEADER_SIZE : HEADER_SIZE + (4 - available)]
    return struct.unpack("<I", raw)[0]


def _chain_walk_offsets(image: bytes, begin: int, count: int, capacity: int) -> list[int]:
    """Independent oracle: walk Length fields exactly as the on-disk format links records.

    Returns the starting offset of each of the ``count`` records; the walk is not
    continued past the final record because that position is the EOF EndRecord
    (which may sit inside a free-area gap rather than at a readable header).
    """
    offsets = []
    position = begin
    for _ in range(count):
        offsets.append(position)
        length = _read_wrapped_dword(image, position, capacity)
        if length is None or (length != EOF_SIZE and length < EVENTLOGRECORD_SIZE):
            raise AssertionError(f"unreadable record length at {position:#x}")
        next_position = position + length
        if next_position > capacity:
            next_position = HEADER_SIZE + (length - (capacity - position))
        elif next_position == capacity:
            next_position = HEADER_SIZE
        position = next_position
    return offsets


def assert_matches_ground_truth(
    image: bytes, truth: GroundTruth, expected_end_offset: int | None = None
) -> None:
    """Checks set, multiplicity, logical order, byte positions and termination."""
    capacity = len(image)
    expected_end = truth.eof_offset if expected_end_offset is None else expected_end_offset

    # Oracle based purely on the format: the chain starting at BeginRecord must
    # visit every survivor's first byte in ascending record-number order.
    chain_offsets = _chain_walk_offsets(image, truth.begin_offset, len(truth.survivors), capacity)
    assert chain_offsets == [truth.placement(number).first_offset for number in truth.expected_order]
    assert chain_offsets[-1:]  # non-empty sanity guard

    evt = Evt(io.BytesIO(image))
    assert evt.start_offset == truth.begin_offset
    assert evt.end_offset == expected_end

    collected: list[int] = []
    for record in evt:
        collected.append(record.RecordNumber)
        if len(collected) > len(truth.expected_order) + TERMINATION_SLACK:
            pytest.fail("iterator did not terminate within the expected record bound")

    # Exact ordered sequence covers set, occurrence count (no duplicates) and order.
    assert collected == truth.expected_order
    assert set(collected) == set(truth.expected_order)
    assert len(collected) == len(truth.expected_order)


def build_ring(
    capacity: int,
    record_count: int,
    dirty: bool,
    templates: dict[int, bytes],
    eof_mutator: Callable[[bytearray], bytearray] | None = None,
    header_mutator: Callable[[bytearray], bytearray] | None = None,
) -> tuple[bytes, GroundTruth]:
    builder = EvtRingBuilder(capacity, templates)
    builder.add_records(record_count)
    builder.write_eof()
    truth = builder.ground_truth()
    image = builder.finalize(truth, dirty=dirty, eof_mutator=eof_mutator, header_mutator=header_mutator)
    return image, truth


def find_split_capacity(templates: dict[int, bytes], record_count: int) -> int:
    for capacity in range(HEADER_SIZE + 0x400, HEADER_SIZE + 0x900):
        builder = EvtRingBuilder(capacity, templates)
        builder.add_records(record_count)
        builder.write_eof()
        truth = builder.ground_truth()
        if any(truth.placement(number).is_split for number in truth.survivors):
            return capacity
    raise AssertionError("no capacity produced a record spanning the tail free area")


@pytest.fixture(scope="module")
def templates() -> dict[int, bytes]:
    sample_path = Path(__file__).parent / "_data" / "TestLog.evt"
    return _load_template_blobs(sample_path)


# ---------------------------------------------------------------------------
# Baseline: the shipped normal and dirty samples
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("log_filename", ["_data/TestLog.evt", "_data/TestLog-dirty.evt"])
def test_shipped_samples_match_explicit_order(
    get_absolute_path: Callable[[str], Path], log_filename: str
) -> None:
    # Ground truth established from the sample's own byte layout:
    # records 1..5 occupy 0x30..0x3b0 and the EOF marker sits at 0x3b0.
    image = get_absolute_path(log_filename).read_bytes()
    eof_offset = len(image) - EOF_SIZE if log_filename.endswith("TestLog.evt") else 0x3B0
    assert struct.unpack_from("<I", image, eof_offset)[0] == EOF_SIZE

    truth = GroundTruth(
        capacity=len(image),
        placements=[
            Placement(number, ((offset, 0),), 0, number)
            for number, offset in zip(range(1, 6), (0x30, 0xD8, 0x174, 0x214, 0x2E0), strict=True)
        ],
        eof_offset=eof_offset,
        survivors=[1, 2, 3, 4, 5],
        begin_offset=0x30,
    )
    assert_matches_ground_truth(image, truth)


# ---------------------------------------------------------------------------
# Ring wrap-around: split records and oldest-record position drift
# ---------------------------------------------------------------------------


def test_dirty_ring_record_spanning_tail_free_area(templates: dict[int, bytes]) -> None:
    capacity = find_split_capacity(templates, record_count=12)
    builder = EvtRingBuilder(capacity, templates)
    builder.add_records(12)
    builder.write_eof()
    truth = builder.ground_truth()

    split_numbers = [number for number in truth.survivors if truth.placement(number).is_split]
    assert split_numbers, "fixture must contain at least one tail-spanning record"
    split = truth.placement(split_numbers[0])
    # The split really straddles the physical end and the post-header region.
    assert split.intervals[0][0] + split.intervals[0][1] == capacity
    assert split.intervals[1][0] == HEADER_SIZE

    image = builder.finalize(truth, dirty=True)
    assert_matches_ground_truth(image, truth)


def test_clean_ring_record_spanning_tail_free_area(templates: dict[int, bytes]) -> None:
    capacity = find_split_capacity(templates, record_count=12)
    builder = EvtRingBuilder(capacity, templates)
    builder.add_records(12)
    builder.write_eof()
    truth = builder.ground_truth()
    assert any(truth.placement(number).is_split for number in truth.survivors)

    image = builder.finalize(truth, dirty=False)
    assert_matches_ground_truth(image, truth)


def test_oldest_record_position_changes_across_multiple_wraps(templates: dict[int, bytes]) -> None:
    observed_begins: set[int] = set()
    last_order: list[int] = []
    for record_count in (12, 18, 24, 30):
        image, truth = build_ring(0x500, record_count, dirty=True, templates=templates)
        observed_begins.add(truth.begin_offset)
        last_order = truth.expected_order
        assert_matches_ground_truth(image, truth)

    # Multiple wraps must move the oldest record around instead of pinning it at 0x30.
    assert len(observed_begins) > 1
    assert all(offset >= HEADER_SIZE for offset in observed_begins)
    # The logical order remains a contiguous, ascending record-number window.
    assert last_order == list(range(last_order[0], last_order[-1] + 1))


def test_tail_gap_between_last_record_and_eof_is_skipped(templates: dict[int, bytes]) -> None:
    builder = EvtRingBuilder(0x900, templates)
    builder.add_records(5)
    last_record_end = builder.write_position
    # Reserve a zero-filled free area, then place the EOF marker inside it.
    # EndRecord still names the end of the last record so the Length chain and
    # the EOF metadata describe the same recoverable range.
    eof_position = last_record_end + 0x60
    builder.write_eof(position=eof_position)
    truth = builder.ground_truth()
    assert eof_position - last_record_end > EOF_SIZE

    image = builder.finalize(truth, dirty=True, end_record_override=last_record_end)
    assert_matches_ground_truth(image, truth, expected_end_offset=last_record_end)


# ---------------------------------------------------------------------------
# Header metadata vs EOF record disagreement
# ---------------------------------------------------------------------------


def test_dirty_header_ignored_in_favour_of_recovered_eof(templates: dict[int, bytes]) -> None:
    builder = EvtRingBuilder(0x400, templates)
    builder.add_records(12)
    builder.write_eof()
    truth = builder.ground_truth()
    # Dirty header intentionally carries placeholder values that disagree with the EOF.
    image = builder.finalize(truth, dirty=True)
    header = struct.unpack_from("<12I", image, 0)
    assert header[4] == HEADER_SIZE and header[5] == HEADER_SIZE

    assert_matches_ground_truth(image, truth)


def test_clean_stale_header_recovers_full_chain_via_eof_marker(templates: dict[int, bytes]) -> None:
    builder = EvtRingBuilder(0x400, templates)
    builder.add_records(12)
    builder.write_eof()
    truth = builder.ground_truth()
    assert truth.begin_offset != HEADER_SIZE

    def stale_header(header: bytearray) -> bytearray:
        # Claim the oldest record sits right after the header; that region now
        # holds the continuation of a wrapped record followed by zeroed space.
        struct.pack_into("<I", header, 4 * 4, HEADER_SIZE)
        struct.pack_into("<I", header, 5 * 4, truth.eof_offset)
        return header

    image = builder.finalize(truth, dirty=False, header_mutator=stale_header)

    # The lying header points into overwritten/zeroed space, but the EOF marker
    # is still reachable and its chain walk is intact. The parser must recover
    # the complete logical order rather than silently dropping every event.
    collected = [record.RecordNumber for record in Evt(io.BytesIO(image))]
    assert collected == truth.expected_order
    assert len(collected) == len(truth.survivors)


def test_eof_self_heals_walkable_chain_when_header_start_is_stale(templates: dict[int, bytes]) -> None:
    # Large ring with a zeroed free area between the records and the EOF marker.
    builder = EvtRingBuilder(0x1000, templates)
    builder.add_records(6)
    last_record_end = builder.write_position
    eof_position = last_record_end + 0x80
    builder.write_eof(position=eof_position)
    truth = builder.ground_truth()

    # A non-dirty header whose StartOffset points into the zeroed gap: the first
    # traversal yields nothing there, then reaches the EOF marker, whose intact
    # chain recovers the real StartOffset.
    def gap_start_header(header: bytearray) -> bytearray:
        struct.pack_into("<I", header, 4 * 4, last_record_end)
        return header

    image = builder.finalize(
        truth, dirty=False, header_mutator=gap_start_header, end_record_override=last_record_end
    )
    collected = [record.RecordNumber for record in Evt(io.BytesIO(image))]
    assert collected == truth.expected_order
    assert len(collected) == len(truth.survivors)


def test_header_start_offset_out_of_range_rejected(templates: dict[int, bytes]) -> None:
    builder = EvtRingBuilder(0x600, templates)
    builder.add_records(4)
    builder.write_eof()
    truth = builder.ground_truth()

    def bad_header(header: bytearray) -> bytearray:
        struct.pack_into("<I", header, 4 * 4, len(builder.buffer) + 0x100)
        return header

    image = builder.finalize(truth, dirty=False, header_mutator=bad_header)
    with pytest.raises(MalformedEofRecordError):
        Evt(io.BytesIO(image))


# ---------------------------------------------------------------------------
# Corrupt floating EOF records in dirty files
# ---------------------------------------------------------------------------


def test_dirty_file_without_any_eof_rejected(templates: dict[int, bytes]) -> None:
    builder = EvtRingBuilder(0x600, templates)
    builder.add_records(4)
    builder.buffer[0:HEADER_SIZE] = pack_header(HEADER_SIZE, HEADER_SIZE, 1, 0, builder.capacity, DIRTY_FLAG)
    with pytest.raises(MalformedEofRecordError):
        Evt(io.BytesIO(bytes(builder.buffer)))


def test_corrupt_eof_signature_rejected(templates: dict[int, bytes]) -> None:
    def clobber_magic(eof: bytearray) -> bytearray:
        eof[4:8] = b"\xAA\xBB\xCC\xDD"
        return eof

    image, _ = build_ring(0x600, 6, dirty=True, templates=templates, eof_mutator=clobber_magic)
    with pytest.raises(MalformedEofRecordError):
        Evt(io.BytesIO(image))


def test_eof_begin_record_out_of_range_rejected(templates: dict[int, bytes]) -> None:
    def bad_begin(eof: bytearray) -> bytearray:
        struct.pack_into("<I", eof, 5 * 4, 0xFFFF)
        return eof

    image, _ = build_ring(0x600, 6, dirty=True, templates=templates, eof_mutator=bad_begin)
    with pytest.raises(MalformedEofRecordError):
        Evt(io.BytesIO(image))


def test_eof_end_record_breaks_record_chain_rejected(templates: dict[int, bytes]) -> None:
    def bad_end(eof: bytearray) -> bytearray:
        struct.pack_into("<I", eof, 6 * 4, HEADER_SIZE + 0x10)
        return eof

    image, truth = build_ring(0x600, 8, dirty=True, templates=templates, eof_mutator=bad_end)
    # Sanity: the same ring without mutation would recover exactly these records.
    healthy, healthy_truth = build_ring(0x600, 8, dirty=True, templates=templates)
    assert_matches_ground_truth(healthy, healthy_truth)
    with pytest.raises(MalformedEofRecordError):
        Evt(io.BytesIO(image))
    assert truth.survivors  # the records are still on disk; only the metadata lies


def test_eof_record_size_tail_mismatch_rejected(templates: dict[int, bytes]) -> None:
    def bad_tail(eof: bytearray) -> bytearray:
        struct.pack_into("<I", eof, 9 * 4, 0x99)
        return eof

    image, _ = build_ring(0x600, 6, dirty=True, templates=templates, eof_mutator=bad_tail)
    with pytest.raises(MalformedEofRecordError):
        Evt(io.BytesIO(image))


def test_eof_record_number_span_inverted_rejected(templates: dict[int, bytes]) -> None:
    def inverted_span(eof: bytearray) -> bytearray:
        struct.pack_into("<I", eof, 7 * 4, 1)  # CurrentRecordNumber
        struct.pack_into("<I", eof, 8 * 4, 9)  # OldestRecordNumber
        return eof

    image, _ = build_ring(0x600, 6, dirty=True, templates=templates, eof_mutator=inverted_span)
    with pytest.raises(MalformedEofRecordError):
        Evt(io.BytesIO(image))


# ---------------------------------------------------------------------------
# EOF-like markers inside record payloads
# ---------------------------------------------------------------------------


def test_payload_eof_marker_in_dirty_file_does_not_duplicate_or_lose(templates: dict[int, bytes]) -> None:
    builder = EvtRingBuilder(0x900, templates)
    builder.add_records(3)

    carrier = bytearray(templates[4])
    struct.pack_into("<I", carrier, RECORD_NUMBER_OFFSET, 4)
    data_offset = struct.unpack_from("<I", carrier, DATA_OFFSET_FIELD)[0]
    data_length = struct.unpack_from("<I", carrier, DATA_LENGTH_OFFSET)[0]
    carrier[data_offset : data_offset + data_length] = DIRTY_NEEDLE + b"\x00" * (
        data_length - len(DIRTY_NEEDLE)
    )
    carrier_number = builder.add_record(bytes(carrier))
    builder.add_records(2)
    builder.write_eof()
    truth = builder.ground_truth()

    image = builder.finalize(truth, dirty=True)
    needle_hits = list(find_needle(io.BytesIO(image), DIRTY_NEEDLE))
    payload_hit = _resolve_record_relative_offset(truth.placement(carrier_number), data_offset)
    assert payload_hit in needle_hits and truth.eof_offset in needle_hits

    assert_matches_ground_truth(image, truth)


def test_payload_eof_marker_in_clean_file_is_ignored(templates: dict[int, bytes]) -> None:
    builder = EvtRingBuilder(0x900, templates)
    builder.add_records(3)
    carrier = bytearray(templates[4])
    struct.pack_into("<I", carrier, RECORD_NUMBER_OFFSET, 4)
    data_offset = struct.unpack_from("<I", carrier, DATA_OFFSET_FIELD)[0]
    data_length = struct.unpack_from("<I", carrier, DATA_LENGTH_OFFSET)[0]
    carrier[data_offset : data_offset + data_length] = DIRTY_NEEDLE + b"\x00" * (
        data_length - len(DIRTY_NEEDLE)
    )
    builder.add_record(bytes(carrier))
    builder.add_records(2)
    builder.write_eof()
    truth = builder.ground_truth()

    image = builder.finalize(truth, dirty=False)
    assert_matches_ground_truth(image, truth)


def test_two_conflicting_valid_eofs_produce_explicit_ambiguity(templates: dict[int, bytes]) -> None:
    builder = EvtRingBuilder(0x2000, templates)

    # Chain A: records 1..4 followed by EOF A.
    builder.add_records(4)
    eof_a = builder.write_position
    chain_a_begin = builder.placements[0].first_offset
    builder.write_eof(position=eof_a)

    # Chain B: a disjoint sequence (records 10..13) followed by EOF B.
    builder.record_number = 9
    builder.add_records(4)
    eof_b = builder.write_position
    chain_b_begin = builder.placements[4].first_offset
    builder.write_eof(position=eof_b)
    builder.eof_offset = eof_b

    current_b = builder.record_number + 1
    builder.place_bytes(eof_a, bytes(pack_eof(chain_a_begin, eof_a, 5, 1)))
    builder.place_bytes(eof_b, bytes(pack_eof(chain_b_begin, eof_b, current_b, 10)))
    builder.buffer[0:HEADER_SIZE] = pack_header(HEADER_SIZE, HEADER_SIZE, 1, 0, builder.capacity, DIRTY_FLAG)
    image = bytes(builder.buffer)

    # Both markers are needle matches and both chains are independently walkable,
    # but they describe incompatible logical timelines, so no unique order exists.
    assert list(find_needle(io.BytesIO(image), DIRTY_NEEDLE)) == [eof_a, eof_b]
    alive = builder._surviving_placements()
    assert [placement.record_number for placement in alive] == [1, 2, 3, 4, 10, 11, 12, 13]

    with pytest.raises(AmbiguousEofRecordError):
        Evt(io.BytesIO(image))


def test_duplicate_identical_eofs_are_not_treated_as_ambiguous(templates: dict[int, bytes]) -> None:
    builder = EvtRingBuilder(0x1200, templates)
    builder.add_records(4)
    first_eof = builder.write_eof()
    # A second, byte-identical EOF copy in the trailing free area.
    second_eof = first_eof + EOF_SIZE + 0x20
    builder.place_bytes(second_eof, bytes(builder.buffer[first_eof : first_eof + EOF_SIZE]))
    builder.eof_offset = first_eof
    truth = builder.ground_truth()
    image = builder.finalize(truth, dirty=True)
    # Keep both copies identical after finalisation.
    builder.place_bytes(second_eof, bytes(image[first_eof : first_eof + EOF_SIZE]))
    image = bytes(builder.buffer)

    assert list(find_needle(io.BytesIO(image), DIRTY_NEEDLE)) == [first_eof, second_eof]
    assert_matches_ground_truth(image, truth)


# ---------------------------------------------------------------------------
# Termination and tolerable edge cases
# ---------------------------------------------------------------------------


def test_non_dirty_file_truncated_before_eof_still_yields_records(templates: dict[int, bytes]) -> None:
    image, truth = build_ring(0x800, 5, dirty=False, templates=templates)
    truncated = image[: truth.eof_offset]
    truncated_truth = GroundTruth(
        capacity=len(truncated),
        placements=truth.placements,
        eof_offset=truth.eof_offset,
        survivors=truth.survivors,
        begin_offset=truth.begin_offset,
    )
    # The header still names the original EndOffset, which now lies past EOF;
    # iteration must simply stop when the bytes run out, without duplicating.
    collected = [record.RecordNumber for record in Evt(io.BytesIO(truncated))]
    assert collected == truncated_truth.expected_order


def test_iterator_terminates_on_zero_length_tail(templates: dict[int, bytes]) -> None:
    image, truth = build_ring(0x600, 6, dirty=True, templates=templates)
    # Corrupt the byte right after the EOF region into a zero-length record trap.
    corrupted = bytearray(image)
    trap = truth.eof_offset + EOF_SIZE
    if trap + 4 <= len(corrupted):
        struct.pack_into("<I", corrupted, trap, 0)
    collected = [record.RecordNumber for record in Evt(io.BytesIO(bytes(corrupted)))]
    assert collected == truth.expected_order


def test_iterator_crosses_zero_gap_without_looping(templates: dict[int, bytes]) -> None:
    # Records, then a zeroed free area, then the EOF marker. The iterator must
    # cross the gap exactly once, recover the marker and still terminate.
    builder = EvtRingBuilder(0xC00, templates)
    builder.add_records(5)
    last_record_end = builder.write_position
    eof_position = last_record_end + 0x100
    builder.write_eof(position=eof_position)
    truth = builder.ground_truth()
    image = builder.finalize(truth, dirty=True, end_record_override=last_record_end)

    bounded = [record.RecordNumber for record in Evt(io.BytesIO(image))]
    assert bounded == truth.expected_order
    assert len(bounded) == len(truth.survivors)


def test_invalid_signature_still_raises_base_error(templates: dict[int, bytes]) -> None:
    image, _ = build_ring(0x600, 4, dirty=True, templates=templates)
    broken = bytearray(image)
    broken[4:8] = b"XXXX"
    with pytest.raises(Error):
        Evt(io.BytesIO(bytes(broken)))
