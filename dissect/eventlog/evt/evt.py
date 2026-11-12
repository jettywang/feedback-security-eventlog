# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-eventlogrecord
# https://github.com/libyal/libevt/blob/main/documentation/Windows%20Event%20Log%20(EVT)%20format.asciidoc
from __future__ import annotations

import io
import struct
from collections import namedtuple
from datetime import datetime, timezone
from typing import TYPE_CHECKING, BinaryIO

from dissect.eventlog.evt.c_evt import c_evt
from dissect.eventlog.exceptions import AmbiguousEofRecordError, Error, MalformedEofRecordError

EVENTLOGRECORD_SIZE = len(c_evt.EVENTLOGRECORD)

if TYPE_CHECKING:
    from collections.abc import Iterator

# Should be refactored to a NamedTuple, but this requires fix all typing in the project
Record = namedtuple(  # noqa: PYI024
    "Record",
    [
        "RecordNumber",
        "TimeGenerated",
        "TimeWritten",
        "EventID",
        "EventCode",
        "EventFacility",
        "EventCustomerFlag",
        "EventSeverity",
        "EventType",
        "EventCategory",
        "SourceName",
        "Computername",
        "UserSid",
        "Strings",
        "Data",
        "record",
    ],
)

BLOCK_SIZE = 4096
DIRTY_NEEDLE = b"\x28\x00\x00\x00" + (b"\x11" * 4) + (b"\x22" * 4) + (b"\x33" * 4) + (b"\x44" * 4)


class Evt:
    """Windows Event files for WinOS up until Windows XP."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        if not hasattr(fh, "size"):
            pos = fh.tell()
            fh.seek(0, io.SEEK_END)
            self.size = fh.tell()
            fh.seek(pos)
        else:
            self.size = fh.size

        self.header = c_evt.EVENTLOGHEADER(fh)

        if self.header.Signature != b"LfLe":
            raise Error("Invalid signature")

        self._post_header_offset = fh.tell()

        self.start_offset = self.header.StartOffset
        self.end_offset = self.header.EndOffset
        self.current_record_number = self.header.CurrentRecordNumber
        self.oldest_record_number = self.header.OldestRecordNumber
        self.flags = self.header.Flags

        # In the case of a "dirty" not-finalised file, the header might be outdated.
        # We can't trust header.StartOffset and header.EndOffset values, so we
        # need to look for end-of-file record
        if self._is_dirty():
            self._recover_metadata_from_floating_eof(fh)
        else:
            self._validate_header_offsets()

    def _recover_metadata_from_floating_eof(self, fh: BinaryIO) -> None:
        # A DIRTY_NEEDLE match is only a signature: it can also occur inside the
        # payload of a regular record. Validate every candidate and only accept
        # structurally sound EOF records whose record chain is fully walkable.
        # Two candidates describing different log layouts make the recovery
        # ambiguous, so refuse to pick one silently.
        candidates: list[c_evt.EVENTLOGEOF] = []
        for offset in find_needle(fh, DIRTY_NEEDLE):
            fh.seek(offset)
            eof_record = c_evt.EVENTLOGEOF(fh)
            if self._is_valid_eof_record(eof_record) and self._eof_chain_is_intact(eof_record):
                candidates.append(eof_record)

        if not candidates:
            raise MalformedEofRecordError("Dirty evt file with no valid floating EOF record")

        reference = candidates[0]
        for candidate in candidates[1:]:
            if not _same_eof_metadata(candidate, reference):
                raise AmbiguousEofRecordError(
                    f"Dirty evt file contains {len(candidates)} conflicting EOF records; "
                    "record order cannot be recovered uniquely"
                )

        self._update_meta_from_eof_record(reference)

    def _eof_chain_is_intact(self, eof_record: c_evt.EVENTLOGEOF) -> bool:
        # Independently verify the on-disk geometry instead of trusting the
        # EOF metadata: walk record Length fields from BeginRecord, honouring
        # ring wrap-around, and require the walk to land exactly on this EOF
        # marker after CurrentRecordNumber - OldestRecordNumber records.
        expected_count = eof_record.CurrentRecordNumber - eof_record.OldestRecordNumber
        if expected_count == 0:
            return eof_record.BeginRecord == eof_record.EndRecord

        position = eof_record.BeginRecord
        for _ in range(expected_count):
            if not (self._post_header_offset <= position < self.size):
                return False

            record_length = self._read_record_length(position)
            if record_length is None or record_length < EVENTLOGRECORD_SIZE:
                return False

            next_position = position + record_length
            if next_position > self.size:
                # record spans the end of the file and continues after the header
                next_position = self._post_header_offset + (record_length - (self.size - position))
            elif next_position == self.size:
                next_position = self._post_header_offset

            position = next_position

        return position == eof_record.EndRecord

    def _read_record_length(self, position: int) -> int | None:
        # A record header can itself straddle the physical end of the file;
        # reassemble the 4-byte Length across the wrap before interpreting it.
        available = self.size - position
        if available >= 4:
            return self._read_dword(position)
        if available <= 0 or self._post_header_offset + (4 - available) > self.size:
            return None
        fh = self.fh
        current = fh.tell()
        fh.seek(position)
        tail = fh.read(available)
        fh.seek(self._post_header_offset)
        head = fh.read(4 - available)
        fh.seek(current)
        return struct.unpack("<I", tail + head)[0]

    def _read_dword(self, offset: int) -> int:
        fh = self.fh
        current = fh.tell()
        fh.seek(offset)
        value = struct.unpack("<I", fh.read(4))[0]
        fh.seek(current)
        return value

    @staticmethod
    def _read_exact(fh: BinaryIO, size: int) -> bytes:
        data = fh.read(size)
        if len(data) != size:
            raise EOFError(f"requested {size} bytes but only {len(data)} available")
        return data

    def _find_eof_marker_after(self, start: int) -> int | None:
        fh = self.fh
        current = fh.tell()
        fh.seek(start)
        scan = fh.read(self.size - start)
        fh.seek(current)
        relative = scan.find(DIRTY_NEEDLE)
        if relative == -1:
            return None
        return start + relative

    def _validate_header_offsets(self) -> None:
        if not (self._post_header_offset <= self.start_offset < self.size):
            raise MalformedEofRecordError(
                f"Invalid StartOffset {self.start_offset:#x} for file of size {self.size:#x}"
            )
        if not (self._post_header_offset <= self.end_offset <= self.size):
            raise MalformedEofRecordError(
                f"Invalid EndOffset {self.end_offset:#x} for file of size {self.size:#x}"
            )

    def _is_valid_eof_record(self, eof_record: c_evt.EVENTLOGEOF) -> bool:
        if eof_record.RecordSizeBeginning != len(c_evt.EVENTLOGEOF):
            return False
        if eof_record.RecordSizeEnd != len(c_evt.EVENTLOGEOF):
            return False
        if not (self._post_header_offset <= eof_record.BeginRecord < self.size):
            return False
        if not (self._post_header_offset <= eof_record.EndRecord <= self.size):
            return False
        if eof_record.CurrentRecordNumber < eof_record.OldestRecordNumber:
            return False
        # The physical ordering of BeginRecord/EndRecord relative to each other
        # (and relative to this marker) is arbitrary after a ring wrap, so the
        # actual geometry is verified separately by _eof_chain_is_intact().
        return True

    def _is_dirty(self) -> bool:
        return self.header.Flags & c_evt.ELF_LOGFILE_HEADER_DIRTY == c_evt.ELF_LOGFILE_HEADER_DIRTY

    @staticmethod
    def _looks_like_eof_marker(eof_record: c_evt.EVENTLOGEOF) -> bool:
        return eof_record.One == 0x11111111 and eof_record.Four == 0x44444444

    def _handle_eof_record(
        self,
        eof_record: c_evt.EVENTLOGEOF,
        offset: int,
        visited_start_offsets: set[int],
        yielded_record_numbers: set[int],
        fh: BinaryIO,
    ) -> bool:
        """Return True when traversal is complete, False when a re-read is scheduled."""
        if not self._is_valid_eof_record(eof_record) or not self._eof_chain_is_intact(eof_record):
            raise MalformedEofRecordError(f"Invalid EOF record encountered at offset {offset:#x}")

        if eof_record.BeginRecord == self.start_offset and eof_record.EndRecord == self.end_offset:
            # EOF metadata matches the recovered layout, traversal is complete.
            return True

        # A re-read from a StartOffset that was already the entry point of a
        # previous pass can only repeat records; the conflicting EOF adds no
        # recoverable information, so refuse instead of duplicating the timeline.
        if eof_record.BeginRecord in visited_start_offsets and yielded_record_numbers:
            raise MalformedEofRecordError("Conflicting EOF record does not recover any additional records")

        # Recover the layout described by this EOF and re-read from its start.
        # Termination is guaranteed by the visited-start check in __iter__.
        self._update_meta_from_eof_record(eof_record)
        fh.seek(self.start_offset)
        return False

    def _update_meta_from_eof_record(self, eof_record: c_evt.EVENTLOGEOF) -> None:
        self.start_offset = eof_record.BeginRecord
        self.end_offset = eof_record.EndRecord
        self.current_record_number = eof_record.CurrentRecordNumber
        self.oldest_record_number = eof_record.OldestRecordNumber

    def __iter__(self) -> Iterator[Record]:
        fh = self.fh
        fh.seek(self.start_offset)

        # Every metadata re-read restarts traversal at a StartOffset that has
        # already been visited. Tracking visited starts guarantees termination
        # while still allowing one recovery re-read per distinct EOF record.
        visited_start_offsets = set()
        yielded_record_numbers: set[int] = set()

        next_pos = 0
        last_pos = -1

        while True:
            pos = fh.tell()

            if pos == last_pos:
                # break the loop if position is the same
                # in 2 consecutive cycles
                break

            if pos == self.start_offset:
                if self.start_offset in visited_start_offsets:
                    # this layout was already traversed, nothing new can follow
                    break
                visited_start_offsets.add(self.start_offset)

            if pos >= self.size or (self.size - pos) < 4:
                # No Length field can be read here. A record whose header starts
                # this close to the end must instead be reached after wrapping
                # back to the post-header offset.
                if self._post_header_offset == self.start_offset:
                    break
                fh.seek(self._post_header_offset)
                pos = fh.tell()

            record_length = self._read_record_length(pos)
            if record_length == 0:
                # Zero-filled free area. The only legitimate structure that can
                # follow it is the EOF marker (a new event record would have been
                # written contiguously). Locate that marker directly; otherwise
                # the recoverable chain ends here.
                marker_offset = self._find_eof_marker_after(pos)
                if marker_offset is None:
                    break
                fh.seek(marker_offset)
                continue
            if record_length is None or (
                record_length != len(c_evt.EVENTLOGEOF) and record_length < EVENTLOGRECORD_SIZE
            ):
                raise MalformedEofRecordError(
                    f"Unreadable record length at offset {pos:#x}; log metadata is inconsistent"
                )

            if pos + record_length > self.size:
                # The whole record (header included) spans the physical end and
                # continues right after the file header. Reassemble both parts
                # into a contiguous buffer before parsing.
                part1_size = self.size - pos
                part2_size = record_length - part1_size
                try:
                    fh.seek(pos)
                    data_part1 = self._read_exact(fh, part1_size)
                    fh.seek(self._post_header_offset)
                    data_part2 = self._read_exact(fh, part2_size)
                except EOFError as e:
                    raise MalformedEofRecordError(
                        f"Record at offset {pos:#x} with length {record_length} exceeds the file"
                    ) from e
                record_buffer = io.BytesIO(data_part1 + data_part2)
                next_pos = self._post_header_offset + part2_size
            else:
                try:
                    fh.seek(pos)
                    record_buffer = io.BytesIO(self._read_exact(fh, record_length))
                except EOFError as e:
                    raise MalformedEofRecordError(
                        f"Record at offset {pos:#x} with length {record_length} exceeds the file"
                    ) from e
                next_pos = pos + record_length
                if next_pos == self.size:
                    # jump back to after the header for the next record
                    next_pos = self._post_header_offset

            if record_length == len(c_evt.EVENTLOGEOF):
                record_buffer.seek(0)
                eof_record = c_evt.EVENTLOGEOF(record_buffer)
                if not self._looks_like_eof_marker(eof_record):
                    raise MalformedEofRecordError(
                        f"Record of EOF size at offset {pos:#x} lacks the EOF marker fields"
                    )
                if self._handle_eof_record(
                    eof_record, pos, visited_start_offsets, yielded_record_numbers, fh
                ):
                    break
                continue

            try:
                record = c_evt.EVENTLOGRECORD(record_buffer)
            except EOFError as e:
                raise MalformedEofRecordError(
                    f"Truncated record header encountered at offset {pos:#x}; log metadata is inconsistent"
                ) from e

            if record.UserSidOffset > self.header.MaxSize:
                # UserSidOffset is the first offset after the record header,
                # so if it is incorrect, skip the record
                fh.seek(next_pos)
                continue

            if record.RecordNumber in yielded_record_numbers:
                raise MalformedEofRecordError(
                    f"Record number {record.RecordNumber} encountered twice; ring layout is inconsistent"
                )

            try:
                parsed = parse_record(record, record_buffer)
            except EOFError as e:
                raise MalformedEofRecordError(
                    f"Truncated record body at offset {pos:#x}; log metadata is inconsistent"
                ) from e

            yielded_record_numbers.add(record.RecordNumber)

            yield parsed

            last_pos = pos
            fh.seek(next_pos)


def find_needle(fh: BinaryIO, needle: bytes) -> Iterator[int]:
    needle_len = len(needle)
    overlap_len = needle_len - 1

    # A needle that starts in the overlap of the previous block and extends past
    # the block end is reachable from both blocks, so de-duplicate reported
    # offsets. The frontier also keeps the scan progressing on small files.
    frontier = 0
    seen: set[int] = set()

    while True:
        offset = fh.tell()
        buf = fh.read(BLOCK_SIZE)
        if not buf:
            break

        block_end = offset + len(buf)
        search_from = max(0, frontier - offset)
        while True:
            relative = buf.find(needle, search_from)
            if relative == -1:
                break
            absolute = offset + relative
            if absolute not in seen:
                seen.add(absolute)
                yield absolute
            search_from = relative + 1

        if len(buf) < BLOCK_SIZE:
            break

        frontier = block_end - overlap_len
        fh.seek(frontier)


def parse_record(record: c_evt.EVENTLOGRECORD, buf: BinaryIO) -> Record:
    pos = buf.tell()

    source = c_evt.wchar[None](buf)
    computer = c_evt.wchar[None](buf)

    # pos value is a position after a record header has been read
    # but UserSidOffset, StringOffset and DataOffset are all relative
    # to the start of the record
    record_start = pos - EVENTLOGRECORD_SIZE

    sid = b""
    if record.UserSidLength > 0:
        buf.seek(record_start + record.UserSidOffset)
        sid = buf.read(record.UserSidLength)

    fields = []
    if record.StringOffset > 0:
        buf.seek(record_start + record.StringOffset)
        fields = [c_evt.wchar[None](buf) for _ in range(record.NumStrings)]

    data = b""
    if record.DataLength > 0:
        buf.seek(record_start + record.DataOffset)
        data = buf.read(record.DataLength)

    return Record(
        record.RecordNumber,
        datetime.fromtimestamp(record.TimeGenerated, tz=timezone.utc),
        datetime.fromtimestamp(record.TimeWritten, tz=timezone.utc),
        record.EventID,
        record.EventID & 0x0000FFFF,
        record.EventID & 0x0FFF0000,
        record.EventID & 0x20000000,
        record.EventID & 0xC0000000,
        record.EventType,
        record.EventCategory,
        source,
        computer,
        reprsid(sid),
        fields,
        data,
        record,
    )


def reprsid(s: bytes) -> str | None:
    if not s:
        return None

    try:
        r = "S-" + str(ord(s[0])) + "-" + str(ord(s[1])) + "-" + str(c_evt.uint48(s[2:8]))
        for i in range(8, len(s), 4):
            r += "-" + str(struct.unpack(">I", s[i : i + 4])[0])
    except Exception:
        return "S-?"
    return r


def is_eof_record(record: c_evt.EVENTLOGRECORD) -> bool:
    return (
        record.Length == len(c_evt.EVENTLOGEOF)
        and record.Reserved == 0x11111111  # _EVENTLOGEOF.One
        and record.TimeWritten == 0x44444444  # _EVENTLOGEOF.Four
    )


def _same_eof_metadata(first: c_evt.EVENTLOGEOF, second: c_evt.EVENTLOGEOF) -> bool:
    return (
        first.BeginRecord == second.BeginRecord
        and first.EndRecord == second.EndRecord
        and first.CurrentRecordNumber == second.CurrentRecordNumber
        and first.OldestRecordNumber == second.OldestRecordNumber
    )


def is_header_record(record: c_evt.EVENTLOGRECORD) -> bool:
    # https://forensicswiki.xyz/page/Windows_Event_Log_(EVT)
    return record.Length == len(c_evt.EVENTLOGHEADER) == 0x30


def parse_chunk(chunk: bytes) -> Iterator[Record]:
    """Requires a chunk that starts with EVENTLOGRECORD header."""
    buffer = io.BytesIO(chunk)
    record = c_evt.EVENTLOGRECORD(buffer)
    if is_eof_record(record) or is_header_record(record):
        return
    yield parse_record(record, buffer)
