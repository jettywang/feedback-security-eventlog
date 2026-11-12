"""Recover records from damaged EVTX chunks without changing the evidence.

The normal :class:`~dissect.eventlog.evtx.evtx.Evtx` iterator intentionally keeps its strict contract: a damaged
chunk is skipped as a whole.  This module implements the opt-in recovery path.  A candidate is only accepted when
all of the following hold:

* it starts with the ``0x2a2a`` record signature at an 8-byte aligned offset;
* the declared record size is inside the chunk's record region (and the chunk itself);
* the declared size does not reach into a following record header;
* the size stored at the end of the record equals the size stored in the header;
* the record payload is a complete, parseable BinXML fragment with a valid ``TimeCreated_SystemTime``.

Signature bytes alone are never enough.  Signatures inside another record's payload or in the chunk's free space are
therefore rejected, and accepted records are further checked against the chunk's record-ID range and last-record link.
The byte ranges that were not covered by an accepted record are returned as :class:`SkippedRange` objects with
absolute offsets and the reason why the bytes were rejected.

Recovery never writes to the source.  The report includes the source SHA-256 so it can be tied to the exact bytes
that were examined.
"""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from dissect.eventlog.bxml import Bxml, BxmlSub, EvtxNameReader, parse_bxml
from dissect.eventlog.evtx.c_evtx import c_evtx
from dissect.eventlog.utils import KeyValueCollection

if TYPE_CHECKING:
    from pathlib import Path
    from typing import BinaryIO

EVTX_FILE_HEADER_SIZE = 0x1000
EVTX_CHUNK_SIZE = 0x10000
EVTX_CHUNK_HEADER_SIZE = 0x200
EVTX_RECORD_HEADER_SIZE = 24
EVTX_RECORD_MIN_SIZE = 28
EVTX_RECORD_ALIGNMENT = 8
EVTX_RECORD_SIGNATURE = b"**\x00\x00"


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _json_value(value: Any) -> Any:
    """Convert parser values to JSON-friendly values without changing the source data."""
    if isinstance(value, BxmlSub):
        value = value.get()

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}

    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]

    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()

    if isinstance(value, bool) or value is None or isinstance(value, (int, float, str)):
        return value

    return str(value)


@dataclass(frozen=True)
class SkippedRange:
    """A contiguous range of source bytes that did not become a recovered record."""

    offset: int
    size: int
    reason: str
    chunk_index: int | None = None
    chunk_offset: int | None = None
    details: tuple[str, ...] = ()

    @property
    def end(self) -> int:
        return self.offset + self.size

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "size": self.size,
            "end": self.end,
            "chunk_index": self.chunk_index,
            "chunk_offset": self.chunk_offset,
            "reason": self.reason,
            "details": list(self.details),
        }


class RecoveredRecord(KeyValueCollection):
    """A recovered event with the evidence location and checks that justified it.

    The object is still a :class:`KeyValueCollection`, so existing event access such as ``record["EventID"]``
    continues to work.
    """

    file_offset: int
    chunk_offset: int
    chunk_index: int
    record_size: int
    record_id: int
    time_written: int
    confidence: tuple[str, ...]
    skipped_before: SkippedRange | None

    def __init__(
        self,
        record: KeyValueCollection,
        *,
        file_offset: int,
        chunk_offset: int,
        chunk_index: int,
        record_size: int,
        record_id: int,
        time_written: int,
        confidence: tuple[str, ...],
        skipped_before: SkippedRange | None = None,
    ) -> None:
        super().__init__()
        dict.update(self, record)

        self.file_offset = file_offset
        self.chunk_offset = chunk_offset
        self.chunk_index = chunk_index
        self.record_size = record_size
        self.record_id = record_id
        self.time_written = time_written
        self.confidence = confidence
        self.skipped_before = skipped_before

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_offset": self.file_offset,
            "chunk_index": self.chunk_index,
            "chunk_offset": self.chunk_offset,
            "record_size": self.record_size,
            "record_id": self.record_id,
            "time_written": self.time_written,
            "confidence": list(self.confidence),
            "skipped_before": self.skipped_before.to_dict() if self.skipped_before else None,
            "event": _json_value(self),
        }


@dataclass
class ChunkRecovery:
    """Recovery details for one (possibly partial) chunk."""

    index: int
    file_offset: int
    length: int
    expected_length: int
    header_valid: bool
    record_region_start: int
    record_region_end: int
    records: list[RecoveredRecord] = field(default_factory=list)
    skipped_ranges: list[SkippedRange] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.length == self.expected_length

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int) -> RecoveredRecord:
        return self.records[index]

    def __iter__(self) -> Any:
        return iter(self.records)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "file_offset": self.file_offset,
            "length": self.length,
            "expected_length": self.expected_length,
            "complete": self.complete,
            "header_valid": self.header_valid,
            "record_region": {
                "offset": self.file_offset + self.record_region_start,
                "size": max(0, self.record_region_end - self.record_region_start),
            },
            "record_offsets": [record.file_offset for record in self.records],
            "warnings": list(self.warnings),
        }


@dataclass
class RecoveryReport:
    """Result of an EVTX recovery run."""

    source: str | None
    file_size: int
    source_sha256: str
    records: list[RecoveredRecord] = field(default_factory=list)
    skipped_ranges: list[SkippedRange] = field(default_factory=list)
    chunks: list[ChunkRecovery] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        covered = sum(record.record_size for record in self.records)
        return {
            "mode": "recovery",
            "source": self.source,
            "file_size": self.file_size,
            "source_sha256": self.source_sha256,
            "summary": {
                "recovered_records": len(self.records),
                "skipped_ranges": len(self.skipped_ranges),
                "skipped_bytes": sum(skipped.size for skipped in self.skipped_ranges),
                "record_bytes": covered,
            },
            "records": [record.to_dict() for record in self.records],
            "skipped_ranges": [skipped.to_dict() for skipped in self.skipped_ranges],
            "chunks": [chunk.to_dict() for chunk in self.chunks],
            "warnings": list(self.warnings),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def _snapshot(value: Any) -> Any:
    """Detach parser values from the shared chunk template cache.

    EVTX templates are reused between records and their substitution objects are filled in while a record is
    parsed.  Without a snapshot, a later record can mutate the values of an earlier recovered record.  This helper
    keeps the value types (including ``BxmlSub``) but gives every recovered record its own objects.
    """
    if isinstance(value, BxmlSub):
        clone = BxmlSub(value.sub_id)
        clone.set(_snapshot(value.get()))
        return clone

    if isinstance(value, KeyValueCollection):
        result = KeyValueCollection()
        for key, item in value.items():
            result[key] = _snapshot(item)
        return result

    if isinstance(value, dict):
        return {key: _snapshot(item) for key, item in value.items()}

    if isinstance(value, list):
        return [_snapshot(item) for item in value]

    return value


@dataclass
class _Candidate:
    start: int
    end: int
    record: KeyValueCollection
    record_id: int
    time_written: int
    confidence: tuple[str, ...]
    templates: dict[int, Any]


@dataclass
class _Rejection:
    offset: int
    reason: str


def _chunk_header(chunk: bytes) -> Any | None:
    if len(chunk) < 128:
        return None

    try:
        return c_evtx.EVTX_CHUNK(io.BytesIO(chunk))
    except Exception:
        return None


def _record_region(chunk: bytes, header: Any | None, warnings: list[str]) -> tuple[bool, int, int]:
    """Determine which part of the chunk can contain active records.

    ``free_space_offset`` marks the end of the active record area.  It is preferred when it is plausible.  A
    damaged free-space field is not a reason to stop recovery: in that case the whole chunk is offered to the
    structural validator, which still rejects wrapped (stale) records by their links and payload consistency.
    """
    length = len(chunk)
    start = EVTX_CHUNK_HEADER_SIZE
    header_valid = header is not None and header.magic == b"ElfChnk\x00"

    end = length
    if header is not None:
        free_space = int(header.free_space_offset)
        last_record = int(header.last_record_offset)

        if start <= free_space <= length and free_space >= last_record:
            end = free_space
        elif start <= free_space <= length and free_space == start:
            end = start
        else:
            # ``free_space_offset`` is damaged.  The last-record link usually still lets us find the real end of
            # the active area; without it the whole chunk is validated structurally (never signature-only).
            inferred_end = None
            if start <= last_record < length:
                last_size = int.from_bytes(chunk[last_record + 4 : last_record + 8], "little")
                if last_size >= EVTX_RECORD_MIN_SIZE and last_record + last_size <= length:
                    inferred_end = last_record + last_size

            if inferred_end is not None and inferred_end >= start:
                end = inferred_end
                warnings.append(
                    f"implausible free_space_offset {_hex(free_space)}; "
                    f"record region inferred from last_record_offset {_hex(last_record)}"
                )
            else:
                end = length
                warnings.append(
                    f"implausible free_space_offset {_hex(free_space)} and last_record_offset {_hex(last_record)}; "
                    "validating the whole chunk with structural checks"
                )

    if not header_valid:
        warnings.append("invalid ElfChnk magic; record region inferred from the chunk boundary")

    if end < start:
        end = start

    return header_valid, start, end


def _load_chunk_templates(chunk: bytes, header: Any | None) -> tuple[dict[int, Any], list[str]]:
    """Load the chunk template table so records after a damaged record can still be parsed."""
    templates: dict[int, Any] = {}
    warnings: list[str] = []

    # Only a structurally valid chunk header has a usable template table.  A damaged magic means the table bytes
    # are arbitrary and must not generate a long list of meaningless warnings.
    if header is None or header.magic != b"ElfChnk\x00":
        return templates, warnings

    for raw_offset in header.template_ptr:
        offset = int(raw_offset)
        if offset == 0:
            continue

        if offset < EVTX_RECORD_MIN_SIZE or offset >= len(chunk):
            warnings.append(f"template pointer {_hex(offset)} is outside the chunk")
            continue

        try:
            bxml = Bxml(io.BytesIO(chunk), io.BytesIO(chunk))
            bxml.data_offset = 0
            bxml.templates = templates
            bxml.template = None
            bxml.set_name_reader(EvtxNameReader(bxml))
            bxml.bxml_stream.seek(offset)
            templates[offset] = bxml._create_and_fill_template()
        except Exception as exception:
            warnings.append(f"template pointer {_hex(offset)} could not be parsed: {type(exception).__name__}")

    return templates, warnings


def _aligned_start(value: int) -> int:
    return (value + EVTX_RECORD_ALIGNMENT - 1) // EVTX_RECORD_ALIGNMENT * EVTX_RECORD_ALIGNMENT


def _embedded_record_start(chunk: bytes, start: int, end: int, consumed: int) -> int | None:
    """Find a complete record header inside the trailing part of a declared record payload.

    Valid BinXML data does not contain another record's header.  If one is present after the parser's consumed
    position, the declared ``size`` is reaching into a following record and must not be trusted.
    """
    limit = end - 4
    probe = _aligned_start(start + EVTX_RECORD_HEADER_SIZE + consumed)

    while probe + EVTX_RECORD_MIN_SIZE <= limit:
        if chunk[probe : probe + 4] == EVTX_RECORD_SIGNATURE:
            inner_size = int.from_bytes(chunk[probe + 4 : probe + 8], "little")
            inner_end = probe + inner_size
            if (
                inner_size >= EVTX_RECORD_MIN_SIZE
                and inner_end <= end
                and int.from_bytes(chunk[inner_end - 4 : inner_end], "little") == inner_size
            ):
                return probe

        probe += EVTX_RECORD_ALIGNMENT

    return None


def _parse_candidate(
    chunk: bytes,
    start: int,
    size: int,
    templates: dict[int, Any],
) -> tuple[KeyValueCollection | None, str | None, tuple[str, ...], dict[int, Any]]:
    data = chunk[start + EVTX_RECORD_HEADER_SIZE : start + size - 4]
    candidate_templates = dict(templates)

    bxml = Bxml(io.BytesIO(data), io.BytesIO(chunk))
    bxml.data_offset = start + EVTX_RECORD_HEADER_SIZE
    bxml.templates = candidate_templates
    bxml.template = None
    bxml.set_name_reader(EvtxNameReader(bxml))

    try:
        record = parse_bxml(bxml)
    except Exception as exception:
        # Use only the exception type: object reprs can contain memory addresses and are not reproducible.
        return None, f"invalid BinXML structure ({type(exception).__name__})", (), {}

    consumed = bxml.bxml_stream.tell()
    if consumed > len(data):
        return None, "BinXML parser consumed more bytes than the record payload", (), {}

    embedded = _embedded_record_start(chunk, start, start + size, consumed)
    if embedded is not None:
        return (
            None,
            f"declared record size overlaps a following record header at offset {embedded}",
            (),
            {},
        )

    timestamp = record.get("TimeCreated_SystemTime")
    if timestamp is None or (isinstance(timestamp, BxmlSub) and timestamp.get() is None):
        return None, "BinXML parsed but TimeCreated_SystemTime is missing", (), {}

    return _snapshot(record), None, (), candidate_templates


def _candidate_at(
    chunk: bytes,
    start: int,
    region_end: int,
    templates: dict[int, Any],
) -> tuple[_Candidate | None, _Rejection | None]:
    """Validate one signature hit using all structural checks."""
    if start % 8 != 0:
        return None, _Rejection(start, "record start is not 8-byte aligned")

    if start + EVTX_RECORD_MIN_SIZE > region_end:
        return None, _Rejection(start, "record header or tail is outside the chunk record region")

    size = int.from_bytes(chunk[start + 4 : start + 8], "little")
    if size < EVTX_RECORD_MIN_SIZE:
        return None, _Rejection(
            start,
            f"record size {size} is smaller than the minimum {EVTX_RECORD_MIN_SIZE}",
        )

    end = start + size
    if end > region_end:
        return None, _Rejection(start, f"record size {size} extends past the chunk record region")

    tail_size = int.from_bytes(chunk[end - 4 : end], "little")
    if tail_size != size:
        return None, _Rejection(start, f"record header size {size} does not match tail size {tail_size}")

    record_id = int.from_bytes(chunk[start + 8 : start + 16], "little")
    time_written = int.from_bytes(chunk[start + 16 : start + 24], "little")

    record, reason, _, candidate_templates = _parse_candidate(chunk, start, size, templates)
    if record is None:
        return None, _Rejection(start, reason or "invalid BinXML structure")

    confidence = (
        "record signature 0x2a2a",
        "record is inside the chunk record region",
        f"header size {size} equals tail size",
        "8-byte aligned record start",
        "BinXML parsed successfully",
        "TimeCreated_SystemTime present",
    )
    return (
        _Candidate(
            start=start,
            end=end,
            record=record,
            record_id=record_id,
            time_written=time_written,
            confidence=confidence,
            templates=candidate_templates,
        ),
        None,
    )


def _wrap_link_check(
    chunk: bytes,
    header: Any | None,
    candidate: _Candidate,
    region_end: int,
) -> str | None:
    """Check the chunk's record-link metadata when it is usable.

    The record ID must be inside the chunk's first/last ID range.  The chunk's ``last_record_offset`` must point at
    the last active record when it is plausible; a structurally identical record beyond that offset is a wrapped
    stale copy, not a new event.
    """
    if header is None or header.magic != b"ElfChnk\x00":
        return None

    first_id = int(header.first_record_id)
    last_id = int(header.last_record_id)
    if first_id == 0 or last_id == 0:
        return None

    record_id = candidate.record_id
    if record_id < first_id or record_id > last_id:
        return "record ID outside the chunk's first/last record ID range"

    last_record_offset = int(header.last_record_offset)
    if last_record_offset != 0 and EVTX_CHUNK_HEADER_SIZE <= last_record_offset < region_end:
        declared_end = last_record_offset + int.from_bytes(
            chunk[last_record_offset + 4 : last_record_offset + 8], "little"
        )
        if declared_end <= region_end:
            if candidate.start > last_record_offset:
                return "record starts beyond the chunk's last_record_offset"
            if candidate.end > declared_end and candidate.start != last_record_offset:
                return "record extends past the chunk's last active record"

    return None


def _select_candidates(candidates: list[_Candidate]) -> list[_Candidate]:
    """Pick non-overlapping valid candidates in source order.

    Walking forward from the first valid candidate and skipping its complete range ensures a signature inside a
    record's payload can never produce a second event.  A damaged record whose size field points into a following
    record is rejected by the structural checks, so the scan continues and still finds the following record.
    """
    selected: list[_Candidate] = []
    cursor = -1

    for candidate in sorted(candidates, key=lambda candidate: (candidate.start, candidate.end)):
        if candidate.start < cursor:
            continue

        selected.append(candidate)
        cursor = candidate.end

    return selected


def _rejection_reason(
    start: int, end: int, rejections: list[_Rejection], region_end: int
) -> tuple[str, tuple[str, ...]]:
    if start >= region_end:
        return "outside the chunk record region", ()

    relevant = [rejection for rejection in rejections if start <= rejection.offset < end]
    if not relevant:
        return "no structurally valid record signature in this range", ()

    reasons = tuple(sorted({rejection.reason for rejection in relevant}))
    if len(reasons) == 1:
        return reasons[0], ()
    return "one or more candidate records failed structural validation", reasons


def recover_chunk(
    chunk: bytes,
    *,
    chunk_offset: int = 0,
    chunk_index: int = 0,
) -> ChunkRecovery:
    """Recover records from a single chunk.

    ``chunk_offset`` is the absolute source offset of the chunk.  The input bytes are never modified.
    """
    length = len(chunk)
    warnings: list[str] = []
    header = _chunk_header(chunk)
    header_valid, region_start, region_end = _record_region(chunk, header, warnings)
    templates, template_warnings = _load_chunk_templates(chunk, header)
    warnings.extend(template_warnings)

    result = ChunkRecovery(
        index=chunk_index,
        file_offset=chunk_offset,
        length=length,
        expected_length=EVTX_CHUNK_SIZE,
        header_valid=header_valid,
        record_region_start=region_start,
        record_region_end=region_end,
        warnings=warnings,
    )

    candidates: list[_Candidate] = []
    rejections: list[_Rejection] = []
    position = region_start

    while position + 4 <= region_end:
        found = chunk.find(EVTX_RECORD_SIGNATURE, position, region_end)
        if found == -1:
            break

        candidate, rejection = _candidate_at(chunk, found, region_end, templates)
        if candidate is not None:
            wrap_reason = _wrap_link_check(chunk, header, candidate, region_end)
            if wrap_reason is None:
                candidates.append(candidate)
            else:
                rejections.append(_Rejection(found, wrap_reason))
        elif rejection is not None:
            rejections.append(rejection)

        # Continue one byte at a time so a corrupted outer record cannot hide an inner valid one.
        position = found + 1

    selected = _select_candidates(candidates)

    skipped_ranges: list[SkippedRange] = []
    cursor = region_start
    for candidate in selected:
        if cursor < candidate.start:
            reason, details = _rejection_reason(cursor, candidate.start, rejections, region_end)
            skipped_ranges.append(
                SkippedRange(
                    offset=chunk_offset + cursor,
                    size=candidate.start - cursor,
                    reason=reason,
                    chunk_index=chunk_index,
                    chunk_offset=cursor,
                    details=details,
                )
            )

        previous_skip = None
        if skipped_ranges and skipped_ranges[-1].end == chunk_offset + candidate.start:
            previous_skip = skipped_ranges[-1]
        result.records.append(
            RecoveredRecord(
                candidate.record,
                file_offset=chunk_offset + candidate.start,
                chunk_offset=candidate.start,
                chunk_index=chunk_index,
                record_size=candidate.end - candidate.start,
                record_id=candidate.record_id,
                time_written=candidate.time_written,
                confidence=candidate.confidence,
                skipped_before=previous_skip,
            )
        )

        # Templates discovered in an accepted record are trustworthy for later records in this chunk.
        templates.update(candidate.templates)
        cursor = candidate.end

    if cursor < region_end:
        reason, details = _rejection_reason(cursor, region_end, rejections, region_end)
        skipped_ranges.append(
            SkippedRange(
                offset=chunk_offset + cursor,
                size=region_end - cursor,
                reason=reason,
                chunk_index=chunk_index,
                chunk_offset=cursor,
                details=details,
            )
        )

    result.skipped_ranges = skipped_ranges
    return result


def recover_evtx(fh: BinaryIO, path: Path | str | None = None) -> RecoveryReport:
    """Recover records from an EVTX stream.

    The stream is only read; it is never written to.  The source SHA-256 is included in the report so a run can be
    tied back to the exact evidence bytes.
    """
    if path is None:
        name = getattr(fh, "name", None)
        path = name if isinstance(name, str) else None

    if not hasattr(fh, "seek"):
        raise TypeError("recover_evtx requires a seekable binary stream")

    fh.seek(0, io.SEEK_END)
    file_size = fh.tell()
    fh.seek(0)

    digest = hashlib.sha256()
    report = RecoveryReport(
        source=str(path) if path is not None else None,
        file_size=file_size,
        source_sha256="",
    )

    file_header = fh.read(EVTX_FILE_HEADER_SIZE)
    digest.update(file_header)

    if len(file_header) < EVTX_FILE_HEADER_SIZE:
        report.source_sha256 = digest.hexdigest()
        report.skipped_ranges.append(
            SkippedRange(
                offset=0,
                size=len(file_header),
                reason="file is shorter than the 4096-byte EVTX file header",
            )
        )
        report.warnings.append("file header is truncated")
        return report

    header = c_evtx.EVTX_HEADER(io.BytesIO(file_header))
    if header.magic != b"ElfFile\x00":
        report.warnings.append("invalid EVTX file magic; recovery continued from the first chunk boundary")

    chunk_offset = int(header.header_block_size)
    if not EVTX_FILE_HEADER_SIZE <= chunk_offset <= file_size:
        report.warnings.append(
            f"implausible header_block_size {_hex(chunk_offset)}; using {_hex(EVTX_FILE_HEADER_SIZE)}"
        )
        chunk_offset = EVTX_FILE_HEADER_SIZE
    # Bytes between the file header and the first chunk are not record data but are still accounted for.
    if chunk_offset > len(file_header):
        gap = fh.read(chunk_offset - len(file_header))
        digest.update(gap)
        if gap:
            report.skipped_ranges.append(
                SkippedRange(
                    offset=len(file_header),
                    size=len(gap),
                    reason="bytes between the EVTX file header and the first chunk",
                )
            )

    index = 0
    while True:
        start = chunk_offset
        chunk = fh.read(EVTX_CHUNK_SIZE)
        if not chunk:
            break

        digest.update(chunk)

        if len(chunk) < EVTX_CHUNK_HEADER_SIZE:
            report.skipped_ranges.append(
                SkippedRange(
                    offset=start,
                    size=len(chunk),
                    reason="trailing partial chunk is smaller than a chunk header",
                    chunk_index=index,
                    chunk_offset=0,
                )
            )
            report.warnings.append(f"trailing partial chunk at {_hex(start)} has only {len(chunk)} bytes")
            break

        chunk_result = recover_chunk(chunk, chunk_offset=start, chunk_index=index)
        report.chunks.append(chunk_result)
        report.records.extend(chunk_result.records)
        report.skipped_ranges.extend(chunk_result.skipped_ranges)

        if len(chunk) < EVTX_CHUNK_SIZE:
            report.warnings.append(
                f"trailing chunk at {_hex(start)} is truncated "
                f"({len(chunk)} of {EVTX_CHUNK_SIZE} bytes); recovered records inside it"
            )

        index += 1
        chunk_offset += len(chunk)

    report.source_sha256 = digest.hexdigest()
    return report
