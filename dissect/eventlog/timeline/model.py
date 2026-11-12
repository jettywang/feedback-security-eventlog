"""Data models for the evidence-preserving multi-file event timeline merger.

The merger never mutates records produced by the existing :class:`~dissect.eventlog.evt.Evt`
and :class:`~dissect.eventlog.evtx.Evtx` readers.  Every normalised event keeps an explicit
:class:`EvidenceRef` back to the physical file (or other source) it came from, and every merge
decision is recorded with the auditable criteria that caused it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class MergeReason(str, Enum):
    """Why two observations were collapsed into a single timeline event."""

    CONTENT_HASH = "content_hash"
    WHOLE_FILE_DUPLICATE = "whole_file_duplicate"


class TimelineFlag(str, Enum):
    """Explicit, non-destructive annotations attached to timeline entries."""

    CLOCK_ROLLBACK = "clock_rollback"
    RECORD_NUMBER_REUSE = "record_number_reuse"
    ORDER_UNDETERMINED = "order_undetermined"


def _stable_value(value: Any) -> Any:
    if isinstance(value, datetime):
        # Keep the original timestamp verbatim; only serialise it for the fingerprint.
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {key: _stable_value(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_stable_value(item) for item in value]
    return value


def canonical_fingerprint(payload: dict[str, Any]) -> str:
    """Return a stable SHA-256 over the semantic payload of an event.

    The fingerprint intentionally excludes the record number and the source description: a log
    clear followed by record-number reuse must therefore produce a *different* event even when the
    number matches, while an overlapping copy of the very same event keeps the same fingerprint
    regardless of which file it was read from.
    """
    canonical = json.dumps(_stable_value(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceRef:
    """One physical observation of an event, fully traceable to its source.

    Args:
        source_id: Stable identifier of the :class:`LogSource` (unique per file or caller given).
        source_name: Human readable source description (path, stream name, synthetic label).
        stream_index: Zero-based position of the record in read order inside its source.
        record_number: Native record number as reported by the log format.
        file_offset: Physical offset inside the source when known, otherwise ``None``.
    """

    source_id: str
    source_name: str
    stream_index: int
    record_number: int | None
    file_offset: int | None = None


@dataclass(frozen=True)
class NormalizedEvent:
    """Format-independent view of one record read through the existing EVT/EVTX interfaces."""

    host: str | None
    channel: str | None
    record_number: int | None
    timestamp: datetime | None
    payload: dict[str, Any]
    evidence: EvidenceRef

    @property
    def content_hash(self) -> str:
        return canonical_fingerprint(self.payload)

    @property
    def event_key(self) -> tuple[str, str, str]:
        """Identity scope for an event: host + channel + content fingerprint."""
        return (self.host or "", self.channel or "", self.content_hash)


@dataclass
class MergeAudit:
    """One auditable merge/duplicate decision."""

    reason: MergeReason
    kept_event_key: tuple[str, str, str]
    added_source: str
    matched_source: str
    detail: str


@dataclass
class MergedEvent:
    """A unique event in the timeline, with every evidence source that contains a copy."""

    host: str | None
    channel: str | None
    record_number: int | None
    timestamp: datetime | None
    payload: dict[str, Any]
    content_hash: str
    event_key: tuple[str, str, str]
    evidence: list[EvidenceRef] = field(default_factory=list)
    record_numbers_seen: set[int] = field(default_factory=set)
    flags: set[TimelineFlag] = field(default_factory=set)
    merge_reasons: set[MergeReason] = field(default_factory=set)


@dataclass
class RollbackRegion:
    """An interval inside one source where timestamps move backwards instead of forwards."""

    source_id: str
    source_name: str
    previous_stream_index: int
    previous_timestamp: datetime
    current_stream_index: int
    current_timestamp: datetime


@dataclass
class TimelineLayer:
    """A group of merged events that must be presented together.

    Events in the same layer could not be ordered against each other from the evidence; they are
    presented side by side rather than in an arbitrary order.
    """

    events: list[MergedEvent]
    flags: set[TimelineFlag] = field(default_factory=set)
