"""Log sources feeding the timeline merger.

Two source kinds are supported, both yielding :class:`NormalizedEvent` instances:

* :class:`FileLogSource` streams a real EVT/EVTX file through the existing
  :class:`~dissect.eventlog.evt.Evt` / :class:`~dissect.eventlog.evtx.Evtx` readers.
* :class:`SyntheticLogSource` replays small, hand-crafted records so that rotation, log clears and
  clock rollbacks can be demonstrated deterministically.

File names are only used as a human readable label: ordering and identity never depend on them.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from dissect.eventlog.evt.evt import Evt
from dissect.eventlog.evtx.evtx import Evtx
from dissect.eventlog.timeline.model import EvidenceRef, NormalizedEvent

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

EVT_SIGNATURE = b"LfLe"
EVTX_SIGNATURE = b"ElfFile\x00"


def _bxml_scalar(value: object) -> object:
    get = getattr(value, "get", None)
    if callable(get):
        try:
            return get()
        except Exception:  # noqa: BLE001 - malformed optional element, keep raw representation
            return str(value)
    return value


@dataclass(frozen=True)
class SourceMeta:
    source_id: str
    name: str
    host: str | None
    channel: str | None
    format: str
    file_hash: str | None
    oldest_record_number: int | None
    current_record_number: int | None


class LogSource:
    """Base class providing normalised iteration and source metadata."""

    def __init__(self, name: str, host: str | None, channel: str | None, source_id: str | None):
        self.name = name
        self._explicit_host = host
        self._explicit_channel = channel
        self.source_id = source_id or name
        self.meta: SourceMeta | None = None

    def events(self) -> Iterator[NormalizedEvent]:
        raise NotImplementedError

    def __iter__(self) -> Iterator[NormalizedEvent]:
        return self.events()


class FileLogSource(LogSource):
    """A physical EVT or EVTX file, read entirely through the existing reader interfaces."""

    def __init__(self, path: Path | str, host: str | None = None, channel: str | None = None):
        self.path = str(path)
        super().__init__(name=self.path, host=host, channel=channel, source_id=None)

    def _read_bytes(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def events(self) -> Iterator[NormalizedEvent]:
        data = self._read_bytes()
        file_hash = hashlib.sha256(data).hexdigest()
        signature = data[:8]

        # EVT files start with a 4-byte header size followed by the "LfLe" signature at offset 4.
        if data[4:8] == EVT_SIGNATURE:
            yield from self._iter_evt(data, file_hash)
        elif signature == EVTX_SIGNATURE:
            yield from self._iter_evtx(data, file_hash)
        else:
            raise ValueError(f"Unrecognised event log signature in {self.path}: {signature!r}")

    def _iter_evt(self, data: bytes, file_hash: str) -> Iterator[NormalizedEvent]:
        reader = Evt(io.BytesIO(data))
        host = self._explicit_host
        channel = self._explicit_channel
        self.source_id = f"file:{self.name}"
        self.meta = SourceMeta(
            source_id=self.source_id,
            name=self.name,
            host=host,
            channel=channel,
            format="evt",
            file_hash=file_hash,
            oldest_record_number=reader.oldest_record_number,
            current_record_number=reader.current_record_number,
        )

        for stream_index, record in enumerate(reader):
            observed_host = host or record.Computername or None
            payload = {
                "format": "evt",
                "event_id": record.EventID,
                "event_type": record.EventType,
                "event_category": record.EventCategory,
                "source_name": record.SourceName,
                "computer": record.Computername,
                "time_generated": record.TimeGenerated,
                "time_written": record.TimeWritten,
                "strings": list(record.Strings),
                "data": record.Data,
                "sid": record.UserSid,
            }
            evidence = EvidenceRef(
                source_id=self.source_id,
                source_name=self.name,
                stream_index=stream_index,
                record_number=record.RecordNumber,
            )
            yield NormalizedEvent(
                host=observed_host,
                channel=channel,
                record_number=record.RecordNumber,
                timestamp=record.TimeGenerated,
                payload=payload,
                evidence=evidence,
            )

    def _iter_evtx(self, data: bytes, file_hash: str) -> Iterator[NormalizedEvent]:
        reader = Evtx(io.BytesIO(data))
        self.source_id = f"file:{self.name}"
        observed_host: str | None = None
        observed_channel: str | None = None

        for stream_index, record in enumerate(reader):
            payload = {"format": "evtx"}
            for key, value in record.items():
                payload[key] = _bxml_scalar(value)

            observed_host = observed_host or record.get("Computer")
            observed_channel = observed_channel or record.get("Channel")
            timestamp = _bxml_scalar(record.get("TimeCreated_SystemTime"))
            record_number = _bxml_scalar(record.get("EventRecordID"))
            evidence = EvidenceRef(
                source_id=self.source_id,
                source_name=self.name,
                stream_index=stream_index,
                record_number=record_number,
            )
            yield NormalizedEvent(
                host=self._explicit_host or record.get("Computer"),
                channel=self._explicit_channel or record.get("Channel"),
                record_number=record_number,
                timestamp=timestamp,
                payload=payload,
                evidence=evidence,
            )

        self.meta = SourceMeta(
            source_id=self.source_id,
            name=self.name,
            host=self._explicit_host or observed_host,
            channel=self._explicit_channel or observed_channel,
            format="evtx",
            file_hash=file_hash,
            oldest_record_number=None,
            current_record_number=None,
        )


@dataclass(frozen=True)
class SyntheticRecord:
    """A minimal record for deterministic tests and demonstrations."""

    record_number: int
    timestamp: datetime
    event_id: int
    message: str
    channel: str = "Security"
    host: str = "HOST-DEMO"
    extra: str = ""


class SyntheticLogSource(LogSource):
    """An in-memory source replaying synthetic records in the given stream order."""

    def __init__(
        self,
        name: str,
        records: list[SyntheticRecord],
        host: str | None = None,
        channel: str | None = None,
        source_id: str | None = None,
    ):
        super().__init__(name=name, host=host, channel=channel, source_id=source_id)
        self.records = records
        first = records[0] if records else None
        self.source_id = source_id or f"synthetic:{name}"
        self.meta = SourceMeta(
            source_id=self.source_id,
            name=name,
            host=host or (first.host if first else None),
            channel=channel or (first.channel if first else None),
            format="synthetic",
            file_hash=None,
            oldest_record_number=records[0].record_number if records else None,
            current_record_number=records[-1].record_number if records else None,
        )

    def events(self) -> Iterator[NormalizedEvent]:
        for stream_index, record in enumerate(self.records):
            payload = {
                "format": "synthetic",
                "event_id": record.event_id,
                "message": record.message,
                "host": record.host,
                "channel": record.channel,
                "timestamp": record.timestamp,
                "extra": record.extra,
            }
            evidence = EvidenceRef(
                source_id=self.source_id,
                source_name=self.name,
                stream_index=stream_index,
                record_number=record.record_number,
            )
            yield NormalizedEvent(
                host=self._explicit_host or record.host,
                channel=self._explicit_channel or record.channel,
                record_number=record.record_number,
                timestamp=record.timestamp,
                payload=payload,
                evidence=evidence,
            )


def open_log(path: Path | str, host: str | None = None, channel: str | None = None) -> FileLogSource:
    """Convenience factory matching the existing reader entry points."""
    return FileLogSource(path, host=host, channel=channel)
