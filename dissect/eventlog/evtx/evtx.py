# - http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-EVEN6].pdf
# - https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
from __future__ import annotations

import io
import logging
import os
from typing import TYPE_CHECKING, BinaryIO

from dissect.eventlog.bxml import Bxml, BxmlSub, EvtxNameReader, parse_bxml
from dissect.eventlog.evtx.c_evtx import c_evtx
from dissect.eventlog.exceptions import MalformedElfChnkException, ResourceLimitExceeded
from dissect.eventlog.limits import ResourceLimit

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.eventlog.utils import KeyValueCollection

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EVTX", "CRITICAL"))


class ElfChnk:
    def __init__(self, d: bytes, path: Path | None = None, limits: ResourceLimit | None = None):
        self.path = path
        self.limits = limits or ResourceLimit()
        self.stream = io.BytesIO(d)
        self.header = c_evtx.EVTX_CHUNK(self.stream)

        if self.header.magic != b"ElfChnk\x00":
            if self.header.magic != b"\x00\x00\x00\x00\x00\x00\x00\x00":
                log.error("%s: Bad ElfChnk magic", self.path)

            raise MalformedElfChnkException("Bad ElfChnk magic")

        self.empty = self.header.free_space_offset == 512

        self.names = {}
        self.templates = {}
        self.data_offset = 0

    def read(self, records: bool = True) -> Iterator[KeyValueCollection]:
        try:
            while True:
                offset = self.stream.tell()
                try:
                    r = c_evtx.EVTX_RECORD(self.stream)
                except EOFError:
                    break

                if r.signature != 0x2A2A:
                    break

                # Truncated or partially written record
                if r.size != r.size_copy:
                    continue

                self.data_offset = offset + 24

                bxml_data = io.BytesIO(r.data)
                bxml = Bxml(bxml_stream=bxml_data, elf_chunk_stream=self.stream, limits=self.limits)
                bxml.data_offset = self.data_offset
                bxml.templates = self.templates
                bxml.template = None
                bxml.set_name_reader(EvtxNameReader(bxml))
                rec = parse_bxml(bxml)

                # Validate record
                if (
                    "TimeCreated_SystemTime" not in rec
                    or (
                        isinstance(rec["TimeCreated_SystemTime"], BxmlSub)
                        and rec["TimeCreated_SystemTime"].get() is None
                    )
                    or rec["TimeCreated_SystemTime"] is None
                ):
                    log.warning("Missing timestamp in record")
                    continue

                yield rec
        except ResourceLimitExceeded:
            # A configured boundary was crossed. Records already yielded from this chunk were fully
            # validated and stay with the caller; the boundary is re-raised so it is never silently
            # swallowed and a half-parsed event can never be presented as a complete record.
            if not self.empty:
                log.exception("Resource limit exceeded when processing chunk")
            raise
        except Exception:
            if not self.empty:
                log.exception("Exception when processing chunk")
                raise MalformedElfChnkException


class Evtx:
    """Microsoft Event logs."""

    def __init__(self, fh: BinaryIO, path: Path | None = None, limits: ResourceLimit | None = None):
        self.path = path
        self.fh = fh
        self.limits = limits or ResourceLimit()
        self.header = c_evtx.EVTX_HEADER(self.fh)
        self.count = 0
        # Recovery bookkeeping: chunks are independent 64 KiB units, so a failure in one chunk never
        # invalidates the next. Both corruption and exhausted limits are recorded per chunk and the
        # parser moves on; the failure is never swallowed into a half-finished record.
        self.malformed_chunks: list[int] = []
        self.limited_chunks: list[int] = []

    def __iter__(self) -> Iterator[KeyValueCollection]:
        chunk_offset = self.header.header_block_size

        skip = self.header.header_block_size - len(c_evtx.EVTX_HEADER)
        if skip > 0:
            self.fh.read(skip)

        chunk_index = -1
        while True:
            chunk = self.fh.read(0x10000)
            if len(chunk) != 0x10000:
                break

            chunk_index += 1
            try:
                c = ElfChnk(chunk, self.path, self.limits)
                for r in c.read():
                    yield r
                    self.count += 1
            except ResourceLimitExceeded:
                # The configured budget was exhausted. Any records yielded before this point were
                # complete and remain delivered; the remainder of this chunk is abandoned and the
                # next independent chunk is still processed.
                self.limited_chunks.append(chunk_index)
                log.warning("Resource limit exceeded in chunk %d of %s", chunk_index, self.path)
            except MalformedElfChnkException:
                self.malformed_chunks.append(chunk_index)
                log.warning("Malformed chunk %d of %s skipped", chunk_index, self.path)

            chunk_offset += 0x10000
