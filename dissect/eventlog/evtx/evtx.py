# - http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MS-EVEN6].pdf
# - https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
from __future__ import annotations

import io
import logging
import os
from typing import TYPE_CHECKING, BinaryIO

from dissect.eventlog.bxml import Bxml, BxmlSub, EvtxNameReader, parse_bxml
from dissect.eventlog.evtx.c_evtx import c_evtx
from dissect.eventlog.exceptions import MalformedElfChnkException
from dissect.eventlog.utils import attach_sources

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.eventlog.utils import KeyValueCollection

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EVTX", "CRITICAL"))


class ElfChnk:
    def __init__(self, d: bytes, path: Path | None = None, offset: int | None = None):
        self.path = path
        self.stream = io.BytesIO(d)
        self.header = c_evtx.EVTX_CHUNK(self.stream)
        # Absolute file offset of this chunk. ``None`` means the caller only supplied raw
        # chunk bytes; provenance ranges are then reported as chunk-relative and carry no
        # absolute file position.
        self.offset = offset

        if self.header.magic != b"ElfChnk\x00":
            if self.header.magic != b"\x00\x00\x00\x00\x00\x00\x00\x00":
                log.error("%s: Bad ElfChnk magic", self.path)

            raise MalformedElfChnkException("Bad ElfChnk magic")

        self.empty = self.header.free_space_offset == 512

        self.names = {}
        self.templates = {}
        self.data_offset = 0

    def read(self, records: bool = True, with_sources: bool = False) -> Iterator[KeyValueCollection]:
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
                bxml = Bxml(bxml_stream=bxml_data, elf_chunk_stream=self.stream)
                bxml.data_offset = self.data_offset
                bxml.templates = self.templates
                bxml.template = None
                bxml.with_sources = with_sources
                bxml.chunk_offset = self.offset or 0
                bxml.record_offset = (self.offset or 0) + offset
                bxml.absolute = self.offset is not None
                bxml.set_name_reader(EvtxNameReader(bxml))
                rec = parse_bxml(bxml, with_sources=with_sources)

                if with_sources:
                    rec, sources = rec
                    sources.record_offset = bxml.record_offset
                    sources.record_id = r.record_id
                    sources.chunk_offset = self.offset if self.offset is not None else 0
                    sources.absolute = self.offset is not None
                    attach_sources(rec, sources)

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
        except Exception:
            if not self.empty:
                log.exception("Exception when processing chunk")
                raise MalformedElfChnkException


class Evtx:
    """Microsoft Event logs."""

    def __init__(self, fh: BinaryIO, path: Path | None = None, include_sources: bool = False):
        self.path = path
        self.fh = fh
        self.header = c_evtx.EVTX_HEADER(self.fh)
        self.count = 0
        # Opt-in constructor flag; plain iteration stays provenance-free by default.
        self.include_sources = include_sources

    def __iter__(self) -> Iterator[KeyValueCollection]:
        yield from self._read_chunks(with_sources=self.include_sources)

    def with_sources(self) -> Iterator[KeyValueCollection]:
        """Iterate records with an attached ``sources`` :class:`SourceCollection`.

        The record values, keys and ordering are identical to :meth:`__iter__`; each yielded
        record additionally carries ``record.sources`` keyed by the exact output key. No
        provenance is collected when using plain iteration.
        """
        yield from self._read_chunks(with_sources=True)

    def _read_chunks(self, with_sources: bool) -> Iterator[KeyValueCollection]:
        chunk_offset = self.header.header_block_size

        skip = self.header.header_block_size - len(c_evtx.EVTX_HEADER)
        if skip > 0:
            self.fh.read(skip)

        while True:
            chunk = self.fh.read(0x10000)
            if len(chunk) != 0x10000:
                break

            try:
                c = ElfChnk(chunk, self.path, offset=chunk_offset)
                for r in c.read(with_sources=with_sources):
                    yield r
                    self.count += 1
            except MalformedElfChnkException:
                continue

            chunk_offset += 0x10000
