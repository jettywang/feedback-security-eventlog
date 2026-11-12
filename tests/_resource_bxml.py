"""Deterministic, fixed-size BinXML builders for the resource-boundary tests.

Everything here is hand-constructed from small, explicit byte sequences: there are no large files,
no network access and no stress loops. Offsets written into the BinXML name/template reference
fields are absolute (``data_offset`` plus the in-stream position), which is how the EVTX name
reader and template reference table address bytes.
"""

from __future__ import annotations

from io import BytesIO

from dissect.eventlog.bxml import Bxml, EvtxNameReader
from dissect.eventlog.bxml.c_bxml import c_bxml

# Mirrors dissect.eventlog.evtx.evtx.ElfChnk: a record's BinXML starts 24 bytes into the record.
DATA_OFFSET = 24

# BinXML type identifiers used by these builders.
STRING_TYPE = 0x01
BINXML_TYPE = 0x21

# Token / marker bytes observed in genuine EVTX records.
FRAGMENT = b"\x0f\x01\x01"
TEMPLATE_INSTANCE = 0x0C
NORMAL_SUBSTITUTION = 0x0D
START_ELEMENT = 0x01
HAS_MORE = 0x40
CLOSE_START = 0x02
CLOSE_EMPTY = 0x03
END_ELEMENT = 0x04
BXML_END = 0x00


class BxmlBuilder:
    """Incrementally assemble BinXML bytes with correct absolute offsets."""

    def __init__(self, base: int):
        self.base = base
        self.buf = bytearray()

    def u8(self, value: int) -> None:
        self.buf += c_bxml.uint8.dumps(value)

    def u16(self, value: int) -> None:
        self.buf += c_bxml.uint16.dumps(value)

    def u32(self, value: int) -> None:
        self.buf += c_bxml.uint32.dumps(value)

    def raw(self, value: bytes) -> None:
        self.buf += value

    def name(self, value: str) -> None:
        # The name offset points at the BXML_NAME structure, i.e. just after this uint32 field.
        self.u32(self.base + len(self.buf) + 4)
        self.u32(0)
        self.u16(0)
        self.u16(len(value))
        self.raw(value.encode("utf-16-le"))
        self.raw(b"\x00\x00")

    def here(self) -> int:
        return len(self.buf)

    def patch_u32(self, position: int, value: int) -> None:
        self.buf[position : position + 4] = c_bxml.uint32.dumps(value)

    def getvalue(self) -> bytes:
        return bytes(self.buf)


def event_substitution_body(builder: BxmlBuilder, substitution_type: int) -> None:
    """Emit ``<Event>{sub0}</Event>`` where sub0 is one substitution token."""
    builder.u8(START_ELEMENT | HAS_MORE)
    builder.u16(0)
    builder.u32(0)
    builder.name("Event")
    builder.u32(0)
    builder.u8(CLOSE_START)
    builder.u8(NORMAL_SUBSTITUTION)
    builder.u16(0)
    builder.u8(substitution_type)
    builder.u8(END_ELEMENT)


def nested_chain(level: int, absolute_base: int = DATA_OFFSET) -> bytes:
    """Build a finite template chain of exactly ``level`` nested BinXML substitution levels.

    Level zero is a plain self-contained ``<Leaf/>`` fragment. Every higher level is a full inline
    template instance whose single BinXML substitution value is the next level, so total size and
    parser recursion depth both grow linearly with ``level``.
    """
    if level == 0:
        leaf = BxmlBuilder(absolute_base)
        leaf.raw(FRAGMENT + bytes([BXML_END]))
        leaf.u8(START_ELEMENT)
        leaf.u32(0)
        leaf.name("Leaf")
        leaf.u8(CLOSE_EMPTY)
        leaf.u8(BXML_END)
        return leaf.getvalue()

    builder = BxmlBuilder(absolute_base)
    # Outer fragment wrapping this whole stream.
    builder.raw(FRAGMENT + bytes([BXML_END]))

    builder.u8(TEMPLATE_INSTANCE)
    builder.u8(0)
    builder.u32(1)
    reference_offset_pos = builder.here()
    builder.u32(0)
    definition_start = builder.here()
    builder.u32(0)
    builder.raw(b"\x00" * 16)
    data_size_pos = builder.here()
    builder.u32(0)
    fragment_start = builder.here()
    # data_size spans the 3-byte fragment header struct plus the body. After the struct reader
    # consumes the header, read_token consumes the standalone fragment token (0x0F, encoded here as
    # a zero-flag byte) before reaching the root element.
    builder.raw(FRAGMENT)
    builder.u8(BXML_END)
    event_substitution_body(builder, BINXML_TYPE)
    builder.u8(BXML_END)
    body_end = builder.here()
    builder.patch_u32(reference_offset_pos, absolute_base + definition_start)
    builder.patch_u32(data_size_pos, body_end - fragment_start)

    # The value begins after the descriptor count (4 bytes) and one descriptor (4 bytes). The
    # nested stream's own leading fragment header is part of those value bytes, not an extra offset.
    value_base = absolute_base + builder.here() + 8
    value = nested_chain(level - 1, value_base)
    builder.u32(1)
    builder.u16(len(value))
    builder.u8(BINXML_TYPE)
    builder.u8(0)
    builder.raw(value)
    builder.u8(BXML_END)
    return builder.getvalue()


def cyclic_templates(repetitions: int) -> bytes:
    """Build a small stream that drives unbounded template recursion.

    An outer template defines a BinXML substitution whose value is a run of identical loop units.
    Each unit is a fragment holding a template instance that back-references the outer definition,
    followed by one BinXML descriptor pointing at the next unit. Without a depth guard this recurses
    one level per unit until the Python stack is exhausted.
    """
    builder = BxmlBuilder(DATA_OFFSET)
    builder.raw(FRAGMENT + bytes([BXML_END]))

    builder.u8(TEMPLATE_INSTANCE)
    builder.u8(0)
    builder.u32(1)
    reference_offset_pos = builder.here()
    builder.u32(0)
    definition_start = builder.here()
    builder.u32(0)
    builder.raw(b"\x00" * 16)
    data_size_pos = builder.here()
    builder.u32(0)
    fragment_start = builder.here()
    builder.raw(FRAGMENT)
    builder.u8(BXML_END)
    event_substitution_body(builder, BINXML_TYPE)
    builder.u8(BXML_END)
    body_end = builder.here()
    builder.patch_u32(reference_offset_pos, DATA_OFFSET + definition_start)
    builder.patch_u32(data_size_pos, body_end - fragment_start)

    # A loop unit: fragment (4) + template instance back-reference (9) + descriptor slot (8).
    unit = bytearray(FRAGMENT + bytes([BXML_END]))
    unit += bytes([TEMPLATE_INSTANCE, 0x00])
    unit += c_bxml.uint32.dumps(1)
    unit += c_bxml.uint32.dumps(DATA_OFFSET + definition_start)
    unit += c_bxml.uint32.dumps(1)
    unit += c_bxml.uint16.dumps(0)  # size patched after the unit length is known
    size_field = len(unit)
    unit += c_bxml.uint8.dumps(BINXML_TYPE)
    unit += c_bxml.uint8.dumps(0)
    unit[size_field : size_field + 2] = c_bxml.uint16.dumps(len(unit))

    region = bytes(unit) * repetitions
    builder.u32(1)
    builder.u16(len(region))
    builder.u8(BINXML_TYPE)
    builder.u8(0)
    builder.raw(region)
    builder.u8(BXML_END)
    return builder.getvalue()


def huge_descriptor_count() -> bytes:
    """A template declaring roughly 4 billion descriptors but providing no descriptor bytes."""
    builder = BxmlBuilder(DATA_OFFSET)
    builder.raw(FRAGMENT + bytes([BXML_END]))
    builder.u8(TEMPLATE_INSTANCE)
    builder.u8(0)
    builder.u32(1)
    reference_offset_pos = builder.here()
    builder.u32(0)
    definition_start = builder.here()
    builder.u32(0)
    builder.raw(b"\x00" * 16)
    data_size_pos = builder.here()
    builder.u32(0)
    fragment_start = builder.here()
    builder.raw(FRAGMENT)
    builder.u8(BXML_END)
    event_substitution_body(builder, STRING_TYPE)
    builder.u8(BXML_END)
    body_end = builder.here()
    builder.patch_u32(reference_offset_pos, DATA_OFFSET + definition_start)
    builder.patch_u32(data_size_pos, body_end - fragment_start)

    builder.u32(0xFFFFFFFF)
    builder.u8(BXML_END)
    return builder.getvalue()


def make_bxml(data: bytes, limits=None) -> Bxml:
    """Construct a standalone Bxml parser over fixed bytes with the EVTX name reader."""
    bxml = Bxml(BytesIO(data), BytesIO(b""), limits=limits)
    bxml.data_offset = DATA_OFFSET
    bxml.templates = {}
    bxml.set_name_reader(EvtxNameReader(bxml))
    return bxml
