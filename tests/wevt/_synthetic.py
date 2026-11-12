"""Minimal, hand-assembled WEVT_TEMPLATE resources for evidence-view tests.

Real WEVT files are large and never contain the pathological layouts the evidence view
must defend against (duplicate identifiers across providers, shuffled MAPS pointers,
cross-provider references).  These helpers assemble just enough of the documented binary
format to build deterministic, fully controlled fixtures where every byte offset is
known to the test.

Layout of one provider (all offsets are absolute file offsets, as in the real format)::

    WEVT header + WEVT_TYPES table
    type blocks (LEVL / TASK / OPCO / TTBL / MAPS / EVNT), each a WEVT_TYPE header
    followed by its payload records.
"""

from __future__ import annotations

import struct
from uuid import UUID

from dissect.eventlog.wevt.c_wevt import c_wevt
from tests._utils import TEMP_HEADER

# Numeric WEVT_TYPES type codes observed in real resources.
TYPE_CODE = {"EVNT": 4, "LEVL": 0, "OPCO": 1, "TASK": 3, "MAPS": 6, "TTBL": 7}

# The known-good TEMP blob is position dependent because its BXML names store absolute
# file offsets. Keep its original anchor so it can be relocated by shifting every
# internal absolute offset together.
TEMP_ORIGIN = 0xE84


def data_item(text: str) -> bytes:
    """Build an 8-byte aligned DATA_ITEM holding a UTF-16LE string."""
    raw = (text + "\x00").encode("utf-16-le")
    padding = (-(4 + len(raw))) % 8
    return struct.pack("<I", 4 + len(raw) + padding) + raw + b"\x00" * padding


def level_record(numeric_id: int, name: str) -> bytes:
    """LEVL struct (12 bytes) followed by its name DATA_ITEM; data_offset patched later."""
    return struct.pack("<III", numeric_id, 0xFFFFFFFF, 0) + data_item(name)


def task_record(numeric_id: int, name: str) -> bytes:
    """TASK struct (28 bytes) followed by its name DATA_ITEM."""
    return struct.pack("<II16sI", numeric_id, 0xFFFFFFFF, b"\x00" * 16, 0) + data_item(name)


def opcode_record(value: int, name: str) -> bytes:
    """OPCO struct (12 bytes) followed by its name DATA_ITEM."""
    return struct.pack("<HHII", 0, value, 0xFFFFFFFF, 0) + data_item(name)


def vmap_block(name: str, values: list[tuple[int, int]]) -> bytes:
    """A standalone VMAP WEVT object: header, value pairs, sentinel, then name item.

    The header ``data_offset`` is an absolute file offset and is finalized to the real
    anchor during layout; here it stores the offset of the name item relative to the
    block start as a placeholder.
    """
    name_item = data_item(name)
    entries = b"".join(struct.pack("<II", value, message_id) for value, message_id in values)
    entries += struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)
    size = 12 + len(entries) + len(name_item)
    return struct.pack("<4sII", b"VMAP", size, 12 + len(entries)) + entries + name_item


def _finalize_vmap(raw: bytes, anchor: int) -> bytes:
    """Patch the absolute name-item offset now that the block has an anchor."""
    name_rel = struct.unpack_from("<I", raw, 8)[0]
    blob = bytearray(raw)
    struct.pack_into("<I", blob, 8, anchor + name_rel)
    return bytes(blob)


def _finalize_named_record(raw: bytes, anchor: int, struct_len: int) -> bytes:
    """Point a LEVL/TASK/OPCO struct's last uint32 at its trailing name DATA_ITEM."""
    blob = bytearray(raw)
    struct.pack_into("<I", blob, struct_len - 4, anchor + struct_len)
    return bytes(blob)


def temp_block(temp_id: int) -> bytes:
    """A relocatable TEMP block with a deterministic GUID, based on a real BXML template.

    The block still carries its original absolute offsets and is finalized (relocated to
    its real anchor and re-identified) by :class:`ProviderBuilder` during layout.
    """
    guid = UUID(bytes_le=struct.pack("<II", temp_id, 0) + b"\x00" * 8)
    blob = bytearray(TEMP_HEADER)
    blob[24:40] = guid.bytes_le
    return bytes(blob)


def _relocate_temp(raw: bytes, new_anchor: int) -> bytes:
    """Shift every absolute offset inside a TEMP block to ``new_anchor``."""
    blob = bytearray(raw)
    delta = new_anchor - TEMP_ORIGIN
    for offset in range(0, len(blob) - 3, 4):
        value = struct.unpack_from("<I", blob, offset)[0]
        if TEMP_ORIGIN <= value < TEMP_ORIGIN + len(blob):
            struct.pack_into("<I", blob, offset, value + delta)
    return bytes(blob)


def evnt_record(
    *,
    event_id: int,
    level: int,
    level_offset: int,
    task: int,
    task_offset: int,
    opcode: int = 0,
    opcode_offset: int = 0,
    template_offset: int = 0,
) -> bytes:
    """Build one 48-byte EVNT struct."""
    return c_wevt.EVNT(
        id=event_id,
        version=0,
        channel=0,
        level=level,
        opcode=opcode,
        task=task,
        keyword=0,
        message_table_id=0xFFFFFFFF,
        template_offset=template_offset,
        opcode_offset=opcode_offset,
        level_offset=level_offset,
        task_offset=task_offset,
        data_counter=0,
        data_offset=0,
        flags=0,
    ).dumps()


class ProviderBuilder:
    """Collects typed record payloads and lays them out into a provider region."""

    def __init__(self, provider_id: UUID):
        self.provider_id = provider_id
        # kind -> list of raw payload records (without the WEVT_TYPE container header).
        self._records: dict[str, list[bytes]] = {}
        # VMAP blocks destined for the MAPS container, in insertion order.
        self._vmaps: list[bytes] = []
        # Absolute offsets populated during layout.
        self.level_offsets: dict[int, int] = {}
        self.task_offsets: dict[int, int] = {}
        self.opcode_offsets: dict[int, int] = {}
        self.temp_offsets: dict[int, int] = {}
        self.event_offsets: list[int] = []
        self.vmap_offsets: list[int] = []
        self.maps_pointer_table_offset = 0
        self.wevt_offset = 0
        self.range_end = 0

    def add_level(self, numeric_id: int, name: str) -> None:
        self._records.setdefault("LEVL", []).append(level_record(numeric_id, name))

    def add_task(self, numeric_id: int, name: str) -> None:
        self._records.setdefault("TASK", []).append(task_record(numeric_id, name))

    def add_opcode(self, value: int, name: str) -> None:
        self._records.setdefault("OPCO", []).append(opcode_record(value, name))

    def add_event(self, record: bytes) -> None:
        self._records.setdefault("EVNT", []).append(record)

    def reserve_event(self) -> int:
        """Reserve a 48-byte EVNT slot and return its future absolute offset.

        The slot is filled later via :meth:`fill_event`, allowing a test to build an
        event that references offsets computed during this same layout.
        """
        self._records.setdefault("EVNT", []).append(b"\x00" * 48)
        return len(self._records["EVNT"]) - 1

    def fill_event(self, slot: int, record: bytes) -> None:
        """Overwrite a reserved EVNT slot with a fully populated record."""
        if len(record) != 48:
            raise ValueError("EVNT record must be 48 bytes")
        self._records["EVNT"][slot] = record

    def add_temp(self, temp_id: int) -> None:
        self._records.setdefault("TTBL", []).append(temp_block(temp_id))

    def add_vmap(self, name: str, values: list[tuple[int, int]]) -> None:
        self._vmaps.append(vmap_block(name, values))

    def build_region(self, base: int) -> bytes:
        """Render the full WEVT region starting at absolute offset ``base``."""
        # Reset derived indices so repeated (two-phase) builds stay idempotent.
        self.level_offsets = {}
        self.task_offsets = {}
        self.opcode_offsets = {}
        self.temp_offsets = {}
        self.event_offsets = []
        self.vmap_offsets = []
        block_order = [kind for kind in ("LEVL", "TASK", "OPCO", "TTBL", "MAPS", "EVNT") if kind in self._present()]
        type_table = b""
        body = bytearray()
        # The WEVT header is 16 bytes + 8 bytes per type entry.
        header_size = 16 + 8 * len(block_order)
        cursor = base + header_size
        for kind in block_order:
            block, block_size = self._render_block(kind, cursor)
            type_table += struct.pack("<II", TYPE_CODE[kind], cursor)
            body += block
            cursor += block_size
        header = struct.pack("<4sIII", b"WEVT", header_size + len(body), 0xFFFFFFFF, len(block_order))
        region = header + type_table + bytes(body)
        self.wevt_offset = base
        self.range_end = base + len(region)
        self._index_offsets(base, region)
        return region

    def _present(self) -> set[str]:
        present = set(self._records)
        if self._vmaps:
            present.add("MAPS")
        return present

    def _render_block(self, kind: str, block_abs: int) -> tuple[bytes, int]:
        if kind == "MAPS":
            return self._render_maps(block_abs)
        if kind == "TTBL":
            return self._render_ttbl(block_abs)
        payload_records = self._records[kind]
        record_lens = {"LEVL": 12, "TASK": 28, "OPCO": 12, "CHAN": 20}
        record_len = record_lens.get(kind, 48)
        cursor = block_abs + 12
        payload = b""
        for record in payload_records:
            if kind in record_lens:
                # Finalize the absolute data_offset that points at the name DATA_ITEM.
                record = _finalize_named_record(record, cursor, record_len)
            payload += record
            cursor += len(record)
        nr_items = len(payload_records)
        if kind == "EVNT":
            # EVNT blocks carry a 4-byte zero prefix before the first record.
            payload = b"\x00\x00\x00\x00" + payload
        block = struct.pack("<4sII", kind.encode("ascii"), 12 + len(payload), nr_items) + payload
        return block, len(block)

    def _render_ttbl(self, block_abs: int) -> tuple[bytes, int]:
        # Each TEMP is preceded by the 12-byte TTBL header and laid out back to back.
        cursor = block_abs + 12
        payload = b""
        for raw in self._records["TTBL"]:
            relocated = _relocate_temp(raw, cursor)
            payload += relocated
            cursor += len(relocated)
        block = struct.pack("<4sII", b"TTBL", 12 + len(payload), len(self._records["TTBL"])) + payload
        return block, len(block)

    def _render_maps(self, block_abs: int) -> tuple[bytes, int]:
        nr_maps = len(self._vmaps)
        table_len = nr_maps * 4
        header_len = 12
        # VMAP blocks follow the pointer table; remember where each one lands.
        first_map = block_abs + header_len + table_len
        cursor = first_map
        pointers = b""
        body = b""
        for raw_vmap in self._vmaps:
            pointers += struct.pack("<I", cursor)
            vmap = _finalize_vmap(raw_vmap, cursor)
            body += vmap
            cursor += len(vmap)
        self.maps_pointer_table_offset = block_abs + header_len
        header = struct.pack("<4sII", b"MAPS", header_len + table_len + len(body), nr_maps)
        return header + pointers + body, header_len + table_len + len(body)

    def _index_offsets(self, base: int, region: bytes) -> None:
        """Record absolute offsets of every nested record for test assertions."""
        # Walk type blocks using the WEVT_TYPES table rather than hardcoding positions.
        nr_types = struct.unpack_from("<I", region, 12)[0]
        table_at = 16
        block_locations = {}
        for index in range(nr_types):
            type_code, abs_offset = struct.unpack_from("<II", region, table_at + index * 8)
            block_locations[abs_offset] = type_code
        for abs_offset in sorted(block_locations):
            rel = abs_offset - base
            signature = region[rel : rel + 4]
            nr_items = struct.unpack_from("<I", region, rel + 8)[0]
            if signature == b"LEVL":
                self._index_named(region, rel, nr_items, 12, self.level_offsets)
            elif signature == b"TASK":
                self._index_named(region, rel, nr_items, 28, self.task_offsets)
            elif signature == b"OPCO":
                self._index_named(region, rel, nr_items, 12, self.opcode_offsets, id_at=2)
            elif signature == b"TTBL":
                self._index_temps(region, rel, nr_items)
            elif signature == b"MAPS":
                self._index_maps(region, rel, nr_items)
            elif signature == b"EVNT":
                record_at = rel + 12 + 4  # skip the EVNT 4-byte zero prefix
                for index in range(nr_items):
                    self.event_offsets.append(self.wevt_offset + record_at + index * 48)

    def _index_named(
        self, region: bytes, block_rel: int, nr_items: int, record_len: int, target: dict[int, int], id_at: int = 0
    ) -> None:
        record_at = block_rel + 12
        pack_format = "<I" if id_at == 0 else "<H"
        for index in range(nr_items):
            record_rel = record_at + index * record_len
            numeric_id = struct.unpack_from(pack_format, region, record_rel + id_at)[0]
            target.setdefault(numeric_id, self.wevt_offset + record_rel)

    def _index_temps(self, region: bytes, block_rel: int, nr_items: int) -> None:
        cursor = block_rel + 12
        for _ in range(nr_items):
            temp_id = struct.unpack_from("<I", region, cursor + 24)[0]
            self.temp_offsets.setdefault(temp_id, self.wevt_offset + cursor)
            size = struct.unpack_from("<I", region, cursor + 4)[0]
            cursor += size

    def _index_maps(self, region: bytes, block_rel: int, nr_items: int) -> None:
        table_rel = block_rel + 12
        for index in range(nr_items):
            pointer = struct.unpack_from("<I", region, table_rel + index * 4)[0]
            self.vmap_offsets.append(pointer)


def build_resource(builders: list[ProviderBuilder]) -> bytes:
    """Assemble a complete CRIM file from fully independent provider builders."""
    provider_count = len(builders)
    cursor = 16 + provider_count * 20
    regions: list[bytes] = []
    descriptors = b""
    for builder in builders:
        descriptors += builder.provider_id.bytes_le
        region = builder.build_region(cursor)
        descriptors += struct.pack("<I", builder.wevt_offset)
        regions.append(region)
        cursor = builder.range_end
    header = struct.pack("<4sIII", b"CRIM", cursor, 0, provider_count)
    return header + descriptors + b"".join(regions)
