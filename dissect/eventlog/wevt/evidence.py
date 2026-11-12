"""Provider-scoped, offset-anchored evidence view over a WEVT_TEMPLATE resource.

The low level :mod:`dissect.eventlog.wevt` parser turns a WEVT resource into nested
objects, but it does not tie those objects back to the provider that owns them and it
does not validate the references stored inside an ``EVNT`` record or a ``MAPS`` pointer
table.  This module wraps that parser and produces an *evidence view* that a backend can
use to explain the task, level, opcode, template and mapped values of an event.

The guiding rule is that an interpretation is only ever trusted when every byte it is
based on lives inside the byte range of the provider that emitted the event.  A numeric
identifier is never resolved against another provider, even when that other provider
happens to use the same number.  Anything that cannot be verified is kept as the raw
identifier together with an error reason instead of being turned into a plausible but
unfounded description.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.eventlog.wevt import CRIM
from dissect.eventlog.wevt.c_wevt import c_wevt
from dissect.eventlog.wevt.wevt_object import (
    BMAP,
    EVNT,
    TEMP,
    VMAP,
    WevtObject,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

#: Object kinds that carry a single numeric identifier and can be indexed by it.
NAMED_ID_KINDS = frozenset({"CHAN", "LEVL", "TASK", "KEYW", "OPCO"})

#: Last entry of a value map is a sentinel with this value/message id.
MAP_SENTINEL = 0xFFFFFFFF


class EvidenceError(ValueError):
    """Raised internally when a reference cannot be verified inside its provider."""


@dataclass(frozen=True, slots=True)
class ByteRange:
    """The absolute ``[start, end)`` byte range occupied by one provider payload."""

    start: int
    end: int

    def contains(self, offset: int, length: int = 0) -> bool:
        """Return whether ``[offset, offset + length)`` is fully inside the range."""
        return self.start <= offset and offset + length <= self.end

    def __str__(self) -> str:
        return f"0x{self.start:x}-0x{self.end:x}"


@dataclass(frozen=True, slots=True)
class Evidence:
    """A single parsed object with full provenance.

    Attributes:
        provider_id: GUID of the provider that owns this object.
        kind: WEVT element signature, e.g. ``"EVNT"`` or ``"TASK"``.
        offset: Absolute byte offset of the object inside the resource file.
        size: Declared size of the object in bytes.
        range: Byte range of the owning provider payload.
        numeric_id: Numeric identifier, if the kind exposes one (else ``None``).
        name: Resolved name, when available (else ``None``).
        object: The underlying parsed :class:`WevtObject`.
    """

    provider_id: UUID
    kind: str
    offset: int
    size: int
    range: ByteRange
    numeric_id: int | None = None
    name: str | None = None
    object: WevtObject | None = None

    @property
    def in_range(self) -> bool:
        """Whether the full declared object lies inside its provider range."""
        return self.range.contains(self.offset, self.size)


@dataclass(frozen=True, slots=True)
class Reference:
    """The result of resolving one pointer stored inside an ``EVNT`` record.

    A reference always carries the raw numeric identifier that the event itself stores
    (``raw_id``) and the raw pointer (``raw_offset``).  When the pointer can be verified,
    ``evidence`` points at the owning provider's object.  Otherwise ``evidence`` is
    ``None`` and ``error`` explains why, while the raw values are preserved.
    """

    field: str
    raw_id: int | None
    raw_offset: int
    evidence: Evidence | None
    error: str | None = None

    @property
    def resolved(self) -> bool:
        """Whether the reference was verified against an in-provider object."""
        return self.evidence is not None and self.error is None

    @property
    def name(self) -> str | None:
        """Name of the resolved object, or ``None`` when unresolved."""
        return self.evidence.name if self.evidence is not None else None


@dataclass(frozen=True, slots=True)
class MapEntry:
    """One ``(value, message_table_id)`` pair inside a value or bit map."""

    value: int
    message_table_id: int
    offset: int


@dataclass(frozen=True, slots=True)
class ValueMap:
    """A validated ``VMAP``/``BMAP`` and its value entries.

    ``entries`` is ordered exactly as stored; it is not re-keyed, so a shuffled ``MAPS``
    pointer table cannot cause values from two maps to be mixed.
    """

    provider_id: UUID
    kind: str
    name: str
    offset: int
    size: int
    range: ByteRange
    entries: tuple[MapEntry, ...]

    def lookup(self, value: int) -> MapEntry | None:
        """Return the entry for ``value`` from this map only, or ``None``."""
        for entry in self.entries:
            if entry.value == value:
                return entry
        return None


@dataclass(frozen=True, slots=True)
class EventInterpretation:
    """A verified explanation of one ``EVNT`` record."""

    event: Evidence
    task: Reference
    level: Reference
    opcode: Reference
    template: Reference

    @property
    def references(self) -> tuple[Reference, ...]:
        """All four references in a fixed order."""
        return (self.task, self.level, self.opcode, self.template)

    @property
    def fully_resolved(self) -> bool:
        """Whether every present reference was verified inside the provider."""
        return all(reference.resolved for reference in self.references if reference.raw_offset)

    @property
    def errors(self) -> tuple[Reference, ...]:
        """References that could not be verified, each carrying its reason."""
        return tuple(reference for reference in self.references if reference.error is not None)


@dataclass(slots=True)
class ProviderEvidence:
    """Everything that can be proven about a single provider in the resource."""

    provider_id: UUID
    range: ByteRange
    wevt_offset: int
    payload_size: int
    _by_kind: dict[str, list[Evidence]] = field(default_factory=dict)
    _id_index: dict[tuple[str, int], Evidence] = field(default_factory=dict)
    _offset_index: dict[int, Evidence] = field(default_factory=dict)
    _templates: dict[UUID, Evidence] = field(default_factory=dict)
    _value_maps: list[ValueMap] = field(default_factory=list)
    _events: list[Evidence] = field(default_factory=list)

    def evidence(self, kind: str) -> tuple[Evidence, ...]:
        """Return all evidence objects of ``kind`` in storage order."""
        return tuple(self._by_kind.get(kind, ()))

    def all_evidence(self) -> Iterator[Evidence]:
        """Iterate every collected evidence object."""
        for items in self._by_kind.values():
            yield from items

    def lookup_id(self, kind: str, numeric_id: int) -> Evidence | None:
        """Resolve an identifier strictly inside this provider.

        Returns ``None`` when this provider has no such identifier; the caller must never
        fall back to another provider's same-numbered definition.
        """
        return self._id_index.get((kind, numeric_id))

    def lookup_offset(self, offset: int) -> Evidence | None:
        """Return the evidence object anchored at ``offset``, if any."""
        return self._offset_index.get(offset)

    def lookup_template(self, identifier: UUID) -> Evidence | None:
        """Resolve a ``TEMP`` by its GUID inside this provider only."""
        return self._templates.get(identifier)

    @property
    def value_maps(self) -> tuple[ValueMap, ...]:
        """All validated value/bit maps owned by this provider."""
        return tuple(self._value_maps)

    @property
    def events(self) -> tuple[Evidence, ...]:
        """All ``EVNT`` evidence objects owned by this provider."""
        return tuple(self._events)

    def interpret_event(self, event: Evidence) -> EventInterpretation:
        """Verify every reference of an ``EVNT`` evidence object.

        The numeric identifiers stored in the event (``task``, ``level``, ``opcode``) are
        resolved strictly through this provider's own index, and the accompanying pointers
        must both land inside this provider's byte range and anchor an object of the
        expected kind.  A failed reference keeps its raw id and an error reason.
        """
        if event.kind != "EVNT":
            raise EvidenceError(f"Expected EVNT evidence, got {event.kind}")
        record: EVNT = event.object
        return EventInterpretation(
            event=event,
            task=self._resolve_id_reference("TASK", record.task, record.task_offset),
            level=self._resolve_id_reference("LEVL", record.level, record.level_offset),
            opcode=self._resolve_id_reference("OPCO", record.opcode, record.opcode_offset),
            template=self._resolve_template_reference(record.template_offset),
        )

    def _resolve_id_reference(self, kind: str, raw_id: int, raw_offset: int) -> Reference:
        field_name = kind.lower()
        if raw_offset == 0:
            return Reference(field_name, raw_id, raw_offset, None, None)
        if not self.range.contains(raw_offset):
            return Reference(
                field_name,
                raw_id,
                raw_offset,
                None,
                f"{kind} offset 0x{raw_offset:x} is outside provider range {self.range}",
            )
        evidence = self._offset_index.get(raw_offset)
        if evidence is None:
            return Reference(
                field_name,
                raw_id,
                raw_offset,
                None,
                f"no parsed {kind} anchored at offset 0x{raw_offset:x}",
            )
        if evidence.kind != kind:
            # Keep the anchored object as evidence of what is actually there, but never
            # treat it as a valid explanation for the expected kind.
            return Reference(
                field_name,
                raw_id,
                raw_offset,
                evidence,
                f"offset 0x{raw_offset:x} anchors {evidence.kind}, expected {kind}",
            )
        if evidence.numeric_id is not None and evidence.numeric_id != raw_id and raw_id != 0:
            return Reference(
                field_name,
                raw_id,
                raw_offset,
                evidence,
                f"{kind} numeric id {raw_id} does not match anchored id {evidence.numeric_id}",
            )
        return Reference(field_name, raw_id, raw_offset, evidence, None)

    def _resolve_template_reference(self, raw_offset: int) -> Reference:
        if raw_offset == 0:
            return Reference("template", None, raw_offset, None, None)
        if not self.range.contains(raw_offset):
            return Reference(
                "template",
                None,
                raw_offset,
                None,
                f"TEMP offset 0x{raw_offset:x} is outside provider range {self.range}",
            )
        evidence = self._offset_index.get(raw_offset)
        if evidence is None or evidence.kind != "TEMP":
            return Reference(
                "template",
                None,
                raw_offset,
                None,
                f"no TEMP anchored at offset 0x{raw_offset:x}",
            )
        return Reference("template", None, raw_offset, evidence, None)


class EvidenceView:
    """A complete, provider-partitioned evidence view over a WEVT_TEMPLATE file."""

    def __init__(self, fh: BinaryIO):
        self._providers: dict[UUID, ProviderEvidence] = {}
        self._ordered: list[ProviderEvidence] = []
        crim = CRIM(fh)
        self.file_size = crim.file_size
        for wevt in crim.wevt_headers():
            builder = _ProviderBuilder(wevt)
            provider = builder.build()
            self._providers[provider.provider_id] = provider
            self._ordered.append(provider)

    def __iter__(self) -> Iterator[ProviderEvidence]:
        return iter(self._ordered)

    def __len__(self) -> int:
        return len(self._ordered)

    @property
    def providers(self) -> tuple[ProviderEvidence, ...]:
        """All providers in resource order."""
        return tuple(self._ordered)

    def provider(self, provider_id: UUID) -> ProviderEvidence:
        """Return one provider's evidence, keyed by its GUID."""
        return self._providers[provider_id]

    def interpret_event(self, provider_id: UUID, event: Evidence) -> EventInterpretation:
        """Interpret an event using only the named provider's own definitions."""
        return self._providers[provider_id].interpret_event(event)


class _ProviderBuilder:
    """Walks one :class:`~dissect.eventlog.wevt.wevt.WEVT` payload into evidence."""

    def __init__(self, wevt: object):
        self._wevt = wevt
        provider_id = wevt.provider_id
        byte_range = ByteRange(wevt.offset, wevt.offset + wevt.payload_size)
        self._evidence = ProviderEvidence(
            provider_id=provider_id,
            range=byte_range,
            wevt_offset=wevt.offset,
            payload_size=wevt.payload_size,
        )

    def build(self) -> ProviderEvidence:
        for wevt_type in self._wevt:
            container_kind = wevt_type.signature
            if container_kind == "MAPS":
                self._collect_maps(wevt_type)
                continue
            # A TTBL only groups TEMP objects; index each parsed object by its own
            # signature so template pointers resolve to TEMP evidence, not the container.
            collected: list[Evidence] = []
            for parsed in self._safe_iter(wevt_type):
                evidence = self._to_evidence(parsed)
                collected.append(evidence)
            self._store(container_kind, collected)
        return self._evidence

    def _safe_iter(self, wevt_type: object) -> Iterator[WevtObject]:
        try:
            yield from wevt_type
        except (EOFError, struct.error):
            return

    def _store(self, container_kind: str, collected: Sequence[Evidence]) -> None:
        bucket = self._evidence._by_kind.setdefault(container_kind, [])
        bucket.extend(collected)
        for evidence in collected:
            kind = evidence.kind
            if kind != container_kind:
                self._evidence._by_kind.setdefault(kind, []).append(evidence)
            self._evidence._offset_index[evidence.offset] = evidence
            if kind in NAMED_ID_KINDS and evidence.numeric_id is not None:
                # First occurrence wins; duplicate ids inside one provider stay visible
                # in the kind bucket but never overwrite the primary index entry.
                self._evidence._id_index.setdefault((kind, evidence.numeric_id), evidence)
            if kind == "TEMP":
                template: TEMP = evidence.object
                self._evidence._templates.setdefault(template.identifier, evidence)
            if kind == "EVNT":
                self._evidence._events.append(evidence)

    def _to_evidence(self, parsed: WevtObject) -> Evidence:
        kind = parsed.__class__.__name__
        numeric_id = getattr(parsed, "id", None)
        if kind == "EVNT":
            numeric_id = parsed.header.id
        name = getattr(parsed, "name", None)
        size = getattr(parsed.header, "size", None)
        if not isinstance(size, int):
            size = len(parsed.header)
        return Evidence(
            provider_id=self._evidence.provider_id,
            kind=kind,
            offset=parsed.offset,
            size=size,
            range=self._evidence.range,
            numeric_id=numeric_id,
            name=name,
            object=parsed,
        )

    def _collect_maps(self, maps_type: object) -> None:
        # ``payload`` starts directly after the 12-byte WEVT_TYPE header, i.e. at the
        # first uint32 pointer of the MAPS pointer table.
        payload = maps_type.payload
        provider_range = self._evidence.range
        for index in range(maps_type.nr_of_items):
            pointer = c_wevt.uint32(payload[index * 4 : index * 4 + 4])
            value_map = self._build_value_map(pointer, provider_range)
            if value_map is not None:
                self._evidence._value_maps.append(value_map)

    def _build_value_map(self, pointer: int, byte_range: ByteRange) -> ValueMap | None:
        if pointer == 0:
            return None
        if not byte_range.contains(pointer, 12):
            # A pointer leaving the provider (e.g. into another provider's region) is
            # recorded nowhere as a usable map, so it can never explain an event.
            return None
        relative = pointer - self._wevt.offset
        signature = bytes(c_wevt.char[4](self._wevt.data[relative:]))
        if signature not in (b"VMAP", b"BMAP"):
            return None
        parsed = (
            VMAP(pointer, self._wevt.data[relative:])
            if signature == b"VMAP"
            else BMAP(pointer, self._wevt.data[relative:])
        )
        entries = self._read_map_entries(pointer, parsed.header.size, byte_range)
        return ValueMap(
            provider_id=self._evidence.provider_id,
            kind=signature.decode("ascii"),
            name=parsed.name,
            offset=pointer,
            size=parsed.header.size,
            range=byte_range,
            entries=tuple(entries),
        )

    def _read_map_entries(self, map_offset: int, map_size: int, byte_range: ByteRange) -> list[MapEntry]:
        entries: list[MapEntry] = []
        cursor = map_offset + 12
        end = map_offset + map_size
        while cursor + 8 <= end and byte_range.contains(cursor, 8):
            value, message_table_id = struct.unpack_from("<II", self._wevt.data, cursor - self._wevt.offset)
            if value == MAP_SENTINEL and message_table_id == MAP_SENTINEL:
                break
            entries.append(MapEntry(value=value, message_table_id=message_table_id, offset=cursor))
            cursor += 8
        return entries
