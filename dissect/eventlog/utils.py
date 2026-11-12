from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SourceKind(str, Enum):
    """Where a byte range that contributes to a field lives.

    The kinds are intentionally coarse: they answer the forensic question "which evidence
    container do I need to keep, and can I trust that the bytes are still the ones used?".
    """

    RECORD = "record"
    """Bytes inside the BXML payload of the record currently being read."""

    TEMPLATE = "template"
    """Bytes of a template definition stored in the chunk and reused by (possibly other) records."""

    NAME = "name"
    """A name-table entry stored in the chunk (element or attribute name).

    A ``BXML_NAME`` record is a separate structure from the template fragment, even when the
    chunk packs them adjacently, so it is always reported as its own range.
    """

    CHUNK_RELATIVE = "chunk_relative"
    """A byte range relative to the start of a chunk.

    Used only when the parser was given raw chunk bytes without an absolute file offset.
    ``start`` is exact within the chunk, but callers must supply the chunk base offset to
    read it back from a file.
    """

    UNRESOLVED = "unresolved"
    """A range that could not be determined exactly.

    Such ranges are never given a guessed offset. ``start`` and ``length`` are ``None`` and
    ``reason`` explains why the evidence boundary is unknown.
    """


@dataclass(frozen=True)
class ByteRange:
    """A half-open byte range ``[start, start + length)`` in the EVTX file.

    ``start`` and ``length`` are ``None`` only for :attr:`SourceKind.UNRESOLVED` ranges.
    :attr:`kind` says which evidence region the range belongs to, and
    :attr:`SourceKind.CHUNK_RELATIVE` means ``start`` is relative to the chunk base rather
    than to the start of the file.
    """

    kind: SourceKind
    start: int | None = None
    length: int | None = None
    role: str | None = None
    reason: str | None = None

    @property
    def end(self) -> int | None:
        if self.start is None or self.length is None:
            return None
        return self.start + self.length

    @property
    def offset(self) -> int | None:
        """Alias for :attr:`start` (absolute file offset unless the kind is chunk-relative)."""
        return self.start

    @property
    def size(self) -> int | None:
        """Alias for :attr:`length`."""
        return self.length

    @property
    def is_resolved(self) -> bool:
        return self.start is not None and self.length is not None

    def read(self, source: Any, chunk_offset: int | None = None) -> bytes:
        """Read the original bytes for this range from a file-like or ``bytes`` source.

        The range is validated against the source length, so an inconsistent report can never
        silently return bytes from a different field. A seekable stream is read at the
        reported absolute offset without leaving the caller's file position modified.

        For :attr:`SourceKind.CHUNK_RELATIVE` ranges, ``chunk_offset`` supplies the absolute
        base of the chunk; without it the range cannot be mapped to a whole-file stream.
        """
        if not self.is_resolved:
            raise ValueError(f"Unresolved byte range: {self.reason or 'unknown'}")

        start = self.start
        if self.kind is SourceKind.CHUNK_RELATIVE:
            if chunk_offset is None:
                raise ValueError("Chunk-relative byte range requires a chunk_offset")
            start += chunk_offset
        end = start + self.length

        if isinstance(source, bytes | bytearray | memoryview):
            data = bytes(source)
            length = len(data)
            if end > length:
                raise ValueError(f"Byte range {start:#x}+{self.length:#x} exceeds source of {length:#x} bytes")
            return data[start:end]

        if hasattr(source, "seek") and hasattr(source, "tell"):
            position = source.tell()
            size = None
            try:
                source.seek(0, 2)
                size = source.tell()
            except (OSError, ValueError):
                size = None
            finally:
                source.seek(position)

            if size is not None and end > size:
                raise ValueError(f"Byte range {start:#x}+{self.length:#x} exceeds source of {size:#x} bytes")

            try:
                source.seek(start)
                return bytes(source.read(self.length))
            finally:
                source.seek(position)

        data = bytes(source.read())
        if end > len(data):
            raise ValueError(f"Byte range {start:#x}+{self.length:#x} exceeds source of {len(data):#x} bytes")
        return data[start:end]

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"kind": self.kind.value, "start": self.start, "length": self.length}
        if self.role is not None:
            result["role"] = self.role
        if self.reason is not None:
            result["reason"] = self.reason
        return result

    def __repr__(self) -> str:
        if not self.is_resolved:
            return f"ByteRange(kind={self.kind.value!r}, unresolved={self.reason!r})"
        return (
            f"ByteRange(kind={self.kind.value!r}, start={self.start:#x}, "
            f"length={self.length:#x}, role={self.role!r})"
        )


def unresolved(reason: str, role: str | None = None) -> ByteRange:
    """Create an explicitly unresolved range; never guess an offset."""
    return ByteRange(SourceKind.UNRESOLVED, None, None, role, reason)


def merge_ranges(ranges: list[ByteRange]) -> list[ByteRange]:
    """Return ranges unchanged, preserving order, duplicates and overlaps.

    Merging adjacent ranges would fabricate a contiguous span across unrelated evidence (for
    example a template value followed by a name entry), so this helper deliberately only
    normalises the container type. It exists to make the "keep every range" rule explicit at
    call sites.
    """
    return list(ranges)


def source_for(record: KeyValueCollection, key: str) -> FieldSource | None:
    """Return the :class:`FieldSource` for ``key`` if the record was read with sources."""
    sources = getattr(record, "sources", None)
    return sources.get(key) if sources is not None else None


@dataclass(frozen=True)
class FieldSource:
    """The complete source chain for a single flattened output key.

    ``key`` is the key as it appears in the :class:`KeyValueCollection`, including any
    duplicate suffix such as ``Data_1``. ``ranges`` contains every byte range that contributed
    to the value; it is never reduced to a single range. ``path`` records the nested element
    path with attributes named ``@attr`` and the substitution slot marked ``#``.
    """

    key: str
    ranges: tuple[ByteRange, ...] = ()
    path: tuple[str, ...] = ()
    value_type: str | None = None
    sub_id: int | None = None
    template_offset: int | None = None
    record_offset: int | None = None
    record_id: int | None = None
    chunk_offset: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def read_all(self, source: Any) -> list[bytes]:
        """Read every range, in report order.

        Raises ``ValueError`` when any part of the chain is unresolved: a partial read would
        hide that the evidence boundary is unknown.
        """
        if not self.is_resolved:
            unresolved_ranges = [byte_range for byte_range in self.ranges if not byte_range.is_resolved]
            reason = unresolved_ranges[0].reason if unresolved_ranges else "no ranges recorded"
            raise ValueError(f"Field source for {self.key!r} is not fully resolved: {reason}")
        return [
            byte_range.read(source, chunk_offset=self.chunk_offset)
            if byte_range.kind is SourceKind.CHUNK_RELATIVE
            else byte_range.read(source)
            for byte_range in self.ranges
        ]

    @property
    def is_resolved(self) -> bool:
        return bool(self.ranges) and all(byte_range.is_resolved for byte_range in self.ranges)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "key": self.key,
            "ranges": [byte_range.to_dict() for byte_range in self.ranges],
            "path": list(self.path),
        }
        for name in ("value_type", "sub_id", "template_offset", "record_offset", "record_id"):
            value = getattr(self, name)
            if value is not None:
                result[name] = value
        if self.detail:
            result["detail"] = dict(self.detail)
        return result


class SourceCollection(dict):
    """Mapping of output key to its :class:`FieldSource`, stored alongside a record.

    ``SourceCollection`` never replaces the :class:`KeyValueCollection`; it is attached to the
    record as an attribute. Keys mirror the flattened output exactly, so a lookup is a direct
    key access rather than a search through the record.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.record_offset: int | None = None
        self.record_id: int | None = None
        self.chunk_offset: int | None = None
        # Whether ranges are absolute file offsets or chunk-relative.
        self.absolute: bool = True

    def copy(self) -> SourceCollection:
        """Copy the collection, keeping the record identity."""
        result = type(self)(self)
        result.record_offset = self.record_offset
        result.record_id = self.record_id
        result.chunk_offset = self.chunk_offset
        result.absolute = self.absolute
        return result

    def to_dict(self) -> dict[str, Any]:
        """Serialize the whole record's source chains, including record identity."""
        result: dict[str, Any] = {"fields": {key: source.to_dict() for key, source in self.items()}}
        for name in ("record_offset", "record_id", "chunk_offset"):
            value = getattr(self, name)
            if value is not None:
                result[name] = value
        result["absolute"] = self.absolute
        return result


class KeyValueCollection(dict):
    """A dictionary subclass that handles setting duplicate keys by appending an index number to the duplicate key.

    Example:
        >>>  d = KeyValueCollection()
        >>>  d["foo"] = "bar"
        >>>  d["foo"] = "baz"  # Duplicate key
        >>>  d
        {'foo': 'bar', 'foo_1': 'baz'}
    """

    def __init__(self):
        super().__init__()
        self.idx = {}

    def add(self, key: str, value: Any) -> str:
        """Store ``value`` and return the key that was actually used.

        Duplicate handling is identical to :meth:`__setitem__`. Returning the final key lets
        provenance bookkeeping use exactly the same names as the record output, including
        suffixes such as ``Data_1``.
        """
        if key in self.idx:
            self.idx[key] += 1
            key = f"{key}_{self.idx[key]}"
        else:
            self.idx[key] = 0

        dict.__setitem__(self, key, value)
        return key

    def __setitem__(self, key: str, value: Any) -> None:
        self.add(key, value)

    def copy(self) -> KeyValueCollection | dict:
        """Copy the collection, preserving an attached :class:`SourceCollection`.

        Records without source information keep the historical ``dict.copy`` return type so
        the default interface is unchanged.
        """
        if not hasattr(self, "sources"):
            return super().copy()

        result = type(self)()
        dict.update(result, self)
        result.idx = dict(self.idx)
        result.sources = self.sources.copy()
        return result


def attach_sources(record: KeyValueCollection, sources: SourceCollection) -> KeyValueCollection:
    """Attach a fully staged :class:`SourceCollection` to ``record``.

    Every :class:`FieldSource` is rebuilt once with the record identity so callers never see a
    partially populated source chain, even during iteration.
    """
    staged = {}
    for key, field_source in sources.items():
        staged[key] = FieldSource(
            key=field_source.key,
            ranges=field_source.ranges,
            path=field_source.path,
            value_type=field_source.value_type,
            sub_id=field_source.sub_id,
            template_offset=field_source.template_offset,
            record_offset=sources.record_offset,
            record_id=sources.record_id,
            chunk_offset=sources.chunk_offset,
            detail=field_source.detail,
        )
    sources.clear()
    sources.update(staged)
    record.sources = sources
    return record
