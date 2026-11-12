"""Structured export of parsed Binary XML event data.

Unlike the convenience mapping (``Template.as_full_map`` / ``parse_bxml``), the structured
export keeps the forensic details that a flat string dictionary loses:

* the original field order and every duplicate (same-named) node,
* the declared Binary XML type of each value (scalar, array, null, ...),
* the distinction between an explicit null, an empty array and a missing substitution,
* stable representations for FileTime/SystemTime, SID and GUID values,
* the original bytes plus a reason for values whose descriptors are unsupported or corrupt.

Field paths are tuples of element names (attributes are prefixed with ``@``). Keeping the path
as a tuple means real underscores inside a node name can never be confused with a separator.
The convenience flattening helper joins the tuple with ``/``, which is not a legal XML name
character.

The model is JSON-serializable through :meth:`StructuredEvent.to_dict` /
:meth:`StructuredEvent.from_dict`, so an export can be written to disk and read back without
losing any of the distinctions above.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from dissect.eventlog.bxml.bxml import BxmlSub, BxmlTag, BxmlType, CorruptValue, Template

if TYPE_CHECKING:
    from collections.abc import Iterator

PATH_SEPARATOR = "/"
ATTRIBUTE_PREFIX = "@"

# Named fields that carry a substitution value. ``Template._get_map_recursive`` unwraps these
# the same way; the tag name is used (or the Data ``Name`` attribute) instead of the path.
_NAMED_DATA_TAG = "Data"
_NAME_ATTRIBUTE = "Name"
_ROOT_EVENT_TAG = "Event"


class FieldState(str, Enum):
    """How a field's value relates to the binary data."""

    SCALAR = "scalar"
    ARRAY = "array"
    NULL = "null"
    EMPTY_ARRAY = "empty_array"
    MISSING = "missing"
    CORRUPT = "corrupt"


def type_name(value_type: BxmlType | None) -> str | None:
    """Stable textual identifier for a Binary XML type (e.g. ``win:UINT32``)."""
    if value_type is None:
        return None
    return str(value_type)


def type_from_name(name: str | None) -> BxmlType | None:
    """Reverse :func:`type_name`, including pseudo-members created for unknown type ids."""
    if name is None:
        return None
    identifier = name.split(":", 1)[1]
    if identifier.isdigit():
        return BxmlType(int(identifier))
    return BxmlType[identifier]


def _json_safe(value: Any, value_type: BxmlType | None) -> Any:
    """Convert an in-memory value into a stable, JSON-serializable representation."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        if value_type == BxmlType.ANSITRING:
            return value.decode("latin-1")
        return value.hex()
    if isinstance(value, CorruptValue):
        return {"raw": value.raw.hex(), "reason": value.reason}
    if isinstance(value, list):
        return [_json_safe(item, value_type) for item in value]
    return value


def _from_json_value(value: Any, value_type: BxmlType | None) -> Any:
    """Reverse :func:`_json_safe` for the types with a non-trivial stable representation."""
    if value is None:
        return None
    if value_type in (BxmlType.FILETIME, BxmlType.SYSTEMTIME):
        return datetime.fromisoformat(value)
    if value_type == BxmlType.BINARY:
        return bytes.fromhex(value)
    if value_type == BxmlType.ANSITRING and isinstance(value, str):
        return value.encode("latin-1")
    if value_type == BxmlType.STRING and isinstance(value, str):
        return value
    return value


@dataclass
class BxmlField:
    """A single leaf value in the structured export."""

    path: tuple[str, ...]
    name: str
    state: FieldState
    value: Any = None
    type: str | None = None
    raw: str | None = None
    reason: str | None = None
    array: bool = False

    @property
    def flat_path(self) -> str:
        """Path joined with :data:`PATH_SEPARATOR`; real underscores stay untouched."""
        return PATH_SEPARATOR.join(self.path)

    def to_dict(self) -> dict[str, Any]:
        bxml_type = type_from_name(self.type)
        result: dict[str, Any] = {
            "path": list(self.path),
            "name": self.name,
            "state": self.state.value,
            "type": self.type,
            "array": self.array,
            "value": _json_safe(self.value, bxml_type)
            if self.state not in (FieldState.CORRUPT, FieldState.MISSING)
            else None,
        }
        if self.state == FieldState.CORRUPT:
            result["raw"] = self.raw
            result["reason"] = self.reason
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BxmlField:
        state = FieldState(data["state"])
        bxml_type = type_from_name(data.get("type"))
        if state == FieldState.CORRUPT:
            value = CorruptValue(bytes.fromhex(data["raw"]), data["reason"])
        elif state == FieldState.MISSING:
            value = None
        else:
            value = _from_json_value(data.get("value"), bxml_type)
        return cls(
            path=tuple(data["path"]),
            name=data["name"],
            state=state,
            value=value,
            type=data.get("type"),
            raw=data.get("raw"),
            reason=data.get("reason"),
            array=data.get("array", False),
        )


@dataclass
class StructuredEvent:
    """An ordered collection of :class:`BxmlField`, preserving duplicates and field order."""

    fields: list[BxmlField] = field(default_factory=list)

    def __iter__(self) -> Iterator[BxmlField]:
        return iter(self.fields)

    def __len__(self) -> int:
        return len(self.fields)

    def names(self) -> list[str]:
        """All field names in order, including duplicates."""
        return [item.name for item in self.fields]

    def get_all(self, name: str) -> list[BxmlField]:
        """Every field carrying ``name`` (same-named nodes are kept as separate entries)."""
        return [item for item in self.fields if item.name == name]

    def flatten(self) -> dict[str, Any]:
        """Convenience view keyed by :attr:`BxmlField.flat_path`.

        The first occurrence keeps the plain key; later duplicates get a ``_<index>`` suffix,
        mirroring :class:`dissect.eventlog.utils.KeyValueCollection`.
        """
        result: dict[str, Any] = {}
        seen: dict[str, int] = {}
        for item in self.fields:
            key = item.flat_path
            if key in seen:
                seen[key] += 1
                key = f"{key}_{seen[key]}"
            else:
                seen[key] = 0
            result[key] = item.value
        return result

    def to_dict(self) -> dict[str, Any]:
        return {"fields": [item.to_dict() for item in self.fields]}

    def to_json(self) -> str:
        import json

        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StructuredEvent:
        return cls(fields=[BxmlField.from_dict(item) for item in data["fields"]])

    @classmethod
    def from_json(cls, payload: str) -> StructuredEvent:
        import json

        return cls.from_dict(json.loads(payload))


def _field_path(path: list[BxmlTag], tag: BxmlTag, attribute: str | None = None) -> tuple[str, ...]:
    # The root Event element is structural only; paths start below it.
    names = [node.name for node in path if node.name != _ROOT_EVENT_TAG] + [tag.name]
    if attribute is not None:
        names.append(ATTRIBUTE_PREFIX + attribute)
    return tuple(names)


def _field_from_sub(path: tuple[str, ...], name: str, sub: BxmlSub) -> BxmlField:
    value = sub.get()
    declared_type = type_name(sub.value_type)

    if not sub.assigned:
        # A substitution that no template descriptor supplied a value for.
        return BxmlField(
            path=path, name=name, state=FieldState.MISSING, value=None, type=declared_type, array=sub.is_array
        )

    if value is None:
        # Explicit NullType value, distinct from a missing substitution.
        return BxmlField(
            path=path, name=name, state=FieldState.NULL, value=None, type=declared_type, array=sub.is_array
        )

    if isinstance(value, CorruptValue):
        return BxmlField(
            path=path,
            name=name,
            state=FieldState.CORRUPT,
            value=value,
            type=declared_type,
            raw=value.raw.hex(),
            reason=value.reason,
            array=sub.is_array,
        )

    if isinstance(value, list):
        if not value:
            return BxmlField(
                path=path, name=name, state=FieldState.EMPTY_ARRAY, value=[], type=declared_type, array=True
            )
        return BxmlField(path=path, name=name, state=FieldState.ARRAY, value=value, type=declared_type, array=True)

    return BxmlField(path=path, name=name, state=FieldState.SCALAR, value=value, type=declared_type, array=False)


def _walk(obj: Any, path: list[BxmlTag], event: StructuredEvent) -> None:
    if isinstance(obj, Template):
        _walk(obj.element, path, event)
        return

    if isinstance(obj, BxmlSub):
        inner = obj.get()
        if isinstance(inner, BxmlTag | Template):
            _walk(inner, path, event)
            return

        if path:
            tag = path[-1]
            name = (
                tag.attributes[_NAME_ATTRIBUTE]
                if tag.name == _NAMED_DATA_TAG and _NAME_ATTRIBUTE in tag.attributes
                else tag.name
            )
            field_path = _field_path(path[:-1], tag)
        else:
            name = f"sub_{obj.sub_id}"
            field_path = (name,)
        event.fields.append(_field_from_sub(field_path, name, obj))
        return

    if isinstance(obj, BxmlTag):
        for child in obj.children:
            _walk(child, [*path, obj], event)

        if obj.name == _ROOT_EVENT_TAG:
            return

        for key, attribute_value in obj.attributes.items():
            if obj.name == _NAMED_DATA_TAG and key == _NAME_ATTRIBUTE:
                continue
            field_path = _field_path(path, obj, key)
            if isinstance(attribute_value, BxmlSub):
                event.fields.append(_field_from_sub(field_path, key, attribute_value))
            else:
                event.fields.append(
                    BxmlField(
                        path=field_path,
                        name=key,
                        state=FieldState.SCALAR if attribute_value is not None else FieldState.NULL,
                        value=attribute_value,
                        type=type_name(BxmlType.STRING),
                    )
                )
        return

    # Bare value outside a substitution (inline text) or an untyped leaf.
    if path:
        tag = path[-1]
        if tag.name == _NAMED_DATA_TAG and _NAME_ATTRIBUTE in tag.attributes:
            name = tag.attributes[_NAME_ATTRIBUTE]
        else:
            name = tag.name
        field_path = _field_path(path[:-1], tag)
        event.fields.append(
            BxmlField(
                path=field_path,
                name=name,
                state=FieldState.SCALAR if obj is not None else FieldState.NULL,
                value=obj,
                type=None,
            )
        )


def structurize(element: BxmlTag | Template) -> StructuredEvent:
    """Build a :class:`StructuredEvent` from a parsed BXML tag or template."""
    event = StructuredEvent()
    _walk(element, [], event)
    return event
