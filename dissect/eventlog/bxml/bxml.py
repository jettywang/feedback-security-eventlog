"""Binary XML classes."""

from __future__ import annotations

import binascii
import uuid
from datetime import datetime
from enum import IntEnum
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.eventlog.bxml.c_bxml import c_bxml
from dissect.eventlog.exceptions import BxmlException
from dissect.eventlog.utils import (
    ByteRange,
    FieldSource,
    KeyValueCollection,
    SourceCollection,
    SourceKind,
    unresolved,
)
from dissect.util.ts import wintimestamp

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

    from typing_extensions import Self


class BxmlToken(IntEnum):
    BXML_END = 0x00
    BXML_START_ELEMENT = 0x01
    BXML_CLOSE_START_ELEMENT_TAG = 0x02
    BXML_CLOSE_EMPTY_ELEMENT_TAG = 0x03
    BXML_END_ELEMENT = 0x04
    BXML_VALUE = 0x05
    BXML_ATTRIBUTE = 0x06
    BXML_TOKEN_CHAR_REFERENCE = 0x08
    BXML_TOKEN_ENTITY_REFERENCE = 0x09
    BXML_TEMPLATE_INSTANCE = 0x0C
    BXML_TOKEN_NORMAL_SUBSTITUTION = 0x0D
    BXML_TOKEN_OPTIONAL_SUBSTITUTION = 0x0E
    BXML_FRAGMENT_HEADER = 0x0F


class BxmlType(IntEnum):
    NULL = 0x00
    STRING = 0x01
    ANSITRING = 0x02
    INT8 = 0x03
    UINT8 = 0x04
    INT16 = 0x05
    UINT16 = 0x06
    INT32 = 0x07
    UINT32 = 0x08
    INT64 = 0x09
    UINT64 = 0x0A
    FLOAT = 0x0B
    DOUBLE = 0x0C
    BOOL = 0x0D
    BINARY = 0x0E
    GUID = 0x0F
    SIZET = 0x10
    FILETIME = 0x11
    SYSTEMTIME = 0x12
    SID = 0x13
    HEXINT32 = 0x14
    HEXINT64 = 0x15
    EVTHANDLE = 0x20
    BINXML = 0x21
    EVTXML = 0x23

    @classmethod
    def _missing_(cls, value: int) -> Any:
        """Create a new member if it was missing.

        In some cases the value is win:<number>, this is to accomodate that edge case.
        """
        new_member = int.__new__(cls, value)
        new_member._name_ = str(value)
        new_member._value_ = value
        return cls._value2member_map_.setdefault(value, new_member)

    def __str__(self) -> str:
        return f"win:{self.name.lstrip('_')}"


def read_systemtime(stream: BinaryIO) -> datetime:
    """Read systemtime from stream."""
    st = c_bxml.SYSTEMTIME(stream)
    return datetime(  # noqa: DTZ001
        year=st.wYear,
        month=st.wMonth,
        day=st.wDay,
        hour=st.wHour,
        minute=st.wMinute,
        second=st.wSecond,
        microsecond=st.wMilliseconds * 1000,
    )


def read_guid(stream: BinaryIO) -> str:
    """Read guid from stream."""
    guid = uuid.UUID(bytes=stream.read(16))
    guid_str = str(guid).upper()
    return f"{{{guid_str}}}"


def read_sid(stream: BinaryIO) -> str:
    """Read SID from stream."""
    sid = c_bxml.SID(stream)
    revision_str = str(sid.revision)
    last_authority = str(bytearray(sid.authority)[-1])
    sub_authorities = [str(authority) for authority in sid.subAuthorities]
    return "-".join(["S", revision_str, last_authority, *sub_authorities])


TYPE_READERS: dict[BxmlType, Callable[[BinaryIO], Any]] = {
    BxmlType.NULL: lambda s: None,
    BxmlType.STRING: c_bxml.wchar[None].read,
    BxmlType.ANSITRING: c_bxml.char[None].read,
    BxmlType.INT8: c_bxml.int8.read,
    BxmlType.UINT8: c_bxml.uint8.read,
    BxmlType.INT16: c_bxml.int16.read,
    BxmlType.UINT16: c_bxml.uint16.read,
    BxmlType.INT32: c_bxml.int32.read,
    BxmlType.UINT32: c_bxml.uint32.read,
    BxmlType.INT64: c_bxml.int64.read,
    BxmlType.UINT64: c_bxml.uint64.read,
    BxmlType.FLOAT: c_bxml.float.read,
    BxmlType.DOUBLE: c_bxml.double.read,
    BxmlType.BOOL: lambda stream: c_bxml.uint8.read(stream),
    BxmlType.BINARY: lambda stream: binascii.hexlify(stream.read()),
    BxmlType.GUID: read_guid,
    BxmlType.SIZET: (
        lambda stream: f"0x{c_bxml.uint32(stream):x}" if len(stream.getvalue()) == 4 else f"0x{c_bxml.uint64(stream):x}"
    ),
    BxmlType.FILETIME: lambda stream: wintimestamp(c_bxml.uint64(stream)),
    BxmlType.SYSTEMTIME: lambda stream: read_systemtime(stream),
    BxmlType.SID: read_sid,
    BxmlType.HEXINT32: lambda stream: f"0x{c_bxml.uint32(stream):x}",
    BxmlType.HEXINT64: lambda stream: f"0x{c_bxml.uint64(stream):x}",
}


class BxmlTag:
    name: str
    attributes: dict[str, str | None]
    children: list[BxmlSub]

    def __init__(self, name: str):
        self.name = name
        self.attributes = {}
        self.children = []
        self.name_range: ByteRange | None = None
        self.attribute_ranges: dict[str, ByteRange | None] = {}
        self.attribute_value_ranges: dict[str, ByteRange | None] = {}
        self.inline_value_range: ByteRange | None = None
        self.template: Template | None = None

    def __str__(self) -> str:
        if self.attributes:
            temp_items = " ".join(f'{k}="{v}"' for k, v in self.attributes.items())
            result = f"<{self.name} {temp_items}>"
        else:
            result = f"<{self.name}>"

        for child in self.children:
            result += str(child)

        result += f"</{self.name}>"

        return result

    def add_children(self, tags: Iterable[BxmlSub]) -> None:
        self.children.extend(tags)

    def add_attributes(self, attribute: dict[str, str | None]) -> None:
        self.attributes.update(attribute)


class BxmlSub:
    def __init__(self, sub_id: int):
        self.sub_id = sub_id
        self.value = None
        # Provenance metadata, only populated when the parser runs with provenance enabled.
        self.token_range: ByteRange | None = None
        self.value_range: ByteRange | None = None
        self.missing_reason: str | None = None
        # Whether a template descriptor actually supplied a value for this substitution.
        self.assigned = False
        self.descriptor_range: ByteRange | None = None
        # Declared Binary XML type of the value (from the template descriptor).
        self.value_type: Any = None

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return str(self.value)

    def set(self, value: Any) -> None:
        self.value = value

    def get(self) -> Any:
        return self.value


class Template:
    element: BxmlTag

    def __init__(self):
        self.subs: dict[int, BxmlSub] = {}
        self.mapping = {}
        self.element = None
        self.child_templates: list[Template] = []
        # Outer templates that lexically contain this template's definition.
        self.parents: list[Template] = []
        # Absolute file position of the template definition (``BXML_TEMPLATE_DEFINITION``).
        self.offset: int | None = None
        # Absolute file range covering the definition and its fragment.
        self.range: ByteRange | None = None
        # The template-instance reference that first defined (or reused) this template.
        self.reference_range: ByteRange | None = None
        # Per-record references to an already-defined template (one entry per reuse).
        self.record_reference_ranges: list[ByteRange] = []

    def __str__(self) -> str:
        return str(self.element)

    def add_sub(self, sub_id: int, tag: BxmlSub) -> None:
        self.subs[sub_id] = tag

    def create_map(self) -> None:
        self.mapping = {}
        self._createmap(self.element, [])

    def _createmap(self, tag: BxmlTag, path: list[BxmlTag]) -> None:
        for child in tag.children:
            if isinstance(child, BxmlTag):
                self._createmap(child, [*path, child])

            if isinstance(child, BxmlSub):
                if not path:
                    continue

                previous_tag: BxmlTag = path[-1]
                if "Name" in previous_tag.attributes:
                    self.mapping[previous_tag.attributes["Name"]] = child.sub_id
                elif previous_tag.name == "UserData":
                    continue
                else:
                    self.mapping[previous_tag.name] = child.sub_id

        for key, value in tag.attributes.items():
            if isinstance(value, BxmlSub):
                self.mapping[key] = value.sub_id

    def as_map(self) -> dict[str, Any]:
        result_dict = {}

        for key, value in self.mapping.items():
            result_dict[key] = self.subs[value].get()

        for template in self.child_templates:
            result_dict.update(template.as_map())

        return result_dict

    def as_full_map(self) -> KeyValueCollection:
        key_value_pair = KeyValueCollection()
        self._get_map_recursive(self.element, [], key_value_pair)
        return key_value_pair

    def as_full_map_with_sources(self) -> tuple[KeyValueCollection, SourceCollection]:
        """Flatten the template like :meth:`as_full_map`, additionally collecting field sources.

        The resulting collection is identical to :meth:`as_full_map` (same keys, same order of
        assignment) and every key receives a :class:`FieldSource`. Duplicate keys are kept as
        separate source entries, so the last duplicate never overwrites the earlier evidence.
        """
        key_value_pair = KeyValueCollection()
        sources = SourceCollection()
        self._get_map_recursive(self.element, [], key_value_pair, sources)
        return key_value_pair, sources

    def _get_map_recursive(
        self,
        obj: Template | BxmlSub | BxmlTag | Any,
        path: list[BxmlTag | Any],
        collection: KeyValueCollection,
        sources: SourceCollection | None = None,
        sub: BxmlSub | None = None,
    ) -> None:
        if isinstance(obj, Template):
            self._get_map_recursive(obj.element, path, collection, sources)

        elif isinstance(obj, BxmlSub):
            value = obj.get()
            if sources is not None and isinstance(value, BxmlTag | Template):
                # A substitution that expands to a nested tag/template is flattened in place.
                self._get_map_recursive(value, path, collection, sources)
                return
            self._get_map_recursive(value, path, collection, sources, obj if sources is not None else None)

        elif isinstance(obj, BxmlTag):
            for child in obj.children:
                self._get_map_recursive(child, [*path, obj], collection, sources)

            if obj.name == "Event":
                return

            for key, value in obj.attributes.items():
                if obj.name == "Data" and key == "Name":
                    continue

                resolved_key = collection.add(obj.name + "_" + key, value)
                if sources is not None:
                    sources[resolved_key] = _attribute_source(obj, key, value, resolved_key, path)
        elif isinstance(path[-1], BxmlTag):
            previous_tag: BxmlTag = path[-1]
            # Inline text was read as a bare value; attribute it to the immediately enclosing tag.
            if sub is None and isinstance(obj, str | bytes) and previous_tag.inline_value_range is None:
                previous_tag.inline_value_range = getattr(self, "_last_value_range", None)
            path_str = "_".join([val.name for val in path[2:]])
            if previous_tag.name == "Data" and "Name" in previous_tag.attributes:
                resolved_key = collection.add(previous_tag.attributes["Name"], obj)
                if sources is not None:
                    value = sub if sub is not None else obj
                    sources[resolved_key] = _leaf_source(
                        previous_tag, previous_tag.attributes["Name"], value, resolved_key, path
                    )
                return

            resolved_key = collection.add(path_str, obj)
            if sources is not None:
                sources[resolved_key] = _leaf_source(
                    previous_tag, path_str, sub if sub is not None else obj, resolved_key, path
                )

    def add_child_template(self, tpl: Template) -> None:
        self.child_templates.append(tpl)


class Bxml:
    """An object that keeps track of the BXML streams."""

    def __init__(self, bxml_stream: BytesIO, elf_chunk_stream: BytesIO) -> None:
        self.bxml_stream = bxml_stream
        self.elf_chunk_stream = elf_chunk_stream
        self.data_offset: int = None
        self.template: Template = None
        self.templates: dict[int, Template] = None
        # When enabled, reads record byte ranges for field provenance. Disabled by default so
        # the existing parsing path and output stay unchanged.
        self.with_sources: bool = False
        # Absolute file offset of the start of the ELF chunk, used to translate chunk-relative
        # template and name offsets into file ranges.
        self.chunk_offset: int = 0
        # Whether the caller supplied an absolute file offset for the chunk. When false, byte
        # ranges are chunk-relative and cannot be read back from the whole file.
        self.absolute: bool = True
        # Absolute file offset of the record header (signature of EVTX_RECORD).
        self.record_offset: int = 0
        # Active template while parsing its definition, used to attach template ranges to tags.
        self._active_template: Template | None = None
        # Attribute name/value ranges collected while reading an attribute list.
        self._pending_attribute_values: dict[str, tuple[ByteRange | None, ByteRange | None]] = {}
        # Range of the most recently read name entry.
        self._last_name_range: ByteRange | None = None
        # Range of the most recently read inline value.
        self._last_value_range: ByteRange | None = None
        # True while parsing a template definition; its bytes live in the chunk template area.
        self._reading_template: bool = False

    @property
    def current_offset(self) -> int:
        """Current offset in the BXML data stream."""
        return self.data_offset + self.bxml_stream.tell()

    def _record_range(self, start: int, length: int, role: str) -> ByteRange:
        """Absolute range within the record's BXML payload (``start`` is stream-relative).

        ``data_offset`` stays chunk-relative to preserve the existing template matching logic,
        so the chunk's absolute file offset is added here. While a template definition is being
        parsed, its bytes belong to the chunk template area instead of the current record.
        """
        if not self.absolute:
            return ByteRange(SourceKind.CHUNK_RELATIVE, self.data_offset + start, length, role)
        if self._reading_template:
            return ByteRange(SourceKind.TEMPLATE, self.chunk_offset + self.data_offset + start, length, role)
        return ByteRange(SourceKind.RECORD, self.chunk_offset + self.data_offset + start, length, role)

    def _chunk_range(self, start: int, length: int, kind: SourceKind = SourceKind.TEMPLATE) -> ByteRange:
        """Range for a chunk-relative offset (template definitions, name entries)."""
        if start < 0 or length < 0:
            return unresolved("negative chunk-relative offset", role=kind.value)
        if not self.absolute:
            return ByteRange(SourceKind.CHUNK_RELATIVE, start, length, kind.value)
        return ByteRange(kind, self.chunk_offset + start, length, kind.value)

    def read_name_from_stream(self) -> str:
        """Use _reader to read a specific name from stream."""
        name = self._reader.read()
        if self.with_sources:
            self._last_name_range = self._reader.last_range()
        return name

    def set_name_reader(self, reader: BxmlNameReader) -> None:
        self._reader = reader

    def read_token(self, template: Template | None = None) -> BxmlToken | str | Any:
        """Read the next BXML token from stream."""
        token_start = self.bxml_stream.tell() if self.with_sources else 0
        token = Token(c_bxml.uint8(self.bxml_stream))

        if token == BxmlToken.BXML_END:
            return BxmlToken.BXML_END
        if token == BxmlToken.BXML_START_ELEMENT:
            return self.parse_start_element(token.has_more, template)
        if token == BxmlToken.BXML_CLOSE_START_ELEMENT_TAG:
            return BxmlToken.BXML_CLOSE_START_ELEMENT_TAG
        if token == BxmlToken.BXML_CLOSE_EMPTY_ELEMENT_TAG:
            return BxmlToken.BXML_CLOSE_EMPTY_ELEMENT_TAG
        if token == BxmlToken.BXML_END_ELEMENT:
            return BxmlToken.BXML_END_ELEMENT
        if token == BxmlToken.BXML_VALUE:
            value = self.read_value(token.has_more, template)
            if self.with_sources:
                self._last_value_range = self._record_range(
                    token_start, self.bxml_stream.tell() - token_start, "inline_value"
                )
            return value
        if token == BxmlToken.BXML_ATTRIBUTE:
            return self.read_attribute(template)
        if token == BxmlToken.BXML_TOKEN_CHAR_REFERENCE:
            return self.read_char_reference()
        if token == BxmlToken.BXML_TOKEN_ENTITY_REFERENCE:
            return self.read_entity_reference(token.has_more, template)
        if token == BxmlToken.BXML_TEMPLATE_INSTANCE:
            return self.read_template_instance()
        if token == BxmlToken.BXML_TOKEN_NORMAL_SUBSTITUTION or token == BxmlToken.BXML_TOKEN_OPTIONAL_SUBSTITUTION:
            return self.substitute_token_and_add_to_template(template)
        if token == BxmlToken.BXML_FRAGMENT_HEADER:
            return self.read_fragment_header()
        raise BxmlException(f"Unknown BXML token {token}")

    def parse_start_element(self, more_data: bool, template: Template | None = None) -> BxmlTag:
        if template:
            c_bxml.BXML_ELEMENT_START_TPL(self.bxml_stream)
        else:
            c_bxml.BXML_ELEMENT_START(self.bxml_stream)

        tag = self._read_tag_and_attributes(more_data, template)

        next_tag = self.read_token(template)

        if self._is_end_empty_element(next_tag):
            return tag

        if not self._is_end_start_element(next_tag):
            raise BxmlException("Unexpected tag, expected an END element")

        tag.add_children(self._read_children(template, tag))
        return tag

    def _read_tag_and_attributes(self, flag_more: bool, template: Template) -> BxmlTag:
        tag = BxmlTag(self.read_name_from_stream())
        if self.with_sources:
            tag.name_range = self._last_name_range
        if flag_more:
            attributes = dict(self._read_attributes(template))
            tag.add_attributes(attributes)
            if self.with_sources:
                tag.attribute_ranges = {
                    key: values[0] for key, values in self._pending_attribute_values.items() if key in attributes
                }
                tag.attribute_value_ranges = {
                    key: values[1] for key, values in self._pending_attribute_values.items() if key in attributes
                }
                for key in attributes:
                    self._pending_attribute_values.pop(key, None)
        if self.with_sources and self._active_template is not None:
            tag.template = self._active_template
            if tag.name_range is None:
                tag.name_range = unresolved("element name offset was not recorded", role="name")
        return tag

    def _read_attributes(self, template: Template) -> str | BxmlToken | Any:
        attr_size = c_bxml.uint32(self.bxml_stream)
        attr_end = self.bxml_stream.tell() + attr_size
        while self.bxml_stream.tell() < attr_end:
            yield self.read_token(template)

    def _read_template_reference_and_data(self) -> Template:
        """Read template reference and create a template."""
        start = self.bxml_stream.tell() if self.with_sources else 0
        reference = c_bxml.BXML_TEMPLATE_REFERENCE(self.bxml_stream)
        reference_range = (
            self._record_range(start, self.bxml_stream.tell() - start, "template_reference")
            if self.with_sources
            else None
        )

        if reference.offset == self.current_offset:
            template = self._create_and_fill_template()
            if self.with_sources:
                template.reference_range = reference_range

            self.templates[reference.offset] = template
        else:
            template = self.templates[reference.offset]
            if self.with_sources and template.reference_range is not None:
                # Later records reference the definition site, not their own bytes. Keep a
                # per-record record of this reference separately from the definition range.
                template.record_reference_ranges = [
                    *getattr(template, "record_reference_ranges", []),
                    reference_range,
                ]

        return template

    def _create_and_fill_template(self) -> Template:
        """Create and fill a template from its definition.

        The caller has already read the template reference; per [MS-EVEN6] the reference is
        immediately followed by the ``BXML_TEMPLATE_DEFINITION`` and then a fragment header.
        The definition's ``data_size`` covers the fragment that follows it.
        """
        definition_start = self.bxml_stream.tell()
        definition = c_bxml.BXML_TEMPLATE_DEFINITION(self.bxml_stream)
        c_bxml.BXML_FRAGMENT_HEADER(self.bxml_stream)

        template = Template()

        if self.with_sources:
            # ``current_offset`` is chunk-relative and points just past the definition header and
            # fragment header; subtracting the bytes just consumed yields the definition start.
            template.offset = self.current_offset - (self.bxml_stream.tell() - definition_start)
            # ``data_size`` covers the fragment contents after the 3-byte fragment header, so the
            # full definition span is the 24-byte header plus the declared data size.
            definition_length = c_bxml.BXML_TEMPLATE_DEFINITION.size + definition.data_size
            template.range = self._chunk_range(template.offset, definition_length)

        previous_template = self._active_template
        if self.with_sources:
            self._active_template = template
            self._reading_template = True

        try:
            tag = self.read_token(template)
            if tag == BxmlToken.BXML_FRAGMENT_HEADER:
                tag = self.read_token(template)

            template.element = self.read_token(template)
            if self.read_token(template) != BxmlToken.BXML_END:
                raise BxmlException("Expected BxmlEnd")

            template.create_map()
        finally:
            if self.with_sources:
                self._active_template = previous_template
                self._reading_template = False

        if self.with_sources:
            for child in _walk_tags(template.element):
                if child.template is None:
                    child.template = template

        return template

    def _is_end_empty_element(self, next_tag: BxmlTag) -> bool:
        return next_tag is BxmlToken.BXML_CLOSE_EMPTY_ELEMENT_TAG

    def _is_end_start_element(self, next_tag: BxmlTag) -> bool:
        return next_tag is BxmlToken.BXML_CLOSE_START_ELEMENT_TAG

    def _read_children(self, template: Template, parent: BxmlTag | None = None) -> Iterator[BxmlTag]:
        while True:
            tag = self.read_token(template)
            if tag == BxmlToken.BXML_END_ELEMENT:
                break
            if parent is not None and self.with_sources and isinstance(tag, str):
                # A bare string child is inline text stored in the record/template bytes.
                parent.inline_value_range = self._last_value_range
            yield tag

    def _read_string_value(self, flag_more: bool, template: Template) -> str:
        value = c_bxml.BXML_VALUE_TEXT(self.bxml_stream).value
        if flag_more:
            value += self.read_token(template)
        return value

    def read_value(self, flag_more: bool, template: Template) -> str:
        start = self.bxml_stream.tell() if self.with_sources else 0
        value_type = c_bxml.uint8(self.bxml_stream)
        if value_type == BxmlType.STRING:
            value = self._read_string_value(flag_more, template)
            if self.with_sources:
                self._last_value_range = self._record_range(start, self.bxml_stream.tell() - start, "inline_value")
            return value

        raise BxmlException(f"Unexpected value type 0x{value_type:x}")

    def read_attribute(self, template: Template) -> tuple[str, Any]:
        name = self.read_name_from_stream()
        name_range = self._last_name_range if self.with_sources else None
        value_start = self.bxml_stream.tell() if self.with_sources else 0
        value = self.read_token(template)
        if self.with_sources:
            self._pending_attribute_values[name] = (
                name_range,
                self._record_range(value_start, self.bxml_stream.tell() - value_start, "attribute_value"),
            )
        return name, value

    def read_entity_reference(self, flag_more: bool, template: Template) -> str:
        entity = self.read_name_from_stream()
        reference = f"&{entity};"
        if flag_more:
            reference += self.read_token(template)
        return reference

    def substitute_token_and_add_to_template(self, template: Template) -> BxmlSub:
        start = self.bxml_stream.tell() if self.with_sources else 0
        substitution = c_bxml.BXML_OPTIONAL_SUBSTITUTION(self.bxml_stream)
        bxml_sub = BxmlSub(substitution.sub_id)
        if self.with_sources:
            bxml_sub.token_range = self._record_range(start, self.bxml_stream.tell() - start, "substitution_token")
        template.add_sub(substitution.sub_id, bxml_sub)
        return bxml_sub

    def read_fragment_header(self) -> BxmlToken:
        c_bxml.BXML_FRAGMENT_HEADER(self.bxml_stream)
        return BxmlToken.BXML_FRAGMENT_HEADER

    def read_char_reference(self) -> str:
        return f"&x{c_bxml.uint16(self.bxml_stream):x};"

    def read_template_instance(self) -> Template:
        _template = self._read_template_reference_and_data()

        descriptors_start = self.bxml_stream.tell() if self.with_sources else 0
        descriptors = list(BxmlTemplateDescriptor.read_descriptors_from_stream(self.bxml_stream))
        descriptor_ranges = self._descriptor_ranges(descriptors_start, descriptors) if self.with_sources else []

        for index, descriptor in enumerate(descriptors):
            value_start = self.bxml_stream.tell() if self.with_sources else 0
            value = _read_descriptor_value(self, descriptor, _template)

            if isinstance(value, Template):
                _template.add_child_template(value)
                if self.with_sources and _template not in value.parents:
                    value.parents.append(_template)

            if index in _template.subs:
                sub = _template.subs[index]
                sub.set(value)
                if self.with_sources:
                    sub.assigned = True
                    sub.value_type = descriptor.type_id
                    if descriptor_ranges:
                        sub.descriptor_range = descriptor_ranges[index]
                    # ``descriptor.size`` is authoritative for every value, including nested
                    # BINXML fragments; the parser seeks to ``value_start + size`` afterwards.
                    sub.value_range = self._record_range(value_start, descriptor.size, "substitution_value")

        if self.with_sources:
            # Substitutions that the descriptor list did not cover are explicitly marked
            # instead of silently inheriting a previous value.
            for index, sub in _template.subs.items():
                if not sub.assigned:
                    sub.missing_reason = (
                        f"template declared substitution {index} but the record supplied "
                        f"{len(descriptors)} descriptor(s)"
                    )

        return _template

    def _descriptor_ranges(
        self, start: int, descriptors: list[BxmlTemplateDescriptor]
    ) -> list[ByteRange]:
        """Byte ranges of each descriptor entry, in declaration order.

        The list starts with its ``uint32`` entry count. Descriptor entries are four bytes each
        and their values follow the whole list, so a descriptor's range only covers the
        ``BXML_TEMPLATE_VALUE_DESC`` entry itself.
        """
        descriptor_size = c_bxml.BXML_TEMPLATE_VALUE_DESC.size
        first = start + 4
        return [
            self._record_range(first + index * descriptor_size, descriptor_size, "substitution_descriptor")
            for index, _ in enumerate(descriptors)
        ]


class BxmlNameReader:
    """An interface to facilitate different methods to read names with BXML data."""

    def __init__(self, bxml: Bxml) -> None:
        self.bxml = bxml
        self.bxml_datastream = bxml.bxml_stream
        self.elf_chunk_stream = bxml.elf_chunk_stream
        self._last_range: ByteRange | None = None

    def read(self) -> str:
        """Read the name from the bxml_datastream."""
        raise NotImplementedError

    def last_range(self) -> ByteRange | None:
        """Byte range of the most recently read name entry."""
        return self._last_range

    def _read_and_validate_padding(self) -> None:
        """Determine if the padding after name equals 0."""
        padding = self.bxml_datastream.read(2)
        if padding != b"\x00\x00":
            raise BxmlException("No padding after BXML_NAME")


class EvtxNameReader(BxmlNameReader):
    """Evtx method to read names in BXML."""

    def read(self) -> str:
        """Read name from BXML data.

        If the offset is outside the BXML data range elf_chunk data is used.
        """
        offset = c_bxml.uint32(self.bxml_datastream)
        if offset == self.bxml.current_offset:
            element_name = self._read_name_from_bxml_stream()
        else:
            element_name = self._read_name_from_elf_stream(offset)

        return element_name.value

    def _read_name_from_elf_stream(self, offset: int) -> c_bxml.BXML_NAME:
        """Read the name from the ELF chunk, but keeps the needle position."""
        pos = self.elf_chunk_stream.tell()
        self.elf_chunk_stream.seek(offset)
        element_name = c_bxml.BXML_NAME(self.elf_chunk_stream)
        end = self.elf_chunk_stream.tell()
        self.elf_chunk_stream.seek(pos)
        if self.bxml.with_sources:
            self._last_range = ByteRange(
                SourceKind.NAME,
                self.bxml.chunk_offset + offset,
                end - offset,
                "name",
            )
        return element_name

    def _read_name_from_bxml_stream(self) -> c_bxml.BXML_NAME:
        """Read the name from the bxml_datastream."""
        start = self.bxml_datastream.tell()
        element_name = c_bxml.BXML_NAME(self.bxml_datastream)
        self._read_and_validate_padding()
        if self.bxml.with_sources:
            self._last_range = self.bxml._record_range(start, self.bxml_datastream.tell() - start, "name")
        return element_name


class WevtNameReader(BxmlNameReader):
    """WEVT method for reading names.

    WEVT uses a different method to read BXML_NAME
    There is no offset and additional unknown 32-bit value.
    """

    def read(self) -> str:
        return self._read_bxml_data_name().value

    def _read_bxml_data_name(self) -> c_bxml.BXML_VALUE_TEXT:
        self._read_hash_value()
        element_name = c_bxml.BXML_VALUE_TEXT(self.bxml_datastream)
        self._read_and_validate_padding()
        return element_name

    def _read_hash_value(self) -> c_bxml.uint16:
        """Reads the hash value for the object."""
        return c_bxml.uint16(self.bxml_datastream)


class Token:
    TOKEN_MASK = 0x1F
    MORE_MASK = 0x40

    def __init__(self, token: int) -> None:
        self.flags = token & ~self.TOKEN_MASK
        self.token = token & self.TOKEN_MASK
        self.has_more = self.flags & self.MORE_MASK

    def __eq__(self, other: BxmlToken | Any) -> bool:
        if isinstance(other, BxmlToken):
            return self.token == other
        return False


def _field_path(path: list[BxmlTag | Any], tag: BxmlTag, extra: str | None = None) -> tuple[str, ...]:
    """Build the nested element path used in provenance reports.

    The structural root ``Event`` is skipped, attributes are prefixed with ``@`` and
    substitutions are marked with ``#`` so a report can distinguish a real child element from
    an attribute with the same name. The tag is already the last element of ``path`` for
    leaves, so it is only appended for attribute paths where the caller points at the owning
    tag.
    """
    names = [node.name for node in path if isinstance(node, BxmlTag) and node.name != "Event"]
    if extra is not None and extra.startswith("@"):
        names.append(tag.name)
    names.append(extra if extra is not None else tag.name)
    return tuple(names)


def _template_ranges(template: Template | None) -> list[ByteRange]:
    """Template definition bytes that contributed to a field.

    A nested template is declared inside the outer template's definition, so all templates
    that lexically contain the field are relevant evidence. Their definitions are separate
    byte ranges and must not be collapsed.
    """
    if template is None or template.range is None:
        return []

    return [
        byte_range
        for byte_range in [template.range, *(parent.range for parent in getattr(template, "parents", []))]
        if byte_range is not None
    ]


def _walk_tags(tag: BxmlTag) -> Iterator[BxmlTag]:
    """Yield every tag in a parsed tree, including those inside nested substitutions."""
    yield tag
    for child in tag.children:
        if isinstance(child, BxmlTag):
            yield from _walk_tags(child)
        elif isinstance(child, BxmlSub) and isinstance(child.get(), BxmlTag | Template):
            inner = child.get()
            if isinstance(inner, Template):
                if inner.element is not None:
                    yield from _walk_tags(inner.element)
            else:
                yield from _walk_tags(inner)


def _attribute_source(
    tag: BxmlTag, key: str, value: Any, resolved_key: str, path: list[BxmlTag | Any]
) -> FieldSource:
    """Source chain for a ``<Tag Attribute="value">`` pair.

    The *tag name* is the template constant (stored in the chunk), while the attribute value
    and its name may come from the current record. All of them are kept as separate ranges.
    """
    ranges: list[ByteRange] = []
    sub: BxmlSub | None = None
    detail: dict[str, Any] = {"origin": "attribute"}
    if isinstance(value, BxmlSub):
        sub = value
        ranges.extend(_substitution_ranges(value, detail))
        detail["origin"] = "substitution"
    else:
        value_range = tag.attribute_value_ranges.get(key)
        if value_range is not None:
            ranges.append(value_range)
        else:
            ranges.append(unresolved("attribute value has no recorded byte span", role="attribute_value"))

    # The attribute's own name entry and the element's name entry are separate evidence.
    attribute_name_range = tag.attribute_ranges.get(key)
    if attribute_name_range is not None:
        ranges.append(attribute_name_range)
    if tag.name_range is not None:
        ranges.append(tag.name_range)
    ranges.extend(_template_ranges(_template_for_tag(tag)))

    detail["attribute"] = key
    template = _template_for_tag(tag)
    return FieldSource(
        key=resolved_key,
        ranges=tuple(ranges),
        path=_field_path(path, tag, f"@{key}"),
        value_type=str(sub.value_type) if sub is not None and sub.value_type is not None else None,
        sub_id=sub.sub_id if sub is not None else None,
        template_offset=template.offset if template is not None else None,
        detail=detail,
    )


def _leaf_source(
    tag: BxmlTag, key: str, value: Any, resolved_key: str, path: list[BxmlTag | Any]
) -> FieldSource:
    """Source chain for element content, which is either a substitution or inline text."""
    ranges: list[ByteRange] = []
    sub: BxmlSub | None = None
    detail: dict[str, Any] = {"origin": "inline"}
    if isinstance(value, BxmlSub):
        sub = value
        ranges.extend(_substitution_ranges(value, detail))
        detail["origin"] = "substitution"
    elif tag.inline_value_range is not None:
        # Inline text (element content) is stored in the record itself.
        ranges.append(tag.inline_value_range)
    else:
        ranges.append(unresolved("inline value has no recorded byte span", role="inline_value"))

    if tag.name_range is not None:
        ranges.append(tag.name_range)
    ranges.extend(_template_ranges(_template_for_tag(tag)))

    template = _template_for_tag(tag)
    return FieldSource(
        key=resolved_key,
        ranges=tuple(ranges),
        path=_field_path(path, tag, "#"),
        value_type=str(sub.value_type) if sub is not None and sub.value_type is not None else None,
        sub_id=sub.sub_id if sub is not None else None,
        template_offset=template.offset if template is not None else None,
        detail=detail,
    )


def _substitution_ranges(sub: BxmlSub, detail: dict[str, Any]) -> list[ByteRange]:
    """Every byte range involved in producing a substitution's value."""
    ranges: list[ByteRange] = []
    if sub.token_range is not None:
        ranges.append(sub.token_range)
    if sub.descriptor_range is not None:
        ranges.append(sub.descriptor_range)
    if sub.value_range is not None:
        ranges.append(sub.value_range)
    if not sub.assigned:
        detail["missing"] = sub.missing_reason or "substitution was not assigned a value"
    if sub.value_range is None:
        ranges.append(
            unresolved(sub.missing_reason or "substitution was not assigned a value", role="substitution_value")
        )
    return ranges


def _template_for_tag(tag: BxmlTag) -> Template | None:
    template = getattr(tag, "template", None)
    return template if isinstance(template, Template) else None


def parse_bxml(
    bxml: Bxml, with_sources: bool = False
) -> KeyValueCollection | tuple[KeyValueCollection, SourceCollection]:
    """Parse a BXML record into a :class:`KeyValueCollection`.

    With ``with_sources=True`` the result is ``(record, sources)``; the record is byte-for-byte
    identical to the default output and ``sources`` maps every output key to a
    :class:`FieldSource`. The default call signature and return type are unchanged.
    """
    while True:
        token = bxml.read_token(bxml.template)
        if token == BxmlToken.BXML_END:
            raise BxmlException("Unexpected BxmlEnd")

        if token == BxmlToken.BXML_FRAGMENT_HEADER:
            continue

        if isinstance(token, BxmlTag):
            if with_sources:
                key_collection = KeyValueCollection()
                sources = SourceCollection()
                _tag_map_recursive(token, [], key_collection, sources)
                return key_collection, sources
            key_collection = KeyValueCollection()
            Template()._get_map_recursive(token, [], key_collection)
            return key_collection
        if bxml.read_token() != BxmlToken.BXML_END:
            pass

        if with_sources:
            return token.as_full_map_with_sources()

        return token.as_full_map()


def _tag_map_recursive(
    obj: BxmlTag | BxmlSub | Any,
    path: list[BxmlTag | Any],
    collection: KeyValueCollection,
    sources: SourceCollection,
    sub: BxmlSub | None = None,
) -> None:
    """Flatten a bare tag tree, mirroring ``Template._get_map_recursive`` key derivation."""
    if isinstance(obj, BxmlSub):
        value = obj.get()
        if isinstance(value, BxmlTag | Template):
            _tag_map_recursive(value, path, collection, sources)
            return
        _tag_map_recursive(value, path, collection, sources, obj)
        return

    if isinstance(obj, BxmlTag):
        for child in obj.children:
            _tag_map_recursive(child, [*path, obj], collection, sources)

        if obj.name == "Event":
            return

        for key, value in obj.attributes.items():
            if obj.name == "Data" and key == "Name":
                continue
            resolved_key = collection.add(obj.name + "_" + key, value)
            sources[resolved_key] = _attribute_source(obj, key, value, resolved_key, path)
        return

    if path and isinstance(path[-1], BxmlTag):
        previous_tag: BxmlTag = path[-1]
        leaf = sub if sub is not None else obj
        path_str = "_".join([val.name for val in path[2:]])
        if previous_tag.name == "Data" and "Name" in previous_tag.attributes:
            resolved_key = collection.add(previous_tag.attributes["Name"], leaf)
            sources[resolved_key] = _leaf_source(
                previous_tag, previous_tag.attributes["Name"], leaf, resolved_key, path
            )
            return

        resolved_key = collection.add(path_str, leaf)
        sources[resolved_key] = _leaf_source(previous_tag, path_str, leaf, resolved_key, path)


class BxmlTemplateDescriptor:
    DESCRIPTOR_MASK = 0x7F
    ARRAY_MASK = 0x80

    def __init__(self, descriptor_struct: c_bxml.BXML_TEMPLATE_VALUE_DESC):
        self.descriptor_struct = descriptor_struct

        self.type_id = BxmlType(self.descriptor_struct.type_id & self.DESCRIPTOR_MASK)
        self.is_array = (self.descriptor_struct.type_id & self.ARRAY_MASK) == self.ARRAY_MASK
        self.has_type_reader = self.type_id in TYPE_READERS

    @property
    def size(self) -> int:
        return self.descriptor_struct.size

    @property
    def value_type(self) -> Any:
        return TYPE_READERS[self.type_id]

    @classmethod
    def read_descriptors_from_stream(cls, stream: BytesIO) -> Iterator[Self]:
        """Read a range of BXML descriptors from stream."""
        entry_count = c_bxml.uint32(stream)
        for _ in range(entry_count):
            yield cls.from_stream(stream)

    @classmethod
    def from_stream(cls, stream: BytesIO) -> Self:
        """Read a singular BXML descriptors from stream."""
        struct = c_bxml.BXML_TEMPLATE_VALUE_DESC(stream)
        return cls(struct)


def _read_descriptor_value(bxml: Bxml, descriptor: BxmlTemplateDescriptor, template: Template | None = None) -> Any:
    try:
        value = read_value(bxml, descriptor, template)
    except BxmlException:
        value = "<CORRUPT DATA>"
    return value


def read_value(binxml: Bxml, descriptor: BxmlTemplateDescriptor, template: Template) -> Any:
    """Read a value from a bxml node.

    0x00 NullType NULL or empty
    0x01 StringType Unicode string
    0x02 AnsiStringType ASCII string
    0x03 Int8Type 8-bit integer signed
    0x04 UInt8Type 8-bit integer unsigned
    0x05 Int16Type 16-bit integer signed
    0x06 UInt16Type 16-bit integer unsigned
    0x07 Int32Type 32-bit integer signed
    0x08 UInt32Type 32-bit integer unsigned
    0x09 Int64Type 64-bit integer signed
    0x0a UInt64Type 64-bit integer unsigned
    0x0b Real32Type Floating point 32-bit (single precision)
    0x0c Real64Type Floating point 64-bit (double precision)
    0x0d BoolType Boolean
    0x0e BinaryType Binary data
    0x0f GuidType GUID
    0x10 SizeT Type Size type
    0x11 FileTimeType Filetime (64-bit)
    0x12 SysTimeType System time (128-bit)
    0x13 SidType NT Security Identifier (SID)
    0x14 HexInt32Type 32-bit integer hexadecimal
    0x15 HexInt64Type 64-bit integer hexadecimal
    0x20 EvtHandle
    0x21 BinXmlType Binary XML fragment
    0x23 EvtXml
    """
    if descriptor.has_type_reader:
        data = binxml.bxml_stream.read(descriptor.size)
        stream = BytesIO(data)

        if descriptor.is_array:
            return list(read_descriptor_array(stream, descriptor))

        if descriptor.type_id == BxmlType.STRING:
            return data.decode("utf-16-le").rstrip("\x00")

        if descriptor.type_id == BxmlType.ANSITRING:
            return data.rstrip(b"\x00")

        return descriptor.value_type(stream)

    if descriptor.type_id == BxmlType.BINXML:
        return read_binxml_fragment(binxml, template, descriptor.size)

    raise BxmlException(f"Unknown value type 0x{descriptor.type_id:x}")


def read_descriptor_array(stream: BinaryIO, descriptor: BxmlTemplateDescriptor) -> list[Any]:
    while stream.tell() != descriptor.size:
        yield descriptor.value_type(stream)


def read_binxml_fragment(bxml: Bxml, template: Template, length: int) -> Any:
    pos = bxml.bxml_stream.tell()
    element = bxml.read_token(template)
    if element == BxmlToken.BXML_FRAGMENT_HEADER:
        element = bxml.read_token(template)

    bxml.bxml_stream.seek(pos + length)
    return element
