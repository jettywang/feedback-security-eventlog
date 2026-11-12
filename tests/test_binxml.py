from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.eventlog.bxml import Bxml, BxmlToken, BxmlType
from dissect.eventlog.bxml.bxml import (
    BxmlTemplateDescriptor,
    CorruptValue,
    read_descriptor_value,
)
from dissect.eventlog.bxml.c_bxml import c_bxml
from dissect.eventlog.exceptions import BxmlException

if TYPE_CHECKING:
    from types import FunctionType


@pytest.mark.parametrize(
    ("token", "mocked_method"),
    [
        (BxmlToken.BXML_START_ELEMENT, Bxml.parse_start_element),
        (BxmlToken.BXML_VALUE, Bxml.read_value),
        (BxmlToken.BXML_ATTRIBUTE, Bxml.read_attribute),
        (BxmlToken.BXML_TOKEN_CHAR_REFERENCE, Bxml.read_char_reference),
        (BxmlToken.BXML_TOKEN_ENTITY_REFERENCE, Bxml.read_entity_reference),
        (BxmlToken.BXML_TEMPLATE_INSTANCE, Bxml.read_template_instance),
        (BxmlToken.BXML_TOKEN_NORMAL_SUBSTITUTION, Bxml.substitute_token_and_add_to_template),
        (BxmlToken.BXML_TOKEN_OPTIONAL_SUBSTITUTION, Bxml.substitute_token_and_add_to_template),
    ],
)
def test_bxml_read_token(token: BxmlToken, mocked_method: FunctionType) -> None:
    bxml_obj = Bxml(bytes([token]), None)
    with patch.object(Bxml, mocked_method.__name__) as obj:
        assert bxml_obj.read_token() == obj.return_value


@pytest.mark.parametrize(
    ("token", "expected_end"),
    [
        (BxmlToken.BXML_END, BxmlToken.BXML_END),
        (BxmlToken.BXML_CLOSE_START_ELEMENT_TAG, BxmlToken.BXML_CLOSE_START_ELEMENT_TAG),
        (BxmlToken.BXML_CLOSE_EMPTY_ELEMENT_TAG, BxmlToken.BXML_CLOSE_EMPTY_ELEMENT_TAG),
        (BxmlToken.BXML_END_ELEMENT, BxmlToken.BXML_END_ELEMENT),
        (BxmlToken.BXML_FRAGMENT_HEADER, BxmlToken.BXML_FRAGMENT_HEADER),
    ],
)
def test_bxml_read_token_end_states(token: BxmlToken, expected_end: BxmlToken) -> None:
    bxml_obj = Bxml(bytes([token, 0x0, 0x0, 0x0]), None)
    assert bxml_obj.read_token() == expected_end


def test_bxml_read_unknown_token() -> None:
    bxml_obj = Bxml(bytes([0x10]), None)
    with pytest.raises(BxmlException):
        bxml_obj.read_token()


def test_bxml_substitution() -> None:
    mocked_template = Mock()
    bxml_obj = Bxml(BytesIO(b"\x01\x00\x00"), Mock())

    sub = bxml_obj.substitute_token_and_add_to_template(mocked_template)

    assert sub.sub_id == 0x1
    mocked_template.add_sub.assert_called_with(0x1, sub)


def test_value_text() -> None:
    bxml_obj = Bxml(b"\x05\x00h\x00e\x00l\x00l\x00o\x00", None)
    assert bxml_obj._read_string_value(False, Mock()) == "hello"


@patch.object(Bxml, Bxml.read_token.__name__, return_value=" World")
def test_value_more(mock: Mock) -> None:
    bxml_obj = Bxml(b"\x05\x00H\x00e\x00l\x00l\x00o\x00", None)
    assert bxml_obj._read_string_value(True, Mock()) == "Hello World"


@patch.object(Bxml, Bxml.read_name_from_stream.__name__, return_value="data")
def test_read_tag_and_attributes(mocked_read: Mock) -> None:
    tag = Bxml(None, None)._read_tag_and_attributes(False, Mock())
    assert tag.name == mocked_read.return_value
    assert len(tag.attributes) == 0


@patch.object(Bxml, Bxml.read_name_from_stream.__name__, return_value="data")
def test_read_tag_and_attributes_attributes(mocked_tag: Mock) -> None:
    with patch.object(Bxml, Bxml._read_attributes.__name__) as attributes:
        attributes.return_value = [("name", "test")]
        bxml_obj = Bxml(None, None)
        tag = bxml_obj._read_tag_and_attributes(True, Mock())
        assert tag.name == mocked_tag.return_value
        assert tag.attributes["name"] == "test"


@pytest.mark.parametrize(
    ("side_effects", "expected_length"),
    [
        (["children_tag", BxmlToken.BXML_END_ELEMENT], 1),
        (["children_tag", "children_tag", BxmlToken.BXML_END_ELEMENT], 2),
        (["children_tag", BxmlToken.BXML_END_ELEMENT, "children_tag"], 1),
    ],
)
@patch.object(Bxml, Bxml.read_token.__name__)
def test_read_children(mocked_token: Mock, side_effects: list[str | BxmlToken], expected_length: int) -> None:
    mocked_token.side_effect = side_effects
    bxml_obj = Bxml(None, None)
    children = list(bxml_obj._read_children(Mock()))
    assert len(children) == expected_length


@pytest.mark.parametrize(
    ("bxml_data", "expected_output"),
    [
        (b"\x01\x01", "101"),
        (b"\xde\xad\xbe\xef", "adde"),
    ],
)
def text_bxml_char_reference(bxml_data: bytes, expected_output: str) -> None:
    bxml_obj = Bxml(bxml_data, None)
    assert bxml_obj.read_char_reference() == "&x" + expected_output


@pytest.mark.parametrize("data", [b"\x01", b"\x01\x00"])
@patch.object(Bxml, Bxml._read_string_value.__name__)
def test_bxml_value(mocked_string: Mock, data: bytes) -> None:
    bxml_obj = Bxml(data, None)
    assert mocked_string.return_value == bxml_obj.read_value(Mock(), Mock())


@pytest.mark.parametrize("data", [b"\x02", b"\x03"])
def test_bxml_value_failed(data: bytes) -> None:
    bxml_obj = Bxml(data, None)
    with pytest.raises(BxmlException):
        bxml_obj.read_value(Mock(), Mock())


def test_parse_entity_reference() -> None:
    with patch.object(Bxml, Bxml.read_name_from_stream.__name__, return_value="Hello"):
        assert Bxml(None, None).read_entity_reference(False, Mock()) == "&Hello;"


def test_parse_entity_more() -> None:
    with (
        patch.object(Bxml, Bxml.read_name_from_stream.__name__, return_value="Hello"),
        patch.object(Bxml, Bxml.read_token.__name__, return_value=" World"),
    ):
        assert Bxml(None, None).read_entity_reference(True, Mock()) == "&Hello; World"


def _descriptor(type_id: int, size: int) -> BxmlTemplateDescriptor:
    return BxmlTemplateDescriptor(c_bxml.BXML_TEMPLATE_VALUE_DESC(size=size, type_id=type_id, a=0))


def test_read_descriptor_value_scalar_and_array() -> None:
    bxml = Bxml(BytesIO(b""), None)
    bxml.bxml_stream = BytesIO((7).to_bytes(4, "little") + (8).to_bytes(4, "little"))

    first = read_descriptor_value(bxml, _descriptor(BxmlType.UINT32, 4))
    second = read_descriptor_value(bxml, _descriptor(BxmlType.UINT32, 4))

    assert first == 7
    assert second == 8
    assert bxml.bxml_stream.tell() == 8


def test_read_descriptor_value_empty_array_preserved() -> None:
    bxml = Bxml(BytesIO(b""), None)
    bxml.bxml_stream = BytesIO(b"")

    descriptor = _descriptor(BxmlType.UINT32 | BxmlTemplateDescriptor.ARRAY_MASK, 0)
    assert read_descriptor_value(bxml, descriptor) == []
    assert descriptor.is_array is True


def test_read_descriptor_value_unsupported_type_keeps_raw_and_reason() -> None:
    payload = b"\x99\x88\x77"
    bxml = Bxml(BytesIO(b""), None)
    bxml.bxml_stream = BytesIO(payload + (5).to_bytes(4, "little"))

    corrupt = read_descriptor_value(bxml, _descriptor(0x19, len(payload)))
    following = read_descriptor_value(bxml, _descriptor(BxmlType.UINT32, 4))

    assert isinstance(corrupt, CorruptValue)
    assert corrupt.raw == payload
    assert "Unknown value type" in corrupt.reason
    # The next descriptor must not borrow the corrupt field's bytes or type.
    assert following == 5
    assert bxml.bxml_stream.tell() == len(payload) + 4


def test_read_descriptor_value_truncated_data_does_not_shift_next_field() -> None:
    # Real BXML streams are arbitrary file-like objects, not BytesIO: a short read raises EOFError.
    source = Mock()
    source.tell.side_effect = [0, 8, 12]
    source.read.side_effect = [
        b"\x01\x02",  # Descriptor claims 8 bytes, only 2 available
        (9).to_bytes(4, "little"),  # Next, intact descriptor
    ]
    source.seek.return_value = None

    bxml = Bxml(BytesIO(b""), None)
    bxml.bxml_stream = source

    corrupt = read_descriptor_value(bxml, _descriptor(BxmlType.UINT64, 8))
    following = read_descriptor_value(bxml, _descriptor(BxmlType.UINT32, 4))

    assert isinstance(corrupt, CorruptValue)
    assert corrupt.raw == b"\x01\x02"
    assert isinstance(corrupt.reason, str) and corrupt.reason
    # The declared size, not the consumed byte count, anchors the next descriptor.
    source.seek.assert_called_with(8)
    assert following == 9
    assert source.read.call_count == 2


def test_read_descriptor_value_legacy_marker_rendering() -> None:
    bxml = Bxml(BytesIO(b""), None)
    bxml.bxml_stream = BytesIO(b"\x00")

    from dissect.eventlog.bxml.bxml import _read_descriptor_value

    assert _read_descriptor_value(bxml, _descriptor(0x19, 1)) == "<CORRUPT DATA>"
