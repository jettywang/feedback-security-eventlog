from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.eventlog.bxml import Bxml, BxmlToken
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


def test_sources_keep_duplicate_keys_and_paths() -> None:
    """Same-named nodes must each keep their own source chain, not just the last one."""
    from dissect.eventlog.bxml.bxml import BxmlSub, BxmlTag, _leaf_source
    from dissect.eventlog.utils import KeyValueCollection, SourceCollection, SourceKind

    root = BxmlTag("Event")
    event_data = BxmlTag("EventData")
    first = BxmlTag("Data")
    first.attributes["Name"] = "Field"
    first_sub = BxmlSub(0)
    first_sub.set("first")
    first_sub.assigned = True
    first_sub.value_range = None
    first.children.append(first_sub)

    second = BxmlTag("Data")
    second.attributes["Name"] = "Field"
    second_sub = BxmlSub(1)
    second_sub.set("second")
    second_sub.assigned = True
    second.children.append(second_sub)

    collection = KeyValueCollection()
    sources = SourceCollection()
    path = [root, event_data, first]
    key_one = collection.add("Field", "first")
    sources[key_one] = _leaf_source(first, "Field", first_sub, key_one, path)
    key_two = collection.add("Field", "second")
    sources[key_two] = _leaf_source(second, "Field", second_sub, key_two, path)

    assert list(collection.keys()) == ["Field", "Field_1"]
    assert sources["Field"].key == "Field"
    assert sources["Field_1"].key == "Field_1"
    assert sources["Field"].sub_id == 0
    assert sources["Field_1"].sub_id == 1

    # A missing substitution value is explicitly unresolved instead of borrowing bytes.
    missing = BxmlSub(2)
    missing.missing_reason = "template declared substitution 2 but no descriptor was present"
    key_three = collection.add("Missing", None)
    sources[key_three] = _leaf_source(first, "Missing", missing, key_three, path)
    assert not sources["Missing"].is_resolved
    assert sources["Missing"].ranges[0].kind is SourceKind.UNRESOLVED
    with pytest.raises(ValueError):
        sources["Missing"].read_all(b"\x00")


def test_sources_attribute_and_inline_are_distinct() -> None:
    from dissect.eventlog.bxml.bxml import BxmlTag, _attribute_source
    from dissect.eventlog.utils import SourceKind, unresolved

    tag = BxmlTag("Provider")
    tag.attributes["Name"] = "Constant"
    tag.attribute_ranges["Name"] = unresolved("no attribute name range", role="name")
    tag.attribute_value_ranges["Name"] = unresolved("no attribute value range", role="attribute_value")
    source = _attribute_source(tag, "Name", "Constant", "Provider_Name", [])
    assert source.detail["origin"] == "attribute"
    assert not source.is_resolved
    assert {range_.kind for range_ in source.ranges} == {SourceKind.UNRESOLVED}


def test_template_flatten_with_sources_matches_default() -> None:
    """The provenance-bearing flattening must produce the same keys as the default path."""
    from dissect.eventlog.bxml.bxml import BxmlTag, Template

    root = BxmlTag("Event")
    system = BxmlTag("System")
    provider = BxmlTag("Provider")
    provider.attributes["Name"] = "TestAppX"
    system.children.append(provider)
    channel = BxmlTag("Channel")
    channel.inline_value_range = None
    channel.children.append("TestLogX")
    system.children.append(channel)
    root.children.append(system)

    template = Template()
    template.element = root

    default = template.as_full_map()
    sourced, sources = template.as_full_map_with_sources()

    assert dict(default) == dict(sourced)
    assert list(default.keys()) == list(sources.keys())
    assert sources["Provider_Name"].path == ("System", "Provider", "@Name")


def test_duplicate_named_fields_keep_all_sources() -> None:
    """Two same-named Data fields must each retain their own ranges and keys."""
    from dissect.eventlog.bxml.bxml import BxmlSub, BxmlTag, Template
    from dissect.eventlog.utils import ByteRange, SourceKind

    event = BxmlTag("Event")
    event_data = BxmlTag("EventData")
    event.children.append(event_data)

    for index in range(2):
        data = BxmlTag("Data")
        data.attributes["Name"] = "Value"
        sub = BxmlSub(index)
        sub.assigned = True
        sub.value_type = 1
        sub.token_range = ByteRange(SourceKind.TEMPLATE, 0x100 + index, 3)
        sub.value_range = ByteRange(SourceKind.RECORD, 0x500 + index, 4)
        sub.set(f"value-{index}")
        data.children.append(sub)
        event_data.children.append(data)

    template = Template()
    template.element = event
    record, sources = template.as_full_map_with_sources()

    assert list(record) == ["Value", "Value_1"]
    assert record["Value"] == "value-0"
    assert record["Value_1"] == "value-1"
    assert sources["Value"].sub_id == 0
    assert sources["Value_1"].sub_id == 1
    assert sources["Value"].ranges[0].start == 0x100
    assert sources["Value_1"].ranges[0].start == 0x101
    assert sources["Value"].ranges[1].start == 0x500
    assert sources["Value_1"].ranges[1].start == 0x501


def test_same_named_nested_tags_keep_separate_sources() -> None:
    """Repeated element names at different nesting levels must not collapse to one source."""
    from dissect.eventlog.bxml.bxml import BxmlTag, Template
    from dissect.eventlog.utils import ByteRange, SourceKind

    event = BxmlTag("Event")
    system = BxmlTag("System")
    first = BxmlTag("EventID")
    first.inline_value_range = ByteRange(SourceKind.RECORD, 0x100, 2, "inline_value")
    first.name_range = ByteRange(SourceKind.NAME, 0x200, 8, "name")
    first.children.append("one")
    system.children.append(first)

    nested = BxmlTag("Nested")
    second = BxmlTag("EventID")
    second.inline_value_range = ByteRange(SourceKind.RECORD, 0x300, 2, "inline_value")
    second.name_range = ByteRange(SourceKind.NAME, 0x210, 8, "name")
    second.children.append("two")
    nested.children.append(second)
    system.children.append(nested)

    event.children.append(system)
    template = Template()
    template.element = event

    record, sources = template.as_full_map_with_sources()
    assert "EventID" in record
    assert "Nested_EventID" in record
    assert sources["EventID"].path == ("System", "EventID", "#")
    assert sources["Nested_EventID"].path == ("System", "Nested", "EventID", "#")
    assert sources["EventID"].ranges[0].start != sources["Nested_EventID"].ranges[0].start


def test_plain_parse_does_not_require_source_metadata() -> None:
    """Default parsing must work with minimal hand-built tags and no provenance fields."""
    from dissect.eventlog.bxml.bxml import BxmlTag, Template

    event = BxmlTag("Event")
    data = BxmlTag("Data")
    data.attributes["Name"] = "Field"
    data.children.append("value")
    event.children.append(data)

    template = Template()
    template.element = event
    record = template.as_full_map()
    assert record["Field"] == "value"
