from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from dissect.eventlog.bxml import (
    BxmlField,
    BxmlSub,
    BxmlTag,
    BxmlType,
    CorruptValue,
    FieldState,
    StructuredEvent,
    structurize,
)
from dissect.eventlog.bxml.bxml import BxmlTemplateDescriptor
from dissect.eventlog.bxml.c_bxml import c_bxml


def _sub(
    sub_id: int,
    value: object,
    value_type: BxmlType,
    *,
    is_array: bool = False,
    assigned: bool = True,
) -> BxmlSub:
    sub = BxmlSub(sub_id, value_type, is_array)
    if assigned:
        sub.value = value
        sub.assigned = True
    return sub


def _descriptor(type_id: int, size: int) -> BxmlTemplateDescriptor:
    return BxmlTemplateDescriptor(c_bxml.BXML_TEMPLATE_VALUE_DESC(size=size, type_id=type_id, a=0))


def _data_tag(name: str, sub: BxmlSub) -> BxmlTag:
    tag = BxmlTag("Data")
    tag.add_attributes({"Name": name})
    tag.add_children([sub])
    return tag


def _sample_event() -> BxmlTag:
    root = BxmlTag("Event")
    event_data = BxmlTag("EventData")

    # Same-named nodes: two separate "Duplicate" fields, plus an empty string and empty array.
    event_data.add_children(
        [
            _data_tag("Duplicate", _sub(0, "first", BxmlType.STRING)),
            _data_tag("Duplicate", _sub(1, "second", BxmlType.STRING)),
            _data_tag("EmptyString", _sub(2, "", BxmlType.STRING)),
            _data_tag("EmptyArray", _sub(3, [], BxmlType.STRING, is_array=True)),
            _data_tag("NullValue", _sub(4, None, BxmlType.NULL)),
            _data_tag("MissingValue", _sub(5, None, BxmlType.STRING, assigned=False)),
            _data_tag("Numbers", _sub(6, [1, 2, 3], BxmlType.UINT32, is_array=True)),
        ]
    )

    # Nested node whose real name contains an underscore must survive flattening untouched.
    user_data = BxmlTag("UserData")
    underscore_node = BxmlTag("Real_Underscore_Name")
    underscore_node.add_children([_sub(7, 42, BxmlType.UINT32)])
    nested = BxmlTag("Nested")
    nested.add_children([underscore_node])
    user_data.add_children([nested])

    root.add_children([event_data, user_data])
    return root


def test_structurize_preserves_order_types_and_duplicates() -> None:
    event = structurize(_sample_event())

    assert event.names() == [
        "Duplicate",
        "Duplicate",
        "EmptyString",
        "EmptyArray",
        "NullValue",
        "MissingValue",
        "Numbers",
        "Real_Underscore_Name",
    ]

    duplicates = event.get_all("Duplicate")
    assert len(duplicates) == 2
    assert [field.value for field in duplicates] == ["first", "second"]
    assert all(field.type == "win:STRING" and field.state == FieldState.SCALAR for field in duplicates)
    assert duplicates[0].path == ("EventData", "Data")
    assert duplicates[1].path == duplicates[0].path


def test_structurize_distinguishes_empty_string_array_null_and_missing() -> None:
    event = structurize(_sample_event())
    by_name = {field.name: field for field in event.fields}

    assert by_name["EmptyString"].state == FieldState.SCALAR
    assert by_name["EmptyString"].value == ""

    assert by_name["EmptyArray"].state == FieldState.EMPTY_ARRAY
    assert by_name["EmptyArray"].value == []
    assert by_name["EmptyArray"].array is True

    assert by_name["NullValue"].state == FieldState.NULL
    assert by_name["NullValue"].value is None
    assert by_name["NullValue"].type == "win:NULL"

    assert by_name["MissingValue"].state == FieldState.MISSING
    assert by_name["MissingValue"].value is None
    assert by_name["MissingValue"].type == "win:STRING"

    assert by_name["Numbers"].state == FieldState.ARRAY
    assert by_name["Numbers"].value == [1, 2, 3]


def test_structurize_flat_separator_does_not_collide_with_underscores() -> None:
    event = structurize(_sample_event())
    flat = event.flatten()

    # The real underscore inside the node name is retained; the flatten separator is "/".
    assert "UserData/Nested/Real_Underscore_Name" in flat
    assert flat["UserData/Nested/Real_Underscore_Name"] == 42
    # Duplicate paths receive ordered suffixes instead of overwriting each other.
    assert flat["EventData/Data"] == "first"
    assert flat["EventData/Data_1"] == "second"


def test_structurize_stable_time_sid_guid_representations() -> None:
    root = BxmlTag("Event")
    event_data = BxmlTag("EventData")
    timestamp = datetime(2026, 11, 12, 8, 30, 15, tzinfo=timezone.utc)
    guid = "{" + str(UUID(bytes=b"\x11" * 16)).upper() + "}"
    event_data.add_children(
        [
            _data_tag("When", _sub(0, timestamp, BxmlType.FILETIME)),
            _data_tag("Sid", _sub(1, "S-1-5-18", BxmlType.SID)),
            _data_tag("Guid", _sub(2, guid, BxmlType.GUID)),
        ]
    )
    root.add_children([event_data])

    event = structurize(root)
    payload = event.to_json()

    assert '"type": "win:FILETIME"' in payload
    assert '"2026-11-12T08:30:15+00:00"' in payload
    assert '"win:SID"' in payload and '"S-1-5-18"' in payload
    assert '"win:GUID"' in payload and guid in payload

    restored = StructuredEvent.from_json(payload)
    assert restored.get_all("When")[0].value == timestamp
    assert restored.get_all("Sid")[0].value == "S-1-5-18"
    assert restored.get_all("Guid")[0].value == guid


def test_structurize_corrupt_field_keeps_raw_and_reason() -> None:
    root = BxmlTag("Event")
    event_data = BxmlTag("EventData")
    corrupt = CorruptValue(b"\xde\xad", "Unknown value type 0x19")
    event_data.add_children(
        [
            _data_tag("Broken", _sub(0, corrupt, BxmlType(0x19))),
            _data_tag("AfterBroken", _sub(1, 7, BxmlType.UINT32)),
        ]
    )
    root.add_children([event_data])

    event = structurize(root)
    broken, after = event.fields

    assert broken.state == FieldState.CORRUPT
    assert broken.raw == "dead"
    assert broken.reason == "Unknown value type 0x19"
    assert broken.type == "win:25"
    # The following field keeps its own value and declared type.
    assert after.state == FieldState.SCALAR
    assert after.value == 7
    assert after.type == "win:UINT32"

    restored = StructuredEvent.from_json(event.to_json())
    restored_broken = restored.get_all("Broken")[0]
    assert isinstance(restored_broken.value, CorruptValue)
    assert restored_broken.value.raw == b"\xde\xad"
    assert restored_broken.value.reason == "Unknown value type 0x19"


def test_bxml_sub_set_records_descriptor_metadata() -> None:
    sub = BxmlSub(0)
    assert sub.assigned is False

    sub.set(123, _descriptor(BxmlType.UINT32, 4))

    assert sub.assigned is True
    assert sub.value_type == BxmlType.UINT32
    assert sub.is_array is False


def test_structured_event_roundtrip_keeps_all_distinctions() -> None:
    event = structurize(_sample_event())
    restored = StructuredEvent.from_json(event.to_json())

    assert [field.to_dict() for field in restored] == [field.to_dict() for field in event]
    assert len(restored.get_all("Duplicate")) == 2
    assert restored.get_all("EmptyArray")[0].state == FieldState.EMPTY_ARRAY
    assert restored.get_all("MissingValue")[0].state == FieldState.MISSING
    assert restored.get_all("NullValue")[0].state == FieldState.NULL


def test_structured_field_dict_uses_path_tuple_and_type_identifier() -> None:
    field = BxmlField(
        path=("EventData", "Data"),
        name="Count",
        state=FieldState.SCALAR,
        value=5,
        type="win:UINT32",
    )
    data = field.to_dict()

    assert data["path"] == ["EventData", "Data"]
    assert data["state"] == "scalar"
    assert data["type"] == "win:UINT32"
    assert BxmlField.from_dict(data) == field


def test_real_evtx_structured_and_legacy_views_coexist() -> None:
    from pathlib import Path

    from dissect.eventlog.evtx import Evtx

    path = Path(__file__).parent / "_data" / "TestLogX.evtx"
    with path.open("rb") as fh:
        legacy = list(Evtx(fh))
    with path.open("rb") as fh:
        structured = list(Evtx(fh).structured_events())

    assert len(legacy) == len(structured) == 5
    # Type information is only present in the structured view.
    event_id = structured[0].get_all("EventID")[0]
    assert event_id.type == "win:UINT16"
    assert event_id.value == legacy[0]["EventID"]
    # Legacy convenience mapping keeps working unchanged.
    assert legacy[0]["Computer"] == "DESKTOP-PJOQLJS"
