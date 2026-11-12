"""Evidence-view tests: provider isolation, offset provenance and bad references.

These tests combine the two shipped WEVT resources with small, hand-built mutations to
prove that an interpretation is only trusted inside its own provider's byte range.
"""

from __future__ import annotations

import io
import struct
from uuid import UUID

import pytest

from dissect.eventlog.wevt.evidence import (
    ByteRange,
    Evidence,
    EvidenceError,
    EvidenceView,
    Reference,
)
from tests.conftest import absolute_path
from tests.wevt._synthetic import ProviderBuilder, build_resource, evnt_record

P0 = UUID("00000000-0000-0000-0000-000000000001")
P1 = UUID("00000000-0000-0000-0000-000000000002")

REAL_RESOURCES = ("_data/services.wevt", "_data/mpengine_etw.wevt")


def _view_from_bytes(blob: bytes) -> EvidenceView:
    return EvidenceView(io.BytesIO(blob))


def _two_providers_with_shared_ids() -> tuple[list[ProviderBuilder], bytes]:
    """Two providers that deliberately reuse the same numeric ids and map values."""
    builders: list[ProviderBuilder] = []
    for index, provider_id in enumerate((P0, P1)):
        builder = ProviderBuilder(provider_id)
        builder.add_level(4, f"Level-From-Provider-{index}")
        builder.add_task(101, f"Task-From-Provider-{index}")
        builder.add_opcode(1, f"Opcode-From-Provider-{index}")
        builder.add_temp(700 + index)
        builder.add_vmap(f"Map-From-Provider-{index}", [(0, 0x100 + index), (1, 0x200 + index)])
        builder.reserve_event()
        builders.append(builder)
    build_resource(builders)  # phase 1: determine all absolute offsets
    for builder in builders:
        builder.fill_event(
            0,
            evnt_record(
                event_id=500,
                level=4,
                level_offset=builder.level_offsets[4],
                task=101,
                task_offset=builder.task_offsets[101],
                opcode=1,
                opcode_offset=builder.opcode_offsets[1],
                template_offset=builder.temp_offsets[700 + (0 if builder.provider_id == P0 else 1)],
            ),
        )
    return builders, build_resource(builders)


def test_real_resources_every_evidence_is_in_provider_range() -> None:
    """Every parsed object on real data must lie inside its owning provider range."""
    for resource in REAL_RESOURCES:
        with absolute_path(resource).open("rb") as fh:
            view = EvidenceView(fh)
        assert len(view) >= 1
        for provider in view:
            for evidence in provider.all_evidence():
                assert isinstance(evidence, Evidence)
                assert evidence.provider_id == provider.provider_id
                assert provider.range.contains(evidence.offset, evidence.size), (
                    resource,
                    evidence.kind,
                    hex(evidence.offset),
                )


def test_real_resources_all_event_references_resolve_in_range() -> None:
    """A successful interpretation on real data always points back into the provider."""
    for resource in REAL_RESOURCES:
        with absolute_path(resource).open("rb") as fh:
            view = EvidenceView(fh)
        for provider in view:
            for event in provider.events:
                interpretation = provider.interpret_event(event)
                for reference in interpretation.references:
                    if reference.raw_offset == 0:
                        assert reference.resolved is False
                        assert reference.error is None
                        continue
                    assert reference.resolved, (resource, reference.field, reference.error)
                    target = reference.evidence
                    assert target.provider_id == provider.provider_id
                    assert provider.range.contains(target.offset, target.size)


def test_duplicate_numeric_ids_stay_separated_per_provider() -> None:
    """Same numeric id in two providers must resolve to two distinct, named objects."""
    builders, blob = _two_providers_with_shared_ids()
    view = _view_from_bytes(blob)
    provider0 = view.provider(P0)
    provider1 = view.provider(P1)

    level0 = provider0.lookup_id("LEVL", 4)
    level1 = provider1.lookup_id("LEVL", 4)
    assert level0 is not None
    assert level1 is not None
    assert level0.offset != level1.offset
    assert level0.name == "Level-From-Provider-0"
    assert level1.name == "Level-From-Provider-1"

    # The raw numeric id is identical but each event is explained by its own provider.
    interpretations = [provider.interpret_event(event) for provider in view for event in provider.events]
    task_names = {ref.name for interp in interpretations for ref in interp.references if ref.field == "task"}
    assert task_names == {"Task-From-Provider-0", "Task-From-Provider-1"}

    # No provider can ever return the other's same-numbered definition.
    assert provider0.lookup_id("LEVL", 4).name != provider1.lookup_id("LEVL", 4).name
    assert provider0.lookup_offset(level1.offset) is None
    assert provider1.lookup_offset(level0.offset) is None


def test_value_maps_with_duplicate_values_are_not_cross_resolved() -> None:
    """Value 0/1 exist in both provider maps but resolve to provider-specific message ids."""
    _, blob = _two_providers_with_shared_ids()
    view = _view_from_bytes(blob)
    map0 = view.provider(P0).value_maps[0]
    map1 = view.provider(P1).value_maps[0]

    assert map0.provider_id == P0
    assert map1.provider_id == P1
    assert map0.lookup(0).message_table_id != map1.lookup(0).message_table_id
    assert map0.lookup(0).message_table_id == 0x100
    assert map1.lookup(0).message_table_id == 0x101
    # A lookup is strictly scoped to the map it was asked on.
    assert map0.lookup(999) is None


def test_shuffled_maps_pointer_table_still_binds_each_map_correctly() -> None:
    """Reordering the MAPS pointer table must not swap map names or values."""
    builder = ProviderBuilder(P0)
    builder.add_vmap("First-Map", [(0, 0xAA)])
    builder.add_vmap("Second-Map", [(5, 0xBB)])
    build_resource([builder])  # phase 1: learn the pointer table anchor
    table_at = builder.maps_pointer_table_offset

    blob = bytearray(build_resource([builder]))
    pointer0, pointer1 = struct.unpack_from("<II", blob, table_at)
    struct.pack_into("<II", blob, table_at, pointer1, pointer0)

    view = _view_from_bytes(bytes(blob))
    maps = {value_map.name: value_map for value_map in view.provider(P0).value_maps}
    assert set(maps) == {"First-Map", "Second-Map"}
    # Despite the shuffled table, each name stays bound to its own entries and range.
    assert maps["First-Map"].lookup(0).message_table_id == 0xAA
    assert maps["Second-Map"].lookup(5).message_table_id == 0xBB
    for value_map in maps.values():
        assert value_map.range.contains(value_map.offset, value_map.size)


def test_cross_provider_reference_is_rejected_with_raw_id_preserved() -> None:
    """An EVNT pointer aimed at another provider's region must not produce a description."""
    builders, blob = _two_providers_with_shared_ids()
    provider0, provider1 = builders
    foreign_level = provider1.level_offsets[4]  # a valid LEVL, but owned by P1

    # Corrupt P0's EVNT level pointer to point at P1's level record.
    event_abs = provider0.event_offsets[0]
    level_pointer_field = event_abs + 28  # level_offset is the 8th uint32 in EVNT
    mutated = bytearray(blob)
    struct.pack_into("<I", mutated, level_pointer_field, foreign_level)

    view = _view_from_bytes(bytes(mutated))
    event = view.provider(P0).events[0]
    interpretation = view.provider(P0).interpret_event(event)
    level_ref = next(ref for ref in interpretation.references if ref.field == "levl")

    assert isinstance(level_ref, Reference)
    assert level_ref.resolved is False
    assert level_ref.evidence is None
    assert level_ref.raw_id == 4  # original numeric id retained
    assert level_ref.raw_offset == foreign_level
    assert "outside provider range" in level_ref.error
    # No plausible name leaks in from the foreign same-numbered level.
    assert level_ref.name is None


def test_out_of_bounds_reference_keeps_id_and_reason() -> None:
    """A pointer past the whole file is reported as an error, not a borrowed definition."""
    builders, blob = _two_providers_with_shared_ids()
    provider0 = builders[0]
    event_abs = provider0.event_offsets[0]
    task_pointer_field = event_abs + 32  # task_offset is the 9th uint32 in EVNT
    mutated = bytearray(blob)
    bogus = len(blob) + 0x100
    struct.pack_into("<I", mutated, task_pointer_field, bogus)

    view = _view_from_bytes(bytes(mutated))
    task_ref = view.provider(P0).interpret_event(view.provider(P0).events[0]).task
    assert task_ref.resolved is False
    assert task_ref.raw_id == 101
    assert task_ref.raw_offset == bogus
    assert task_ref.evidence is None
    assert "outside provider range" in task_ref.error


def test_missing_template_is_an_error_not_a_silent_success() -> None:
    """A template pointer with no TEMP anchored there must keep the offset and reason."""
    builders, blob = _two_providers_with_shared_ids()
    provider0 = builders[0]
    event_abs = provider0.event_offsets[0]
    template_pointer_field = event_abs + 20  # template_offset is the 6th uint32
    mutated = bytearray(blob)
    dangling = provider0.range_end - 4  # inside the range but not a TEMP anchor
    struct.pack_into("<I", mutated, template_pointer_field, dangling)

    view = _view_from_bytes(bytes(mutated))
    template_ref = view.provider(P0).interpret_event(view.provider(P0).events[0]).template
    assert template_ref.resolved is False
    assert template_ref.raw_offset == dangling
    assert template_ref.evidence is None
    assert "no TEMP" in template_ref.error


def test_in_provider_but_wrong_kind_reference_is_rejected() -> None:
    """A pointer landing on a TASK where a LEVL is expected cannot be mislabelled."""
    builders, blob = _two_providers_with_shared_ids()
    provider0 = builders[0]
    event_abs = provider0.event_offsets[0]
    level_pointer_field = event_abs + 28
    mutated = bytearray(blob)
    struct.pack_into("<I", mutated, level_pointer_field, provider0.task_offsets[101])

    view = _view_from_bytes(bytes(mutated))
    level_ref = view.provider(P0).interpret_event(view.provider(P0).events[0]).level
    assert level_ref.resolved is False
    assert level_ref.raw_id == 4
    assert "expected LEVL" in level_ref.error
    assert level_ref.evidence.kind == "TASK"


def test_provider_ranges_are_disjoint_and_cover_payloads() -> None:
    """Provider byte ranges must not overlap, so an offset belongs to at most one provider."""
    _, blob = _two_providers_with_shared_ids()
    view = _view_from_bytes(blob)
    ranges = [provider.range for provider in view]
    assert ranges[0].end == ranges[1].start
    for index in range(len(ranges) - 1):
        assert ranges[index].end <= ranges[index + 1].start
        assert isinstance(ranges[index], ByteRange)


def test_maps_pointer_into_another_provider_is_ignored() -> None:
    """A MAPS entry that points outside the provider yields no usable value map."""
    builders, blob = _two_providers_with_shared_ids()
    provider0, provider1 = builders
    table_at = provider0.maps_pointer_table_offset
    foreign_vmap = provider1.vmap_offsets[0]
    mutated = bytearray(blob)
    struct.pack_into("<I", mutated, table_at, foreign_vmap)

    view = _view_from_bytes(bytes(mutated))
    # P0's own map is no longer trustworthy at that pointer, so it exposes no map there.
    assert view.provider(P0).value_maps == ()
    # P1's map remains intact and usable within its own range.
    assert len(view.provider(P1).value_maps) == 1


def test_unknown_id_within_provider_returns_none_without_fallback() -> None:
    """An id the provider never defined resolves to None, never to a same-id neighbour."""
    _, blob = _two_providers_with_shared_ids()
    provider0 = _view_from_bytes(blob).provider(P0)
    assert provider0.lookup_id("LEVL", 999) is None
    assert provider0.lookup_id("TASK", 4) is None  # id 4 exists for LEVL, not TASK


@pytest.mark.parametrize("resource", REAL_RESOURCES)
def test_value_map_entries_are_inside_their_map_and_provider(resource: str) -> None:
    with absolute_path(resource).open("rb") as fh:
        view = EvidenceView(fh)
    for provider in view:
        for value_map in provider.value_maps:
            assert provider.range.contains(value_map.offset, value_map.size)
            for entry in value_map.entries:
                assert value_map.offset <= entry.offset < value_map.offset + value_map.size
                assert provider.range.contains(entry.offset, 8)


def test_interpret_event_rejects_non_event_evidence() -> None:
    """interpret_event only accepts EVNT evidence and refuses other kinds explicitly."""
    _, blob = _two_providers_with_shared_ids()
    provider = _view_from_bytes(blob).provider(P0)
    level = provider.evidence("LEVL")[0]
    with pytest.raises(EvidenceError):
        provider.interpret_event(level)


def test_template_is_resolvable_by_its_guid_inside_provider_only() -> None:
    """A TEMP is reachable through its GUID, scoped to the owning provider."""
    _, blob = _two_providers_with_shared_ids()
    view = _view_from_bytes(blob)
    provider0 = view.provider(P0)
    template_guid = UUID("000002bc-0000-0000-0000-000000000000")  # temp_id 700

    template = provider0.lookup_template(template_guid)
    assert template is not None
    assert template.kind == "TEMP"
    assert provider0.range.contains(template.offset, template.size)
    # The second provider used temp_id 701, so it must not expose 700's GUID.
    assert view.provider(P1).lookup_template(template_guid) is None


def test_every_evidence_carries_absolute_offset_and_provider_range() -> None:
    """Provenance fields are present and internally consistent for every object."""
    _, blob = _two_providers_with_shared_ids()
    for provider in _view_from_bytes(blob):
        for evidence in provider.all_evidence():
            assert evidence.provider_id == provider.provider_id
            assert provider.range.start <= evidence.offset < provider.range.end
            assert evidence.size > 0
            assert evidence.in_range
