from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.eventlog.timeline import (
    EventTimeline,
    FileLogSource,
    MergeReason,
    SyntheticLogSource,
    SyntheticRecord,
    TimelineFlag,
    canonical_fingerprint,
    render_timeline,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

UTC = timezone.utc


def ts(minutes: int) -> datetime:
    return datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC).replace(minute=minutes)


def synthetic(name: str, rows: list[tuple[int, int, int, str]]) -> SyntheticLogSource:
    return SyntheticLogSource(
        name,
        [
            SyntheticRecord(record_number, ts(minute), event_id, message)
            for record_number, minute, event_id, message in rows
        ],
    )


def test_overlapping_copies_presented_once_with_both_sources() -> None:
    left = synthetic("pre.evtx", [(1, 0, 4624, "a"), (2, 1, 4672, "b"), (3, 2, 4634, "c")])
    right = synthetic("post.evtx", [(2, 1, 4672, "b"), (3, 2, 4634, "c"), (4, 3, 4625, "d")])

    timeline = EventTimeline([left, right])

    assert len(timeline.events) == 4
    shared_b = next(event for event in timeline.events if event.payload["message"] == "b")
    shared_c = next(event for event in timeline.events if event.payload["message"] == "c")
    assert {ref.source_name for ref in shared_b.evidence} == {"pre.evtx", "post.evtx"}
    assert {ref.source_name for ref in shared_c.evidence} == {"post.evtx", "pre.evtx"}
    assert MergeReason.CONTENT_HASH in shared_b.merge_reasons
    assert {audit.reason for audit in timeline.audits} == {MergeReason.CONTENT_HASH}


def test_same_record_number_is_not_duplicate() -> None:
    left = synthetic("one.evtx", [(5, 0, 4624, "first event")])
    right = synthetic("two.evtx", [(5, 9, 4624, "completely different event")])

    timeline = EventTimeline([left, right])

    assert len(timeline.events) == 2
    assert all(TimelineFlag.RECORD_NUMBER_REUSE in event.flags for event in timeline.events)
    assert timeline.audits == []


def test_same_timestamp_is_not_duplicate() -> None:
    left = synthetic("one.evtx", [(1, 5, 4624, "login alice")])
    right = synthetic("two.evtx", [(2, 5, 4625, "login bob")])

    timeline = EventTimeline([left, right])

    assert len(timeline.events) == 2
    assert timeline.audits == []


def test_log_clear_then_number_reuse_keeps_new_event() -> None:
    before = synthetic("before-clear.evtx", [(10, 0, 4624, "old logon"), (11, 1, 4634, "old logoff")])
    after = SyntheticLogSource(
        "after-clear.evtx",
        [SyntheticRecord(10, ts(10), 4720, "account created after clear")],
    )

    timeline = EventTimeline([before, after])

    assert len(timeline.events) == 3
    reused = [event for event in timeline.events if event.record_number == 10]
    assert len(reused) == 2
    assert {event.payload["message"] for event in reused} == {"old logon", "account created after clear"}
    assert all(TimelineFlag.RECORD_NUMBER_REUSE in event.flags for event in reused)


def test_clock_rollback_is_flagged_not_reordered() -> None:
    source = synthetic(
        "rollback.evtx",
        [
            (20, 10, 4624, "before"),
            (21, 11, 4672, "middle"),
            (22, 3, 4625, "written after clock went back"),
            (23, 12, 4634, "after recovery"),
        ],
    )

    timeline = EventTimeline([source])
    layers = timeline.build_layers()

    assert len(timeline.rollback_regions) == 1
    region = timeline.rollback_regions[0]
    assert region.current_stream_index == 2
    assert region.current_timestamp < region.previous_timestamp

    flat_messages = [event.payload["message"] for layer in layers for event in layer.events]
    # Stream order preserved: the timestamp-older record stays physically third, is not sorted first.
    assert flat_messages == ["before", "middle", "written after clock went back", "after recovery"]
    rolled_back = next(event for event in timeline.events if event.record_number == 22)
    assert TimelineFlag.CLOCK_ROLLBACK in rolled_back.flags
    assert rolled_back.timestamp == ts(3)


def test_overlapping_anchors_establish_cross_source_order() -> None:
    # Both sources contain anchor "b"; "a" precedes it in the first source and "c" follows it in
    # the second. The overlap anchor makes that cross-source order provable, so it must not be
    # presented as an undetermined tie.
    left = synthetic("pre.evtx", [(1, 0, 1, "a"), (2, 1, 1, "anchor")])
    right = synthetic("post.evtx", [(2, 1, 1, "anchor"), (3, 2, 1, "c")])

    timeline = EventTimeline([left, right])
    layers = timeline.build_layers()

    flat = [event.payload["message"] for layer in layers for event in layer.events]
    assert flat == ["a", "anchor", "c"]
    assert all(layer.flags == set() for layer in layers)


def test_undetermined_cross_source_order_is_layered() -> None:
    left = synthetic("left.evtx", [(1, 0, 1, "left-only")])
    right = synthetic("right.evtx", [(1, 8, 1, "right-only")])

    timeline = EventTimeline([left, right])
    layers = timeline.build_layers()

    assert len(layers) == 1
    assert TimelineFlag.ORDER_UNDETERMINED in layers[0].flags
    assert len(layers[0].events) == 2


def test_whole_file_duplicate_is_audited(get_absolute_path: Callable[[str], Path], tmp_path: Path) -> None:
    sample = get_absolute_path("_data/TestLog.evt")
    copy = tmp_path / "copy.evt"
    copy.write_bytes(sample.read_bytes())

    timeline = EventTimeline(
        [
            FileLogSource(sample, channel="TestLog"),
            FileLogSource(copy, channel="TestLog"),
        ]
    )

    assert len(timeline.events) == 5
    assert all(len(event.evidence) == 2 for event in timeline.events)
    assert all(MergeReason.WHOLE_FILE_DUPLICATE in event.merge_reasons for event in timeline.events)
    assert all(audit.reason == MergeReason.WHOLE_FILE_DUPLICATE for audit in timeline.audits)


def test_real_evt_samples_overlap_and_keep_two_sources(get_absolute_path: Callable[[str], Path]) -> None:
    clean = FileLogSource(get_absolute_path("_data/TestLog.evt"), channel="TestLog")
    dirty = FileLogSource(get_absolute_path("_data/TestLog-dirty.evt"), channel="TestLog")

    timeline = EventTimeline([clean, dirty])

    assert len(timeline.events) == 5
    assert all(len({ref.source_id for ref in event.evidence}) == 2 for event in timeline.events)
    record_numbers = sorted(event.record_number for event in timeline.events)
    assert record_numbers == [1, 2, 3, 4, 5]
    assert all(event.timestamp is not None for event in timeline.events)


def test_real_evtx_sample_round_trips(get_absolute_path: Callable[[str], Path]) -> None:
    timeline = EventTimeline([FileLogSource(get_absolute_path("_data/TestLogX.evtx"))])

    assert len(timeline.events) == 5
    evtx_event = timeline.events[0]
    assert evtx_event.payload["format"] == "evtx"
    assert evtx_event.record_number == 1
    assert evtx_event.host == "DESKTOP-PJOQLJS"


def test_fingerprint_ignores_record_number_but_catches_content_change() -> None:
    # The record number lives outside the payload, so identical bodies from different numbering
    # contexts share a fingerprint; any semantic change breaks it.
    base = {
        "format": "synthetic",
        "event_id": 4624,
        "message": "same body",
        "timestamp": ts(0),
    }
    identical_body = dict(base)
    modified = dict(base, message="different body")

    assert canonical_fingerprint(base) == canonical_fingerprint(identical_body)
    assert canonical_fingerprint(base) != canonical_fingerprint(modified)


def test_render_contains_audit_and_rollback_sections() -> None:
    source = synthetic("rollback.evtx", [(1, 5, 1, "a"), (2, 1, 1, "b")])
    timeline = EventTimeline([source])
    report = render_timeline(timeline)

    assert "CLOCK-ROLLBACK" in report
    assert "Clock rollback regions" in report
    assert "Deduplication audit trail" in report
