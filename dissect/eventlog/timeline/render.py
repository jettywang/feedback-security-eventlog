"""Human readable rendering of a merged :class:`EventTimeline`.

Rendering is read-only: it prints the original timestamps and the explicit flags/audit decisions,
it never normalises or rewrites any timestamp.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.eventlog.timeline.model import TimelineFlag

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.eventlog.timeline.merger import EventTimeline
    from dissect.eventlog.timeline.model import MergedEvent, TimelineLayer

_FLAG_LABELS = {
    TimelineFlag.CLOCK_ROLLBACK: "CLOCK-ROLLBACK",
    TimelineFlag.RECORD_NUMBER_REUSE: "RECORD-NUMBER-REUSE",
    TimelineFlag.ORDER_UNDETERMINED: "ORDER-UNDETERMINED",
}


def _format_timestamp(event: MergedEvent) -> str:
    return event.timestamp.isoformat() if event.timestamp else "<no-timestamp>"


def _format_event(event: MergedEvent) -> str:
    numbers = ",".join(str(number) for number in sorted(event.record_numbers_seen)) or "-"
    flags = ",".join(_FLAG_LABELS[flag] for flag in sorted(event.flags, key=lambda item: item.value)) or "-"
    message = event.payload.get("message")
    if message is None:
        strings = event.payload.get("strings")
        message = strings[0] if strings else event.payload.get("event_id", "")
    sources = "; ".join(f"{ref.source_name}#idx{ref.stream_index}/rec{ref.record_number}" for ref in event.evidence)
    return (
        f"  - ts={_format_timestamp(event)} rec={numbers} host={event.host or '-'} "
        f"channel={event.channel or '-'} event={event.payload.get('event_id', '-')} "
        f"msg={message!r} copies={len(event.evidence)} flags={flags}\n"
        f"      evidence: {sources}\n"
        f"      content_hash={event.content_hash[:16]}..."
    )


def render_timeline(timeline: EventTimeline) -> str:
    lines: list[str] = []
    lines.append("Merged security event timeline (original timestamps preserved)")
    lines.append(f"sources ingested: {len(timeline.sources)}")
    for source_id in timeline.sources:
        lines.append(f"  * {source_id}")
    lines.append("")

    layers = timeline.build_layers()
    for layer_index, layer in enumerate(layers):
        lines.append(_render_layer_header(layer_index, layer))
        for event in layer.events:
            lines.append(_format_event(event))

    lines.append("")
    lines.append("Clock rollback regions (stream order contradicted the timestamps):")
    if not timeline.rollback_regions:
        lines.append("  none")
    for region in timeline.rollback_regions:
        lines.append(
            f"  * {region.source_name}: idx{region.previous_stream_index} "
            f"{region.previous_timestamp.isoformat()} -> idx{region.current_stream_index} "
            f"{region.current_timestamp.isoformat()}"
        )

    lines.append("")
    lines.append("Deduplication audit trail:")
    if not timeline.audits:
        lines.append("  no duplicates merged")
    for audit in timeline.audits:
        lines.append(f"  * [{audit.reason.value}] {audit.added_source} matched {audit.matched_source}: {audit.detail}")

    return "\n".join(lines)


def _render_layer_header(layer_index: int, layer: TimelineLayer) -> str:
    if not layer.flags:
        return f"layer {layer_index} (ordered):"
    labels = ",".join(_FLAG_LABELS[flag] for flag in sorted(layer.flags, key=lambda item: item.value))
    return f"layer {layer_index} ({labels}):"


def render_events(events: Iterable[MergedEvent]) -> str:
    return "\n".join(_format_event(event) for event in events)
