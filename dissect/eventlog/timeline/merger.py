"""Evidence-preserving merger for multiple EVT/EVTX exports of the same host.

Design constraints implemented here:

* Equal record numbers or equal timestamps are never treated as duplicates by themselves.
* A duplicate requires an auditable match: either byte-identical source files
  (:attr:`MergeReason.WHOLE_FILE_DUPLICATE`) or an identical semantic content fingerprint within
  the same host/channel scope (:attr:`MergeReason.CONTENT_HASH`).
* Record-number reuse after a log clear keeps both events and is explicitly flagged.
* System clock rollback is detected on the physical stream order and explicitly marked; original
  timestamps are never rewritten and events are never silently re-sorted into "normal" time order.
* When source order cannot be established from evidence, events are presented side by side in the
  same :class:`TimelineLayer` instead of being arbitrarily ordered.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from dissect.eventlog.timeline.model import (
    MergeAudit,
    MergedEvent,
    MergeReason,
    NormalizedEvent,
    RollbackRegion,
    TimelineFlag,
    TimelineLayer,
)
from dissect.eventlog.timeline.source import FileLogSource, LogSource

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


class EventTimeline:
    """Merged, auditable timeline built from one or more :class:`LogSource` instances."""

    def __init__(self, sources: Iterable[LogSource] | None = None):
        self._events: dict[tuple[str, str, str], MergedEvent] = {}
        self._source_seen: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
        self._source_hashes: dict[str, str] = {}
        self._source_names: dict[str, str] = {}
        self._ingested_sources: list[str] = []
        self.audits: list[MergeAudit] = []
        self.rollback_regions: list[RollbackRegion] = []
        if sources:
            for source in sources:
                self.add_source(source)

    @property
    def events(self) -> list[MergedEvent]:
        return list(self._events.values())

    @property
    def sources(self) -> list[str]:
        return list(self._ingested_sources)

    def add_source(self, source: LogSource) -> None:
        events = list(source.events())
        source_id = source.source_id
        self._source_names[source_id] = source.name

        whole_file_duplicate_of: str | None = None
        if isinstance(source, FileLogSource) and source.meta and source.meta.file_hash:
            file_hash = source.meta.file_hash
            self._source_hashes[source_id] = file_hash
            for previous_id, previous_hash in self._source_hashes.items():
                if previous_id != source_id and previous_hash == file_hash:
                    whole_file_duplicate_of = previous_id
                    break
        self._ingested_sources.append(source_id)

        for event in events:
            self._ingest(event, whole_file_duplicate_of)

        self._detect_rollbacks(source_id, source.name, events)
        self._flag_record_number_reuse()

    def _ingest(self, event: NormalizedEvent, whole_file_duplicate_of: str | None) -> None:
        key = event.event_key
        seen_in_source = self._source_seen[event.evidence.source_id]
        existing = self._events.get(key)

        if existing is None:
            merged = MergedEvent(
                host=event.host,
                channel=event.channel,
                record_number=event.record_number,
                timestamp=event.timestamp,
                payload=event.payload,
                content_hash=event.content_hash,
                event_key=key,
                evidence=[event.evidence],
                record_numbers_seen={event.record_number} if event.record_number is not None else set(),
            )
            self._events[key] = merged
            seen_in_source.add(key)
            return

        if key in seen_in_source:
            # Same file yielded the same content twice: keep both physical observations.
            existing.evidence.append(event.evidence)
            self._record_merge(existing, event, MergeReason.CONTENT_HASH, "repeated observation inside one source")
        elif whole_file_duplicate_of:
            existing.evidence.append(event.evidence)
            existing.merge_reasons.add(MergeReason.WHOLE_FILE_DUPLICATE)
            if event.record_number is not None:
                existing.record_numbers_seen.add(event.record_number)
            self._record_merge(
                existing,
                event,
                MergeReason.WHOLE_FILE_DUPLICATE,
                f"source file is byte-identical to {self._source_names[whole_file_duplicate_of]}",
            )
        else:
            existing.evidence.append(event.evidence)
            existing.merge_reasons.add(MergeReason.CONTENT_HASH)
            if event.record_number is not None:
                existing.record_numbers_seen.add(event.record_number)
            self._record_merge(
                existing,
                event,
                MergeReason.CONTENT_HASH,
                "identical content fingerprint in same host/channel scope",
            )

        seen_in_source.add(key)

    def _flag_record_number_reuse(self) -> None:
        """Mark distinct events that share a native record number in the same host/channel scope."""
        number_owners: dict[tuple[str | None, str | None, int], list[MergedEvent]] = defaultdict(list)
        for merged in self._events.values():
            for number in merged.record_numbers_seen:
                number_owners[(merged.host, merged.channel, number)].append(merged)

        for owners in number_owners.values():
            distinct_hashes = {owner.content_hash for owner in owners}
            if len(distinct_hashes) > 1:
                for owner in owners:
                    owner.flags.add(TimelineFlag.RECORD_NUMBER_REUSE)

    def _record_merge(
        self,
        existing: MergedEvent,
        event: NormalizedEvent,
        reason: MergeReason,
        detail: str,
    ) -> None:
        existing.merge_reasons.add(reason)
        self.audits.append(
            MergeAudit(
                reason=reason,
                kept_event_key=existing.event_key,
                added_source=event.evidence.source_name,
                matched_source=existing.evidence[0].source_name,
                detail=detail,
            )
        )

    def _detect_rollbacks(
        self,
        source_id: str,
        source_name: str,
        events: Sequence[NormalizedEvent],
    ) -> None:
        previous = None
        for event in events:
            if (
                previous is not None
                and event.timestamp is not None
                and previous.timestamp is not None
                and event.timestamp < previous.timestamp
            ):
                region = RollbackRegion(
                    source_id=source_id,
                    source_name=source_name,
                    previous_stream_index=previous.evidence.stream_index,
                    previous_timestamp=previous.timestamp,
                    current_stream_index=event.evidence.stream_index,
                    current_timestamp=event.timestamp,
                )
                self.rollback_regions.append(region)
                target = self._events.get(event.event_key)
                if target is not None:
                    target.flags.add(TimelineFlag.CLOCK_ROLLBACK)
            previous = event

    def build_layers(self) -> list[TimelineLayer]:
        """Return timeline layers using physical stream order as the primary evidence.

        Ordering is only ever compared inside one host/channel scope. Events belonging to different
        scopes can never be ordered against each other, so each scope gets its own layer sequence.
        """
        scopes: dict[tuple[str | None, str | None], set[tuple[str, str, str]]] = defaultdict(set)
        for key, merged in self._events.items():
            scopes[(merged.host, merged.channel)].add(key)

        layers: list[TimelineLayer] = []
        for scope in sorted(scopes, key=lambda item: (item[0] or "", item[1] or "")):
            nodes = scopes[scope]
            successors: dict[tuple[str, str, str], set[tuple[str, str, str]]] = defaultdict(set)
            predecessors: dict[tuple[str, str, str], set[tuple[str, str, str]]] = defaultdict(set)

            self._add_stream_edges(successors, predecessors, nodes)
            self._add_anchor_edges(successors, predecessors, nodes)
            layers.extend(self._topological_layers(nodes, successors, predecessors))

        return layers

    def _add_stream_edges(self, successors: dict, predecessors: dict, nodes: set) -> None:
        per_source_order: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        for key, merged in self._events.items():
            if key not in nodes:
                continue
            for evidence in merged.evidence:
                per_source_order[evidence.source_id].append((evidence.stream_index, key))
        for ordered in per_source_order.values():
            ordered.sort()
            previous_key = None
            for _, key in ordered:
                if key not in nodes:
                    continue
                if previous_key is not None and previous_key != key:
                    successors[previous_key].add(key)
                    predecessors[key].add(previous_key)
                previous_key = key

    def _add_anchor_edges(self, successors: dict, predecessors: dict, nodes: set) -> None:
        # An event observed in more than one source is an evidence anchor. When two anchors appear
        # in the same order in every source that contains both, that ordering is real and gets an
        # edge. Events that cannot be anchored get no edge and end up side by side in one layer.
        source_keys: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        for key, merged in self._events.items():
            if key not in nodes:
                continue
            for evidence in merged.evidence:
                source_keys[evidence.source_id].append((evidence.stream_index, key))
        for ordered in source_keys.values():
            ordered.sort()

        anchor_sources: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        for source_id, ordered in source_keys.items():
            for _, key in ordered:
                if len(self._events[key].evidence) > 1:
                    anchor_sources[key].add(source_id)

        anchors = list(anchor_sources)
        for index, first in enumerate(anchors):
            for second in anchors[index + 1 :]:
                shared_sources = anchor_sources[first] & anchor_sources[second]
                comparisons = set()
                for source_id in shared_sources:
                    order = [key for _, key in source_keys[source_id]]
                    if first in order and second in order:
                        comparisons.add(order.index(first) < order.index(second))
                if comparisons == {True}:
                    successors[first].add(second)
                    predecessors[second].add(first)
                elif comparisons == {False}:
                    successors[second].add(first)
                    predecessors[first].add(second)
                # Contradictory anchor order: no edge, both stay undetermined.

    def _topological_layers(
        self,
        nodes: set[tuple[str, str, str]],
        successors: dict,
        predecessors: dict,
    ) -> list[TimelineLayer]:
        remaining_predecessors = {key: set(predecessors.get(key, set())) for key in nodes}
        layers: list[TimelineLayer] = []
        placed: set[tuple[str, str, str]] = set()

        while len(placed) < len(nodes):
            ready = [key for key in nodes if key not in placed and not remaining_predecessors[key]]
            if not ready:
                # Defensive: a cycle would mean contradictory stream evidence. Present it as one
                # undetermined layer instead of dropping events.
                ready = [key for key in nodes if key not in placed]
                layer_flags = {TimelineFlag.ORDER_UNDETERMINED}
            else:
                layer_flags = set()

            ready.sort(key=lambda key: self._layer_sort_key(key))
            layer_events = [self._events[key] for key in ready]
            if len(ready) > 1:
                layer_flags.add(TimelineFlag.ORDER_UNDETERMINED)
            rollback_here = any(TimelineFlag.CLOCK_ROLLBACK in event.flags for event in layer_events)
            if rollback_here:
                layer_flags.add(TimelineFlag.CLOCK_ROLLBACK)

            layers.append(TimelineLayer(events=layer_events, flags=layer_flags))
            for key in ready:
                placed.add(key)
                for downstream in successors.get(key, set()):
                    remaining_predecessors[downstream].discard(key)

        return layers

    def _layer_sort_key(self, key: tuple[str, str, str]) -> tuple:
        merged = self._events[key]
        earliest_evidence = min(merged.evidence, key=lambda ref: (ref.source_id, ref.stream_index))
        timestamp = merged.timestamp.isoformat() if merged.timestamp else ""
        # Tie-break only; never presented as inferred order.
        return (earliest_evidence.source_id, earliest_evidence.stream_index, timestamp, merged.record_number or 0)
