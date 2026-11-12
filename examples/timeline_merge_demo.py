"""Demonstration of the evidence-preserving timeline merger.

Scenarios covered:

1. Two real EVT exports from the repository test data overlap physically: the same five events are
   present in both files (one copy is a dirty, not-finalised export). The overlapping events are
   presented once while both evidence sources remain attached.
2. Re-importing a byte-identical file is classified as a whole-file duplicate.
3. Synthetic records show a log clear followed by record-number reuse: the new event with the same
   record number still exists as its own timeline event.
4. Synthetic records show a system clock rollback: the backwards interval is explicitly flagged
   instead of being silently re-sorted into chronological order.

Run with::

    python examples/timeline_merge_demo.py
"""

from __future__ import annotations

import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from dissect.eventlog.timeline import (
    EventTimeline,
    FileLogSource,
    SyntheticLogSource,
    SyntheticRecord,
    TimelineFlag,
    render_timeline,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "tests" / "_data"
OUTPUT_DIR = Path(os.environ.get("TMPDIR", tempfile.gettempdir())) / "dissect_eventlog_timeline_demo"


def dt(epoch_seconds: int) -> datetime:
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)


def build_sources() -> list:
    # Real repository samples: two physical EVT files containing the same five events.
    clean = FileLogSource(str(DATA_DIR / "TestLog.evt"), channel="TestLog")
    dirty = FileLogSource(str(DATA_DIR / "TestLog-dirty.evt"), channel="TestLog")

    # A byte-identical re-import of the clean file under a different acquisition name.
    duplicate_path = OUTPUT_DIR / "reimported_identical.evt"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(DATA_DIR / "TestLog.evt", duplicate_path)
    whole_duplicate = FileLogSource(str(duplicate_path), channel="TestLog")

    # Synthetic "Security" channel on the same host. Records 10..12 are pre-clear events; the log
    # is then cleared and numbering restarts, so record 10 is reused by a brand new event.
    pre_clear = SyntheticLogSource(
        "security-before-clear.evtx",
        [
            SyntheticRecord(10, dt(1_700_000_000), 4624, "logon A"),
            SyntheticRecord(11, dt(1_700_000_060), 4672, "privileged logon A"),
            SyntheticRecord(12, dt(1_700_000_120), 4634, "logoff A"),
        ],
    )
    post_clear = SyntheticLogSource(
        "security-after-clear.evtx",
        [
            SyntheticRecord(10, dt(1_700_001_000), 4720, "user account created (reused rec 10)"),
            SyntheticRecord(11, dt(1_700_001_060), 4624, "logon B"),
        ],
    )

    # Synthetic source whose clock is wound back while the stream keeps appending.
    rollback = SyntheticLogSource(
        "security-clock-rollback.evtx",
        [
            SyntheticRecord(20, dt(1_700_002_000), 4624, "logon C before rollback"),
            SyntheticRecord(21, dt(1_700_002_060), 4672, "privileged logon C"),
            SyntheticRecord(22, dt(1_700_000_900), 4625, "failed logon after clock set backwards"),
            SyntheticRecord(23, dt(1_700_002_120), 4634, "logoff C after clock restored"),
        ],
    )

    return [clean, dirty, whole_duplicate, pre_clear, post_clear, rollback]


def main() -> None:
    timeline = EventTimeline(build_sources())
    report = render_timeline(timeline)
    print(report)

    # Assertions making the four required behaviours self-verifying.
    overlap = [event for event in timeline.events if len(event.evidence) >= 2 and event.payload.get("format") == "evt"]
    assert overlap, "overlapping EVT copies must merge into single events"
    assert all(len({ref.source_id for ref in event.evidence}) >= 2 for event in overlap)

    reused = [
        event
        for event in timeline.events
        if TimelineFlag.RECORD_NUMBER_REUSE in event.flags and event.record_number == 10
    ]
    assert len(reused) == 2, "pre-clear rec 10 and post-clear rec 10 must both survive"

    assert timeline.rollback_regions, "clock rollback interval must be detected"
    rolled_back = [event for event in timeline.events if TimelineFlag.CLOCK_ROLLBACK in event.flags]
    assert rolled_back, "rollback event must be explicitly flagged"

    duplicate_audits = [audit for audit in timeline.audits if audit.reason.value == "whole_file_duplicate"]
    assert duplicate_audits, "byte-identical reimport must be audited as whole-file duplicate"

    print("\nAll demonstration assertions passed.")


if __name__ == "__main__":
    main()
