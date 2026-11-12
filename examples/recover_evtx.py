#!/usr/bin/env python
"""Recover structurally valid records from a damaged EVTX file and report skipped byte ranges.

The source file is opened read-only and is never rewritten.  The JSON report can be written to a separate path so
the original evidence and the recovery output stay separate artifacts.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from dissect.eventlog.evtx import recover_evtx


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recover records from damaged EVTX chunks with an auditable skip report."
    )
    parser.add_argument("evtx_file", metavar="EVTX", help="EVTX file to read (never modified)")
    parser.add_argument("--report", "-r", metavar="PATH", help="write the JSON report to PATH instead of stdout")
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    args = parser.parse_args()

    with Path(args.evtx_file).open("rb") as fh:
        report = recover_evtx(fh, path=args.evtx_file)

    payload = report.to_dict()
    output = json.dumps(payload, indent=None if args.compact else 2, sort_keys=True)

    if args.report:
        Path(args.report).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
