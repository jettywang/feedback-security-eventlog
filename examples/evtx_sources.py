#!/usr/bin/env python
"""Print field-level byte provenance for EVTX records.

For every field the report distinguishes bytes stored in the current record (substitution
values, descriptors and inline text) from bytes stored in the chunk's shared template and
name tables. Every contributing range is printed; unresolved evidence is called out instead of
being approximated.
"""

from __future__ import annotations

import sys
from pathlib import Path

from dissect.eventlog.evtx import Evtx


def describe(value: bytes) -> str:
    try:
        text = value.decode("utf-16-le").rstrip("\x00")
        if text.isprintable():
            return f"utf-16le={text!r}"
    except UnicodeDecodeError:
        pass
    return f"hex={value.hex()[:32]}"


def main() -> None:
    for path in sys.argv[1:]:
        with Path(path).open("rb") as fh:
            for record in Evtx(fh).with_sources():
                print(f"record {record.sources.record_id} @ 0x{record.sources.record_offset:x}")
                for key, source in record.sources.items():
                    print(f"  {key}: path={source.path} template=0x{source.template_offset or 0:x}")
                    for byte_range in source.ranges:
                        if not byte_range.is_resolved:
                            print(f"    [{byte_range.kind.value}] unresolved: {byte_range.reason}")
                            continue
                        raw = byte_range.read(fh)
                        print(
                            f"    [{byte_range.kind.value}] {byte_range.role} "
                            f"0x{byte_range.start:x}+0x{byte_range.length:x} {describe(raw)}"
                        )
                print()


if __name__ == "__main__":
    main()
