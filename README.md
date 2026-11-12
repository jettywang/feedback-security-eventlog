# dissect.eventlog

A Dissect module implementing parsers for the Windows EVT, EVTX and WEVT log file formats. For more information, please
see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.eventlog/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.eventlog` is available on [PyPI](https://pypi.org/project/dissect.eventlog/).

```bash
pip install dissect.eventlog
```

This module is also automatically installed if you install the `dissect` package.

## Field provenance

Plain iteration returns the familiar `KeyValueCollection`. To trace a field back to the
bytes that produced it, opt in to sources:

```python
from dissect.eventlog.evtx import Evtx
from dissect.eventlog.utils import ByteRange, SourceKind

with path.open("rb") as fh:
    for record in Evtx(fh).with_sources():
        # Keys are identical to the default output, including duplicate suffixes.
        source = record.sources["EventID"]
        for byte_range in source.ranges:
            if byte_range.is_resolved:
                print(byte_range.kind, hex(byte_range.start), byte_range.read(fh))
```

Every output key receives a `FieldSource` with the complete ordered list of ranges that
contributed to the value: the substitution token, the record's descriptor and value bytes,
the element/attribute name table entry, and the chunk template definition (including lexically
containing templates for nested templates). `SourceKind.RECORD` marks bytes in the current
record, while `SourceKind.TEMPLATE` and `SourceKind.NAME` mark bytes reused from the chunk.
Ranges are never merged, so same-named fields and multi-byte values keep every evidence
interval. If a boundary cannot be determined exactly, the range is reported as
`SourceKind.UNRESOLVED` with a reason and has no guessed offset.


## Build and test instructions

This project uses `tox` to build source and wheel distributions. Run the following command from the root folder to build
these:

```bash
tox -e build
```

The build artifacts can be found in the `dist/` directory.

`tox` is also used to run linting and unit tests in a self-contained environment. To run both linting and unit tests
using the default installed Python version, run:

```bash
tox
```

For a more elaborate explanation on how to build and test the project, please see [the
documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/dissect>.

License terms: AGPL3 (<https://www.gnu.org/licenses/agpl-3.0.html>). For more information, see the LICENSE file.
