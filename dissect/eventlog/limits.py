"""Resource boundaries for parsing untrusted event log data.

The EVTX/BinXML format lets a small number of bytes drive a large amount of parser work:
template instances nest through BinXML substitution values, descriptor entry counts are taken
directly from the input, and a template reference can point back at an already cached definition.

The boundaries in this module turn those unbounded operations into finite, explicitly configured
budgets. Every limit raises :class:`ResourceLimitExceeded`, which is deliberately separate from
:class:`~dissect.eventlog.exceptions.BxmlException` (corrupt structure) and from :class:`EOFError`
(a genuine end of stream), so callers can tell the three termination reasons apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO

from dissect.eventlog.exceptions import ResourceLimitExceeded

# A single EVTX chunk is 64 KiB; a record's BinXML stream therefore never legitimately needs to
# read more than that many bytes. The default is deliberately generous so genuine files are not
# affected while pathological read amplification is still bounded.
DEFAULT_MAX_BYTES_PER_RECORD = 64 * 1024

# BinXML substitution values nest templates. Genuine event records stay well below this depth;
# the bound exists to stop a cyclic template reference from recursing until the Python stack dies.
DEFAULT_MAX_TEMPLATE_DEPTH = 64

# The descriptor entry count is a 32-bit field read straight from the input. Cap the number of
# substitution values that may be materialised for a single template instance.
DEFAULT_MAX_SUBSTITUTIONS = 4096

# Bound the number of key/value fields that a single record may produce, independent of the depth
# or substitution counts that produced them.
DEFAULT_MAX_FIELDS = 4096


@dataclass(frozen=True)
class ResourceLimit:
    """Configured resource boundaries for parsing one stream of untrusted records."""

    max_bytes: int = DEFAULT_MAX_BYTES_PER_RECORD
    max_template_depth: int = DEFAULT_MAX_TEMPLATE_DEPTH
    max_substitutions: int = DEFAULT_MAX_SUBSTITUTIONS
    max_fields: int = DEFAULT_MAX_FIELDS


class BoundedStream:
    """Wrap a binary stream and count every byte read against a byte budget.

    Reads that stay within the budget behave exactly like the wrapped stream, including a genuine
    :class:`EOFError` when the underlying data is exhausted. Only an attempt to consume bytes
    *beyond the configured budget* raises :class:`ResourceLimitExceeded`, which keeps the
    corruption / limit / clean-EOF distinction observable to callers.
    """

    def __init__(self, stream: BinaryIO, max_bytes: int):
        self._stream = stream
        self._max_bytes = max_bytes
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            # Never hand an unbounded read to untrusted data: clamp it to the remaining budget.
            size = self._max_bytes - self.bytes_read
            if size < 0:
                raise ResourceLimitExceeded(
                    f"BinXML byte budget of {self._max_bytes} exceeded"
                )

        if self.bytes_read + size > self._max_bytes:
            raise ResourceLimitExceeded(
                f"BinXML byte budget of {self._max_bytes} exceeded; "
                f"read {self.bytes_read} of {self._max_bytes} bytes before requesting {size} more"
            )

        data = self._stream.read(size)
        self.bytes_read += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._stream.seek(offset, whence)

    def tell(self) -> int:
        return self._stream.tell()

    def getvalue(self) -> bytes:
        # Used by the SIZET type reader to distinguish a 32/64 bit stream.
        return self._stream.getvalue()


class DepthGuard:
    """Track template expansion depth across nested BinXML substitution values."""

    def __init__(self, max_depth: int):
        self._max_depth = max_depth
        self.depth = 0

    def __enter__(self) -> DepthGuard:
        if self.depth >= self._max_depth:
            raise ResourceLimitExceeded(
                f"BinXML template expansion depth limit of {self._max_depth} exceeded"
            )
        self.depth += 1
        return self

    def __exit__(self, *exc: object) -> None:
        self.depth -= 1
