from __future__ import annotations

from typing import Any

from dissect.eventlog.exceptions import ResourceLimitExceeded


class KeyValueCollection(dict):
    """A dictionary subclass that handles setting duplicate keys by appending an index number to the duplicate key.

    Example:
        >>>  d = KeyValueCollection()
        >>>  d["foo"] = "bar"
        >>>  d["foo"] = "baz"  # Duplicate key
        >>>  d
        {'foo': 'bar', 'foo_1': 'baz'}
    """

    def __init__(self, max_fields: int | None = None):
        super().__init__()
        self.idx = {}
        self.max_fields = max_fields

    def __setitem__(self, key: str, value: Any) -> None:
        if self.max_fields is not None and len(self) >= self.max_fields:
            raise ResourceLimitExceeded(
                f"Record field limit of {self.max_fields} exceeded while adding key {key!r}"
            )

        if key in self.idx:
            self.idx[key] += 1
            key = f"{key}_{self.idx[key]}"
        else:
            self.idx[key] = 0

        dict.__setitem__(self, key, value)
