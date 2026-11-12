from __future__ import annotations


class Error(Exception):
    pass


class MalformedElfChnkException(Error):
    pass


class BxmlException(Error):
    pass


class ResourceLimitExceeded(Error):
    """Raised when untrusted input crosses a configured resource boundary.

    This is distinct from :class:`BxmlException` (structurally corrupt input) and from
    :class:`EOFError` (a clean end of the underlying stream). A caller can therefore tell
    configuration limits apart from malformed data and normal file termination.
    """


class UnknownSignatureException(Error):
    pass
