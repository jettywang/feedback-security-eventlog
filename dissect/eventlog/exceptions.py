from __future__ import annotations


class Error(Exception):
    pass


class MalformedElfChnkException(Error):
    pass


class MalformedEofRecordError(Error):
    """Raised when a floating EOF record cannot be used to reconstruct the log metadata."""


class AmbiguousEofRecordError(Error):
    """Raised when multiple conflicting EOF records make the record order non-deterministic."""


class BxmlException(Error):
    pass


class UnknownSignatureException(Error):
    pass
