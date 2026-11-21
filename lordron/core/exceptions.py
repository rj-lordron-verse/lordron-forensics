"""
Core exceptions for the LORDRON Forensics toolkit.
"""


class LordronError(Exception):
    """Base exception for all LORDRON operations."""
    pass


class EvidenceIntegrityError(LordronError):
    """Raised when an evidence file fails cryptographic integrity verification."""
    pass


class CaseNotFoundError(LordronError):
    """Raised when the requested case ID does not exist."""
    pass


class CaseAlreadyExistsError(LordronError):
    """Raised when attempting to create a case with an existing ID."""
    pass


class FileAccessError(LordronError):
    """Raised when a file cannot be read due to permissions or missing path."""
    pass


class UnsupportedFormatError(LordronError):
    """Raised when an unsupported file format is encountered."""
    pass


class MalformedLogError(LordronError):
    """Raised when parsing fails on an unrecognizable log structure."""
    pass
