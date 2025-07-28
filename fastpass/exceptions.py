"""
FastPass Exception Classes
Centralized exception definitions for all FastPass modules
"""


class FastPassError(Exception):
    """Base exception class for all FastPass errors"""
    pass


class SecurityViolationError(FastPassError):
    """Raised when security validation fails"""
    pass


class FileFormatError(FastPassError):
    """Raised when file format validation fails"""
    pass


class CryptoToolError(FastPassError):
    """Raised when crypto tools are unavailable"""
    pass


class PasswordError(FastPassError):
    """Raised when password operations fail"""
    pass


class FileProcessingError(FastPassError):
    """Raised when file processing fails (file not found, access issues, etc.)"""
    pass


class ProcessingError(FastPassError):
    """Raised when file processing fails"""
    pass