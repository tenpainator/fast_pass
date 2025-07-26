"""
FastPass Exception Classes
Centralized exception definitions for all FastPass modules
"""


class SecurityViolationError(Exception):
    """Raised when security validation fails"""
    pass


class FileFormatError(Exception):
    """Raised when file format validation fails"""
    pass


class CryptoToolError(Exception):
    """Raised when crypto tools are unavailable"""
    pass


class PasswordError(Exception):
    """Raised when password operations fail"""
    pass


class FileProcessingError(Exception):
    """Raised when file processing fails (file not found, access issues, etc.)"""
    pass


class ProcessingError(Exception):
    """Raised when file processing fails"""
    pass