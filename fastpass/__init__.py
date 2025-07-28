"""
FastPass - Universal File Encryption/Decryption Library

Main library interface for external applications.
Provides both object-oriented and functional interfaces.

Usage:
    # Object-oriented interface
    from fastpass import DocumentProcessor
    processor = DocumentProcessor()
    result = processor.encrypt_file("document.docx", "password")
    
    # Functional interface
    import fastpass
    result = fastpass.encrypt_file("document.docx", "password")
    is_protected = fastpass.is_password_protected("document.pdf")
"""

from fastpass.core.document_processor import (
    DocumentProcessor,
    ProcessingResult,
    encrypt_file,
    decrypt_file,
    is_password_protected
)

from fastpass.core.password.password_manager import PasswordManager

from fastpass.exceptions import (
    FastPassError,
    SecurityViolationError,
    FileFormatError,
    CryptoToolError,
    PasswordError,
    FileProcessingError,
    ProcessingError
)

from fastpass.utils.config import FastPassConfig

# Version information
__version__ = "1.0.0"
__author__ = "FastPass Development Team"
__license__ = "MIT"

# Public API
__all__ = [
    # Main classes
    "DocumentProcessor",
    "ProcessingResult",
    "PasswordManager",
    
    # Convenience functions
    "encrypt_file",
    "decrypt_file", 
    "is_password_protected",
    
    # Exceptions
    "FastPassError",
    "SecurityViolationError",
    "FileFormatError",
    "CryptoToolError",
    "PasswordError",
    "FileProcessingError",
    "ProcessingError",
    
    # Configuration
    "FastPassConfig",
    
    # Version info
    "__version__",
    "__author__",
    "__license__"
]