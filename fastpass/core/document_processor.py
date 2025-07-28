"""
FastPass Library Interface - DocumentProcessor
Main library interface for external applications
"""

import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass

from fastpass.utils.config import FastPassConfig
from fastpass.utils.logger import setup_logger
from fastpass.core.password.password_manager import PasswordManager
from fastpass.core.security import SecurityValidator
from fastpass.core.file_handler import FileValidator, FileProcessor, ResultsReporter
from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
from fastpass.core.crypto_handlers.pdf_handler import PDFHandler
from fastpass.exceptions import (
    SecurityViolationError, FileFormatError, CryptoToolError, 
    PasswordError, FileProcessingError, ProcessingError
)


@dataclass
class ProcessingResult:
    """Result of a file processing operation"""
    success: bool
    input_file: Path
    output_file: Optional[Path] = None
    operation: str = ""
    message: str = ""
    error: Optional[str] = None
    passwords_tried: int = 0
    processing_time: float = 0.0


class DocumentProcessor:
    """
    Main library interface for FastPass file encryption/decryption operations.
    
    Usage:
        processor = DocumentProcessor()
        result = processor.encrypt_file("document.docx", "password123")
        result = processor.decrypt_file("encrypted.pdf", ["pwd1", "pwd2"])
        is_protected = processor.is_password_protected("document.docx")
    """
    
    def __init__(self, 
                 password_manager: Optional[PasswordManager] = None,
                 logger: Optional[logging.Logger] = None,
                 config: Optional[Dict[str, Any]] = None):
        """
        Initialize DocumentProcessor
        
        Args:
            password_manager: Optional password manager instance
            logger: Optional logger instance  
            config: Optional configuration dictionary
        """
        # Setup logging
        self.logger = logger or setup_logger(debug=False, library_mode=True)
        
        # Load configuration
        self.config = config or FastPassConfig.load_default_configuration()
        
        # Initialize password manager
        self.password_manager = password_manager or PasswordManager()
        
        # Initialize validators
        self.security_validator = SecurityValidator(self.logger)
        self.file_validator = FileValidator(self.logger, self.config)
        
        # Initialize crypto handlers
        self._crypto_handlers = {}
        self._initialize_crypto_handlers()
        
        # Temp files tracking
        self.temp_files_created = []
        
        self.logger.debug("DocumentProcessor initialized for library use")
    
    def _initialize_crypto_handlers(self) -> None:
        """Initialize available crypto handlers"""
        try:
            self._crypto_handlers['msoffcrypto'] = OfficeDocumentHandler(self.logger)
            self._crypto_handlers['msoffcrypto'].configure(self.config)
        except ImportError:
            self.logger.warning("Office document handler not available")
        
        try:
            self._crypto_handlers['PyPDF2'] = PDFHandler(self.logger)
            self._crypto_handlers['PyPDF2'].configure(self.config)
        except ImportError:
            self.logger.warning("PDF handler not available")
        
        if not self._crypto_handlers:
            raise CryptoToolError("No crypto handlers available")
    
    def encrypt_file(self, 
                    input_file: Union[str, Path], 
                    password: str,
                    output_dir: Optional[Union[str, Path]] = None) -> ProcessingResult:
        """
        Encrypt a file with the specified password
        
        Args:
            input_file: Path to file to encrypt
            password: Password to use for encryption
            output_dir: Optional output directory (default: in-place)
            
        Returns:
            ProcessingResult with operation details
            
        Raises:
            SecurityViolationError: File path violates security policies
            FileFormatError: Unsupported file format
            ProcessingError: Encryption failed
        """
        return self._process_file(input_file, 'encrypt', [password], output_dir)
    
    def decrypt_file(self, 
                    input_file: Union[str, Path], 
                    passwords: List[str],
                    output_dir: Optional[Union[str, Path]] = None) -> ProcessingResult:
        """
        Decrypt a file using the provided passwords
        
        Args:
            input_file: Path to file to decrypt
            passwords: List of passwords to try
            output_dir: Optional output directory (default: in-place)
            
        Returns:
            ProcessingResult with operation details
            
        Raises:
            SecurityViolationError: File path violates security policies
            FileFormatError: Unsupported file format
            PasswordError: No valid password found
            ProcessingError: Decryption failed
        """
        return self._process_file(input_file, 'decrypt', passwords, output_dir)
    
    def is_password_protected(self, input_file: Union[str, Path]) -> bool:
        """
        Check if a file is password protected
        
        Args:
            input_file: Path to file to check
            
        Returns:
            True if file is password protected, False otherwise
            
        Raises:
            SecurityViolationError: File path violates security policies
            FileFormatError: Unsupported file format
        """
        try:
            input_path = Path(input_file)
            
            # Security validation
            self.security_validator.validate_file_path(input_path)
            
            # File validation - this determines if file is encrypted
            file_manifest = self.file_validator.validate_file(input_path, allow_unsupported=True)
            
            return file_manifest.is_encrypted
        except Exception:
            return False
    
    def get_file_info(self, input_file: Union[str, Path]) -> Dict[str, Any]:
        """
        Get detailed information about a file
        
        Args:
            input_file: Path to file to analyze
            
        Returns:
            Dictionary with file information
            
        Raises:
            SecurityViolationError: File path violates security policies
            FileFormatError: Unsupported file format
        """
        input_path = Path(input_file)
        
        # Security validation
        self.security_validator.validate_file_path(input_path)
        
        # File validation
        file_manifest = self.file_validator.validate_file(input_path, allow_unsupported=True)
        
        return {
            'path': str(file_manifest.path),
            'size': file_manifest.size,
            'format': file_manifest.format,
            'crypto_tool': file_manifest.crypto_tool,
            'supported': True,  # If we got here, format is supported
            'is_password_protected': self.is_password_protected(input_file)
        }
    
    def _process_file(self, 
                     input_file: Union[str, Path], 
                     operation: str,
                     passwords: List[str],
                     output_dir: Optional[Union[str, Path]]) -> ProcessingResult:
        """Internal file processing method"""
        from datetime import datetime
        
        start_time = datetime.now()
        input_path = Path(input_file)
        
        try:
            # Security validation
            self.security_validator.validate_file_path(input_path)
            
            # Output directory validation
            if output_dir:
                output_dir = self.security_validator.validate_output_directory(Path(output_dir))
            
            # File validation
            file_manifest = self.file_validator.validate_file(input_path, allow_unsupported=True)
            
            # Setup password manager with provided passwords
            temp_password_manager = PasswordManager(cli_passwords=passwords)
            
            # Create file processor
            processor = FileProcessor(
                logger=self.logger,
                config=self.config,
                password_manager=temp_password_manager,
                crypto_handlers=self._crypto_handlers,
                temp_files_created=self.temp_files_created
            )
            
            # Process the file
            processing_results = processor.process_files([file_manifest], operation, output_dir)
            
            # Extract result for single file from successful_files/failed_files arrays
            successful_files = processing_results.get('successful_files', [])
            failed_files = processing_results.get('failed_files', [])
            processing_time = (datetime.now() - start_time).total_seconds()
            
            if successful_files:
                # File processed successfully
                file_result = successful_files[0]  # Single file processing
                
                return ProcessingResult(
                    success=True,
                    input_file=input_path,
                    output_file=file_result.final_path if file_result.final_path != input_path else None,
                    operation=operation,
                    message=f"Successfully {operation}ed file",
                    error=None,
                    passwords_tried=len(passwords) if passwords else 0,
                    processing_time=processing_time
                )
            elif failed_files:
                # File processing failed
                error = failed_files[0]  # Single file processing
                
                return ProcessingResult(
                    success=False,
                    input_file=input_path,
                    output_file=None,
                    operation=operation,
                    message='',
                    error=error.message,
                    passwords_tried=len(passwords) if passwords else 0,
                    processing_time=processing_time
                )
            else:
                # No results found (shouldn't happen)
                raise ProcessingError(f"No result found for file: {input_path}")
                
        except Exception as e:
            processing_time = (datetime.now() - start_time).total_seconds()
            return ProcessingResult(
                success=False,
                input_file=input_path,
                operation=operation,
                error=str(e),
                processing_time=processing_time
            )
    
    def cleanup(self) -> None:
        """Clean up temporary files and resources"""
        for temp_file in self.temp_files_created:
            try:
                if temp_file.exists():
                    temp_file.unlink()
                    self.logger.debug(f"Cleaned up temp file: {temp_file}")
            except Exception as e:
                self.logger.warning(f"Failed to remove temp file {temp_file}: {e}")
        
        self.temp_files_created.clear()
        
        # Clear passwords from memory
        if self.password_manager:
            self.password_manager.clear_passwords()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup"""
        self.cleanup()


# Convenience functions for simple operations
def encrypt_file(input_file: Union[str, Path], 
                password: str,
                output_dir: Optional[Union[str, Path]] = None) -> ProcessingResult:
    """
    Convenience function to encrypt a single file
    
    Args:
        input_file: Path to file to encrypt
        password: Password to use for encryption
        output_dir: Optional output directory
        
    Returns:
        ProcessingResult with operation details
    """
    with DocumentProcessor() as processor:
        return processor.encrypt_file(input_file, password, output_dir)


def decrypt_file(input_file: Union[str, Path], 
                passwords: List[str],
                output_dir: Optional[Union[str, Path]] = None) -> ProcessingResult:
    """
    Convenience function to decrypt a single file
    
    Args:
        input_file: Path to file to decrypt
        passwords: List of passwords to try
        output_dir: Optional output directory
        
    Returns:
        ProcessingResult with operation details
    """
    with DocumentProcessor() as processor:
        return processor.decrypt_file(input_file, passwords, output_dir)


def is_password_protected(input_file: Union[str, Path]) -> bool:
    """
    Convenience function to check if file is password protected
    
    Args:
        input_file: Path to file to check
        
    Returns:
        True if password protected, False otherwise
    """
    with DocumentProcessor() as processor:
        return processor.is_password_protected(input_file)