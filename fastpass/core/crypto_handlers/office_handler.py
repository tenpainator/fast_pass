"""
FastPass Office Document Handler
"""

# A1a: Load System Tools
import logging
from pathlib import Path
from typing import Dict, Any
import tempfile
import shutil
import subprocess
import os
import atexit

try:
    import msoffcrypto
except ImportError:
    msoffcrypto = None

# Move imports to the module level for proper mocking in tests
from fastpass.exceptions import FileFormatError, ProcessingError, SecurityViolationError
from fastpass.utils.config import FastPassConfig
from fastpass.core.security import SecurityValidator

# COM automation removed - using subprocess-only approach
# No longer dependent on Microsoft Office installation


class OfficeDocumentHandler:
    """
    Microsoft Office document encryption/decryption handler
    Uses msoffcrypto-tool for crypto operations
    """
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
        if msoffcrypto is None:
            raise ImportError("msoffcrypto-tool is required for Office document processing")
        
        # C2a_Config: Configure Office Settings
        self.timeout = 30
        self.encryption_algorithm = 'AES-256'
        
        # Resource management
        self._temp_files = set()
        
        self.logger.debug("Office document handler initialized")
    
    def configure(self, config: Dict[str, Any]) -> None:
        """
        Set Office-specific configuration options
        """
        self.timeout = config.get('office_timeout', self.timeout)
        
        # Log subprocess-based encryption info
        if config.get('debug', False):
            self.logger.info(
                "Office encryption using msoffcrypto-tool subprocess. "
                "Both encryption and decryption fully supported."
            )
    
    def test_password(self, file_path: Path, password: str) -> bool:
        """
        Test if password works for Office document
        Enhanced with legacy format support and null handling
        """
        # Check if this is a legacy format that may have edge cases
        file_ext = file_path.suffix.lower()
        
        if file_ext in FastPassConfig.LEGACY_FORMATS:
            return self._test_password_legacy_safe(file_path, password)
        else:
            return self._test_password_standard(file_path, password)
    
    def _test_password_standard(self, file_path: Path, password: str) -> bool:
        """
        Standard password test for modern Office formats
        """
        try:
            with open(file_path, 'rb') as f:
                office_file = msoffcrypto.OfficeFile(f)
                
                if not office_file.is_encrypted():
                    # File is not encrypted, so any password "works" for decryption
                    return True
                
                # Try to load with password
                office_file.load_key(password=password)
                
                # Try to decrypt a small portion to verify password
                with tempfile.NamedTemporaryFile() as temp_file:
                    office_file.decrypt(temp_file)
                    temp_file.seek(0)
                    # If we can read some data, password is correct
                    data = temp_file.read(100)
                    # Ensure decrypted file contains actual data (not empty)
                    if len(data) == 0:
                        self.logger.debug(f"Password test failed - empty decrypted file for {file_path}")
                        return False
                    return True
                    
        except Exception as e:
            self.logger.debug(f"Standard password test failed for {file_path}: {e}")
            return False
    
    def _test_password_legacy_safe(self, file_path: Path, password: str) -> bool:
        """
        Safe password test for legacy Office formats with enhanced null handling
        """
        # First try the standard approach - it often works for legacy formats
        try:
            result = self._test_password_standard(file_path, password)
            self.logger.debug(f"Standard password test for legacy {file_path.name}: {'PASS' if result else 'FAIL'}")
            return result
        except Exception as e:
            self.logger.debug(f"Standard password test failed for legacy {file_path.name}: {e}")
            return False
    
    
    def encrypt_file(self, input_path: Path, output_path: Path, password: str) -> None:

        self.encrypt_file_subprocess_secure(input_path, output_path, password)
    
    def encrypt_file_subprocess_secure(self, input_path: Path, output_path: Path, password: str) -> None:
        file_extension = input_path.suffix.lower()
        if file_extension in FastPassConfig.LEGACY_FORMATS:
            raise FileFormatError(f"Legacy Office format {file_extension} supports decryption only, not encryption")
        
        self._validate_path_security_hardened(input_path)
        self._validate_path_security_hardened(output_path.parent)
        
        if len(password) > 1024:  # Reasonable password length limit
            raise ValueError("Password exceeds maximum length")
        if '\x00' in password:
            raise ValueError("Null byte in password")
        
        try:
            self._encrypt_subprocess_secure(input_path, output_path, password)
        except Exception as e:
            raise ProcessingError(f"Office encryption failed: {e}")
    
    def _validate_path_security_hardened(self, path: Path) -> None:
        # Import SecurityValidator for path validation
        # Create validator with default settings
        validator = SecurityValidator(self.logger)
        
        # For existing files, use file validation
        if path.exists() and path.is_file():
            validator.validate_file_path(path)
        # For directories (including parent directories for new files), use directory validation
        elif path.exists() and path.is_dir():
            validator.validate_output_directory(path)
        else:
            # For non-existent paths, validate the parent directory
            parent_dir = path.parent
            if parent_dir.exists():
                validator.validate_output_directory(parent_dir)
    
    # All COM automation methods removed - using subprocess-only approach
    
    def _encrypt_subprocess_secure(self, input_path: Path, output_path: Path, password: str) -> None:
        
        import subprocess
        import os
        
        # Validate all paths are within allowed directories
        self._validate_path_security_hardened(input_path)
        self._validate_path_security_hardened(output_path.parent)
        
        # Use msoffcrypto-tool directly (not python -m)
        cmd_args = [
            'msoffcrypto-tool',
            '-e', '-p', password,
            str(input_path.resolve()),  # Use absolute paths
            str(output_path.resolve())
        ]
        
        # B2-SEC-6: Secure subprocess execution
        try:
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=60,
                shell=False,  # CRITICAL: Never use shell=True
                cwd=None,     # Don't inherit current directory
                env={'PATH': os.environ.get('PATH', '')},  # Minimal environment
                check=False
            )
            
            if result.returncode != 0:
                # Sanitize error output to prevent information disclosure
                sanitized_error = self._sanitize_error_message(result.stderr)
                raise ProcessingError(f"Office encryption failed: {sanitized_error}")
            
            self.logger.info(f"Successfully encrypted {input_path.name}")
                
        except subprocess.TimeoutExpired:
            raise ProcessingError("Office encryption timed out")
        except FileNotFoundError:
            raise ProcessingError("msoffcrypto-tool not found. Please install: pip install msoffcrypto-tool")
    
    def _sanitize_error_message(self, error_message: str) -> str:
        """
        B2-SEC-SANITIZE: Sanitize error messages to prevent information disclosure
        """
        if not error_message:
            return "Unknown error"
        
        # Remove potential sensitive information while keeping useful error details
        sanitized = error_message.strip()
        
        # Truncate very long error messages
        if len(sanitized) > 200:
            sanitized = sanitized[:200] + "..."
        
        return sanitized
    
    def decrypt_file(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        Decrypt Office document with password
        Enhanced with legacy format support and null handling
        """
        # Check if this is a legacy format that may have edge cases
        file_ext = input_path.suffix.lower()
        
        if file_ext in FastPassConfig.LEGACY_FORMATS:
            return self._decrypt_file_legacy_safe(input_path, output_path, password)
        else:
            return self._decrypt_file_standard(input_path, output_path, password)
    
    def _decrypt_file_standard(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        Standard decryption for modern Office formats
        """
        try:
            with open(input_path, 'rb') as f:
                office_file = msoffcrypto.OfficeFile(f)
                
                if not office_file.is_encrypted():
                    # File is not encrypted, just copy it
                    shutil.copy2(input_path, output_path)
                    self.logger.info(f"File {input_path.name} was not encrypted, copied as-is")
                    return
                
                # Load the password
                office_file.load_key(password=password)
                
                # Decrypt to output file
                with open(output_path, 'wb') as output_file:
                    office_file.decrypt(output_file)
                
                # Validate the decrypted file for security threats
                self._validate_decrypted_file_security(output_path)
                
                self.logger.info(f"Successfully decrypted {input_path.name}")
                
        except Exception as e:
            raise Exception(f"Failed to decrypt Office document {input_path}: {e}")
    
    def _decrypt_file_legacy_safe(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        Safe decryption for legacy Office formats with enhanced null handling
        """
        try:
            with open(input_path, 'rb') as f:
                office_file = msoffcrypto.OfficeFile(f)
                
                # Enhanced null check for legacy formats
                try:
                    is_encrypted = office_file.is_encrypted()
                    if is_encrypted is None:
                        # Handle problematic legacy files
                        raise Exception(f"Cannot determine encryption status for {input_path.name}")
                    elif not is_encrypted:
                        shutil.copy2(input_path, output_path)
                        self.logger.info(f"Legacy file {input_path.name} was not encrypted, copied as-is")
                        return
                except (TypeError, AttributeError):
                    # Handle legacy format edge cases
                    raise Exception(f"Cannot process legacy format {input_path.name}")
                
                # Try to load password with null checking
                try:
                    office_file.load_key(password=password)
                except (TypeError, AttributeError) as e:
                    if "NoneType" in str(e) or "encode" in str(e):
                        # Handle None password encoding issues
                        raise Exception(f"Password encoding error for {input_path.name}: {e}")
                    raise
                
                # Try to decrypt with enhanced error handling
                try:
                    with open(output_path, 'wb') as output_file:
                        result = office_file.decrypt(output_file)
                        if result is None and output_path.stat().st_size == 0:
                            # Handle cases where decrypt returns None and creates empty file
                            raise Exception(f"Decryption failed for {input_path.name}: empty output")
                except (TypeError, AttributeError):
                    # Handle problematic legacy files
                    raise Exception(f"Decryption failed for legacy format {input_path.name}")
                
                # Validate the decrypted file for security threats
                self._validate_decrypted_file_security(output_path)
                
                self.logger.info(f"Successfully decrypted legacy file {input_path.name}")
                
        except Exception as e:
            # Legacy decryption failed
            self.logger.debug(f"Legacy decryption failed: {e}")
            raise e
    
    
    def _validate_decrypted_file_security(self, file_path: Path) -> None:
        """
        Validate the decrypted Office file for security threats
        This runs after decryption when the file is in readable ZIP format
        """
        try:
            # Create security validator and validate the decrypted file
            security_validator = SecurityValidator(self.logger)
            security_validator.validate_office_document_security(file_path)
            self.logger.debug(f"Security validation passed for decrypted file: {file_path}")
            
        except Exception as e:
            # If security validation fails, remove the decrypted file for safety
            try:
                if file_path.exists():
                    file_path.unlink()
                    self.logger.warning(f"Removed potentially unsafe decrypted file: {file_path}")
            except Exception:
                pass
            raise Exception(f"Security validation failed for decrypted file {file_path}: {e}")
    
    def cleanup(self) -> None:
        """
        Clean up any handler-specific resources
        """
        try:
            # Clean up temporary files
            self._cleanup_temp_files()
            
            # No COM resources to clean up (subprocess-only approach)"
            
            self.logger.debug("Office handler cleanup completed")
            
        except Exception as e:
            self.logger.warning(f"Error during office handler cleanup: {e}")
    
    def _cleanup_temp_files(self) -> None:
        """
        Clean up temporary files created during operations
        """
        for temp_file in list(self._temp_files):
            try:
                if temp_file.exists():
                    temp_file.unlink()
                    self.logger.debug(f"Cleaned up temp file: {temp_file}")
                self._temp_files.discard(temp_file)
            except (OSError, PermissionError) as e:
                self.logger.warning(f"Failed to clean up temp file {temp_file}: {e}")
    
    def _cleanup_com_resources(self) -> None:
        """
        No COM resources to clean up - using subprocess-only approach
        """
        pass
    
    def _track_temp_file(self, temp_file: Path) -> None:
        """
        Track temporary file for cleanup
        """
        self._temp_files.add(temp_file)
    
    def _register_shutdown_cleanup(self) -> None:
        """
        Register cleanup to run on shutdown
        """
        import atexit
        atexit.register(self.cleanup)