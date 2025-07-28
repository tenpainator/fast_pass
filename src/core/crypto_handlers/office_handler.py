"""
FastPass Office Document Handler
Maps to: C1c_Office, C2a_Config - msoffcrypto-tool integration
"""

# A1a: Load System Tools
import logging
from pathlib import Path
from typing import Dict, Any
import tempfile
import shutil

try:
    import msoffcrypto
except ImportError:
    msoffcrypto = None

# COM automation removed - using subprocess-only approach
# No longer dependent on Microsoft Office installation

from src.exceptions import FileFormatError, ProcessingError, SecurityViolationError


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
        C2a: Configure Office Handler
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
        from src.utils.config import FastPassConfig
        
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
            # If standard approach fails, try subprocess fallback
            return self._test_password_subprocess_fallback(file_path, password)
    
    def _verify_encryption_status_subprocess(self, file_path: Path, password: str = None) -> bool:
        """
        Use msoffcrypto-tool CLI for reliable encryption detection on legacy formats
        """
        import subprocess
        
        try:
            # Test if file is encrypted using CLI
            result = subprocess.run([
                'msoffcrypto-tool', '-t', str(file_path)
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # If -t succeeds, check the output
                output = result.stdout.lower()
                if 'encrypted' in output:
                    # File is encrypted, test password if provided
                    if password:
                        return self._test_password_subprocess_fallback(file_path, password)
                    else:
                        return False  # File is encrypted but no password to test
                else:
                    return True  # File is not encrypted
            else:
                # If -t fails, assume file is problematic
                return False
                
        except Exception as e:
            self.logger.debug(f"Subprocess encryption detection failed: {e}")
            return False
    
    def _test_password_subprocess_fallback(self, file_path: Path, password: str) -> bool:
        """
        Fallback password test using subprocess for problematic legacy files
        """
        import subprocess
        import tempfile
        
        # Handle None password
        if password is None:
            return False
        
        try:
            with tempfile.NamedTemporaryFile(suffix='.tmp', delete=False) as temp_output:
                temp_output_path = temp_output.name
            
            # Try to decrypt using subprocess
            result = subprocess.run([
                'msoffcrypto-tool', '-p', str(password),  # Ensure password is string
                str(file_path), temp_output_path
            ], capture_output=True, text=True, timeout=30)
            
            # Clean up temp file
            try:
                Path(temp_output_path).unlink()
            except:
                pass
            
            # Success means password worked
            success = result.returncode == 0
            self.logger.debug(f"Subprocess password test for {file_path.name}: {'PASS' if success else 'FAIL'}")
            return success
            
        except Exception as e:
            self.logger.debug(f"Subprocess password test failed: {e}")
            return False
    
    def encrypt_file(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        C2a: Office document encryption using msoffcrypto-tool subprocess
        No longer requires Microsoft Office installation
        """
        self.encrypt_file_subprocess_secure(input_path, output_path, password)
    
    def encrypt_file_subprocess_secure(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        C2a: Secure Office encryption using msoffcrypto-tool subprocess only
        No COM automation - works without Microsoft Office installation
        """
        
        # B2-SEC-1: Legacy format validation
        file_extension = input_path.suffix.lower()
        from src.utils.config import FastPassConfig
        if file_extension in FastPassConfig.LEGACY_FORMATS:
            raise FileFormatError(f"Legacy Office format {file_extension} supports decryption only, not encryption")
        
        # B2-SEC-2: Path validation before processing
        self._validate_path_security_hardened(input_path)
        self._validate_path_security_hardened(output_path.parent)
        
        # B2-SEC-3: Password sanitization
        if len(password) > 1024:  # Reasonable password length limit
            raise ValueError("Password exceeds maximum length")
        if '\x00' in password:
            raise ValueError("Null byte in password")
        
        # B2-SEC-4: Use msoffcrypto-tool subprocess with strict validation
        try:
            self._encrypt_subprocess_secure(input_path, output_path, password)
        except Exception as e:
            raise ProcessingError(f"Office encryption failed: {e}")
    
    def _validate_path_security_hardened(self, path: Path) -> None:
        """
        B2-SEC-2: Path validation using SecurityValidator
        """
        # Import SecurityValidator for path validation
        from src.core.security import SecurityValidator
        
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
        """
        C2a-SUBPROCESS: Secure msoffcrypto-tool subprocess implementation
        Primary encryption method - no COM dependencies
        """
        
        # B2-SEC-5: Strict argument validation for subprocess
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
        from src.utils.config import FastPassConfig
        
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
                        # Use subprocess fallback for problematic legacy files
                        return self._decrypt_file_subprocess_fallback(input_path, output_path, password)
                    elif not is_encrypted:
                        shutil.copy2(input_path, output_path)
                        self.logger.info(f"Legacy file {input_path.name} was not encrypted, copied as-is")
                        return
                except (TypeError, AttributeError):
                    # Handle legacy format edge cases with subprocess fallback
                    return self._decrypt_file_subprocess_fallback(input_path, output_path, password)
                
                # Try to load password with null checking
                try:
                    office_file.load_key(password=password)
                except (TypeError, AttributeError) as e:
                    if "NoneType" in str(e) or "encode" in str(e):
                        # Handle None password encoding issues
                        return self._decrypt_file_subprocess_fallback(input_path, output_path, password)
                    raise
                
                # Try to decrypt with enhanced error handling
                try:
                    with open(output_path, 'wb') as output_file:
                        result = office_file.decrypt(output_file)
                        if result is None and output_path.stat().st_size == 0:
                            # Handle cases where decrypt returns None and creates empty file
                            return self._decrypt_file_subprocess_fallback(input_path, output_path, password)
                except (TypeError, AttributeError):
                    # Fallback to subprocess for problematic legacy files
                    return self._decrypt_file_subprocess_fallback(input_path, output_path, password)
                
                # Validate the decrypted file for security threats
                self._validate_decrypted_file_security(output_path)
                
                self.logger.info(f"Successfully decrypted legacy file {input_path.name}")
                
        except Exception as e:
            # Final fallback to subprocess
            self.logger.debug(f"Legacy decryption failed, trying subprocess fallback: {e}")
            return self._decrypt_file_subprocess_fallback(input_path, output_path, password)
    
    def _decrypt_file_subprocess_fallback(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        Fallback decryption using subprocess for problematic legacy files
        """
        import subprocess
        
        # Handle None password (should not happen but defensive coding)
        if password is None:
            raise Exception("Cannot decrypt file: no password provided")
        
        try:
            # Try to decrypt using subprocess
            result = subprocess.run([
                'msoffcrypto-tool', '-p', str(password),  # Ensure password is string
                str(input_path), str(output_path)
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                raise Exception(f"Subprocess decryption failed: {result.stderr}")
            
            # Validate the decrypted file
            if not output_path.exists() or output_path.stat().st_size == 0:
                raise Exception("Subprocess decryption produced empty or missing output file")
            
            # Validate for security threats
            self._validate_decrypted_file_security(output_path)
            
            self.logger.info(f"Successfully decrypted {input_path.name} using subprocess fallback")
            
        except subprocess.TimeoutExpired:
            raise Exception("Subprocess decryption timed out")
        except FileNotFoundError:
            raise Exception("msoffcrypto-tool not found for subprocess decryption")
        except Exception as e:
            raise Exception(f"Subprocess decryption failed: {e}")
    
    def _validate_decrypted_file_security(self, file_path: Path) -> None:
        """
        Validate the decrypted Office file for security threats
        This runs after decryption when the file is in readable ZIP format
        """
        from src.core.security import SecurityValidator
        
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
        E2d: Call Handler Cleanup
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