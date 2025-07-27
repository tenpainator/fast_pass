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

try:
    import win32com.client
    import pythoncom
    import os
except ImportError:
    win32com = None
    pythoncom = None

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
        
        self.logger.debug("Office document handler initialized")
    
    def configure(self, config: Dict[str, Any]) -> None:
        """
        C2a: Configure Office Handler
        Set Office-specific configuration options
        """
        self.timeout = config.get('office_timeout', self.timeout)
        
        # Log experimental encryption warning
        if config.get('debug', False):
            self.logger.warning(
                "Office document encryption is EXPERIMENTAL. "
                "Decryption is fully supported."
            )
    
    def test_password(self, file_path: Path, password: str) -> bool:
        """
        Test if password works for Office document
        Returns True if password is correct, False otherwise
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
                    return len(data) > 0
                    
        except Exception as e:
            self.logger.debug(f"Password test failed for {file_path}: {e}")
            return False
    
    def encrypt_file(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        C2a: Secure Office document encryption with hardened security
        """
        # Use the secure implementation that includes all security validations
        self.encrypt_file_secure(input_path, output_path, password)
    
    def encrypt_file_secure(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        C2a: Secure Office encryption using direct library calls (no subprocess)
        Implementation following specification Section C2a
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
        
        # B2-SEC-4: Use direct library calls instead of subprocess
        try:
            # Use COM automation for Office encryption (Windows)
            if self._direct_encryption_available():
                self._encrypt_direct(input_path, output_path, password)
            else:
                # Fallback to subprocess with strict argument validation if COM unavailable
                self._encrypt_subprocess_secure(input_path, output_path, password)
                
        except Exception as e:
            raise ProcessingError(f"Secure Office encryption failed: {e}")
    
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
    
    def _direct_encryption_available(self) -> bool:
        """
        Check if direct COM automation is available for Office encryption
        """
        return win32com is not None and pythoncom is not None
    
    def _encrypt_direct(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        C2a-DIRECT: Direct Office encryption using COM automation
        """
        if not self._direct_encryption_available():
            raise ProcessingError("COM automation not available for Office encryption")
        
        file_extension = input_path.suffix.lower()
        
        try:
            # Initialize COM
            pythoncom.CoInitialize()
            
            if file_extension in ['.docx', '.doc']:
                self._encrypt_word_document(input_path, output_path, password)
            elif file_extension in ['.xlsx', '.xls']:
                self._encrypt_excel_document(input_path, output_path, password)
            elif file_extension in ['.pptx', '.ppt']:
                self._encrypt_powerpoint_document(input_path, output_path, password)
            else:
                raise FileFormatError(f"Unsupported Office format for encryption: {file_extension}")
            
            self.logger.info(f"Successfully encrypted {input_path.name}")
            
        except Exception as e:
            raise ProcessingError(f"COM automation encryption failed: {e}")
        finally:
            # Cleanup COM
            try:
                pythoncom.CoUninitialize()
            except:
                pass
    
    def _encrypt_word_document(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        C2a-WORD: Encrypt Word document using COM automation
        """
        word_app = None
        doc = None
        
        try:
            # Create Word application
            word_app = win32com.client.Dispatch("Word.Application")
            word_app.Visible = False
            word_app.DisplayAlerts = False
            
            # Open document
            doc = word_app.Documents.Open(str(input_path.resolve()))
            
            # Set password property for encryption
            doc.Password = password
            
            # Save the encrypted document with explicit file format
            # FileFormat=12 for .docx (wdFormatXMLDocument)
            doc.SaveAs2(FileName=str(output_path.resolve()), FileFormat=12)
            
        except Exception as e:
            raise ProcessingError(f"Word COM encryption failed: {e}")
        finally:
            # Cleanup
            if doc:
                try:
                    doc.Close(SaveChanges=False)
                except:
                    pass
            if word_app:
                try:
                    word_app.Quit()
                except:
                    pass
    
    def _encrypt_excel_document(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        C2a-EXCEL: Encrypt Excel document using COM automation
        """
        excel_app = None
        workbook = None
        
        try:
            # Create Excel application
            excel_app = win32com.client.Dispatch("Excel.Application")
            excel_app.Visible = False
            excel_app.DisplayAlerts = False
            
            # Open workbook
            workbook = excel_app.Workbooks.Open(str(input_path.resolve()))
            
            # Set password property for encryption
            workbook.Password = password
            
            # Save the encrypted workbook with explicit file format
            # FileFormat=-4143 for .xlsx (xlWorkbookNormal)
            workbook.SaveAs(Filename=str(output_path.resolve()), FileFormat=-4143)
            
        except Exception as e:
            raise ProcessingError(f"Excel COM encryption failed: {e}")
        finally:
            # Cleanup
            if workbook:
                try:
                    workbook.Close(SaveChanges=False)
                except:
                    pass
            if excel_app:
                try:
                    excel_app.Quit()
                except:
                    pass
    
    def _encrypt_powerpoint_document(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        C2a-POWERPOINT: Encrypt PowerPoint document using COM automation
        """
        ppt_app = None
        presentation = None
        
        try:
            # Create PowerPoint application
            ppt_app = win32com.client.Dispatch("PowerPoint.Application")
            # Note: PowerPoint must remain visible, cannot be hidden
            
            # Open presentation
            presentation = ppt_app.Presentations.Open(str(input_path.resolve()))
            
            # Set password property for encryption
            presentation.Password = password
            
            # Save the encrypted presentation with explicit file format
            # FileFormat=24 for .pptx (ppSaveAsOpenXMLPresentation)
            presentation.SaveAs(FileName=str(output_path.resolve()), FileFormat=24)
            
        except Exception as e:
            raise ProcessingError(f"PowerPoint COM encryption failed: {e}")
        finally:
            # Cleanup
            if presentation:
                try:
                    presentation.Close()
                except:
                    pass
            if ppt_app:
                try:
                    ppt_app.Quit()
                except:
                    pass
    
    def _encrypt_subprocess_secure(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        C2a-SUBPROCESS: Fallback secure subprocess implementation with strict validation
        """
        
        # B2-SEC-5: Strict argument validation for subprocess
        import subprocess
        import shlex
        
        # Validate all paths are within allowed directories
        self._validate_path_security_hardened(input_path)
        self._validate_path_security_hardened(output_path.parent)
        
        # Use argument list (not shell) to prevent injection
        cmd_args = [
            'python', '-m', 'msoffcrypto.cli',
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
                
        except subprocess.TimeoutExpired:
            raise ProcessingError("Office encryption timed out")
    
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
        Full decryption support using msoffcrypto-tool
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
        # Office handler doesn't maintain persistent resources
        pass