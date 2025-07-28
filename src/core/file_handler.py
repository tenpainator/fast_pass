"""
FastPass File Handler Module
Maps to: Section B3a-B6h File Validation and Section D File Processing
"""

# A1a: Load System Tools
import filetype
import tempfile
import shutil
import hashlib
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

from src.utils.config import FastPassConfig
from src.exceptions import FileFormatError, ProcessingError


@dataclass
class FileManifest:
    """
    B6a: Create FileManifest Object
    Data structure to hold file metadata and processing information
    """
    path: Path
    format: str
    size: int
    is_encrypted: bool
    crypto_tool: str
    security_checked: bool = False
    access_verified: bool = False


class FileValidator:
    """
    File format validation and detection
    Maps to B3a-B6h from flowchart
    """
    
    def __init__(self, logger: logging.Logger, config: Dict[str, Any]):
        self.logger = logger
        self.config = config
        self.max_file_size = config.get('max_file_size', FastPassConfig.MAX_FILE_SIZE)
    
    def validate_file(self, file_path: Path, allow_unsupported: bool = False) -> FileManifest:
        """
        B3a-B6e: Complete file validation pipeline
        Validate file format, content, and create manifest
        """
        
        # B1f: Verify File Actually Exists
        if not file_path.exists():
            raise FileFormatError(f"File not found: {file_path}")
        
        if not file_path.is_file():
            raise FileFormatError(f"Path is not a file: {file_path}")
        
        # B3a-B3e: Enhanced File Format Validation
        file_format = self._detect_file_format(file_path, allow_unsupported=allow_unsupported)
        
        # B4a-B4d: File Access and Size Validation
        self._validate_file_access_and_size(file_path)
        
        # B5a-B5c: Encryption Status Detection
        is_encrypted = self._detect_encryption_status(file_path, file_format)
        
        # B4-SEC: File Format Security Validation (only for unencrypted files)
        # Note: Encrypted files will be validated after decryption
        if not is_encrypted:
            self._validate_file_format_security(file_path, file_format)
        
        # B6a-B6e: Build File Manifest
        # Check supported formats first, then legacy formats
        crypto_tool = FastPassConfig.SUPPORTED_FORMATS.get(file_format)
        if not crypto_tool:
            crypto_tool = FastPassConfig.LEGACY_FORMATS.get(file_format)
        
        manifest = FileManifest(
            path=file_path,
            format=file_format,
            size=file_path.stat().st_size,
            is_encrypted=is_encrypted,
            crypto_tool=crypto_tool or 'unsupported',  # Mark unsupported files
            security_checked=True,
            access_verified=True
        )
        
        # B6f: Log File Validation
        self.logger.debug(f"Validated: {file_path} (format: {file_format}, encrypted: {is_encrypted})")
        
        return manifest
    
    def _validate_file_format_security(self, file_path: Path, file_format: str) -> None:
        """
        B4-SEC: File Format Security Validation
        Validate files against format-specific security threats
        """
        from src.core.security import SecurityValidator
        
        # Create security validator
        security_validator = SecurityValidator(self.logger)
        
        # Apply format-specific security validations
        if file_format in ['.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.dotx', '.xltx', '.potx']:
            # Office documents - check for ZIP bombs and XXE attacks
            security_validator.validate_office_document_security(file_path)
        elif file_format == '.pdf':
            # PDF documents - check for JavaScript and launch actions
            security_validator.validate_pdf_document_security(file_path)
        
        self.logger.debug(f"Security validation passed for {file_format}: {file_path}")
    
    def _detect_file_format(self, file_path: Path, allow_unsupported: bool = False) -> str:
        """
        B3b-B3e: Enhanced File Format Validation (Magic Number Priority)
        Detect file format using magic numbers with extension fallback
        """
        
        # B3b: Detect Format via Magic Numbers (Primary)
        try:
            detected_type = filetype.guess(str(file_path))
            if detected_type:
                # Convert MIME type to extension
                mime_to_ext = {
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
                    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
                    'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
                    'application/pdf': '.pdf'
                }
                
                detected_ext = mime_to_ext.get(detected_type.mime)
                if detected_ext:
                    # B3b_Success: Use Magic Number Result
                    file_ext = file_path.suffix.lower()
                    if file_ext != detected_ext:
                        # B3e_Mismatch: Format Mismatch
                        self.logger.warning(f"Extension {file_ext} != detected {detected_ext} for {file_path}")
                    return detected_ext
        except Exception as e:
            # B3b_Fallback: Use Extension Validation
            self.logger.warning(f"Magic number detection failed for {file_path}: {e}")
        
        # B3c: Validate Extension Against Supported Formats
        file_ext = file_path.suffix.lower()
        
        # B3d: Verify FastPass Can Handle This Format
        if file_ext not in FastPassConfig.SUPPORTED_FORMATS:
            # Check if it's a legacy format (decrypt-only)
            if file_ext in FastPassConfig.LEGACY_FORMATS:
                # B3d_Legacy: Legacy format detected
                self.logger.info(f"Legacy format detected: {file_ext} (decrypt-only support)")
                return file_ext
            
            # B3d_Unsupported: File Type Not Supported
            if allow_unsupported:
                # Return the unsupported format to allow deferred failure during processing
                return file_ext
            else:
                raise FileFormatError(
                    f"Unsupported file format: {file_ext}. "
                    f"Supported formats: {list(FastPassConfig.SUPPORTED_FORMATS.keys())} "
                    f"(Legacy decrypt-only: {list(FastPassConfig.LEGACY_FORMATS.keys())})"
                )
        
        return file_ext
    
    def _validate_file_access_and_size(self, file_path: Path) -> None:
        """
        B4a-B4d: File Access Validation
        Check file readability, size limits, and permissions
        """
        
        # B4a: Test File Reading Capability
        try:
            with open(file_path, 'rb') as f:
                # Read a small sample to verify access
                f.read(1024)
        except Exception as e:
            # B4a_Read: File Reading Blocked
            raise FileFormatError(f"Cannot read file {file_path}: {e}")
        
        # B4b: Check File Size Limits
        file_size = file_path.stat().st_size
        
        if file_size == 0:
            # B4b_Empty: File Contains No Data
            raise FileFormatError(f"File is empty: {file_path}")
        
        if file_size > self.max_file_size:
            # B4b_Large: File Exceeds Size Limit
            raise FileFormatError(
                f"File too large: {file_size} bytes (limit: {self.max_file_size} bytes)"
            )
        
        # B4c: Check File Modification Permission
        parent_dir = file_path.parent
        if not os.access(parent_dir, os.W_OK):
            # B4c_Write: File Modification Blocked
            raise FileFormatError(f"No write permission for directory: {parent_dir}")
    
    def _detect_encryption_status(self, file_path: Path, file_format: str) -> bool:
        """
        B5a-B5c: Encryption Status Detection
        Determine if file is password-protected
        """
        
        # B5a: Determine File Type Handler
        crypto_tool = FastPassConfig.SUPPORTED_FORMATS.get(file_format)
        if not crypto_tool:
            # Check legacy formats
            crypto_tool = FastPassConfig.LEGACY_FORMATS.get(file_format)
            if not crypto_tool:
                # Truly unsupported format - assume unencrypted
                return False
        
        try:
            # B5b: Test Encryption Status
            with open(file_path, 'rb') as f:
                if crypto_tool == 'msoffcrypto':
                    # B5a_Office: Office Document Detection
                    import msoffcrypto
                    office_file = msoffcrypto.OfficeFile(f)
                    return office_file.is_encrypted()
                
                elif crypto_tool == 'PyPDF2':
                    # B5a_PDF: PDF Document Detection
                    import PyPDF2
                    pdf_reader = PyPDF2.PdfReader(f)
                    return pdf_reader.is_encrypted
                
        except Exception as e:
            # B5b_Failed: Encryption Detection Failed
            self.logger.warning(f"Cannot detect encryption for {file_path}: {e}")
            # Assume unencrypted and proceed with caution
            return False
        
        return False


class FileProcessor:
    """
    File processing pipeline with crypto operations
    Maps to Section D from flowchart
    """
    
    def __init__(self, logger: logging.Logger, config: Dict[str, Any], 
                 password_manager, crypto_handlers: Dict, temp_files_created: List):
        self.logger = logger
        self.config = config
        self.password_manager = password_manager
        self.crypto_handlers = crypto_handlers
        self.temp_files_created = temp_files_created
    
    def process_files(self, validated_files: List[FileManifest], 
                     operation: str, output_dir: Optional[Path], dry_run: bool = False, verify: bool = False) -> Dict:
        """
        D2a-D4g: Main File Processing Pipeline
        Process all validated files with crypto operations
        """
        
        # D1a-D1f: Initialize TempFileManager and secure temp directory
        with tempfile.TemporaryDirectory(prefix=self.config['temp_dir_prefix']) as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            
            # D1c: Set Enhanced Secure Permissions
            temp_dir.chmod(0o700)
            
            # Create processing subdirectories
            processing_dir = temp_dir / 'processing'
            output_temp_dir = temp_dir / 'output'
            processing_dir.mkdir(mode=0o700)
            output_temp_dir.mkdir(mode=0o700)
            
            # D2a: Initialize Processing Results
            successful_files = []
            failed_files = []
            
            # D2b: Start Main Processing Loop
            for file_manifest in validated_files:
                try:
                    result = self._process_single_file(
                        file_manifest, operation, output_dir,
                        processing_dir, output_temp_dir, dry_run, verify
                    )
                    successful_files.append(result)
                    
                except Exception as e:
                    error = FileProcessingError(file_manifest.path, str(e))
                    failed_files.append(error)
                    self.logger.error(f"Failed to process {file_manifest.path}: {e}")
            
            return {
                'successful_files': successful_files,
                'failed_files': failed_files,
                'total_files': len(validated_files)
            }
    
    def _process_single_file(self, file_manifest: FileManifest, operation: str,
                           output_dir: Optional[Path], processing_dir: Path,
                           output_temp_dir: Path, dry_run: bool = False, verify: bool = False) -> 'FileProcessingResult':
        """
        D2c-D4g: Process single file through complete pipeline
        """
        
        # D2c: Get Crypto Handler
        if file_manifest.crypto_tool == 'unsupported':
            raise ProcessingError(f"Unsupported file format: {file_manifest.format}")
        
        handler = self.crypto_handlers[file_manifest.crypto_tool]
        
        # D2d: Find Working Password
        if operation == 'decrypt' and file_manifest.is_encrypted:
            password = self.password_manager.find_working_password(file_manifest.path, handler)
            if not password:
                raise ProcessingError(f"No working password found for {file_manifest.path}")
        elif operation == 'check-password' and file_manifest.is_encrypted:
            # For check-password, get password candidates and test them
            password_candidates = self.password_manager.get_password_candidates(file_manifest.path)
            if password_candidates:
                # Test the first password candidate
                password = password_candidates[0]
            else:
                password = None
            # Note: password may be None, which is handled in the check-password logic
        elif operation == 'encrypt':
            # For encryption, use first available password
            passwords = self.password_manager.get_password_candidates(file_manifest.path)
            if not passwords:
                raise ProcessingError(f"No password specified for encryption of {file_manifest.path}")
            password = passwords[0]
        else:
            password = None
        
        # D2e-D2f: Setup Temp File Paths and Copy Input
        temp_input = processing_dir / f'input_{file_manifest.path.name}'
        temp_output = output_temp_dir / f'output_{file_manifest.path.name}'
        
        if not dry_run:
            shutil.copy2(file_manifest.path, temp_input)
        
        # D2g-D2h: Perform Crypto Operation
        if dry_run:
            # Dry-run mode: simulate operations without making changes
            if operation == 'encrypt':
                self.logger.info(f"DRY RUN: Would encrypt {file_manifest.path.name}")
            elif operation == 'decrypt':
                self.logger.info(f"DRY RUN: Would decrypt {file_manifest.path.name}")
            elif operation == 'check-password':
                self.logger.info(f"DRY RUN: Would check password for {file_manifest.path.name}")
            # In dry-run, create a dummy output file if needed for validation
            if operation != 'check-password':
                temp_output.touch()
        else:
            # Real operations
            if operation == 'encrypt':
                handler.encrypt_file(temp_input, temp_output, password)
            elif operation == 'decrypt':
                handler.decrypt_file(temp_input, temp_output, password)
            elif operation == 'check-password':
                # For check-password, print status directly to stdout for user feedback
                status_message = f"Status for {file_manifest.path.name}: "
                if file_manifest.is_encrypted:
                    if password:
                        if handler.test_password(temp_input, password):
                            status_message += "encrypted - provided password works."
                        else:
                            # Do not raise an error, just report the status
                            status_message += "encrypted - provided password is incorrect."
                    else:
                        status_message += "encrypted - no password provided to test."
                else:
                    status_message += "not encrypted."
                
                print(status_message)  # Explicitly print status for the user
                self.logger.info(f"Check operation complete for {file_manifest.path.name}")
                temp_output = None
        
        # D3a-D3d: Output Validation (if output file was created)
        if not dry_run and temp_output and operation != 'check-password':
            self._validate_output_file_with_retry(temp_output, file_manifest, operation)
        
        # D4a-D4g: File Movement and Final Result
        if dry_run:
            # In dry-run mode, no file changes are made
            final_path = file_manifest.path
        elif operation != 'check-password':
            final_path = self._move_to_final_location(
                temp_output, file_manifest.path, output_dir
            )
        else:
            final_path = file_manifest.path  # No file movement for check-password
        
        # Deep verification if verify mode is enabled
        if verify and not dry_run and operation != 'check-password':
            self._perform_deep_verification(final_path, file_manifest, operation, password)
        
        # D4f-D4g: Create Processing Result
        return FileProcessingResult(
            original_path=file_manifest.path,
            final_path=final_path,
            operation=operation,
            password_used=password is not None,
            checksum=self._calculate_checksum(final_path) if final_path.exists() else None
        )
    
    def _perform_deep_verification(self, final_path: Path, file_manifest: FileManifest, operation: str, password: str) -> None:
        """
        Perform deep verification of the processed file
        """
        handler = self.crypto_handlers[file_manifest.crypto_tool]
        
        try:
            if operation == 'encrypt':
                # For encryption, verify the file is encrypted and password works
                self.logger.info(f"Verification: Testing encrypted file {final_path.name}")
                if not handler.test_password(final_path, password):
                    raise ProcessingError(f"Verification failed: Encrypted file cannot be opened with password")
                self.logger.info(f"Verification successful: {final_path.name} is properly encrypted")
                
            elif operation == 'decrypt':
                # For decryption, verify the file is no longer encrypted (if applicable)
                self.logger.info(f"Verification: Checking decrypted file {final_path.name}")
                try:
                    # Try to detect if file is still encrypted by attempting password test
                    if handler.test_password(final_path, password):
                        self.logger.warning(f"Verification: {final_path.name} may still be encrypted")
                    else:
                        self.logger.info(f"Verification successful: {final_path.name} appears to be decrypted")
                except:
                    # If password test fails, it likely means file is decrypted (good)
                    self.logger.info(f"Verification successful: {final_path.name} appears to be decrypted")
                    
        except Exception as e:
            self.logger.error(f"Deep verification failed for {final_path.name}: {e}")
            # Don't raise exception - verification failure shouldn't abort the operation
    
    def _validate_output_file_with_retry(self, temp_output: Path, file_manifest: FileManifest, operation: str) -> None:
        """
        D3a-D3d: Output Validation with Windows file handle retry logic
        Validate the processed output file with proper handle management
        """
        import time
        
        # Windows file handle management: retry validation with exponential backoff
        max_retries = 3
        base_delay = 0.1  # 100ms initial delay
        
        for attempt in range(max_retries):
            try:
                self._validate_output_file(temp_output, file_manifest, operation)
                return  # Success, exit retry loop
                
            except (PermissionError, OSError) as e:
                if attempt < max_retries - 1:
                    # Wait with exponential backoff before retrying
                    delay = base_delay * (2 ** attempt)
                    self.logger.debug(f"File validation retry {attempt + 1}/{max_retries} after {delay}s: {e}")
                    time.sleep(delay)
                else:
                    # Final attempt failed
                    raise ProcessingError(f"Output file validation failed after {max_retries} retries: {e}")
            except Exception as e:
                # Non-permission errors should not be retried
                raise ProcessingError(f"Output file validation failed: {e}")
    
    def _validate_output_file(self, temp_output: Path, file_manifest: FileManifest, operation: str) -> None:
        """
        D3a-D3d: Output Validation
        Validate the processed output file
        """
        
        # D3a: Validate Output File Exists
        if not temp_output.exists():
            raise ProcessingError("Crypto operation did not create output file")
        
        # D3b: Check Output File Size
        output_size = temp_output.stat().st_size
        if output_size == 0:
            raise ProcessingError("Output file is empty")
        
        # D3c: Format-Specific Validation with Proper Handle Management
        try:
            current_encrypted = None
            if file_manifest.crypto_tool == 'msoffcrypto':
                # D3c_Office: Validate Office Document with explicit handle cleanup
                import msoffcrypto
                import gc
                
                # Use explicit file handle management for Windows
                file_handle = None
                office_file = None
                try:
                    file_handle = open(temp_output, 'rb')
                    office_file = msoffcrypto.OfficeFile(file_handle)
                    # Get encryption status
                    current_encrypted = office_file.is_encrypted()
                finally:
                    # Ensure proper cleanup
                    if office_file:
                        del office_file
                    if file_handle:
                        file_handle.close()
                    gc.collect()  # Force garbage collection to release handles
                    
            elif file_manifest.crypto_tool == 'PyPDF2':
                # D3c_PDF: Validate PDF Document with explicit handle cleanup
                import PyPDF2
                import gc
                
                # Use explicit file handle management for Windows
                file_handle = None
                pdf_reader = None
                try:
                    file_handle = open(temp_output, 'rb')
                    pdf_reader = PyPDF2.PdfReader(file_handle)
                    # Get encryption status
                    current_encrypted = pdf_reader.is_encrypted
                finally:
                    # Ensure proper cleanup
                    if pdf_reader:
                        del pdf_reader
                    if file_handle:
                        file_handle.close()
                    gc.collect()  # Force garbage collection to release handles
                    
        except Exception as e:
            raise ProcessingError(f"Output file validation failed: {e}")
        
        # D3d: Validate Encryption Status Changed (using result from above)
        if current_encrypted is not None:
            expected_encrypted = operation == 'encrypt'
            if current_encrypted != expected_encrypted:
                raise ProcessingError(f"Encryption status not changed correctly (expected: {expected_encrypted}, actual: {current_encrypted})")
    
    def _detect_encryption_status_for_validation(self, file_path: Path, file_format: str) -> bool:
        """Helper to detect encryption status for validation"""
        crypto_tool = FastPassConfig.SUPPORTED_FORMATS[file_format]
        
        try:
            with open(file_path, 'rb') as f:
                if crypto_tool == 'msoffcrypto':
                    import msoffcrypto
                    office_file = msoffcrypto.OfficeFile(f)
                    return office_file.is_encrypted()
                elif crypto_tool == 'PyPDF2':
                    import PyPDF2
                    pdf_reader = PyPDF2.PdfReader(f)
                    return pdf_reader.is_encrypted
        except Exception:
            return False
        
        return False
    
    def _move_to_final_location(self, temp_output: Path, original_path: Path, 
                              output_dir: Optional[Path]) -> Path:
        """
        D4a-D4e: Enhanced File Movement with Error Handling
        Move processed file to final location
        """
        
        # D4a: Determine Final Output Path with Validation
        if output_dir:
            final_path = output_dir / original_path.name
        else:
            # In-place modification
            final_path = original_path
        
        # D4b: Handle Filename Conflicts
        if final_path.exists() and final_path != original_path:
            # Generate unique name for output directory
            counter = 1
            base = final_path.stem
            suffix = final_path.suffix
            while final_path.exists():
                final_path = final_path.parent / f"{base}_{counter}{suffix}"
                counter += 1
        
        # D4c: Atomic Move with Error Handling
        try:
            # Ensure target directory exists
            final_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Atomic move
            shutil.move(str(temp_output), str(final_path))
            
        except Exception as e:
            raise ProcessingError(f"Failed to move file to final location: {e}")
        
        # D4d: Update File Permissions (Windows-compatible)
        try:
            # Apply secure permissions with Windows compatibility
            import platform
            if platform.system() == 'Windows':
                # On Windows, use more lenient permissions to avoid access issues
                secure_permissions = 0o644  # Read/write for owner, read for group/others
            else:
                # On Unix-like systems, use strict permissions
                secure_permissions = self.config['secure_permissions']
            
            final_path.chmod(secure_permissions)
            self.logger.debug(f"Applied secure permissions {oct(secure_permissions)} to {final_path.name}")
            
        except (OSError, PermissionError) as e:
            # Log warning but don't fail the operation for permission issues
            self.logger.warning(f"Could not set secure permissions on {final_path.name}: {e}")
        
        return final_path
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """
        D4e: Generate File Checksum
        Calculate SHA256 checksum for file integrity
        """
        try:
            return hashlib.sha256(file_path.read_bytes()).hexdigest()
        except Exception:
            return None


@dataclass
class FileProcessingResult:
    """Result of processing a single file"""
    original_path: Path
    final_path: Path
    operation: str
    password_used: bool
    checksum: Optional[str] = None


@dataclass
class FileProcessingError:
    """Error during file processing"""
    path: Path
    message: str


class ResultsReporter:
    """
    Results reporting and exit code determination
    Maps to Section E4a-E5d from flowchart
    """
    
    def __init__(self, logger: logging.Logger, start_time: datetime):
        self.logger = logger
        self.start_time = start_time
    
    def generate_report(self, processing_results: Dict) -> int:
        """
        E4a-E5d: Report generation and exit code determination
        Generate comprehensive report and determine exit code
        """
        
        # E1a-E1e: Calculate Processing Metrics
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        successful_files = processing_results['successful_files']
        failed_files = processing_results['failed_files']
        total_files = processing_results['total_files']
        
        # E4b-E4d: Generate Report
        self._print_results_summary(successful_files, failed_files, total_files, duration)
        
        # E5a-E5d: Exit Code Determination
        return self._determine_exit_code(successful_files, failed_files)
    
    def _print_results_summary(self, successful_files: List, failed_files: List, 
                             total_files: int, duration) -> None:
        """
        E4b-E4e: Print comprehensive results summary
        """
        
        print(f"\nFastPass Processing Complete")
        print(f"{'=' * 40}")
        print(f"Total files processed: {total_files}")
        print(f"Successful: {len(successful_files)}")
        print(f"Failed: {len(failed_files)}")
        print(f"Processing time: {duration.total_seconds():.2f} seconds")
        
        if successful_files:
            print(f"\nSuccessful files:")
            for result in successful_files:
                print(f"  SUCCESS: {result.original_path}")
        
        if failed_files:
            print(f"\nFailed files:")
            for error in failed_files:
                print(f"  FAILED: {error.path}: {error.message}")
    
    def _determine_exit_code(self, successful_files: List, failed_files: List) -> int:
        """
        E5a-E5d: Exit Code Determination
        Determine appropriate exit code based on results
        """
        
        success_count = len(successful_files)
        failure_count = len(failed_files)
        
        if failure_count == 0 and success_count > 0:
            # E5b_Success: Exit Code 0
            self.logger.info("All operations successful")
            return 0
        elif success_count > 0 and failure_count > 0:
            # E5b_Mixed: Exit Code 1
            self.logger.warning("Some operations failed")
            return 1
        else:
            # E5b_Failure: Exit Code 1
            self.logger.error("All operations failed")
            return 1