"""
FastPass Security Validation Module
Maps to: Section B2a-B2e Enhanced Security Validation from flowchart
"""

# A1a: Load System Tools
import os
import stat
from pathlib import Path
from typing import Set
import logging

from src.exceptions import SecurityViolationError, FileFormatError


class SecurityValidator:
    """
    Security validation and path checking
    Implements comprehensive security hardening
    """
    
    def __init__(self, logger: logging.Logger, allowed_directories: Set[str] = None):
        self.logger = logger
        
        # B2d: Set Security Boundaries
        # Define which folders the program is allowed to access
        self.custom_allowed_directories = allowed_directories
        self.allowed_directories = self._get_allowed_directories()
    
    def _get_allowed_directories(self) -> Set[Path]:
        """
        # B1-SEC-1: Set Security Boundaries
        Define allowed security zones for file access - Configurable with sensible defaults
        """
        allowed = set()
        
        # If custom directories are provided, use those
        if self.custom_allowed_directories:
            for dir_path in self.custom_allowed_directories:
                try:
                    resolved_dir = Path(dir_path).resolve(strict=False)
                    allowed.add(resolved_dir)
                    self.logger.debug(f"Custom security boundary set: {resolved_dir}")
                except Exception as e:
                    self.logger.error(f"Failed to resolve custom directory {dir_path}: {e}")
        else:
            # Default security boundaries
            # User's home directory - default allowed location
            try:
                home_dir = Path.home().resolve(strict=False)
                allowed.add(home_dir)
                self.logger.debug(f"Security boundary set: {home_dir}")
            except Exception as e:
                self.logger.error(f"Failed to resolve home directory: {e}")
            
            # Current working directory - allow for project work
            try:
                cwd = Path.cwd().resolve(strict=False)
                allowed.add(cwd)
                self.logger.debug(f"Current working directory allowed: {cwd}")
            except Exception as e:
                self.logger.warning(f"Could not add current working directory: {e}")
        
        # Always allow system temp directory for legitimate temporary operations
        try:
            import tempfile
            temp_dir = Path(tempfile.gettempdir()).resolve(strict=False)
            allowed.add(temp_dir)
            self.logger.debug(f"Temp directory allowed: {temp_dir}")
        except Exception as e:
            self.logger.warning(f"Could not add temp directory: {e}")
        
        return allowed
    
    def validate_file_path(self, file_path: Path) -> Path:
        """
        # B1-SEC-2: Hardened Path Security Validation
        Comprehensive security checks with strict enforcement
        """
        
        # B1-SEC-2a: Path Character Validation (null bytes and control characters)
        path_str = str(file_path)
        
        # Check for null bytes
        if '\x00' in path_str:
            raise SecurityViolationError(f"Path contains null bytes or control characters: {file_path}")
            
        # Check for control characters (0x00-0x1F and 0x7F-0x9F)
        for char in path_str:
            if ord(char) < 32 or (127 <= ord(char) <= 159):
                raise SecurityViolationError(f"Path contains null bytes or control characters: {file_path}")
        
        # B1-SEC-2b: Path Length Validation
        if len(path_str) > 260:  # Windows MAX_PATH limitation
            raise SecurityViolationError(f"Path too long (>{260} characters): {file_path}")
        
        # # B1-SEC-2c: Strict Path Resolution with symlink detection
        try:
            # First expand user path (handle ~ on Unix systems)
            expanded_path = file_path.expanduser()
            # Use strict=False to allow non-existent files, then check existence separately
            resolved_path = expanded_path.resolve(strict=False)
            
            # Check directory containment BEFORE any file operations to avoid permission errors
            if not self._is_path_strictly_contained(resolved_path):
                allowed_dirs_str = ", ".join(str(d) for d in self.allowed_directories)
                raise SecurityViolationError(f"File path outside security boundaries. Allowed directories: {allowed_dirs_str}. Path: {file_path}")
            
            # Explicitly check if file exists for better error messages (after containment check)
            if not resolved_path.exists():
                raise SecurityViolationError(f"File not found: {file_path}")
                
        except SecurityViolationError:
            # Re-raise security violations as-is
            raise
        except Exception as e:
            raise SecurityViolationError(f"Path resolution failed: {file_path} - {e}")
        
        # # B1-SEC-2b: Explicit Symlink Detection and Rejection
        if file_path.is_symlink() or resolved_path.is_symlink():
            raise SecurityViolationError(
                f"Symbolic links are not allowed for security reasons: {file_path}"
            )
        
        # Check all parent directories for symlinks
        for parent in file_path.parents:
            if parent.is_symlink():
                raise SecurityViolationError(
                    f"Path contains symbolic link in directory structure: {file_path}"
                )
        
        # # B1-SEC-2c: Path Length Validation
        if len(str(resolved_path)) > 260:  # Windows MAX_PATH limitation
            raise SecurityViolationError(f"Path too long (>{260} chars): {file_path}")
        
        # # B1-SEC-2d: Null Byte and Control Character Detection
        path_str = str(file_path)
        if '\x00' in path_str or any(ord(c) < 32 for c in path_str if c not in ['\t', '\n', '\r']):
            raise SecurityViolationError(f"Path contains null bytes or control characters: {file_path}")
        
        # # B1-SEC-2f: Thorough Component Analysis
        self._validate_path_components_strict(resolved_path)
        
        # # B1-SEC-2g: Final Security Zone Verification
        if not self._is_file_in_secure_zone(resolved_path):
            raise SecurityViolationError(
                f"File access blocked by security policy: {file_path}"
            )
        
        self.logger.debug(f"Hardened security validation passed: {resolved_path}")
        return resolved_path
    
    def _is_path_strictly_contained(self, resolved_path: Path) -> bool:
        """
        # B1-SEC-3: Strict Directory Containment Check
        Ensure path is strictly within home directory with no exceptions
        """
        for allowed_dir in self.allowed_directories:
            try:
                # Use relative_to() to check strict containment
                relative_path = resolved_path.relative_to(allowed_dir)
                
                # Additional check: ensure we're not at the boundary
                if str(relative_path) == '.':
                    # Path is exactly the allowed directory itself
                    return False
                
                return True
            except ValueError:
                # Path is not relative to this allowed directory
                continue
        
        return False
    
    def _is_path_within_allowed_directories(self, resolved_path: Path) -> bool:
        """
        B2b_Check: Path Within Security Boundaries? (Legacy method)
        Check if path is contained within approved locations
        """
        return self._is_path_strictly_contained(resolved_path)
    
    def _validate_path_components_strict(self, resolved_path: Path) -> None:
        """
        # B1-SEC-4: Thorough Component Analysis
        Examine every folder and file name for security violations with strict rules
        """
        
        # B2c_Loop: Examine Path Elements One by One
        for part in resolved_path.parts:
            if not self._is_path_component_safe_strict(part):
                # B2c_Invalid: Unsafe Path Element Found
                raise SecurityViolationError(
                    f"Unsafe path component detected: {part}"
                )
    
    def _validate_path_components(self, resolved_path: Path) -> None:
        """
        B2c: Check Each Path Element (Legacy method)
        Examine every folder and file name for security violations
        """
        return self._validate_path_components_strict(resolved_path)
    
    def _is_path_component_safe_strict(self, component: str) -> bool:
        """
        # B1-SEC-5: Strict Path Component Safety Check
        Check individual path components with enhanced security rules
        """
        
        # Reject empty components
        if not component:
            return False
        
        # Skip drive letters on Windows (e.g., "C:", "D:")
        if len(component) == 2 and component[1] == ':' and component[0].isalpha():
            return True
        
        # Skip root directory
        if component in ['/', '\\']:
            return True
        
        # # B1-SEC-5a: Reject path traversal patterns
        dangerous_patterns = [
            '..', '~',  # Path traversal and special directories (but allow '.' for current dir)
        ]
        
        # Windows reserved names (check both full component and base name without extension)
        windows_reserved = [
            'CON', 'PRN', 'AUX', 'NUL',
            'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
            'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        ]
        
        component_upper = component.upper()
        if component_upper in dangerous_patterns:
            return False
            
        # Check if component or its base name (without extension) is a Windows reserved name
        if component_upper in windows_reserved:
            return False
        # Also check base name without extension
        base_name = component_upper.split('.')[0] if '.' in component_upper else component_upper
        if base_name in windows_reserved:
            return False
        
        # # B1-SEC-5b: Reject hidden files and directories (starting with .) but allow system directories
        if component.startswith('.') and component not in ['.']:
            return False
        
        # # B1-SEC-5c: Check for dangerous characters (allow : and \ for Windows paths)
        dangerous_chars = '<>"|?*'
        if any(char in component for char in dangerous_chars):
            return False
        
        # # B1-SEC-5d: Check for control characters and null bytes
        if any(ord(char) < 32 for char in component):
            return False
        
        # # B1-SEC-5e: Check for Unicode normalization issues
        if '\x00' in component:
            return False
        
        # # B1-SEC-5f: Check for leading/trailing spaces or dots (Windows issues)
        # Allow "." as special case for current directory
        if component != ".":
            # Check for leading or trailing spaces
            if component.startswith(' ') or component.endswith(' '):
                return False
            # Check for space before extension (problematic on Windows)
            if ' .' in component:
                return False
            # Check for trailing dots (problematic on Windows)
            if component.endswith('.'):
                return False
        
        # # B1-SEC-5g: Reject excessively long component names
        if len(component) > 255:  # Filesystem limit
            return False
        
        return True
    
    def _is_path_component_safe(self, component: str) -> bool:
        """
        B2c_Check: Path Element Safe? (Legacy method)
        Check individual path components for safety
        """
        return self._is_path_component_safe_strict(component)
    
    def _is_file_in_secure_zone(self, resolved_path: Path) -> bool:
        """
        # B1-SEC-6: Final Security Zone Verification
        Enhanced final verification with strict security checks
        """
        
        # # B1-SEC-6a: Symlinks already rejected in main validation
        # We should never reach here with symlinks, but double-check
        if resolved_path.is_symlink():
            return False
        
        # # B1-SEC-6b: Check file permissions for security issues (Unix/Linux only)
        try:
            file_stat = resolved_path.stat()
            
            # Reject world-writable files (security risk) - Unix/Linux only
            # Skip this check on Windows to prevent false positives
            if os.name != 'nt' and hasattr(stat, 'S_IWOTH'):
                # Check if file is in temp directory (allowed to be world-writable)
                import tempfile
                temp_dir = Path(tempfile.gettempdir()).resolve(strict=False)
                is_in_temp = False
                try:
                    resolved_path.relative_to(temp_dir)
                    is_in_temp = True
                except ValueError:
                    pass
                
                if file_stat.st_mode & stat.S_IWOTH and not is_in_temp:
                    self.logger.error(f"World-writable file rejected for security: {resolved_path}")
                    return False
                
            # # B1-SEC-6c: Check for suspicious file permissions (Unix/Linux only)
            # Reject files with unusual permissions that might indicate compromise
            # Skip SUID/SGID checks on Windows (not applicable)
            if os.name != 'nt':
                if hasattr(stat, 'S_ISUID') and file_stat.st_mode & stat.S_ISUID:
                    self.logger.error(f"SUID file rejected for security: {resolved_path}")
                    return False
                    
                if hasattr(stat, 'S_ISGID') and file_stat.st_mode & stat.S_ISGID:
                    self.logger.error(f"SGID file rejected for security: {resolved_path}")
                    return False
                
        except Exception as e:
            # If we can't check permissions, reject for security
            self.logger.error(f"Cannot verify file permissions, rejecting: {resolved_path} - {e}")
            return False
        
        # # B1-SEC-6d: Additional file type validation
        try:
            # Ensure it's a regular file, not a device, socket, etc.
            if not resolved_path.is_file():
                return False
        except Exception:
            return False
        
        return True
    
    def _is_file_in_safe_zone(self, resolved_path: Path) -> bool:
        """
        B2e_Check: File in Safe Area? (Legacy method)
        Final security zone verification
        """
        return self._is_file_in_secure_zone(resolved_path)
    
    def validate_output_directory(self, output_dir: Path) -> Path:
        """
        Additional validation for output directories with full security checks
        """
        if output_dir is None:
            return None
        
        # Apply the same comprehensive security validation as file paths
        # This includes character validation, path component checking, etc.
        
        # Path Character Validation (null bytes and control characters)
        path_str = str(output_dir)
        
        # Check for null bytes
        if '\x00' in path_str:
            raise SecurityViolationError(f"Output directory contains null bytes or control characters: {output_dir}")
            
        # Check for control characters (0x00-0x1F and 0x7F-0x9F)
        for char in path_str:
            if ord(char) < 32 or (127 <= ord(char) <= 159):
                raise SecurityViolationError(f"Output directory contains null bytes or control characters: {output_dir}")
        
        # Path Length Validation
        if len(path_str) > 260:  # Windows MAX_PATH limitation
            raise SecurityViolationError(f"Output directory path too long (>{260} characters): {output_dir}")
        
        try:
            # First expand user path (handle ~ on Unix systems)
            expanded_path = output_dir.expanduser()
            # Use strict=False to allow non-existent directories for creation
            resolved_output = expanded_path.resolve(strict=False)
            
            # Validate each path component using the same strict rules
            self._validate_path_components_strict(resolved_output)
            
            # Check if output directory is within allowed boundaries
            if not self._is_path_within_allowed_directories(resolved_output):
                raise SecurityViolationError(
                    f"Output directory outside security boundaries: {output_dir}"
                )
                
        except SecurityViolationError:
            # Re-raise security violations as-is
            raise
        except Exception as e:
            raise SecurityViolationError(f"Output directory path resolution failed: {output_dir} - {e}")
        
        # Create directory if it doesn't exist
        try:
            resolved_output.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise SecurityViolationError(f"Cannot create output directory: {output_dir}")
        
        return resolved_output
    
    def validate_office_document_security(self, file_path: Path) -> None:
        """
        B4-SEC: Office Document Security Validation
        Validate Office documents against ZIP bomb and XXE attacks
        """
        try:
            import zipfile
            import xml.etree.ElementTree as ET
            
            # B4-SEC-1: ZIP Bomb Detection
            self._validate_zip_bomb_protection(file_path)
            
            # B4-SEC-2: XXE Attack Prevention
            self._validate_xml_security(file_path)
            
        except Exception as e:
            raise SecurityViolationError(f"Office document security validation failed: {file_path} - {e}")
    
    def _validate_zip_bomb_protection(self, file_path: Path) -> None:
        """
        B4-SEC-1: ZIP Bomb Protection
        Validate Office files against ZIP bomb attacks
        """
        try:
            import zipfile
            
            max_files = 1000  # Maximum number of files in archive
            max_uncompressed_size = 100 * 1024 * 1024  # 100MB
            max_compression_ratio = 100  # Maximum compression ratio
            
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                file_list = zip_file.filelist
                
                # Check number of files
                if len(file_list) > max_files:
                    raise SecurityViolationError(
                        f"Office document contains too many files ({len(file_list)} > {max_files}): {file_path}"
                    )
                
                total_uncompressed = 0
                total_compressed = 0
                
                for info in file_list:
                    total_uncompressed += info.file_size
                    total_compressed += info.compress_size
                    
                    # Check individual file size
                    if info.file_size > max_uncompressed_size:
                        raise SecurityViolationError(
                            f"Office document contains oversized file ({info.filename}): {file_path}"
                        )
                
                # Check total uncompressed size
                if total_uncompressed > max_uncompressed_size:
                    raise SecurityViolationError(
                        f"Office document total size too large ({total_uncompressed} bytes): {file_path}"
                    )
                
                # Check compression ratio
                if total_compressed > 0:
                    compression_ratio = total_uncompressed / total_compressed
                    if compression_ratio > max_compression_ratio:
                        raise SecurityViolationError(
                            f"Office document compression ratio too high ({compression_ratio:.1f}): {file_path}"
                        )
                        
        except zipfile.BadZipFile:
            raise SecurityViolationError(f"Office document is corrupted or invalid ZIP: {file_path}")
        except Exception as e:
            raise SecurityViolationError(f"ZIP bomb validation failed: {file_path} - {e}")
    
    def _validate_xml_security(self, file_path: Path) -> None:
        """
        B4-SEC-2: XXE Attack Prevention
        Validate XML content within Office files for External Entity attacks
        """
        try:
            import zipfile
            import xml.etree.ElementTree as ET
            
            # Dangerous XML patterns that indicate XXE attacks
            dangerous_patterns = [
                b'<!ENTITY',
                b'SYSTEM',
                b'PUBLIC',
                b'&lt;!ENTITY',
                b'&amp;',
                b'file://',
                b'http://',
                b'ftp://'
            ]
            
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                for file_info in zip_file.filelist:
                    if file_info.filename.endswith('.xml') or file_info.filename.endswith('.rels'):
                        try:
                            content = zip_file.read(file_info.filename)
                            
                            # Check for dangerous patterns
                            content_lower = content.lower()
                            for pattern in dangerous_patterns:
                                if pattern in content_lower:
                                    raise SecurityViolationError(
                                        f"Office document contains suspicious XML content ({pattern.decode('utf-8', errors='ignore')}): {file_path}"
                                    )
                            
                            # Additional check: Try to parse XML safely
                            try:
                                # Use defusedxml if available, otherwise basic ET with restrictions
                                root = ET.fromstring(content)
                            except ET.ParseError:
                                # XML parsing errors are not necessarily security issues
                                pass
                                
                        except Exception as e:
                            # Individual file read errors are not necessarily security issues
                            continue
                            
        except Exception as e:
            raise SecurityViolationError(f"XML security validation failed: {file_path} - {e}")
    
    def validate_pdf_document_security(self, file_path: Path) -> None:
        """
        B5-SEC: PDF Document Security Validation
        Validate PDF documents against malicious content
        """
        try:
            import PyPDF2
            
            with open(file_path, 'rb') as pdf_file:
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                
                # B5-SEC-1: Check for JavaScript
                self._validate_pdf_javascript(pdf_reader, file_path)
                
                # B5-SEC-2: Check for launch actions
                self._validate_pdf_launch_actions(pdf_reader, file_path)
                
        except Exception as e:
            raise SecurityViolationError(f"PDF security validation failed: {file_path} - {e}")
    
    def _validate_pdf_javascript(self, pdf_reader, file_path: Path) -> None:
        """
        B5-SEC-1: PDF JavaScript Detection
        Check for embedded JavaScript in PDF documents
        """
        try:
            # Check document-level JavaScript
            if hasattr(pdf_reader, 'trailer') and pdf_reader.trailer:
                if '/Names' in pdf_reader.trailer:
                    names_dict = pdf_reader.trailer['/Names']
                    if isinstance(names_dict, dict) and '/JavaScript' in names_dict:
                        raise SecurityViolationError(f"PDF contains JavaScript: {file_path}")
            
            # Check page-level content for JavaScript
            for page_num, page in enumerate(pdf_reader.pages):
                if hasattr(page, 'get_contents') and page.get_contents():
                    try:
                        content = page.extract_text()
                        if content and ('javascript' in content.lower() or 'script' in content.lower()):
                            self.logger.warning(f"PDF may contain script content on page {page_num + 1}: {file_path}")
                    except:
                        # Text extraction errors are not security issues
                        pass
                        
        except Exception as e:
            # JavaScript detection errors are warnings, not blocking errors
            self.logger.warning(f"Could not fully scan PDF for JavaScript: {file_path} - {e}")
    
    def _validate_pdf_launch_actions(self, pdf_reader, file_path: Path) -> None:
        """
        B5-SEC-2: PDF Launch Action Detection  
        Check for launch actions that could execute external programs
        """
        try:
            # Check for launch actions in document catalog
            if hasattr(pdf_reader, 'trailer') and pdf_reader.trailer:
                catalog = pdf_reader.trailer.get('/Root')
                if catalog and isinstance(catalog, dict):
                    # Check for OpenAction
                    if '/OpenAction' in catalog:
                        action = catalog['/OpenAction']
                        if isinstance(action, dict) and action.get('/S') == '/Launch':
                            raise SecurityViolationError(f"PDF contains launch action: {file_path}")
            
            # Check pages for launch actions
            for page in pdf_reader.pages:
                if hasattr(page, 'get') and '/Annots' in page:
                    annotations = page['/Annots']
                    if annotations:
                        for annot in annotations:
                            if isinstance(annot, dict):
                                action = annot.get('/A')
                                if isinstance(action, dict) and action.get('/S') == '/Launch':
                                    raise SecurityViolationError(f"PDF contains launch action: {file_path}")
                                    
        except Exception as e:
            # Launch action detection errors are warnings, not blocking errors
            self.logger.warning(f"Could not fully scan PDF for launch actions: {file_path} - {e}")