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

from app import SecurityViolationError


class SecurityValidator:
    """
    Security validation and path checking
    Implements comprehensive security hardening
    """
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
        # B2d: Set Security Boundaries
        # Define which folders the program is allowed to access
        self.allowed_directories = self._get_allowed_directories()
    
    def _get_allowed_directories(self) -> Set[Path]:
        """
        B2d: Set Security Boundaries
        Define allowed security zones for file access
        """
        allowed = set()
        
        # User's home directory
        try:
            allowed.add(Path.home().resolve())
        except Exception:
            pass
        
        # Current working directory (with explicit allow flag)
        # Note: CWD access should require --allow-cwd flag in production
        try:
            allowed.add(Path.cwd().resolve())
        except Exception:
            pass
        
        return allowed
    
    def validate_file_path(self, file_path: Path) -> Path:
        """
        B2a-B2e: Complete path security validation
        Comprehensive security checks for file paths
        """
        
        # B2a: Resolve Absolute Paths for Security
        # Use Path.resolve() to get canonical paths
        try:
            resolved_path = file_path.resolve()
        except Exception as e:
            raise SecurityViolationError(f"Cannot resolve path: {file_path}")
        
        # B2b: Validate Against Allowed Directories
        # Check if resolved path is within approved locations
        if not self._is_path_within_allowed_directories(resolved_path):
            # B2b_Danger: Security Violation Detected
            raise SecurityViolationError(
                f"File path outside approved security boundaries: {file_path}"
            )
        
        # B2c: Check Each Path Element
        # Examine every folder and file name in the path
        self._validate_path_components(resolved_path)
        
        # B2e: Verify File Within Safe Zone
        # Final verification that file is in safe area
        if not self._is_file_in_safe_zone(resolved_path):
            # B2e_Security: File Access Blocked
            raise SecurityViolationError(
                f"File access blocked by security policy: {file_path}"
            )
        
        self.logger.debug(f"Security validation passed: {resolved_path}")
        return resolved_path
    
    def _is_path_within_allowed_directories(self, resolved_path: Path) -> bool:
        """
        B2b_Check: Path Within Security Boundaries?
        Check if path is contained within approved locations
        """
        for allowed_dir in self.allowed_directories:
            try:
                # Use relative_to() to check containment
                resolved_path.relative_to(allowed_dir)
                return True
            except ValueError:
                # Path is not relative to this allowed directory
                continue
        
        return False
    
    def _validate_path_components(self, resolved_path: Path) -> None:
        """
        B2c: Check Each Path Element
        Examine every folder and file name for security violations
        """
        
        # B2c_Loop: Examine Path Elements One by One
        for part in resolved_path.parts:
            if not self._is_path_component_safe(part):
                # B2c_Invalid: Unsafe Path Element Found
                raise SecurityViolationError(
                    f"Unsafe path component detected: {part}"
                )
    
    def _is_path_component_safe(self, component: str) -> bool:
        """
        B2c_Check: Path Element Safe?
        Check individual path components for safety
        """
        
        # Skip drive letters on Windows (e.g., "C:", "D:")
        if len(component) == 2 and component[1] == ':' and component[0].isalpha():
            return True
        
        # Skip root directory
        if component in ['/', '\\']:
            return True
        
        # Check for dangerous patterns
        dangerous_patterns = [
            '..', '..',  # Path traversal
            'CON', 'PRN', 'AUX', 'NUL',  # Windows reserved names
            'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
            'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        ]
        
        component_upper = component.upper()
        if component_upper in dangerous_patterns:
            return False
        
        # Check for dangerous characters (but allow colon for drive letters already handled above)
        dangerous_chars = '<>"|?*'
        if any(char in component for char in dangerous_chars):
            return False
        
        # Check for control characters
        if any(ord(char) < 32 for char in component):
            return False
        
        # Check for leading/trailing spaces or dots (Windows issues)
        if component != component.strip(' .'):
            return False
        
        return True
    
    def _is_file_in_safe_zone(self, resolved_path: Path) -> bool:
        """
        B2e_Check: File in Safe Area?
        Final security zone verification
        """
        
        # Additional checks for symbolic links
        try:
            if resolved_path.is_symlink():
                # Check if symlink target is also in safe zone
                target = resolved_path.readlink()
                if target.is_absolute():
                    return self._is_path_within_allowed_directories(target)
                else:
                    # Relative symlink - resolve relative to symlink location
                    target_resolved = (resolved_path.parent / target).resolve()
                    return self._is_path_within_allowed_directories(target_resolved)
        except Exception:
            # If we can't validate symlink, reject it
            return False
        
        # Check file permissions for additional security
        try:
            file_stat = resolved_path.stat()
            
            # On Unix-like systems, check for world-writable files
            if hasattr(stat, 'S_IWOTH') and file_stat.st_mode & stat.S_IWOTH:
                self.logger.warning(f"World-writable file detected: {resolved_path}")
                # Continue but log warning
        except Exception:
            # If we can't check permissions, continue
            pass
        
        return True
    
    def validate_output_directory(self, output_dir: Path) -> Path:
        """
        Additional validation for output directories
        """
        if output_dir is None:
            return None
        
        try:
            resolved_output = output_dir.resolve()
        except Exception as e:
            raise SecurityViolationError(f"Cannot resolve output directory: {output_dir}")
        
        # Check if output directory is within allowed boundaries
        if not self._is_path_within_allowed_directories(resolved_output):
            raise SecurityViolationError(
                f"Output directory outside security boundaries: {output_dir}"
            )
        
        # Create directory if it doesn't exist
        try:
            resolved_output.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise SecurityViolationError(f"Cannot create output directory: {output_dir}")
        
        return resolved_output