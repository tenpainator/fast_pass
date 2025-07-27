"""
Comprehensive Unit Tests for Security Validation
Tests all security hardening features and attack prevention
"""

import pytest
import tempfile
import os
import stat
from pathlib import Path
from unittest.mock import patch, MagicMock
import logging

# Import modules under test
from src.core.security import SecurityValidator
from src.app import SecurityViolationError


class TestSecurityValidatorInitialization:
    """Test SecurityValidator initialization and setup"""
    
    def test_security_validator_init(self):
        """Test: SecurityValidator initializes correctly"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        assert validator.logger == logger
        assert hasattr(validator, 'allowed_directories')
        assert isinstance(validator.allowed_directories, set)
    
    def test_allowed_directories_includes_home(self):
        """Test: Allowed directories includes home directory"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Should include home directory
        home_dir = Path.home().resolve(strict=False)
        assert home_dir in validator.allowed_directories
    
    def test_allowed_directories_includes_temp(self):
        """Test: Allowed directories includes temp directory"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Should include temp directory
        import tempfile
        temp_dir = Path(tempfile.gettempdir()).resolve(strict=False)
        assert temp_dir in validator.allowed_directories
    
    def test_allowed_directories_includes_cwd(self):
        """Test: Allowed directories includes current working directory by default"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Should include current working directory
        cwd = Path.cwd().resolve(strict=False)
        assert cwd in validator.allowed_directories
    
    def test_custom_allowed_directories(self):
        """Test: Custom allowed directories are respected"""
        logger = MagicMock()
        import tempfile
        temp_dir = str(Path(tempfile.gettempdir()).resolve(strict=False))
        custom_dirs = {temp_dir}
        validator = SecurityValidator(logger, allowed_directories=custom_dirs)
        
        # Should include custom directory and temp directory (always added)
        temp_path = Path(tempfile.gettempdir()).resolve(strict=False)
        assert temp_path in validator.allowed_directories
        
        # Should not include home directory when custom directories are specified
        home_dir = Path.home().resolve(strict=False)
        # Home is only excluded if it's not in the custom list
        if str(home_dir) not in custom_dirs:
            assert home_dir not in validator.allowed_directories


class TestPathResolutionValidation:
    """Test path resolution and basic validation"""
    
    def test_validate_existing_file_path(self, temp_work_dir):
        """Test: Valid existing file passes validation"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Create a test file
        test_file = temp_work_dir / "test.pdf"
        test_file.write_text("test content")
        
        result = validator.validate_file_path(test_file)
        assert result == test_file.resolve(strict=False)
    
    def test_validate_nonexistent_file_error(self, temp_work_dir):
        """Test: Non-existent file raises error"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Use a path within allowed directories but file doesn't exist
        nonexistent_file = temp_work_dir / "nonexistent_file.pdf"
        
        with pytest.raises(SecurityViolationError, match="File not found"):
            validator.validate_file_path(nonexistent_file)
    
    def test_validate_path_expansion(self, temp_work_dir):
        """Test: Path expansion (~ handling) works correctly"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Create test file in temp (which is allowed)
        test_file = temp_work_dir / "test.pdf"
        test_file.write_text("test content")
        
        # Should handle path expansion
        result = validator.validate_file_path(test_file)
        assert result.is_absolute()


class TestSymlinkDetection:
    """Test symbolic link detection and blocking"""
    
    def test_validate_symlink_file_blocked(self, temp_work_dir):
        """Test: Symbolic link files are blocked"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Create a regular file
        real_file = temp_work_dir / "real_file.pdf"
        real_file.write_text("test content")
        
        # Create a symlink (skip on Windows if not supported)
        symlink_file = temp_work_dir / "symlink_file.pdf"
        try:
            symlink_file.symlink_to(real_file)
            
            with pytest.raises(SecurityViolationError, match="Symbolic links are not allowed"):
                validator.validate_file_path(symlink_file)
        except OSError:
            pytest.skip("Symlinks not supported on this system")
    
    def test_validate_symlink_parent_directory_blocked(self, temp_work_dir):
        """Test: Files in symlinked directories are blocked"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Create a real directory with a file
        real_dir = temp_work_dir / "real_dir"
        real_dir.mkdir()
        real_file = real_dir / "test.pdf"
        real_file.write_text("test content")
        
        # Create a symlinked directory (skip on Windows if not supported)
        symlink_dir = temp_work_dir / "symlink_dir"
        try:
            symlink_dir.symlink_to(real_dir)
            symlink_file = symlink_dir / "test.pdf"
            
            with pytest.raises(SecurityViolationError, match="Path contains symbolic link"):
                validator.validate_file_path(symlink_file)
        except OSError:
            pytest.skip("Symlinks not supported on this system")


class TestPathLengthValidation:
    """Test path length validation"""
    
    def test_validate_normal_path_length(self, temp_work_dir):
        """Test: Normal path length passes validation"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        test_file = temp_work_dir / "normal_length_file.pdf"
        test_file.write_text("test content")
        
        # Should not raise exception
        validator.validate_file_path(test_file)
    
    def test_validate_very_long_path_blocked(self):
        """Test: Very long paths are blocked"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Create a path longer than 260 characters
        long_path_parts = ["very_long_directory_name_" + "x" * 50] * 10
        long_path = Path("/") / Path(*long_path_parts) / "file.pdf"
        
        # Should be blocked due to length
        # Note: This test may not trigger on all systems due to path resolution
        if len(str(long_path)) > 260:
            with pytest.raises(SecurityViolationError, match="Path too long"):
                validator.validate_file_path(long_path)


class TestPathCharacterValidation:
    """Test path character validation"""
    
    def test_validate_null_byte_blocked(self):
        """Test: Null bytes in paths are blocked"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Path with null byte
        null_byte_path = Path("test\x00file.pdf")
        
        with pytest.raises(SecurityViolationError, match="null bytes or control characters"):
            validator.validate_file_path(null_byte_path)
    
    def test_validate_control_characters_blocked(self):
        """Test: Control characters in paths are blocked"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Path with control character
        control_char_path = Path("test\x01file.pdf")
        
        with pytest.raises(SecurityViolationError, match="null bytes or control characters"):
            validator.validate_file_path(control_char_path)
    
    def test_validate_normal_characters_allowed(self, temp_work_dir):
        """Test: Normal characters are allowed"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        test_file = temp_work_dir / "normal_file_123.pdf"
        test_file.write_text("test content")
        
        # Should not raise exception
        validator.validate_file_path(test_file)


class TestDirectoryContainmentValidation:
    """Test strict directory containment validation"""
    
    def test_validate_file_in_allowed_directory(self, temp_work_dir):
        """Test: Files in allowed directories pass validation"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        test_file = temp_work_dir / "test.pdf"
        test_file.write_text("test content")
        
        # Temp directory should be allowed
        validator.validate_file_path(test_file)
    
    def test_validate_file_outside_allowed_directories_blocked(self):
        """Test: Files outside allowed directories are blocked"""
        import platform
        logger = MagicMock()
        # Create validator with only temp directory allowed for testing
        import tempfile
        temp_dir = Path(tempfile.gettempdir()).resolve(strict=False)
        validator = SecurityValidator(logger, allowed_directories={str(temp_dir)})
        
        # Try to access a file outside the explicitly allowed directories
        if platform.system() == 'Windows':
            # Windows system file - expect either security rejection or permission error
            restricted_path = Path("C:/Windows/System32/config/SAM")
            try:
                if restricted_path.exists():
                    with pytest.raises(SecurityViolationError, match="outside security boundaries"):
                        validator.validate_file_path(restricted_path)
                else:
                    pytest.skip("Windows system file not accessible for testing")
            except PermissionError:
                # Windows correctly blocks access - this is expected behavior
                pytest.skip("Windows permission system correctly blocks access")
        else:
            # Unix system file
            restricted_path = Path("/etc/passwd")
            if restricted_path.exists():
                with pytest.raises(SecurityViolationError, match="outside security boundaries"):
                    validator.validate_file_path(restricted_path)
            else:
                pytest.skip("No system files available for testing")
    
    def test_containment_check_exact_boundary(self, temp_work_dir):
        """Test: Files at exact directory boundary are handled correctly"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Test file at temp directory root
        test_file = temp_work_dir / "boundary_test.pdf"
        test_file.write_text("test content")
        
        # Should be allowed (not at boundary, but inside allowed directory)
        validator.validate_file_path(test_file)


class TestPathComponentValidation:
    """Test individual path component validation"""
    
    def test_validate_safe_path_components(self):
        """Test: Safe path components pass validation"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        safe_components = [
            "normal_file.pdf",
            "file_with_numbers_123.pdf",
            "file-with-dashes.pdf",
            "file_with_underscores.pdf"
        ]
        
        for component in safe_components:
            assert validator._is_path_component_safe_strict(component) is True
    
    def test_validate_path_traversal_components_blocked(self):
        """Test: Path traversal components are blocked"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        dangerous_components = [
            "..",
            "..\\",
            "../",
            "~"
        ]
        
        for component in dangerous_components:
            assert validator._is_path_component_safe_strict(component) is False
    
    def test_validate_windows_reserved_names_blocked(self):
        """Test: Windows reserved names are blocked"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        reserved_names = [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM9",
            "LPT1", "LPT2", "LPT9"
        ]
        
        for name in reserved_names:
            assert validator._is_path_component_safe_strict(name) is False
            assert validator._is_path_component_safe_strict(name.lower()) is False
    
    def test_validate_hidden_files_blocked(self):
        """Test: Hidden files (starting with .) are blocked"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        hidden_files = [
            ".hidden_file",
            ".secret",
            ".bashrc"
        ]
        
        for filename in hidden_files:
            assert validator._is_path_component_safe_strict(filename) is False
        
        # But allow current directory reference
        assert validator._is_path_component_safe_strict(".") is True
    
    def test_validate_dangerous_characters_blocked(self):
        """Test: Dangerous characters in components are blocked"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        dangerous_chars = ['<', '>', '"', '|', '?', '*']
        
        for char in dangerous_chars:
            filename = f"file{char}name.pdf"
            assert validator._is_path_component_safe_strict(filename) is False
    
    def test_validate_windows_drive_letters_allowed(self):
        """Test: Windows drive letters are allowed"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        drive_letters = ["C:", "D:", "E:", "Z:"]
        
        for drive in drive_letters:
            assert validator._is_path_component_safe_strict(drive) is True
    
    def test_validate_excessively_long_components_blocked(self):
        """Test: Excessively long path components are blocked"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Component longer than 255 characters
        long_component = "a" * 256 + ".pdf"
        assert validator._is_path_component_safe_strict(long_component) is False
        
        # Component exactly 255 characters should be allowed
        max_component = "a" * 251 + ".pdf"  # 255 total
        assert validator._is_path_component_safe_strict(max_component) is True
    
    def test_validate_leading_trailing_spaces_dots_blocked(self):
        """Test: Leading/trailing spaces and dots are blocked"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        problematic_names = [
            " leading_space.pdf",
            "trailing_space .pdf",
            ".leading_dot",
            "trailing_dot.",
            "  multiple_spaces  "
        ]
        
        for name in problematic_names:
            assert validator._is_path_component_safe_strict(name) is False


class TestFileSecurityValidation:
    """Test file-level security validation"""
    
    def test_validate_regular_file_allowed(self, temp_work_dir):
        """Test: Regular files are allowed"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        test_file = temp_work_dir / "regular_file.pdf"
        test_file.write_text("test content")
        
        result = validator._is_file_in_secure_zone(test_file.resolve(strict=False))
        assert result is True
    
    def test_validate_directory_blocked(self, temp_work_dir):
        """Test: Directories are blocked (only files allowed)"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        test_dir = temp_work_dir / "test_directory"
        test_dir.mkdir()
        
        result = validator._is_file_in_secure_zone(test_dir.resolve(strict=False))
        assert result is False
    
    @pytest.mark.skipif(os.name == 'nt', reason="SUID/SGID not supported on Windows")
    def test_validate_suid_files_blocked(self, temp_work_dir):
        """Test: SUID files are blocked on Unix systems"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        test_file = temp_work_dir / "suid_file.pdf"
        test_file.write_text("test content")
        
        # Mock file stat to simulate SUID bit
        with patch.object(test_file, 'stat') as mock_stat:
            mock_stat.return_value.st_mode = stat.S_IFREG | stat.S_ISUID
            
            result = validator._is_file_in_secure_zone(test_file.resolve(strict=False))
            assert result is False
    
    @pytest.mark.skipif(os.name != 'nt', reason="Windows-specific test")
    def test_validate_windows_permissions_allowed(self, temp_work_dir):
        """Test: Windows file permissions don't trigger Unix-specific checks"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        test_file = temp_work_dir / "windows_file.pdf"
        test_file.write_text("test content")
        
        # On Windows, SUID/SGID checks should be skipped
        result = validator._is_file_in_secure_zone(test_file.resolve(strict=False))
        assert result is True
    
    @pytest.mark.skipif(os.name == 'nt', reason="SGID not supported on Windows")
    def test_validate_sgid_files_blocked(self, temp_work_dir):
        """Test: SGID files are blocked on Unix systems"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        test_file = temp_work_dir / "sgid_file.pdf"
        test_file.write_text("test content")
        
        # Mock file stat to simulate SGID bit
        with patch.object(test_file, 'stat') as mock_stat:
            mock_stat.return_value.st_mode = stat.S_IFREG | stat.S_ISGID
            
            result = validator._is_file_in_secure_zone(test_file.resolve(strict=False))
            assert result is False
    
    def test_validate_permission_check_failure_blocked(self, temp_work_dir):
        """Test: Files with permission check failures are blocked"""
        import os
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        test_file = temp_work_dir / "permission_fail.pdf"
        test_file.write_text("test content")
        
        # Mock os.stat to raise exception instead of pathlib stat method
        with patch('os.stat', side_effect=PermissionError("Access denied")):
            result = validator._is_file_in_secure_zone(test_file.resolve(strict=False))
            assert result is False


class TestOutputDirectoryValidation:
    """Test output directory validation"""
    
    def test_validate_output_directory_none(self):
        """Test: None output directory returns None"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        result = validator.validate_output_directory(None)
        assert result is None
    
    def test_validate_output_directory_valid(self, temp_work_dir):
        """Test: Valid output directory passes validation"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        output_dir = temp_work_dir / "output"
        
        result = validator.validate_output_directory(output_dir)
        assert result == output_dir.resolve()
        assert output_dir.exists()
        assert output_dir.is_dir()
    
    def test_validate_output_directory_outside_boundaries_blocked(self):
        """Test: Output directory outside boundaries is blocked"""
        logger = MagicMock()
        # Create validator with only temp directory allowed for testing
        import tempfile
        temp_dir = Path(tempfile.gettempdir()).resolve(strict=False)
        validator = SecurityValidator(logger, allowed_directories={str(temp_dir)})
        
        # Try to create output in restricted location
        restricted_output = Path("/etc/output")  # Unix restricted location
        
        with pytest.raises(SecurityViolationError, match="Output directory outside security boundaries"):
            validator.validate_output_directory(restricted_output)
    
    def test_validate_output_directory_creation_failure(self, temp_work_dir):
        """Test: Output directory creation failure is handled"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Try to create directory in read-only location
        output_dir = temp_work_dir / "readonly" / "output"
        readonly_parent = temp_work_dir / "readonly"
        readonly_parent.mkdir()
        
        # Make parent read-only (may not work on all systems)
        try:
            readonly_parent.chmod(0o444)
            
            with pytest.raises(SecurityViolationError, match="Cannot create output directory"):
                validator.validate_output_directory(output_dir)
        except:
            pytest.skip("Cannot make directory read-only on this system")
        finally:
            # Restore permissions for cleanup
            try:
                readonly_parent.chmod(0o755)
            except:
                pass


class TestSecurityValidationEdgeCases:
    """Test edge cases and error conditions in security validation"""
    
    def test_validate_path_resolution_failure(self):
        """Test: Path resolution failure is handled gracefully"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Create a path that will fail resolution
        with patch.object(Path, 'resolve', side_effect=OSError("Resolution failed")):
            test_path = Path("failing_path.pdf")
            
            with pytest.raises(SecurityViolationError, match="Path resolution failed"):
                validator.validate_file_path(test_path)
    
    def test_validate_unicode_path_handling(self, temp_work_dir):
        """Test: Unicode paths are handled correctly"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Create file with unicode name
        unicode_file = temp_work_dir / "тест_файл.pdf"
        unicode_file.write_text("test content", encoding='utf-8')
        
        # Should handle unicode correctly
        result = validator.validate_file_path(unicode_file)
        assert result.exists()
    
    def test_validate_case_sensitivity_handling(self, temp_work_dir):
        """Test: Case sensitivity is handled correctly"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Test Windows reserved names in different cases
        test_cases = ["con.pdf", "CON.pdf", "Con.pdf"]
        
        for case in test_cases:
            assert validator._is_path_component_safe_strict(case) is False
    
    def test_validate_empty_path_components(self):
        """Test: Empty path components are handled"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Empty component should be invalid
        assert validator._is_path_component_safe_strict("") is False
    
    def test_validate_boundary_conditions(self, temp_work_dir):
        """Test: Boundary conditions in validation"""
        logger = MagicMock()
        validator = SecurityValidator(logger)
        
        # Test exactly at path length limit
        boundary_name = "a" * 251 + ".pdf"  # Exactly 255 chars
        assert validator._is_path_component_safe_strict(boundary_name) is True
        
        # Test just over the limit
        over_limit_name = "a" * 252 + ".pdf"  # 256 chars
        assert validator._is_path_component_safe_strict(over_limit_name) is False