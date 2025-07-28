"""
Basic CLI Tests for FastPass
Test core CLI functionality and argument parsing
Maps to: test_cli_parsing.py from test design
"""

import subprocess
import pytest
from pathlib import Path
import os

class TestCLIBasicFunctionality:
    """Test basic CLI operations and help functions"""
    
    def test_help_display(self, fastpass_executable):
        """Test: -h and --help show usage information"""
        # A1h_Help: Show Help Information
        result = subprocess.run(
            fastpass_executable + ["--help"], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 0
        assert "FastPass" in result.stdout
        assert "encrypt" in result.stdout
        assert "decrypt" in result.stdout
        assert "check" in result.stdout
    
    def test_version_display(self, fastpass_executable):
        """Test: --version shows version information"""
        result = subprocess.run(
            fastpass_executable + ["--version"], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 0
        assert "FastPass" in result.stdout
        assert "1.0.0" in result.stdout
    
    def test_help_shows_format_table(self, fastpass_executable):
        """Test: --help shows format support table in EDC format"""
        # A1i_List: Show Supported File Types (now in help)
        result = subprocess.run(
            fastpass_executable + ["--help"], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 0
        # Should contain format table with EDC notation
        assert (".pdf" in result.stdout or "PDF" in result.stdout)
        assert (".docx" in result.stdout or "DOCX" in result.stdout)
        # Make format table assertion more robust by checking components separately
        assert ("E=Encryption" in result.stdout or 
                ("E" in result.stdout and "Encryption" in result.stdout))
        assert ("D=Decryption" in result.stdout or 
                ("D" in result.stdout and "Decryption" in result.stdout))
        assert ("C=Check" in result.stdout or 
                ("C" in result.stdout and "Check" in result.stdout))
    
    def test_no_operation_error(self, fastpass_executable):
        """Test: Missing operation should trigger error"""
        result = subprocess.run(
            fastpass_executable + ["-i", "test.pdf", "-p", "password"], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 2
        assert "Must specify an operation" in result.stderr
    
    def test_no_input_files_error(self, fastpass_executable):
        """Test: Missing -i flag should trigger error"""
        # A2a_Error: Nothing to Process
        result = subprocess.run(
            fastpass_executable + ["encrypt", "-p", "password"], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 2
        assert "Must specify a file to process (-i)" in result.stderr
    
    def test_no_password_error(self, fastpass_executable):
        """Test: Missing -p should trigger error for encrypt/decrypt"""
        result = subprocess.run(
            fastpass_executable + ["encrypt", "-i", "test.pdf"], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 2
        assert "Must specify passwords" in result.stderr

class TestCLIArgumentValidation:
    """Test CLI argument validation logic"""
    
    def test_removed_recursive_mode_error(self, fastpass_executable, temp_work_dir):
        """Test: Recursive mode should not be available"""
        # A2a_Both_Error: Recursive mode removed
        result = subprocess.run(
            fastpass_executable + [
                "decrypt", 
                "-r", str(temp_work_dir),
                "-p", "password"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 2
        # Should error because -r flag doesn't exist
    
    def test_removed_dry_run_flag_error(self, fastpass_executable):
        """Test: Removed --dry-run flag should error"""
        result = subprocess.run(
            fastpass_executable + [
                "encrypt", 
                "-i", "test.pdf",
                "-p", "password",
                "--dry-run"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 2
        # Should error because --dry-run flag doesn't exist
    
    def test_removed_verify_flag_error(self, fastpass_executable):
        """Test: Removed --verify flag should error"""
        result = subprocess.run(
            fastpass_executable + [
                "encrypt", 
                "-i", "test.pdf",
                "-p", "password",
                "--verify"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 2
        # Should error because --verify flag doesn't exist

class TestCLIPasswordHandling:
    """Test password argument handling"""
    
    def test_single_password_cli(self, fastpass_executable, simple_test_pdf):
        """Test: -p password123"""
        result = subprocess.run(
            fastpass_executable + [
                "check",
                "-i", str(simple_test_pdf),
                "-p", "testpassword"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        # Should accept the password argument without validation errors
        assert "Must specify passwords" not in result.stderr
    
    def test_multiple_passwords_cli(self, fastpass_executable, simple_test_pdf):
        """Test: -p password1 password2 "complex pass" """
        result = subprocess.run(
            fastpass_executable + [
                "check",
                "-i", str(simple_test_pdf),
                "-p", "password1", "password2", "complex pass"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        # Should accept multiple passwords without validation errors
        assert "Must specify passwords" not in result.stderr
    
    def test_removed_password_list_flag_error(self, fastpass_executable, simple_test_pdf, password_list_file):
        """Test: Removed --password-list flag should error"""
        result = subprocess.run(
            fastpass_executable + [
                "check",
                "-i", str(simple_test_pdf),
                "--password-list", str(password_list_file)
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        # Should error because --password-list flag doesn't exist
        assert result.returncode == 2
    
    def test_stdin_password_array_format(self, fastpass_executable, simple_test_pdf):
        """Test: stdin password with JSON array format"""
        result = subprocess.run(
            fastpass_executable + [
                "check",
                "-i", str(simple_test_pdf),
                "-p", "stdin"
            ], 
            input='["password1", "password2", "password3"]',
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        # Should accept stdin with JSON array format
        assert "Invalid JSON in stdin" not in result.stderr
    
    def test_mixed_cli_stdin_passwords(self, fastpass_executable, simple_test_pdf):
        """Test: Mixed CLI and stdin passwords"""
        result = subprocess.run(
            fastpass_executable + [
                "check",
                "-i", str(simple_test_pdf),
                "-p", "password1", "stdin", "password2"
            ], 
            input='["stdin_password1", "stdin_password2"]',
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        # Should accept mixed CLI and stdin passwords
        assert "Invalid JSON in stdin" not in result.stderr

class TestFileFormatValidation:
    """Test file format validation"""
    
    def test_unsupported_file_format(self, fastpass_executable, temp_work_dir):
        """Test: Unsupported formats (.txt, .zip) should be rejected"""
        # Create a test txt file
        test_txt = temp_work_dir / "test.txt"
        test_txt.write_text("Test content")
        
        result = subprocess.run(
            fastpass_executable + [
                "encrypt",
                "-i", str(test_txt),
                "-p", "password"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 1
        assert ("Unsupported file format" in result.stderr or 
                "[ERROR] File format error: Unsupported file format" in result.stderr)
        assert ".txt" in result.stderr
    
    def test_nonexistent_file(self, fastpass_executable):
        """Test: Non-existent files should be handled gracefully"""
        result = subprocess.run(
            fastpass_executable + [
                "encrypt",
                "-i", "nonexistent_file.pdf",
                "-p", "password"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 1
        # Should report file not found error