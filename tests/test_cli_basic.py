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
        assert "check-password" in result.stdout
    
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
    
    def test_list_supported_formats(self, fastpass_executable):
        """Test: --list-supported shows format list and exits"""
        # A1i_List: Show Supported File Types
        result = subprocess.run(
            fastpass_executable + ["--list-supported"], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 0
        assert "FastPass Supported File Formats" in result.stdout
        assert ".pdf" in result.stdout
        assert ".docx" in result.stdout
        assert "Modern Office Documents" in result.stdout
        assert "PDF Documents" in result.stdout
        assert "Legacy Office Formats" in result.stdout
    
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
        assert "Must specify either files" in result.stderr
    
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
    
    def test_conflicting_input_methods(self, fastpass_executable, temp_work_dir):
        """Test: Conflicting input methods should error"""
        # A2a_Both_Error: Conflicting Instructions
        result = subprocess.run(
            fastpass_executable + [
                "decrypt", 
                "-i", "test.pdf", 
                "-r", str(temp_work_dir),
                "-p", "password"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 2
        assert "Cannot specify both individual files and recursive directory" in result.stderr
    
    def test_recursive_encrypt_blocked(self, fastpass_executable, temp_work_dir):
        """Test: Recursive mode with encrypt should be blocked"""
        # A2a1_Error: Recursive Encryption Blocked
        result = subprocess.run(
            fastpass_executable + [
                "encrypt", 
                "-r", str(temp_work_dir),
                "-p", "password"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 2
        assert "Recursive mode only supported for decrypt operations" in result.stderr
    
    def test_recursive_decrypt_allowed(self, fastpass_executable, temp_work_dir):
        """Test: Recursive mode with decrypt should be allowed"""
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
        
        # Should not error on argument validation
        # May error later on file processing, but that's expected
        assert "Recursive mode only supported for decrypt operations" not in result.stderr

class TestCLIPasswordHandling:
    """Test password argument handling"""
    
    def test_single_password_cli(self, fastpass_executable, simple_test_pdf):
        """Test: -p password123"""
        result = subprocess.run(
            fastpass_executable + [
                "check-password",
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
                "check-password",
                "-i", str(simple_test_pdf),
                "-p", "password1", "password2", "complex pass"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        # Should accept multiple passwords without validation errors
        assert "Must specify passwords" not in result.stderr
    
    def test_password_list_file(self, fastpass_executable, simple_test_pdf, password_list_file):
        """Test: --password-list passwords.txt"""
        result = subprocess.run(
            fastpass_executable + [
                "check-password",
                "-i", str(simple_test_pdf),
                "--password-list", str(password_list_file)
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        # Should accept password list file without validation errors
        assert "Must specify passwords" not in result.stderr

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
        assert "Unsupported file format" in result.stderr
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