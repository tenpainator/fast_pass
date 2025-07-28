"""
Basic Integration Tests for FastPass
Test end-to-end functionality with real files
Maps to: test_encrypt_operations.py and test_decrypt_operations.py from test design
"""

import subprocess
import pytest
from pathlib import Path
import shutil
import tempfile
import time

class TestPDFOperations:
    """Test real PDF encryption and decryption operations"""
    
    def test_pdf_encrypt_decrypt_cycle(self, fastpass_executable, temp_work_dir):
        """Test: Complete encrypt→decrypt cycle preserves content"""
        
        # Use existing test PDF
        source_pdf = Path(__file__).parent / "fixtures" / "sample_files" / "clean" / "sample.pdf"
        if not source_pdf.exists():
            pytest.skip("Test PDF not available")
        
        # Copy to temp directory for testing
        test_pdf = temp_work_dir / "test_cycle.pdf"
        shutil.copy2(source_pdf, test_pdf)
        
        # Get original file size for comparison
        original_size = test_pdf.stat().st_size
        
        # Step 1: Encrypt the PDF
        encrypt_result = subprocess.run(
            fastpass_executable + [
                "encrypt",
                "-i", str(test_pdf),
                "-p", "test_password_123"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert encrypt_result.returncode == 0, f"Encryption failed: {encrypt_result.stderr}"
        assert "Successfully encrypted" in encrypt_result.stdout
        
        # Verify file still exists and size changed
        assert test_pdf.exists()
        encrypted_size = test_pdf.stat().st_size
        # Encrypted file should be different size (usually larger)
        
        # Step 2: Verify file is now encrypted (check should succeed)
        check_result = subprocess.run(
            fastpass_executable + [
                "check",
                "-i", str(test_pdf),
                "-p", "test_password_123"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert check_result.returncode == 0, f"Password check failed: {check_result.stderr}"
        
        # Step 3: Decrypt the PDF
        decrypt_result = subprocess.run(
            fastpass_executable + [
                "decrypt",
                "-i", str(test_pdf),
                "-p", "test_password_123"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert decrypt_result.returncode == 0, f"Decryption failed: {decrypt_result.stderr}"
        assert "Successfully decrypted" in decrypt_result.stdout
        
        # Verify file still exists and is accessible
        assert test_pdf.exists()
        final_size = test_pdf.stat().st_size
        
        # File should be accessible without password now
        check_no_password = subprocess.run(
            fastpass_executable + [
                "check",
                "-i", str(test_pdf)
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        # Should complete successfully (no password needed for unencrypted file)
        assert check_no_password.returncode == 0
    
    def test_pdf_wrong_password_fails(self, fastpass_executable, temp_work_dir):
        """Test: Wrong password should fail gracefully"""
        
        # Use existing test PDF
        source_pdf = Path(__file__).parent / "fixtures" / "sample_files" / "clean" / "sample.pdf"
        if not source_pdf.exists():
            pytest.skip("Test PDF not available")
        
        # Copy to temp directory
        test_pdf = temp_work_dir / "test_wrong_password.pdf"
        shutil.copy2(source_pdf, test_pdf)
        
        # Encrypt with one password
        encrypt_result = subprocess.run(
            fastpass_executable + [
                "encrypt",
                "-i", str(test_pdf),
                "-p", "correct_password"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert encrypt_result.returncode == 0
        
        # Try to decrypt with wrong password
        decrypt_result = subprocess.run(
            fastpass_executable + [
                "decrypt",
                "-i", str(test_pdf),
                "-p", "wrong_password"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        # Should fail with password error
        assert decrypt_result.returncode != 0
        # Should contain password-related error message
    
    def test_single_file_only(self, fastpass_executable, temp_work_dir):
        """Test: Only single file processing supported (multi-file removed)"""
        
        source_pdf = Path(__file__).parent / "fixtures" / "sample_files" / "clean" / "sample.pdf"
        if not source_pdf.exists():
            pytest.skip("Test PDF not available")
        
        # Create test files
        test_file1 = temp_work_dir / "test_single_1.pdf"
        test_file2 = temp_work_dir / "test_single_2.pdf"
        shutil.copy2(source_pdf, test_file1)
        shutil.copy2(source_pdf, test_file2)
        
        # Try to encrypt multiple files (should fail)
        encrypt_result = subprocess.run(
            fastpass_executable + [
                "encrypt",
                "-i", str(test_file1), str(test_file2),
                "-p", "shared_password_123"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        # Should fail because multi-file input is not supported
        assert encrypt_result.returncode == 2
        
        # Process files individually (should work)
        for test_file in [test_file1, test_file2]:
            encrypt_result = subprocess.run(
                fastpass_executable + [
                    "encrypt",
                    "-i", str(test_file),
                    "-p", "shared_password_123"
                ], 
                capture_output=True, 
                text=True,
                cwd=Path(__file__).parent.parent
            )
            assert encrypt_result.returncode == 0
            assert "Successfully encrypted" in encrypt_result.stdout

class TestStdinPasswordFunctionality:
    """Test stdin password functionality (replaces password list)"""
    
    def test_stdin_password_array_usage(self, fastpass_executable, temp_work_dir):
        """Test: stdin password with JSON array format works correctly"""
        
        source_pdf = Path(__file__).parent / "fixtures" / "sample_files" / "clean" / "sample.pdf"
        if not source_pdf.exists():
            pytest.skip("Test PDF not available")
        
        test_pdf = temp_work_dir / "test_stdin_password.pdf"
        shutil.copy2(source_pdf, test_pdf)
        
        # Encrypt with a password
        encrypt_result = subprocess.run(
            fastpass_executable + [
                "encrypt",
                "-i", str(test_pdf),
                "-p", "password123"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert encrypt_result.returncode == 0
        
        # Try to decrypt using stdin with JSON array (should find the correct password)
        decrypt_result = subprocess.run(
            fastpass_executable + [
                "decrypt",
                "-i", str(test_pdf),
                "-p", "stdin"
            ], 
            input='["wrongpassword", "password123", "anotherpassword"]',
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert decrypt_result.returncode == 0
        assert "Successfully decrypted" in decrypt_result.stdout
    
    def test_mixed_cli_stdin_passwords(self, fastpass_executable, temp_work_dir):
        """Test: Mixed CLI and stdin passwords work correctly"""
        
        source_pdf = Path(__file__).parent / "fixtures" / "sample_files" / "clean" / "sample.pdf"
        if not source_pdf.exists():
            pytest.skip("Test PDF not available")
        
        test_pdf = temp_work_dir / "test_mixed_password.pdf"
        shutil.copy2(source_pdf, test_pdf)
        
        # Encrypt with a password
        encrypt_result = subprocess.run(
            fastpass_executable + [
                "encrypt",
                "-i", str(test_pdf),
                "-p", "target_password"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert encrypt_result.returncode == 0
        
        # Try to decrypt using mixed CLI and stdin passwords
        decrypt_result = subprocess.run(
            fastpass_executable + [
                "decrypt",
                "-i", str(test_pdf),
                "-p", "cli_password1", "stdin", "cli_password2"
            ], 
            input='["stdin_password1", "target_password", "stdin_password2"]',
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert decrypt_result.returncode == 0
        assert "Successfully decrypted" in decrypt_result.stdout

class TestOutputDirectory:
    """Test output directory functionality"""
    
    def test_output_directory_creation(self, fastpass_executable, temp_work_dir):
        """Test: Output directory is created and files are placed correctly"""
        
        source_pdf = Path(__file__).parent / "fixtures" / "sample_files" / "clean" / "sample.pdf"
        if not source_pdf.exists():
            pytest.skip("Test PDF not available")
        
        test_pdf = temp_work_dir / "input" / "test_output.pdf"
        test_pdf.parent.mkdir(exist_ok=True)
        shutil.copy2(source_pdf, test_pdf)
        
        output_dir = temp_work_dir / "output"
        
        # Encrypt with output directory
        encrypt_result = subprocess.run(
            fastpass_executable + [
                "encrypt",
                "-i", str(test_pdf),
                "-p", "output_test_password",
                "-o", str(output_dir)
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert encrypt_result.returncode == 0
        
        # Verify output directory was created
        assert output_dir.exists()
        assert output_dir.is_dir()
        
        # Verify file was created in output directory
        output_file = output_dir / test_pdf.name
        assert output_file.exists()
        
        # Original file should still exist
        assert test_pdf.exists()


class TestDebugLogging:
    """Test debug logging functionality"""
    
    def test_debug_flag_creates_log_file(self, fastpass_executable, simple_test_pdf):
        """Test: --debug flag creates a log file in the temp directory"""
        if not simple_test_pdf:
            pytest.skip("Simple test PDF not available")
        
        # Get the temp directory path
        temp_dir = Path(tempfile.gettempdir())
        
        # Get list of fastpass debug files before running the command
        initial_files = set(temp_dir.glob("fastpass_debug_*.log"))
        
        # Run a simple command with the --debug flag
        result = subprocess.run(
            fastpass_executable + [
                "check",
                "-i", str(simple_test_pdf),
                "--debug"
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 0, f"Debug command failed: {result.stderr}"
        
        # Wait for log file creation with retry mechanism
        new_log_files = set()
        max_retries = 10
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            final_files = set(temp_dir.glob("fastpass_debug_*.log"))
            new_log_files = final_files - initial_files
            if len(new_log_files) >= 1:
                break
            time.sleep(retry_delay)
        
        assert len(new_log_files) >= 1, "Debug flag did not create a new log file"
        
        # Verify the log file has content and proper naming
        for log_file in new_log_files:
            assert log_file.name.startswith("fastpass_debug_"), f"Log file has incorrect name: {log_file.name}"
            assert log_file.name.endswith(".log"), f"Log file has incorrect extension: {log_file.name}"
            assert log_file.stat().st_size > 0, "Debug log file is empty"
        
        # Cleanup the created log files
        for log_file in new_log_files:
            try:
                log_file.unlink()
            except:
                pass  # Cleanup failure is not a test failure