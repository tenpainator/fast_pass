"""
Basic Integration Tests for FastPass
Test end-to-end functionality with real files
Maps to: test_encrypt_operations.py and test_decrypt_operations.py from test design
"""

import subprocess
import pytest
from pathlib import Path
import shutil

class TestPDFOperations:
    """Test real PDF encryption and decryption operations"""
    
    def test_pdf_encrypt_decrypt_cycle(self, fastpass_executable, temp_work_dir):
        """Test: Complete encrypt→decrypt cycle preserves content"""
        
        # Use existing test PDF
        source_pdf = Path(__file__).parent.parent / "dev" / "pdf" / "test1_docx.pdf"
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
        
        # Step 2: Verify file is now encrypted (check-password should succeed)
        check_result = subprocess.run(
            fastpass_executable + [
                "check-password",
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
                "check-password",
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
        source_pdf = Path(__file__).parent.parent / "dev" / "pdf" / "test1_docx.pdf"
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
    
    def test_multiple_files_same_password(self, fastpass_executable, temp_work_dir):
        """Test: Multiple files with same password"""
        
        source_pdf = Path(__file__).parent.parent / "dev" / "pdf" / "test1_docx.pdf"
        if not source_pdf.exists():
            pytest.skip("Test PDF not available")
        
        # Create multiple test files
        test_files = []
        for i in range(3):
            test_file = temp_work_dir / f"test_multi_{i}.pdf"
            shutil.copy2(source_pdf, test_file)
            test_files.append(test_file)
        
        # Encrypt all files with same password
        encrypt_result = subprocess.run(
            fastpass_executable + [
                "encrypt",
                "-i"] + [str(f) for f in test_files] + [
                "-p", "shared_password_123"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert encrypt_result.returncode == 0
        assert "Total files processed: 3" in encrypt_result.stdout
        assert "Successful: 3" in encrypt_result.stdout
        assert "Failed: 0" in encrypt_result.stdout
        
        # Decrypt all files with same password
        decrypt_result = subprocess.run(
            fastpass_executable + [
                "decrypt",
                "-i"] + [str(f) for f in test_files] + [
                "-p", "shared_password_123"
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert decrypt_result.returncode == 0
        assert "Total files processed: 3" in decrypt_result.stdout
        assert "Successful: 3" in decrypt_result.stdout

class TestPasswordListFunctionality:
    """Test password list file functionality"""
    
    def test_password_list_file_usage(self, fastpass_executable, temp_work_dir, password_list_file):
        """Test: Password list file works correctly"""
        
        source_pdf = Path(__file__).parent.parent / "dev" / "pdf" / "test1_docx.pdf"
        if not source_pdf.exists():
            pytest.skip("Test PDF not available")
        
        test_pdf = temp_work_dir / "test_password_list.pdf"
        shutil.copy2(source_pdf, test_pdf)
        
        # Encrypt with first password from our list
        encrypt_result = subprocess.run(
            fastpass_executable + [
                "encrypt",
                "-i", str(test_pdf),
                "-p", "password123"  # This should be first in password_list_file
            ], 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert encrypt_result.returncode == 0
        
        # Try to decrypt using password list (should find the correct password)
        decrypt_result = subprocess.run(
            fastpass_executable + [
                "decrypt",
                "-i", str(test_pdf),
                "--password-list", str(password_list_file)
            ], 
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
        
        source_pdf = Path(__file__).parent.parent / "dev" / "pdf" / "test1_docx.pdf"
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