"""
Comprehensive End-to-End Tests for Complete FastPass Workflows
Tests full CLI execution scenarios with real files and operations
"""

import pytest
import subprocess
import shutil
from pathlib import Path
import tempfile
import json

# Import test utilities
from tests.conftest import run_fastpass_command


class TestBasicEncryptDecryptWorkflows:
    """Test basic encrypt and decrypt workflows"""
    
    @pytest.mark.e2e
    def test_encrypt_single_pdf_file(self, fastpass_executable, sample_pdf_file, project_root):
        """Test: Encrypt single PDF file with password"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Get original file size
        original_size = sample_pdf_file.stat().st_size
        
        # Encrypt the file
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(sample_pdf_file), "-p", "test_password_123"],
            cwd=project_root
        )
        
        assert result.returncode == 0, f"Encryption failed: {result.stderr}"
        assert "Successfully encrypted" in result.stdout
        assert sample_pdf_file.exists()
        
        # File size should have changed (encrypted files often different size)
        # We don't check exact size as it depends on encryption implementation
    
    @pytest.mark.e2e
    def test_decrypt_single_pdf_file(self, fastpass_executable, encrypted_test_files, project_root):
        """Test: Decrypt single PDF file with correct password"""
        if not encrypted_test_files or "pdf" not in encrypted_test_files:
            pytest.skip("Encrypted test files not available")
        
        encrypted_file = encrypted_test_files["pdf"]["file"]
        password = encrypted_test_files["pdf"]["password"]
        
        # Decrypt the file
        result = run_fastpass_command(
            fastpass_executable,
            ["decrypt", "-i", str(encrypted_file), "-p", password],
            cwd=project_root
        )
        
        assert result.returncode == 0, f"Decryption failed: {result.stderr}"
        assert "Successfully decrypted" in result.stdout
        assert encrypted_file.exists()
    
    @pytest.mark.e2e
    def test_encrypt_decrypt_cycle_preserves_content(self, fastpass_executable, sample_pdf_file, project_root):
        """Test: Complete encrypt→decrypt cycle preserves file content"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Get original content hash
        original_content = sample_pdf_file.read_bytes()
        
        # Step 1: Encrypt
        encrypt_result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(sample_pdf_file), "-p", "cycle_test_password"],
            cwd=project_root
        )
        assert encrypt_result.returncode == 0
        
        # Step 2: Decrypt
        decrypt_result = run_fastpass_command(
            fastpass_executable,
            ["decrypt", "-i", str(sample_pdf_file), "-p", "cycle_test_password"],
            cwd=project_root
        )
        assert decrypt_result.returncode == 0
        
        # Verify content is preserved
        final_content = sample_pdf_file.read_bytes()
        assert final_content == original_content, "File content not preserved through encrypt/decrypt cycle"
    
    @pytest.mark.e2e
    def test_check_password_encrypted_file(self, fastpass_executable, encrypted_test_files, project_root):
        """Test: Check password on encrypted file"""
        if not encrypted_test_files or "pdf" not in encrypted_test_files:
            pytest.skip("Encrypted test files not available")
        
        encrypted_file = encrypted_test_files["pdf"]["file"]
        password = encrypted_test_files["pdf"]["password"]
        
        # Check correct password
        result = run_fastpass_command(
            fastpass_executable,
            ["check-password", "-i", str(encrypted_file), "-p", password],
            cwd=project_root
        )
        
        assert result.returncode == 0, f"Password check failed: {result.stderr}"
        assert "Password verification successful" in result.stdout or "Success" in result.stdout
    
    @pytest.mark.e2e
    def test_check_password_unencrypted_file(self, fastpass_executable, sample_pdf_file, project_root):
        """Test: Check password on unencrypted file"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Check password on unencrypted file (should succeed without password)
        result = run_fastpass_command(
            fastpass_executable,
            ["check-password", "-i", str(sample_pdf_file)],
            cwd=project_root
        )
        
        assert result.returncode == 0, f"Password check failed: {result.stderr}"


class TestMultipleFileWorkflows:
    """Test workflows with multiple files"""
    
    @pytest.mark.e2e
    def test_encrypt_multiple_files_same_password(self, fastpass_executable, multiple_test_files, project_root):
        """Test: Encrypt multiple files with same password"""
        if not multiple_test_files or len(multiple_test_files) < 2:
            pytest.skip("Multiple test files not available")
        
        file_paths = [str(f) for f in multiple_test_files]
        
        # Encrypt all files with same password
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i"] + file_paths + ["-p", "shared_password_123"],
            cwd=project_root
        )
        
        assert result.returncode == 0, f"Multi-file encryption failed: {result.stderr}"
        assert f"Total files processed: {len(file_paths)}" in result.stdout
        assert f"Successful: {len(file_paths)}" in result.stdout
        assert "Failed: 0" in result.stdout
    
    @pytest.mark.e2e
    def test_decrypt_multiple_files_same_password(self, fastpass_executable, temp_work_dir, sample_pdf_file, project_root):
        """Test: Decrypt multiple files with same password"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Create multiple files by copying the sample
        test_files = []
        for i in range(3):
            test_file = temp_work_dir / f"multi_test_{i}.pdf"
            shutil.copy2(sample_pdf_file, test_file)
            test_files.append(test_file)
        
        # First encrypt all files
        file_paths = [str(f) for f in test_files]
        encrypt_result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i"] + file_paths + ["-p", "multi_password"],
            cwd=project_root
        )
        assert encrypt_result.returncode == 0
        
        # Then decrypt all files
        decrypt_result = run_fastpass_command(
            fastpass_executable,
            ["decrypt", "-i"] + file_paths + ["-p", "multi_password"],
            cwd=project_root
        )
        
        assert decrypt_result.returncode == 0, f"Multi-file decryption failed: {decrypt_result.stderr}"
        assert f"Total files processed: {len(file_paths)}" in decrypt_result.stdout
        assert f"Successful: {len(file_paths)}" in decrypt_result.stdout
    
    @pytest.mark.e2e
    def test_mixed_encrypted_unencrypted_batch(self, fastpass_executable, temp_work_dir, sample_pdf_file, project_root):
        """Test: Process batch with mix of encrypted and unencrypted files"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Create test files
        encrypted_file = temp_work_dir / "encrypted.pdf"
        unencrypted_file = temp_work_dir / "unencrypted.pdf"
        
        shutil.copy2(sample_pdf_file, encrypted_file)
        shutil.copy2(sample_pdf_file, unencrypted_file)
        
        # Encrypt one file
        encrypt_result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(encrypted_file), "-p", "batch_password"],
            cwd=project_root
        )
        assert encrypt_result.returncode == 0
        
        # Now check passwords on both files
        check_result = run_fastpass_command(
            fastpass_executable,
            ["check-password", "-i", str(encrypted_file), str(unencrypted_file)],
            cwd=project_root
        )
        
        assert check_result.returncode == 0, f"Mixed batch check failed: {check_result.stderr}"


class TestPasswordListWorkflows:
    """Test workflows using password list files"""
    
    @pytest.mark.e2e
    def test_decrypt_with_password_list_file(self, fastpass_executable, temp_work_dir, sample_pdf_file, password_list_file, project_root):
        """Test: Decrypt file using password list file"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Create and encrypt a test file with a password from the list
        test_file = temp_work_dir / "password_list_test.pdf"
        shutil.copy2(sample_pdf_file, test_file)
        
        # Encrypt with password that's in the list (password123 is first in list)
        encrypt_result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(test_file), "-p", "password123"],
            cwd=project_root
        )
        assert encrypt_result.returncode == 0
        
        # Decrypt using password list
        decrypt_result = run_fastpass_command(
            fastpass_executable,
            ["decrypt", "-i", str(test_file), "--password-list", str(password_list_file)],
            cwd=project_root
        )
        
        assert decrypt_result.returncode == 0, f"Password list decryption failed: {decrypt_result.stderr}"
        assert "Successfully decrypted" in decrypt_result.stdout
    
    @pytest.mark.e2e
    def test_password_list_priority_order(self, fastpass_executable, temp_work_dir, sample_pdf_file, password_list_file, project_root):
        """Test: Password list tries passwords in correct order"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Create test file encrypted with a password that's NOT first in the list
        test_file = temp_work_dir / "priority_test.pdf"
        shutil.copy2(sample_pdf_file, test_file)
        
        # Encrypt with "secret456" which should be second in the password list
        encrypt_result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(test_file), "-p", "secret456"],
            cwd=project_root
        )
        assert encrypt_result.returncode == 0
        
        # Decrypt using password list (should try passwords in order)
        decrypt_result = run_fastpass_command(
            fastpass_executable,
            ["decrypt", "-i", str(test_file), "--password-list", str(password_list_file)],
            cwd=project_root
        )
        
        assert decrypt_result.returncode == 0, f"Priority order test failed: {decrypt_result.stderr}"
        # The output should indicate that it found the correct password
        assert "Successfully decrypted" in decrypt_result.stdout
    
    @pytest.mark.e2e
    def test_password_list_exhaustion(self, fastpass_executable, temp_work_dir, sample_pdf_file, password_list_file, project_root):
        """Test: Behavior when password list is exhausted"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Create test file encrypted with password NOT in the list
        test_file = temp_work_dir / "exhaustion_test.pdf"
        shutil.copy2(sample_pdf_file, test_file)
        
        # Encrypt with password not in password list
        encrypt_result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(test_file), "-p", "password_not_in_list"],
            cwd=project_root
        )
        assert encrypt_result.returncode == 0
        
        # Try to decrypt using password list (should fail)
        decrypt_result = run_fastpass_command(
            fastpass_executable,
            ["decrypt", "-i", str(test_file), "--password-list", str(password_list_file)],
            cwd=project_root
        )
        
        # Should fail gracefully
        assert decrypt_result.returncode != 0
        assert "Failed: 1" in decrypt_result.stdout or "password" in decrypt_result.stderr.lower()


class TestOutputDirectoryWorkflows:
    """Test workflows with output directories"""
    
    @pytest.mark.e2e
    def test_encrypt_with_output_directory(self, fastpass_executable, sample_pdf_file, temp_work_dir, project_root):
        """Test: Encrypt file to output directory"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        output_dir = temp_work_dir / "output"
        
        # Encrypt with output directory
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(sample_pdf_file), "-p", "output_test_password", "-o", str(output_dir)],
            cwd=project_root
        )
        
        assert result.returncode == 0, f"Output directory encryption failed: {result.stderr}"
        
        # Verify output directory was created
        assert output_dir.exists()
        assert output_dir.is_dir()
        
        # Verify file was created in output directory
        output_file = output_dir / sample_pdf_file.name
        assert output_file.exists()
        
        # Original file should still exist
        assert sample_pdf_file.exists()
    
    @pytest.mark.e2e
    def test_decrypt_with_output_directory(self, fastpass_executable, temp_work_dir, sample_pdf_file, project_root):
        """Test: Decrypt file to output directory"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # First create an encrypted file
        encrypted_file = temp_work_dir / "to_decrypt.pdf"
        shutil.copy2(sample_pdf_file, encrypted_file)
        
        encrypt_result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(encrypted_file), "-p", "decrypt_output_test"],
            cwd=project_root
        )
        assert encrypt_result.returncode == 0
        
        # Now decrypt to output directory
        output_dir = temp_work_dir / "decrypted_output"
        
        decrypt_result = run_fastpass_command(
            fastpass_executable,
            ["decrypt", "-i", str(encrypted_file), "-p", "decrypt_output_test", "-o", str(output_dir)],
            cwd=project_root
        )
        
        assert decrypt_result.returncode == 0, f"Output directory decryption failed: {decrypt_result.stderr}"
        
        # Verify output
        assert output_dir.exists()
        output_file = output_dir / encrypted_file.name
        assert output_file.exists()


class TestSpecialFlagWorkflows:
    """Test workflows with special flags"""
    
    @pytest.mark.e2e 
    def test_dry_run_mode(self, fastpass_executable, sample_pdf_file, project_root):
        """Test: Dry run mode shows operations without executing"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Get original content
        original_content = sample_pdf_file.read_bytes()
        
        # Run in dry-run mode
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(sample_pdf_file), "-p", "dry_run_password", "--dry-run"],
            cwd=project_root
        )
        
        assert result.returncode == 0, f"Dry run failed: {result.stderr}"
        assert "DRY RUN" in result.stdout or "would encrypt" in result.stdout.lower()
        
        # File should be unchanged
        final_content = sample_pdf_file.read_bytes()
        assert final_content == original_content, "Dry run mode modified the file"
    
    @pytest.mark.e2e
    def test_verify_mode(self, fastpass_executable, sample_pdf_file, project_root):
        """Test: Verify mode performs deep verification"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Encrypt with verify mode
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(sample_pdf_file), "-p", "verify_test_password", "--verify"],
            cwd=project_root
        )
        
        assert result.returncode == 0, f"Verify mode encryption failed: {result.stderr}"
        # Should include verification information in output
        assert "verify" in result.stdout.lower() or "verification" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_debug_mode(self, fastpass_executable, sample_pdf_file, project_root):
        """Test: Debug mode provides detailed logging"""
        if not sample_pdf_file:
            pytest.skip("Sample PDF not available")
        
        # Run with debug mode
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(sample_pdf_file), "-p", "debug_test_password", "--debug"],
            cwd=project_root
        )
        
        assert result.returncode == 0, f"Debug mode failed: {result.stderr}"
        # Debug mode should produce more verbose output
        assert "[DEBUG]" in result.stdout or len(result.stdout) > 100


class TestErrorRecoveryWorkflows:
    """Test error conditions and recovery"""
    
    @pytest.mark.e2e
    def test_wrong_password_graceful_failure(self, fastpass_executable, encrypted_test_files, project_root):
        """Test: Wrong password fails gracefully"""
        if not encrypted_test_files or "pdf" not in encrypted_test_files:
            pytest.skip("Encrypted test files not available")
        
        encrypted_file = encrypted_test_files["pdf"]["file"]
        
        # Try to decrypt with wrong password
        result = run_fastpass_command(
            fastpass_executable,
            ["decrypt", "-i", str(encrypted_file), "-p", "wrong_password"],
            cwd=project_root
        )
        
        # Should fail with appropriate error message
        assert result.returncode != 0
        assert "password" in result.stderr.lower() or "Failed: 1" in result.stdout
    
    @pytest.mark.e2e
    def test_nonexistent_file_error(self, fastpass_executable, project_root):
        """Test: Non-existent file produces appropriate error"""
        from pathlib import Path
        # Use a nonexistent file within the home directory (which is allowed by security)
        nonexistent_file = str(Path.home() / "nonexistent_test_file_12345.pdf")
        
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", nonexistent_file, "-p", "password"],
            cwd=project_root
        )
        
        assert result.returncode != 0
        assert "not found" in result.stderr.lower() or "does not exist" in result.stderr.lower()
    
    @pytest.mark.e2e
    def test_unsupported_file_format_error(self, fastpass_executable, unsupported_test_files, project_root):
        """Test: Unsupported file format produces appropriate error"""
        if not unsupported_test_files or "txt" not in unsupported_test_files:
            pytest.skip("Unsupported test files not available")
        
        txt_file = unsupported_test_files["txt"]
        
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(txt_file), "-p", "password"],
            cwd=project_root
        )
        
        assert result.returncode != 0
        assert "unsupported" in result.stderr.lower() or "format" in result.stderr.lower()
    
    @pytest.mark.e2e
    def test_partial_batch_failure_recovery(self, fastpass_executable, temp_work_dir, sample_pdf_file, unsupported_test_files, project_root):
        """Test: Partial failure in batch processes successfully completed files"""
        if not sample_pdf_file or not unsupported_test_files:
            pytest.skip("Test files not available")
        
        # Create a mix of valid and invalid files
        valid_file = temp_work_dir / "valid.pdf"
        shutil.copy2(sample_pdf_file, valid_file)
        invalid_file = unsupported_test_files.get("txt")
        
        if not invalid_file:
            pytest.skip("Invalid file not available")
        
        # Try to process both files
        result = run_fastpass_command(
            fastpass_executable,
            ["encrypt", "-i", str(valid_file), str(invalid_file), "-p", "batch_password"],
            cwd=project_root
        )
        
        # Should report partial success
        assert "Successful: 1" in result.stdout
        assert "Failed: 1" in result.stdout


class TestInformationCommands:
    """Test information and help commands"""
    
    @pytest.mark.e2e
    def test_list_supported_formats(self, fastpass_executable, project_root):
        """Test: --list-supported shows supported formats"""
        result = run_fastpass_command(
            fastpass_executable,
            ["--list-supported"],
            cwd=project_root
        )
        
        assert result.returncode == 0
        assert "FastPass Supported File Formats:" in result.stdout
        assert ".pdf" in result.stdout
        assert ".docx" in result.stdout
        assert ".xlsx" in result.stdout
        assert ".pptx" in result.stdout
    
    @pytest.mark.e2e
    def test_version_display(self, fastpass_executable, project_root):
        """Test: --version shows version information"""
        result = run_fastpass_command(
            fastpass_executable,
            ["--version"],
            cwd=project_root
        )
        
        assert result.returncode == 0
        assert "FastPass" in result.stdout
        # Should include version number
        assert any(char.isdigit() for char in result.stdout)
    
    @pytest.mark.e2e
    def test_help_display(self, fastpass_executable, project_root):
        """Test: --help shows usage information"""
        result = run_fastpass_command(
            fastpass_executable,
            ["--help"],
            cwd=project_root
        )
        
        assert result.returncode == 0
        assert "usage:" in result.stdout.lower()
        assert "encrypt" in result.stdout
        assert "decrypt" in result.stdout
        assert "check-password" in result.stdout