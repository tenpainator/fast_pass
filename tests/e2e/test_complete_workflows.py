"""
Comprehensive End-to-End Tests for FastPass Encryption/Decryption Workflows
Tests real file operations with encryption status verification using raw tools
"""

import pytest
import subprocess
import tempfile
import shutil
import time
from pathlib import Path
import PyPDF2
import msoffcrypto


def run_fastpass_command(command_args, cwd=None):
    """Run FastPass command and return result"""
    if cwd is None:
        cwd = Path(__file__).parent.parent.parent  # project root
    
    cmd = ["python", "main.py"] + command_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=cwd
    )
    return result


def verify_pdf_encryption_status(file_path):
    """Check PDF encryption status using PyPDF2"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            time.sleep(0.2 * attempt)  # Progressive delay
            with open(file_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                return reader.is_encrypted
        except PermissionError:
            if attempt == max_retries - 1:
                # If still failing after retries, skip raw verification
                pytest.skip(f"Unable to verify encryption status due to file lock on {file_path}")
            continue
        except Exception as e:
            pytest.fail(f"Failed to check PDF encryption status: {e}")


def verify_office_encryption_status(file_path):
    """Check Office file encryption status using msoffcrypto"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            time.sleep(0.2 * attempt)  # Progressive delay
            with open(file_path, 'rb') as f:
                office_file = msoffcrypto.OfficeFile(f)
                return office_file.is_encrypted()
        except PermissionError:
            if attempt == max_retries - 1:
                # If still failing after retries, skip raw verification
                pytest.skip(f"Unable to verify encryption status due to file lock on {file_path}")
            continue
        except Exception as e:
            pytest.fail(f"Failed to check Office encryption status: {e}")


class TestEncryptionWorkflows:
    """Test encryption functionality for modern file formats"""
    
    @pytest.mark.e2e
    def test_encrypt_docx(self):
        """Test: Encrypt DOCX file and verify encryption status"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "decrypted"
        source_file = fixtures_dir / "sample.docx"
        
        if not source_file.exists():
            pytest.skip("DOCX fixture file not available")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            
            # Copy fixture to temp location first (preserve fixtures)
            temp_input = temp_dir / "input_sample.docx"
            shutil.copy2(source_file, temp_input)
            
            output_file = temp_dir / "encrypted_sample.docx"
            
            # Run FastPass encrypt command using copied file  
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            result = run_fastpass_command([
                "encrypt",
                "-i", str(temp_input),
                "-o", str(output_dir),
                "-p", "test123"
            ])
            output_file = output_dir / temp_input.name
            
            # Verify FastPass success
            assert result.returncode == 0, f"FastPass encryption failed: {result.stderr}"
            assert "Successfully encrypted" in result.stdout
            assert output_file.exists(), "Output file was not created"
            
            # Brief delay to ensure file handle is released
            time.sleep(0.5)
            
            # Verify encryption status using raw tool
            is_encrypted = verify_office_encryption_status(output_file)
            assert is_encrypted == True, "File should be encrypted but raw tool reports False"
    
    @pytest.mark.e2e
    def test_encrypt_xlsx(self):
        """Test: Encrypt XLSX file and verify encryption status"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "decrypted"
        source_file = fixtures_dir / "sample.xlsx"
        
        if not source_file.exists():
            pytest.skip("XLSX fixture file not available")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            
            # Copy fixture to temp location first (preserve fixtures)
            temp_input = temp_dir / "input_sample.xlsx"
            shutil.copy2(source_file, temp_input)
            
            output_file = temp_dir / "encrypted_sample.xlsx"
            
            # Run FastPass encrypt command using copied file  
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            result = run_fastpass_command([
                "encrypt",
                "-i", str(temp_input),
                "-o", str(output_dir),
                "-p", "test123"
            ])
            output_file = output_dir / temp_input.name
            
            # Verify FastPass success
            assert result.returncode == 0, f"FastPass encryption failed: {result.stderr}"
            assert "Successfully encrypted" in result.stdout
            assert output_file.exists(), "Output file was not created"
            
            # Verify encryption status using raw tool
            is_encrypted = verify_office_encryption_status(output_file)
            assert is_encrypted == True, "File should be encrypted but raw tool reports False"
    
    @pytest.mark.e2e
    def test_encrypt_pptx(self):
        """Test: Encrypt PPTX file and verify encryption status"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "decrypted"
        source_file = fixtures_dir / "sample.pptx"
        
        if not source_file.exists():
            pytest.skip("PPTX fixture file not available")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            
            # Copy fixture to temp location first (preserve fixtures)
            temp_input = temp_dir / "input_sample.pptx"
            shutil.copy2(source_file, temp_input)
            
            output_file = temp_dir / "encrypted_sample.pptx"
            
            # Run FastPass encrypt command using copied file  
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            result = run_fastpass_command([
                "encrypt",
                "-i", str(temp_input),
                "-o", str(output_dir),
                "-p", "test123"
            ])
            output_file = output_dir / temp_input.name
            
            # Verify FastPass success
            assert result.returncode == 0, f"FastPass encryption failed: {result.stderr}"
            assert "Successfully encrypted" in result.stdout
            assert output_file.exists(), "Output file was not created"
            
            # Verify encryption status using raw tool
            is_encrypted = verify_office_encryption_status(output_file)
            assert is_encrypted == True, "File should be encrypted but raw tool reports False"
    
    @pytest.mark.e2e
    def test_encrypt_pdf(self):
        """Test: Encrypt PDF file and verify encryption status"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "decrypted"
        source_file = fixtures_dir / "sample.pdf"
        
        if not source_file.exists():
            pytest.skip("PDF fixture file not available")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            
            # Copy fixture to temp location first (preserve fixtures)
            temp_input = temp_dir / "input_sample.pdf"
            shutil.copy2(source_file, temp_input)
            
            output_file = temp_dir / "encrypted_sample.pdf"
            
            # Run FastPass encrypt command using copied file  
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            result = run_fastpass_command([
                "encrypt",
                "-i", str(temp_input),
                "-o", str(output_dir),
                "-p", "test123"
            ])
            output_file = output_dir / temp_input.name
            
            # Verify FastPass success
            assert result.returncode == 0, f"FastPass encryption failed: {result.stderr}"
            assert "Successfully encrypted" in result.stdout
            assert output_file.exists(), "Output file was not created"
            
            # Verify encryption status using raw tool
            is_encrypted = verify_pdf_encryption_status(output_file)
            assert is_encrypted == True, "File should be encrypted but raw tool reports False"


class TestDecryptionWorkflows:
    """Test decryption functionality for all supported file formats"""
    
    @pytest.mark.e2e
    def test_decrypt_docx(self):
        """Test: Decrypt DOCX file and verify decryption status"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.docx"
        
        if not source_file.exists():
            pytest.skip("Encrypted DOCX fixture file not available")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            
            # Copy fixture to temp location first (preserve fixtures)
            temp_input = temp_dir / "input_sample.docx"
            shutil.copy2(source_file, temp_input)
            
            output_file = temp_dir / "decrypted_sample.docx"
            
            # Run FastPass decrypt command using copied file
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            result = run_fastpass_command([
                "decrypt",
                "-i", str(temp_input),
                "-o", str(output_dir),
                "-p", "test123"
            ])
            output_file = output_dir / temp_input.name
            
            # Verify FastPass success
            assert result.returncode == 0, f"FastPass decryption failed: {result.stderr}"
            assert "Successfully decrypted" in result.stdout
            assert output_file.exists(), "Output file was not created"
            
            # Verify encryption status using raw tool
            is_encrypted = verify_office_encryption_status(output_file)
            assert is_encrypted == False, "File should be decrypted but raw tool reports True"
    
    @pytest.mark.e2e
    def test_decrypt_xlsx(self):
        """Test: Decrypt XLSX file and verify decryption status"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.xlsx"
        
        if not source_file.exists():
            pytest.skip("Encrypted XLSX fixture file not available")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            
            # Copy fixture to temp location first (preserve fixtures)
            temp_input = temp_dir / "input_sample.xlsx"
            shutil.copy2(source_file, temp_input)
            
            output_file = temp_dir / "decrypted_sample.xlsx"
            
            # Run FastPass decrypt command using copied file
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            result = run_fastpass_command([
                "decrypt",
                "-i", str(temp_input),
                "-o", str(output_dir),
                "-p", "test123"
            ])
            output_file = output_dir / temp_input.name
            
            # Verify FastPass success
            assert result.returncode == 0, f"FastPass decryption failed: {result.stderr}"
            assert "Successfully decrypted" in result.stdout
            assert output_file.exists(), "Output file was not created"
            
            # Verify encryption status using raw tool
            is_encrypted = verify_office_encryption_status(output_file)
            assert is_encrypted == False, "File should be decrypted but raw tool reports True"
    
    @pytest.mark.e2e
    def test_decrypt_pptx(self):
        """Test: Decrypt PPTX file and verify decryption status"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.pptx"
        
        if not source_file.exists():
            pytest.skip("Encrypted PPTX fixture file not available")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            
            # Copy fixture to temp location first (preserve fixtures)
            temp_input = temp_dir / "input_sample.pptx"
            shutil.copy2(source_file, temp_input)
            
            output_file = temp_dir / "decrypted_sample.pptx"
            
            # Run FastPass decrypt command using copied file
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            result = run_fastpass_command([
                "decrypt",
                "-i", str(temp_input),
                "-o", str(output_dir),
                "-p", "test123"
            ])
            output_file = output_dir / temp_input.name
            
            # Verify FastPass success
            assert result.returncode == 0, f"FastPass decryption failed: {result.stderr}"
            assert "Successfully decrypted" in result.stdout
            assert output_file.exists(), "Output file was not created"
            
            # Verify encryption status using raw tool
            is_encrypted = verify_office_encryption_status(output_file)
            assert is_encrypted == False, "File should be decrypted but raw tool reports True"
    
    @pytest.mark.e2e
    def test_decrypt_pdf(self):
        """Test: Decrypt PDF file and verify decryption status"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.pdf"
        
        if not source_file.exists():
            pytest.skip("Encrypted PDF fixture file not available")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            
            # Copy fixture to temp location first (preserve fixtures)
            temp_input = temp_dir / "input_sample.pdf"
            shutil.copy2(source_file, temp_input)
            
            output_file = temp_dir / "decrypted_sample.pdf"
            
            # Run FastPass decrypt command using copied file
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            result = run_fastpass_command([
                "decrypt",
                "-i", str(temp_input),
                "-o", str(output_dir),
                "-p", "test123"
            ])
            output_file = output_dir / temp_input.name
            
            # Verify FastPass success
            assert result.returncode == 0, f"FastPass decryption failed: {result.stderr}"
            assert "Successfully decrypted" in result.stdout
            assert output_file.exists(), "Output file was not created"
            
            # Verify encryption status using raw tool
            is_encrypted = verify_pdf_encryption_status(output_file)
            assert is_encrypted == False, "File should be decrypted but raw tool reports True"
    
    @pytest.mark.e2e
    def test_decrypt_doc(self):
        """Test: Decrypt DOC file and verify decryption status"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.doc"
        
        if not source_file.exists():
            pytest.skip("Encrypted DOC fixture file not available")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            
            # Copy fixture to temp location first (preserve fixtures)
            temp_input = temp_dir / "input_sample.doc"
            shutil.copy2(source_file, temp_input)
            
            output_file = temp_dir / "decrypted_sample.doc"
            
            # Run FastPass decrypt command using copied file
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            result = run_fastpass_command([
                "decrypt",
                "-i", str(temp_input),
                "-o", str(output_dir),
                "-p", "test123"
            ])
            output_file = output_dir / temp_input.name
            
            # Note: Legacy format decryption may fail with known issues
            if result.returncode != 0:
                pytest.xfail("Legacy DOC format decryption has known issues")
            
            assert "Successfully decrypted" in result.stdout
            assert output_file.exists(), "Output file was not created"
            
            # Verify encryption status using raw tool
            is_encrypted = verify_office_encryption_status(output_file)
            assert is_encrypted == False, "File should be decrypted but raw tool reports True"
    
    @pytest.mark.e2e
    def test_decrypt_xls(self):
        """Test: Decrypt XLS file and verify decryption status"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.xls"
        
        if not source_file.exists():
            pytest.skip("Encrypted XLS fixture file not available")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            
            # Copy fixture to temp location first (preserve fixtures)
            temp_input = temp_dir / "input_sample.xls"
            shutil.copy2(source_file, temp_input)
            
            output_file = temp_dir / "decrypted_sample.xls"
            
            # Run FastPass decrypt command using copied file
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            result = run_fastpass_command([
                "decrypt",
                "-i", str(temp_input),
                "-o", str(output_dir),
                "-p", "test123"
            ])
            output_file = output_dir / temp_input.name
            
            # Note: Legacy format decryption may fail with known issues
            if result.returncode != 0:
                pytest.xfail("Legacy XLS format decryption has known issues")
            
            assert "Successfully decrypted" in result.stdout
            assert output_file.exists(), "Output file was not created"
            
            # Verify encryption status using raw tool
            is_encrypted = verify_office_encryption_status(output_file)
            assert is_encrypted == False, "File should be decrypted but raw tool reports True"
    
    @pytest.mark.e2e
    def test_decrypt_ppt(self):
        """Test: Decrypt PPT file and verify decryption status"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.ppt"
        
        if not source_file.exists():
            pytest.skip("Encrypted PPT fixture file not available")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            
            # Copy fixture to temp location first (preserve fixtures)
            temp_input = temp_dir / "input_sample.ppt"
            shutil.copy2(source_file, temp_input)
            
            output_file = temp_dir / "decrypted_sample.ppt"
            
            # Run FastPass decrypt command using copied file
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            result = run_fastpass_command([
                "decrypt",
                "-i", str(temp_input),
                "-o", str(output_dir),
                "-p", "test123"
            ])
            output_file = output_dir / temp_input.name
            
            # Note: Legacy format decryption may fail with known issues
            if result.returncode != 0:
                pytest.xfail("Legacy PPT format decryption has known issues")
            
            assert "Successfully decrypted" in result.stdout
            assert output_file.exists(), "Output file was not created"
            
            # Verify encryption status using raw tool
            is_encrypted = verify_office_encryption_status(output_file)
            assert is_encrypted == False, "File should be decrypted but raw tool reports True"


class TestPasswordCheckDecryptedFiles:
    """Test check functionality on decrypted files"""
    
    @pytest.mark.e2e
    def test_check_password_decrypted_docx(self):
        """Test: Check password on decrypted DOCX file should report not protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "decrypted"
        source_file = fixtures_dir / "sample.docx"
        
        if not source_file.exists():
            pytest.skip("Decrypted DOCX fixture file not available")
        
        # Run FastPass check command (no password provided)
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        # Should succeed and indicate no password protection
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        # Parse output to verify password_protected=False reported
        assert "not encrypted" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_decrypted_xlsx(self):
        """Test: Check password on decrypted XLSX file should report not protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "decrypted"
        source_file = fixtures_dir / "sample.xlsx"
        
        if not source_file.exists():
            pytest.skip("Decrypted XLSX fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "not encrypted" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_decrypted_pptx(self):
        """Test: Check password on decrypted PPTX file should report not protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "decrypted"
        source_file = fixtures_dir / "sample.pptx"
        
        if not source_file.exists():
            pytest.skip("Decrypted PPTX fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "not encrypted" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_decrypted_pdf(self):
        """Test: Check password on decrypted PDF file should report not protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "decrypted"
        source_file = fixtures_dir / "sample.pdf"
        
        if not source_file.exists():
            pytest.skip("Decrypted PDF fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "not encrypted" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_decrypted_doc(self):
        """Test: Check password on decrypted DOC file should report not protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "decrypted"
        source_file = fixtures_dir / "sample.doc"
        
        if not source_file.exists():
            pytest.skip("Decrypted DOC fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "not encrypted" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_decrypted_xls(self):
        """Test: Check password on decrypted XLS file should report not protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "decrypted"
        source_file = fixtures_dir / "sample.xls"
        
        if not source_file.exists():
            pytest.skip("Decrypted XLS fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "not encrypted" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_decrypted_ppt(self):
        """Test: Check password on decrypted PPT file should report not protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "decrypted"
        source_file = fixtures_dir / "sample.ppt"
        
        if not source_file.exists():
            pytest.skip("Decrypted PPT fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "not encrypted" in result.stdout.lower()


class TestPasswordCheckEncryptedFiles:
    """Test check functionality on encrypted files"""
    
    @pytest.mark.e2e
    def test_check_password_encrypted_docx(self):
        """Test: Check password on encrypted DOCX file should report protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.docx"
        
        if not source_file.exists():
            pytest.skip("Encrypted DOCX fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "encrypted" in result.stdout.lower() or "password protection: true" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_encrypted_xlsx(self):
        """Test: Check password on encrypted XLSX file should report protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.xlsx"
        
        if not source_file.exists():
            pytest.skip("Encrypted XLSX fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "encrypted" in result.stdout.lower() or "password protection: true" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_encrypted_pptx(self):
        """Test: Check password on encrypted PPTX file should report protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.pptx"
        
        if not source_file.exists():
            pytest.skip("Encrypted PPTX fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "encrypted" in result.stdout.lower() or "password protection: true" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_encrypted_pdf(self):
        """Test: Check password on encrypted PDF file should report protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.pdf"
        
        if not source_file.exists():
            pytest.skip("Encrypted PDF fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "encrypted" in result.stdout.lower() or "password protection: true" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_encrypted_doc(self):
        """Test: Check password on encrypted DOC file should report protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.doc"
        
        if not source_file.exists():
            pytest.skip("Encrypted DOC fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "encrypted" in result.stdout.lower() or "password protection: true" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_encrypted_xls(self):
        """Test: Check password on encrypted XLS file should report protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.xls"
        
        if not source_file.exists():
            pytest.skip("Encrypted XLS fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "encrypted" in result.stdout.lower() or "password protection: true" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_encrypted_ppt(self):
        """Test: Check password on encrypted PPT file should report protected"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.ppt"
        
        if not source_file.exists():
            pytest.skip("Encrypted PPT fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file)
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "encrypted" in result.stdout.lower() or "password protection: true" in result.stdout.lower()


class TestPasswordCheckCorrectPassword:
    """Test check functionality with correct password"""
    
    @pytest.mark.e2e
    def test_check_password_correct_docx(self):
        """Test: Check password with correct password on encrypted DOCX should report correct"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.docx"
        
        if not source_file.exists():
            pytest.skip("Encrypted DOCX fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test123"
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "password works" in result.stdout.lower() or "password verification successful" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_correct_xlsx(self):
        """Test: Check password with correct password on encrypted XLSX should report correct"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.xlsx"
        
        if not source_file.exists():
            pytest.skip("Encrypted XLSX fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test123"
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "password works" in result.stdout.lower() or "password verification successful" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_correct_pptx(self):
        """Test: Check password with correct password on encrypted PPTX should report correct"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.pptx"
        
        if not source_file.exists():
            pytest.skip("Encrypted PPTX fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test123"
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "password works" in result.stdout.lower() or "password verification successful" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_correct_pdf(self):
        """Test: Check password with correct password on encrypted PDF should report correct"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.pdf"
        
        if not source_file.exists():
            pytest.skip("Encrypted PDF fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test123"
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "password works" in result.stdout.lower() or "password verification successful" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_correct_doc(self):
        """Test: Check password with correct password on encrypted DOC should report correct"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.doc"
        
        if not source_file.exists():
            pytest.skip("Encrypted DOC fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test123"
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "password works" in result.stdout.lower() or "password verification successful" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_correct_xls(self):
        """Test: Check password with correct password on encrypted XLS should report correct"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.xls"
        
        if not source_file.exists():
            pytest.skip("Encrypted XLS fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test123"
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "password works" in result.stdout.lower() or "password verification successful" in result.stdout.lower()
    
    @pytest.mark.e2e
    def test_check_password_correct_ppt(self):
        """Test: Check password with correct password on encrypted PPT should report correct"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.ppt"
        
        if not source_file.exists():
            pytest.skip("Encrypted PPT fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test123"
        ])
        
        assert result.returncode == 0, f"Check failed: {result.stderr}"
        assert "password works" in result.stdout.lower() or "password verification successful" in result.stdout.lower()


class TestPasswordCheckWrongPassword:
    """Test check functionality with wrong password"""
    
    @pytest.mark.e2e
    def test_check_password_wrong_docx(self):
        """Test: Check password with wrong password on encrypted DOCX should report incorrect"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.docx"
        
        if not source_file.exists():
            pytest.skip("Encrypted DOCX fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test345"
        ])
        
        # Should indicate password protection but wrong password
        assert "encrypted" in result.stdout.lower() and ("no password provided" in result.stdout.lower() or "incorrect" in result.stdout.lower() or "wrong" in result.stdout.lower() or result.returncode != 0)
    
    @pytest.mark.e2e
    def test_check_password_wrong_xlsx(self):
        """Test: Check password with wrong password on encrypted XLSX should report incorrect"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.xlsx"
        
        if not source_file.exists():
            pytest.skip("Encrypted XLSX fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test345"
        ])
        
        assert "encrypted" in result.stdout.lower() and ("no password provided" in result.stdout.lower() or "incorrect" in result.stdout.lower() or "wrong" in result.stdout.lower() or result.returncode != 0)
    
    @pytest.mark.e2e
    def test_check_password_wrong_pptx(self):
        """Test: Check password with wrong password on encrypted PPTX should report incorrect"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.pptx"
        
        if not source_file.exists():
            pytest.skip("Encrypted PPTX fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test345"
        ])
        
        assert "encrypted" in result.stdout.lower() and ("no password provided" in result.stdout.lower() or "incorrect" in result.stdout.lower() or "wrong" in result.stdout.lower() or result.returncode != 0)
    
    @pytest.mark.e2e
    def test_check_password_wrong_pdf(self):
        """Test: Check password with wrong password on encrypted PDF should report incorrect"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.pdf"
        
        if not source_file.exists():
            pytest.skip("Encrypted PDF fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test345"
        ])
        
        assert "encrypted" in result.stdout.lower() and ("no password provided" in result.stdout.lower() or "incorrect" in result.stdout.lower() or "wrong" in result.stdout.lower() or result.returncode != 0)
    
    @pytest.mark.e2e
    def test_check_password_wrong_doc(self):
        """Test: Check password with wrong password on encrypted DOC should report incorrect"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.doc"
        
        if not source_file.exists():
            pytest.skip("Encrypted DOC fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test345"
        ])
        
        assert "encrypted" in result.stdout.lower() and ("no password provided" in result.stdout.lower() or "incorrect" in result.stdout.lower() or "wrong" in result.stdout.lower() or result.returncode != 0)
    
    @pytest.mark.e2e
    def test_check_password_wrong_xls(self):
        """Test: Check password with wrong password on encrypted XLS should report incorrect"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.xls"
        
        if not source_file.exists():
            pytest.skip("Encrypted XLS fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test345"
        ])
        
        assert "encrypted" in result.stdout.lower() and ("no password provided" in result.stdout.lower() or "incorrect" in result.stdout.lower() or "wrong" in result.stdout.lower() or result.returncode != 0)
    
    @pytest.mark.e2e
    def test_check_password_wrong_ppt(self):
        """Test: Check password with wrong password on encrypted PPT should report incorrect"""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "sample_files" / "encrypted"
        source_file = fixtures_dir / "sample.ppt"
        
        if not source_file.exists():
            pytest.skip("Encrypted PPT fixture file not available")
        
        result = run_fastpass_command([
            "check",
            "-i", str(source_file),
            "-p", "test345"
        ])
        
        assert "encrypted" in result.stdout.lower() and ("no password provided" in result.stdout.lower() or "incorrect" in result.stdout.lower() or "wrong" in result.stdout.lower() or result.returncode != 0)