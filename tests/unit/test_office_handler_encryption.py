"""
Office Document Handler Encryption Tests (Fixed - No COM)
Tests the office handler encryption functionality using subprocess-only approach
"""

import pytest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
import tempfile
import shutil
import subprocess

from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
from fastpass.exceptions import ProcessingError, FileFormatError


@pytest.fixture
def office_handler():
    """Create OfficeDocumentHandler instance for testing"""
    import logging
    logger = logging.getLogger('test')
    handler = OfficeDocumentHandler(logger)
    return handler


@pytest.fixture
def temp_office_files():
    """Create temporary office files for testing"""
    temp_dir = Path(tempfile.mkdtemp())
    
    # Create mock office files
    files = {}
    for ext in ['.docx', '.xlsx', '.pptx']:
        test_file = temp_dir / f"test{ext}"
        test_file.write_bytes(b"Mock Office Document Content")
        files[ext] = test_file
    
    # Create output directory
    output_dir = temp_dir / "output"
    output_dir.mkdir()
    files['output_dir'] = output_dir
    
    yield files
    
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


class TestOfficeEncryption:
    """Test Office document encryption using subprocess approach"""
    
    def test_encrypt_docx_success(self, office_handler, temp_office_files):
        """Test: Successful DOCX encryption"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password123"
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        
        with patch('subprocess.run', return_value=mock_result) as mock_subprocess, \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('fastpass.core.crypto_handlers.office_handler.FastPassConfig.LEGACY_FORMATS', {}):
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            # Verify correct subprocess call
            mock_subprocess.assert_called_once()
            cmd_args = mock_subprocess.call_args[0][0]
            assert cmd_args[0] == 'msoffcrypto-tool'
            assert '-e' in cmd_args
            assert password in cmd_args
    
    def test_encrypt_xlsx_success(self, office_handler, temp_office_files):
        """Test: Successful XLSX encryption"""
        input_path = temp_office_files['.xlsx']
        output_path = temp_office_files['output_dir'] / "encrypted.xlsx"
        password = "excel_pwd"
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        
        with patch('subprocess.run', return_value=mock_result), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('fastpass.core.crypto_handlers.office_handler.FastPassConfig.LEGACY_FORMATS', {}):
            
            office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_pptx_success(self, office_handler, temp_office_files):
        """Test: Successful PPTX encryption"""
        input_path = temp_office_files['.pptx']
        output_path = temp_office_files['output_dir'] / "encrypted.pptx"
        password = "ppt_password"
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        
        with patch('subprocess.run', return_value=mock_result), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('fastpass.core.crypto_handlers.office_handler.FastPassConfig.LEGACY_FORMATS', {}):
            
            office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_failure_handling(self, office_handler, temp_office_files):
        """Test: Encryption failure handling"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password123"
        
        # Mock subprocess failure
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Encryption failed"
        
        with patch('subprocess.run', return_value=mock_result), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('fastpass.core.crypto_handlers.office_handler.FastPassConfig.LEGACY_FORMATS', {}):
            
            with pytest.raises(ProcessingError, match="Office encryption failed"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_timeout(self, office_handler, temp_office_files):
        """Test: Encryption timeout handling"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password123"
        
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('msoffcrypto-tool', 60)), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('fastpass.core.crypto_handlers.office_handler.FastPassConfig.LEGACY_FORMATS', {}):
            
            with pytest.raises(ProcessingError, match="Office encryption timed out"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_tool_not_found(self, office_handler, temp_office_files):
        """Test: msoffcrypto-tool not found"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password123"
        
        with patch('subprocess.run', side_effect=FileNotFoundError()), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('fastpass.core.crypto_handlers.office_handler.FastPassConfig.LEGACY_FORMATS', {}):
            
            with pytest.raises(ProcessingError, match="msoffcrypto-tool not found"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_legacy_format_rejection(self, office_handler, temp_office_files):
        """Test: Legacy format encryption rejection"""
        input_path = temp_office_files['.docx'].with_suffix('.doc')
        output_path = temp_office_files['output_dir'] / "encrypted.doc"
        password = "password123"
        
        with patch('fastpass.core.crypto_handlers.office_handler.FastPassConfig.LEGACY_FORMATS', {'.doc': 'msoffcrypto'}), \
             patch.object(office_handler, '_validate_path_security_hardened'):
            
            with pytest.raises(FileFormatError, match="Legacy Office format .doc supports decryption only"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_password_validation(self, office_handler, temp_office_files):
        """Test: Password validation (length and null bytes)"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        
        with patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('fastpass.core.crypto_handlers.office_handler.FastPassConfig.LEGACY_FORMATS', {}):
            
            # Test long password
            long_password = "a" * 1025
            with pytest.raises(ValueError, match="Password exceeds maximum length"):
                office_handler.encrypt_file(input_path, output_path, long_password)
            
            # Test null byte in password
            null_password = "password\x00injection"
            with pytest.raises(ValueError, match="Null byte in password"):
                office_handler.encrypt_file(input_path, output_path, null_password)


class TestPasswordTesting:
    """Test password testing functionality"""
    
    def test_password_test_standard_format(self, office_handler, temp_office_files):
        """Test: Password test for standard format"""
        file_path = temp_office_files['.docx']
        password = "test123"

        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True

        # CORRECTIVE ACTION 1: Define a side effect for the decrypt method.
        # This function will be called instead of the mock, and it simulates
        # writing data to the temporary file handle passed to it.
        def mock_decrypt_side_effect(file_handle):
            file_handle.write(b"mock decrypted content")

        mock_office_file.decrypt.side_effect = mock_decrypt_side_effect

        # Mock the file operations and the OfficeFile class
        with patch('builtins.open', mock_open()):
            with patch('fastpass.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                # CORRECTIVE ACTION 2: No need to mock NamedTemporaryFile, as the real one
                # will work perfectly with our side_effect.
                result = office_handler.test_password(file_path, password)

                # Verify the result is True and the decrypt method was called
                assert result is True
                mock_office_file.decrypt.assert_called_once()
    
    
    def test_password_test_unencrypted_file(self, office_handler, temp_office_files):
        """Test: Password test on unencrypted file"""
        file_path = temp_office_files['.docx']
        password = "test123"
        
        # Mock unencrypted file
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = False
        
        with patch('builtins.open'), \
             patch('msoffcrypto.OfficeFile', return_value=mock_office_file), \
             patch('fastpass.core.crypto_handlers.office_handler.FastPassConfig.LEGACY_FORMATS', {}):
            
            result = office_handler.test_password(file_path, password)
            assert result == True  # Unencrypted files always "pass" password test
    


class TestDecryption:
    """Test Office document decryption (existing functionality)"""
    
    def test_decrypt_encrypted_file(self, office_handler, temp_office_files):
        """Test: Decrypt encrypted file using msoffcrypto library"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "decrypted.docx"
        password = "test123"
        
        # Mock encrypted file
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.decrypt.return_value = None
        
        with patch('builtins.open'), \
             patch('msoffcrypto.OfficeFile', return_value=mock_office_file), \
             patch.object(office_handler, '_validate_decrypted_file_security'):
            
            office_handler.decrypt_file(input_path, output_path, password)
            
            # Verify library methods were called
            mock_office_file.load_key.assert_called_once_with(password=password)
            mock_office_file.decrypt.assert_called_once()
    
    def test_decrypt_unencrypted_file(self, office_handler, temp_office_files):
        """Test: Decrypt file that's not encrypted (copy operation)"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "copied.docx"
        password = "test123"
        
        # Mock unencrypted file
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = False
        
        with patch('builtins.open'), \
             patch('msoffcrypto.OfficeFile', return_value=mock_office_file), \
             patch('shutil.copy2') as mock_copy:
            
            office_handler.decrypt_file(input_path, output_path, password)
            
            # Should copy file instead of decrypt
            mock_copy.assert_called_once_with(input_path, output_path)


class TestResourceManagement:
    """Test resource management without COM dependencies"""
    
    def test_cleanup_without_com(self, office_handler):
        """Test: Cleanup works without COM resources"""
        # Should complete without errors
        office_handler.cleanup()
        office_handler._cleanup_com_resources()  # Should be no-op
    
    def test_configuration_subprocess_mode(self, office_handler):
        """Test: Configuration for subprocess mode"""
        config = {'debug': True, 'office_timeout': 120}
        
        with patch.object(office_handler.logger, 'info') as mock_info:
            office_handler.configure(config)
            
            # Should log subprocess info
            mock_info.assert_called_once()
            assert "msoffcrypto-tool subprocess" in mock_info.call_args[0][0]
            
            # Should update timeout
            assert office_handler.timeout == 120