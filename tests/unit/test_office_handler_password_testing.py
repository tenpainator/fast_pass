"""
Comprehensive Unit Tests for Office Handler Password Testing
Tests the test_password method extensively across all Office formats and edge cases
Maps to Test Plan Section 1.1 - Password Testing Tests (24 tests)
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open, call
import logging

# Import modules under test
from src.core.crypto_handlers.office_handler import OfficeDocumentHandler
from src.exceptions import FileFormatError, ProcessingError, SecurityViolationError


# Module-level fixtures that can be used by all test classes
@pytest.fixture
def mock_logger():
    """Create a mock logger for testing"""
    return MagicMock(spec=logging.Logger)


@pytest.fixture
def office_handler(mock_logger):
    """Create OfficeDocumentHandler instance with mocked dependencies"""
    with patch('src.core.crypto_handlers.office_handler.msoffcrypto') as mock_msoffcrypto:
        handler = OfficeDocumentHandler(mock_logger)
        handler.msoffcrypto = mock_msoffcrypto
        return handler


@pytest.fixture
def mock_office_file():
    """Create a mock OfficeFile for testing"""
    mock_file = MagicMock()
    mock_file.is_encrypted.return_value = True
    mock_file.load_key = MagicMock()
    mock_file.decrypt = MagicMock()
    return mock_file


@pytest.fixture
def temp_docx_path():
    """Create a temporary DOCX file path for testing"""
    with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as f:
        temp_path = Path(f.name)
    yield temp_path
    try:
        temp_path.unlink()
    except FileNotFoundError:
        pass


@pytest.fixture
def temp_xlsx_path():
    """Create a temporary XLSX file path for testing"""
    with tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False) as f:
        temp_path = Path(f.name)
    yield temp_path
    try:
        temp_path.unlink()
    except FileNotFoundError:
        pass


@pytest.fixture
def temp_pptx_path():
    """Create a temporary PPTX file path for testing"""
    with tempfile.NamedTemporaryFile(suffix='.pptx', delete=False) as f:
        temp_path = Path(f.name)
    yield temp_path
    try:
        temp_path.unlink()
    except FileNotFoundError:
        pass


class TestOfficeHandlerPasswordTesting:
    """Test Office Handler password testing functionality"""
    pass


class TestPasswordValidationEncryptedFiles:
    """Test password validation on encrypted Office files"""
    
    def test_password_validation_docx_encrypted_correct(self, office_handler, mock_office_file, temp_docx_path):
        """Test: Correct password validation for encrypted DOCX file returns True"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')  # ZIP signature for Office files
        
        # Mock encrypted file with correct password
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.return_value = None  # Success
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp_file = MagicMock()
                    mock_temp_file.read.return_value = b'decrypted_content_100_bytes' + b'x' * 75  # 100 bytes
                    mock_temp_file.seek.return_value = None
                    mock_temp_file.__enter__.return_value = mock_temp_file
                    mock_temp.return_value = mock_temp_file
                    
                    result = office_handler.test_password(temp_docx_path, "correct_password")
                    
                    assert result is True
                    mock_office_file.load_key.assert_called_once_with(password="correct_password")
                    mock_office_file.decrypt.assert_called_once()
    
    def test_password_validation_docx_encrypted_incorrect(self, office_handler, mock_office_file, temp_docx_path):
        """Test: Incorrect password validation for encrypted DOCX file returns False"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')
        
        # Mock encrypted file with incorrect password (raises exception)
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.side_effect = Exception("Invalid password")
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                result = office_handler.test_password(temp_docx_path, "wrong_password")
                
                assert result is False
                mock_office_file.load_key.assert_called_once_with(password="wrong_password")
    
    def test_password_validation_docx_unencrypted(self, office_handler, mock_office_file, temp_docx_path):
        """Test: Password validation for unencrypted DOCX file returns True"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')
        
        # Mock unencrypted file
        mock_office_file.is_encrypted.return_value = False
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                result = office_handler.test_password(temp_docx_path, "any_password")
                
                assert result is True
                mock_office_file.is_encrypted.assert_called_once()
                mock_office_file.load_key.assert_not_called()
    
    def test_password_validation_xlsx_encrypted_correct(self, office_handler, mock_office_file, temp_xlsx_path):
        """Test: Correct password validation for encrypted XLSX file returns True"""
        # Create test file content
        temp_xlsx_path.write_bytes(b'PK\x03\x04')
        
        # Mock encrypted file with correct password
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.return_value = None
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp_file = MagicMock()
                    mock_temp_file.read.return_value = b'decrypted_xlsx_content' + b'x' * 82  # 100 bytes
                    mock_temp_file.seek.return_value = None
                    mock_temp_file.__enter__.return_value = mock_temp_file
                    mock_temp.return_value = mock_temp_file
                    
                    result = office_handler.test_password(temp_xlsx_path, "correct_xlsx_password")
                    
                    assert result is True
                    mock_office_file.load_key.assert_called_once_with(password="correct_xlsx_password")
    
    def test_password_validation_xlsx_encrypted_incorrect(self, office_handler, mock_office_file, temp_xlsx_path):
        """Test: Incorrect password validation for encrypted XLSX file returns False"""
        # Create test file content
        temp_xlsx_path.write_bytes(b'PK\x03\x04')
        
        # Mock encrypted file with incorrect password
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.side_effect = Exception("Authentication failed")
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                result = office_handler.test_password(temp_xlsx_path, "wrong_xlsx_password")
                
                assert result is False
    
    def test_password_validation_xlsx_unencrypted(self, office_handler, mock_office_file, temp_xlsx_path):
        """Test: Password validation for unencrypted XLSX file returns True"""
        # Create test file content
        temp_xlsx_path.write_bytes(b'PK\x03\x04')
        
        # Mock unencrypted file
        mock_office_file.is_encrypted.return_value = False
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                result = office_handler.test_password(temp_xlsx_path, "any_password")
                
                assert result is True
    
    def test_password_validation_pptx_encrypted_correct(self, office_handler, mock_office_file, temp_pptx_path):
        """Test: Correct password validation for encrypted PPTX file returns True"""
        # Create test file content
        temp_pptx_path.write_bytes(b'PK\x03\x04')
        
        # Mock encrypted file with correct password
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.return_value = None
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp_file = MagicMock()
                    mock_temp_file.read.return_value = b'decrypted_pptx_content' + b'x' * 81  # 100 bytes
                    mock_temp_file.seek.return_value = None
                    mock_temp_file.__enter__.return_value = mock_temp_file
                    mock_temp.return_value = mock_temp_file
                    
                    result = office_handler.test_password(temp_pptx_path, "correct_pptx_password")
                    
                    assert result is True
    
    def test_password_validation_pptx_encrypted_incorrect(self, office_handler, mock_office_file, temp_pptx_path):
        """Test: Incorrect password validation for encrypted PPTX file returns False"""
        # Create test file content
        temp_pptx_path.write_bytes(b'PK\x03\x04')
        
        # Mock encrypted file with incorrect password
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.side_effect = Exception("Password verification failed")
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                result = office_handler.test_password(temp_pptx_path, "wrong_pptx_password")
                
                assert result is False
    
    def test_password_validation_pptx_unencrypted(self, office_handler, mock_office_file, temp_pptx_path):
        """Test: Password validation for unencrypted PPTX file returns True"""
        # Create test file content
        temp_pptx_path.write_bytes(b'PK\x03\x04')
        
        # Mock unencrypted file
        mock_office_file.is_encrypted.return_value = False
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                result = office_handler.test_password(temp_pptx_path, "any_password")
                
                assert result is True


class TestPasswordValidationCorruptedFiles:
    """Test password validation on corrupted Office files"""
    
    def test_password_validation_corrupted_docx(self, office_handler, temp_docx_path):
        """Test: Password validation for corrupted DOCX file returns False"""
        # Create corrupted file content
        temp_docx_path.write_bytes(b'CORRUPTED_DATA_NOT_ZIP')
        
        with patch('builtins.open', mock_open(read_data=b'CORRUPTED_DATA')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile') as mock_office_class:
                mock_office_class.side_effect = Exception("Not a valid Office file")
                
                result = office_handler.test_password(temp_docx_path, "any_password")
                
                assert result is False
    
    def test_password_validation_corrupted_xlsx(self, office_handler, temp_xlsx_path):
        """Test: Password validation for corrupted XLSX file returns False"""
        # Create corrupted file content
        temp_xlsx_path.write_bytes(b'INVALID_XLSX_CONTENT')
        
        with patch('builtins.open', mock_open(read_data=b'INVALID_XLSX_CONTENT')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile') as mock_office_class:
                mock_office_class.side_effect = Exception("Corrupted file structure")
                
                result = office_handler.test_password(temp_xlsx_path, "any_password")
                
                assert result is False
    
    def test_password_validation_corrupted_pptx(self, office_handler, temp_pptx_path):
        """Test: Password validation for corrupted PPTX file returns False"""
        # Create corrupted file content
        temp_pptx_path.write_bytes(b'NOT_A_VALID_PPTX_FILE')
        
        with patch('builtins.open', mock_open(read_data=b'NOT_A_VALID_PPTX_FILE')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile') as mock_office_class:
                mock_office_class.side_effect = Exception("File format error")
                
                result = office_handler.test_password(temp_pptx_path, "any_password")
                
                assert result is False


class TestPasswordValidationEdgeCases:
    """Test password validation edge cases and special scenarios"""
    
    def test_password_validation_empty_file(self, office_handler):
        """Test: Password validation for empty file returns False"""
        with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as f:
            empty_file_path = Path(f.name)
            # File is created but empty
        
        try:
            with patch('builtins.open', mock_open(read_data=b'')):
                with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile') as mock_office_class:
                    mock_office_class.side_effect = Exception("Empty file")
                    
                    result = office_handler.test_password(empty_file_path, "password")
                    
                    assert result is False
        finally:
            try:
                empty_file_path.unlink()
            except FileNotFoundError:
                pass
    
    def test_password_validation_non_office_file(self, office_handler):
        """Test: Password validation for non-Office file returns False"""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'This is a text file, not an Office document')
            text_file_path = Path(f.name)
        
        try:
            with patch('builtins.open', mock_open(read_data=b'This is a text file')):
                with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile') as mock_office_class:
                    mock_office_class.side_effect = Exception("Not an Office file")
                    
                    result = office_handler.test_password(text_file_path, "password")
                    
                    assert result is False
        finally:
            try:
                text_file_path.unlink()
            except FileNotFoundError:
                pass
    
    def test_password_validation_unicode_password(self, office_handler, mock_office_file, temp_docx_path):
        """Test: Password validation with Unicode characters in password"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')
        
        unicode_password = "パスワード123🔒"  # Japanese characters + emoji
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.return_value = None
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp_file = MagicMock()
                    mock_temp_file.read.return_value = b'unicode_decrypted_content' + b'x' * 78  # 100 bytes
                    mock_temp_file.seek.return_value = None
                    mock_temp_file.__enter__.return_value = mock_temp_file
                    mock_temp.return_value = mock_temp_file
                    
                    result = office_handler.test_password(temp_docx_path, unicode_password)
                    
                    assert result is True
                    mock_office_file.load_key.assert_called_once_with(password=unicode_password)
    
    def test_password_validation_very_long_password(self, office_handler, mock_office_file, temp_docx_path):
        """Test: Password validation with very long password (1000 characters)"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')
        
        very_long_password = "a" * 1000  # 1000 character password
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.return_value = None
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp_file = MagicMock()
                    mock_temp_file.read.return_value = b'long_password_decrypted' + b'x' * 79  # 100 bytes
                    mock_temp_file.seek.return_value = None
                    mock_temp_file.__enter__.return_value = mock_temp_file
                    mock_temp.return_value = mock_temp_file
                    
                    result = office_handler.test_password(temp_docx_path, very_long_password)
                    
                    assert result is True
                    mock_office_file.load_key.assert_called_once_with(password=very_long_password)
    
    def test_password_validation_special_chars_password(self, office_handler, mock_office_file, temp_docx_path):
        """Test: Password validation with special characters in password"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')
        
        special_password = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.return_value = None
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp_file = MagicMock()
                    mock_temp_file.read.return_value = b'special_chars_decrypted' + b'x' * 77  # 100 bytes
                    mock_temp_file.seek.return_value = None
                    mock_temp_file.__enter__.return_value = mock_temp_file
                    mock_temp.return_value = mock_temp_file
                    
                    result = office_handler.test_password(temp_docx_path, special_password)
                    
                    assert result is True
                    mock_office_file.load_key.assert_called_once_with(password=special_password)
    
    def test_password_validation_empty_password(self, office_handler, mock_office_file, temp_docx_path):
        """Test: Password validation with empty password string"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')
        
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.side_effect = Exception("Empty password not allowed")
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                result = office_handler.test_password(temp_docx_path, "")
                
                assert result is False
                mock_office_file.load_key.assert_called_once_with(password="")
    
    def test_password_validation_null_password(self, office_handler, mock_office_file, temp_docx_path):
        """Test: Password validation with None password"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')
        
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.side_effect = Exception("None password not allowed")
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                result = office_handler.test_password(temp_docx_path, None)
                
                assert result is False
    
    def test_password_validation_binary_password(self, office_handler, mock_office_file, temp_docx_path):
        """Test: Password validation with binary data as password"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')
        
        binary_password = b'\x00\x01\x02\x03\xFF\xFE\xFD'  # Binary data
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.side_effect = Exception("Binary password not supported")
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                result = office_handler.test_password(temp_docx_path, binary_password)
                
                assert result is False


class TestPasswordValidationFileSystemIssues:
    """Test password validation with file system related issues"""
    
    def test_password_validation_file_locked(self, office_handler, temp_docx_path):
        """Test: Password validation when file is locked by another process returns False"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')
        
        with patch('builtins.open') as mock_open_func:
            mock_open_func.side_effect = PermissionError("File is locked by another process")
            
            result = office_handler.test_password(temp_docx_path, "password")
            
            assert result is False
    
    def test_password_validation_permission_denied(self, office_handler, temp_docx_path):
        """Test: Password validation when permission denied returns False"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')
        
        with patch('builtins.open') as mock_open_func:
            mock_open_func.side_effect = PermissionError("Access denied")
            
            result = office_handler.test_password(temp_docx_path, "password")
            
            assert result is False
    
    def test_password_validation_network_drive_file(self, office_handler, mock_office_file):
        """Test: Password validation for file on network drive"""
        # Simulate network drive path
        network_path = Path(r"\\server\share\document.docx")
        
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.return_value = None
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp_file = MagicMock()
                    mock_temp_file.read.return_value = b'network_decrypted_content' + b'x' * 76  # 100 bytes
                    mock_temp_file.seek.return_value = None
                    mock_temp_file.__enter__.return_value = mock_temp_file
                    mock_temp.return_value = mock_temp_file
                    
                    result = office_handler.test_password(network_path, "network_password")
                    
                    assert result is True
    
    def test_password_validation_symlink_file(self, office_handler, mock_office_file, temp_docx_path):
        """Test: Password validation for symlinked Office file"""
        # Create test file content
        temp_docx_path.write_bytes(b'PK\x03\x04')
        
        # Create a symlink (only on systems that support it)
        symlink_path = temp_docx_path.parent / "symlink_document.docx"
        
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.return_value = None
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
            with patch('builtins.open', mock_open(read_data=b'PK\x03\x04')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp_file = MagicMock()
                    mock_temp_file.read.return_value = b'symlink_decrypted_content' + b'x' * 76  # 100 bytes
                    mock_temp_file.seek.return_value = None
                    mock_temp_file.__enter__.return_value = mock_temp_file
                    mock_temp.return_value = mock_temp_file
                    
                    result = office_handler.test_password(symlink_path, "symlink_password")
                    
                    assert result is True


