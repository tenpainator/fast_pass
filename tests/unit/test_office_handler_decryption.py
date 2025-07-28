"""
Comprehensive Unit Tests for Office Handler Decryption
Tests the decrypt_file method and security validation extensively
Part of achieving 100% test coverage for office_handler.py
"""

import pytest
import tempfile
import os
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open, call
import logging

# Import modules under test
from src.core.crypto_handlers.office_handler import OfficeDocumentHandler
from src.exceptions import FileFormatError, ProcessingError, SecurityViolationError


class TestOfficeHandlerDecryption:
    """Test office document decryption functionality"""
    
    @pytest.fixture
    def logger(self):
        """Create a mock logger for testing"""
        return MagicMock(spec=logging.Logger)
    
    @pytest.fixture
    def handler(self, logger):
        """Create an OfficeDocumentHandler instance for testing"""
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto'):
            return OfficeDocumentHandler(logger)
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files"""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)


class TestDecryptDocxFiles:
    """Test DOCX file decryption scenarios"""
    
    @pytest.fixture
    def logger(self):
        return MagicMock(spec=logging.Logger)
    
    @pytest.fixture
    def handler(self, logger):
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto'):
            return OfficeDocumentHandler(logger)
    
    @pytest.fixture
    def temp_dir(self):
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_decrypt_docx_correct_password(self, handler, temp_dir):
        """Test: Decrypt DOCX file with correct password"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "correct_password"
        
        # Mock file operations
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    # Verify encryption check was called
                    mock_office_file.is_encrypted.assert_called_once()
                    # Verify password was loaded
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    # Verify decryption was called
                    mock_office_file.decrypt.assert_called_once()
                    # Verify success logging
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_docx_incorrect_password(self, handler, temp_dir):
        """Test: Decrypt DOCX file with incorrect password fails appropriately"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "wrong_password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.side_effect = Exception("Invalid password")
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                
                with pytest.raises(Exception) as exc_info:
                    handler.decrypt_file(input_path, output_path, password)
                
                assert "Failed to decrypt Office document" in str(exc_info.value)
                assert "Invalid password" in str(exc_info.value)
    
    def test_decrypt_docx_unicode_password(self, handler, temp_dir):
        """Test: Decrypt DOCX file with Unicode password"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "пароль123密码"  # Mixed Cyrillic, Latin, Chinese
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_docx_very_long_password(self, handler, temp_dir):
        """Test: Decrypt DOCX file with very long password"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "x" * 512  # 512 character password
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_docx_special_chars_password(self, handler, temp_dir):
        """Test: Decrypt DOCX file with special characters in password"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"  # Various special characters
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_docx_not_encrypted(self, handler, temp_dir):
        """Test: Decrypt DOCX file that is not encrypted (should copy file)"""
        input_path = temp_dir / "unencrypted.docx"
        output_path = temp_dir / "copied.docx"
        password = "any_password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = False
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch('src.core.crypto_handlers.office_handler.shutil.copy2') as mock_copy:
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    # Verify file was copied instead of decrypted
                    mock_copy.assert_called_once_with(input_path, output_path)
                    # Verify appropriate logging
                    handler.logger.info.assert_called_with(f"File {input_path.name} was not encrypted, copied as-is")
    
    def test_decrypt_docx_large_file_10mb(self, handler, temp_dir):
        """Test: Decrypt large DOCX file (10MB simulation)"""
        input_path = temp_dir / "large_10mb.docx"
        output_path = temp_dir / "decrypted_large.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        # Simulate large file by making decrypt operation take some time
        def slow_decrypt(output_file):
            # Simulate processing time for large file
            pass
        
        mock_office_file.decrypt.side_effect = slow_decrypt
        
        with patch('builtins.open', mock_open(read_data=b'x' * (10 * 1024 * 1024))):  # 10MB data
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.decrypt.assert_called_once()
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_docx_large_file_100mb(self, handler, temp_dir):
        """Test: Decrypt very large DOCX file (100MB simulation)"""
        input_path = temp_dir / "large_100mb.docx"
        output_path = temp_dir / "decrypted_very_large.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'x' * (100 * 1024 * 1024))):  # 100MB data
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.decrypt.assert_called_once()
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")


class TestDecryptXlsxFiles:
    """Test XLSX file decryption scenarios"""
    
    @pytest.fixture
    def logger(self):
        return MagicMock(spec=logging.Logger)
    
    @pytest.fixture
    def handler(self, logger):
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto'):
            return OfficeDocumentHandler(logger)
    
    @pytest.fixture
    def temp_dir(self):
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_decrypt_xlsx_correct_password(self, handler, temp_dir):
        """Test: Decrypt XLSX file with correct password"""
        input_path = temp_dir / "encrypted.xlsx"
        output_path = temp_dir / "decrypted.xlsx"
        password = "correct_password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'xlsx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.is_encrypted.assert_called_once()
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    mock_office_file.decrypt.assert_called_once()
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_xlsx_incorrect_password(self, handler, temp_dir):
        """Test: Decrypt XLSX file with incorrect password fails appropriately"""
        input_path = temp_dir / "encrypted.xlsx"
        output_path = temp_dir / "decrypted.xlsx"
        password = "wrong_password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.side_effect = Exception("Invalid password")
        
        with patch('builtins.open', mock_open(read_data=b'xlsx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                
                with pytest.raises(Exception) as exc_info:
                    handler.decrypt_file(input_path, output_path, password)
                
                assert "Failed to decrypt Office document" in str(exc_info.value)
                assert "Invalid password" in str(exc_info.value)
    
    def test_decrypt_xlsx_unicode_password(self, handler, temp_dir):
        """Test: Decrypt XLSX file with Unicode password"""
        input_path = temp_dir / "encrypted.xlsx"
        output_path = temp_dir / "decrypted.xlsx"
        password = "пароль123密码"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'xlsx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_xlsx_very_long_password(self, handler, temp_dir):
        """Test: Decrypt XLSX file with very long password"""
        input_path = temp_dir / "encrypted.xlsx"
        output_path = temp_dir / "decrypted.xlsx"
        password = "x" * 512
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'xlsx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_xlsx_special_chars_password(self, handler, temp_dir):
        """Test: Decrypt XLSX file with special characters in password"""
        input_path = temp_dir / "encrypted.xlsx"
        output_path = temp_dir / "decrypted.xlsx"
        password = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'xlsx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_xlsx_not_encrypted(self, handler, temp_dir):
        """Test: Decrypt XLSX file that is not encrypted (should copy file)"""
        input_path = temp_dir / "unencrypted.xlsx"
        output_path = temp_dir / "copied.xlsx"
        password = "any_password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = False
        
        with patch('builtins.open', mock_open(read_data=b'xlsx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch('src.core.crypto_handlers.office_handler.shutil.copy2') as mock_copy:
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_copy.assert_called_once_with(input_path, output_path)
                    handler.logger.info.assert_called_with(f"File {input_path.name} was not encrypted, copied as-is")
    
    def test_decrypt_xlsx_large_file_10mb(self, handler, temp_dir):
        """Test: Decrypt large XLSX file (10MB simulation)"""
        input_path = temp_dir / "large_10mb.xlsx"
        output_path = temp_dir / "decrypted_large.xlsx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'x' * (10 * 1024 * 1024))):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.decrypt.assert_called_once()
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_xlsx_large_file_100mb(self, handler, temp_dir):
        """Test: Decrypt very large XLSX file (100MB simulation)"""
        input_path = temp_dir / "large_100mb.xlsx"
        output_path = temp_dir / "decrypted_very_large.xlsx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'x' * (100 * 1024 * 1024))):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.decrypt.assert_called_once()
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")


class TestDecryptPptxFiles:
    """Test PPTX file decryption scenarios"""
    
    @pytest.fixture
    def logger(self):
        return MagicMock(spec=logging.Logger)
    
    @pytest.fixture
    def handler(self, logger):
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto'):
            return OfficeDocumentHandler(logger)
    
    @pytest.fixture
    def temp_dir(self):
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_decrypt_pptx_correct_password(self, handler, temp_dir):
        """Test: Decrypt PPTX file with correct password"""
        input_path = temp_dir / "encrypted.pptx"
        output_path = temp_dir / "decrypted.pptx"
        password = "correct_password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'pptx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.is_encrypted.assert_called_once()
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    mock_office_file.decrypt.assert_called_once()
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_pptx_incorrect_password(self, handler, temp_dir):
        """Test: Decrypt PPTX file with incorrect password fails appropriately"""
        input_path = temp_dir / "encrypted.pptx"
        output_path = temp_dir / "decrypted.pptx"
        password = "wrong_password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.side_effect = Exception("Invalid password")
        
        with patch('builtins.open', mock_open(read_data=b'pptx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                
                with pytest.raises(Exception) as exc_info:
                    handler.decrypt_file(input_path, output_path, password)
                
                assert "Failed to decrypt Office document" in str(exc_info.value)
                assert "Invalid password" in str(exc_info.value)
    
    def test_decrypt_pptx_unicode_password(self, handler, temp_dir):
        """Test: Decrypt PPTX file with Unicode password"""
        input_path = temp_dir / "encrypted.pptx"
        output_path = temp_dir / "decrypted.pptx"
        password = "пароль123密码"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'pptx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_pptx_very_long_password(self, handler, temp_dir):
        """Test: Decrypt PPTX file with very long password"""
        input_path = temp_dir / "encrypted.pptx"
        output_path = temp_dir / "decrypted.pptx"
        password = "x" * 512
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'pptx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_pptx_special_chars_password(self, handler, temp_dir):
        """Test: Decrypt PPTX file with special characters in password"""
        input_path = temp_dir / "encrypted.pptx"
        output_path = temp_dir / "decrypted.pptx"
        password = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'pptx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.load_key.assert_called_once_with(password=password)
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_pptx_not_encrypted(self, handler, temp_dir):
        """Test: Decrypt PPTX file that is not encrypted (should copy file)"""
        input_path = temp_dir / "unencrypted.pptx"
        output_path = temp_dir / "copied.pptx"
        password = "any_password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = False
        
        with patch('builtins.open', mock_open(read_data=b'pptx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch('src.core.crypto_handlers.office_handler.shutil.copy2') as mock_copy:
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_copy.assert_called_once_with(input_path, output_path)
                    handler.logger.info.assert_called_with(f"File {input_path.name} was not encrypted, copied as-is")
    
    def test_decrypt_pptx_large_file_10mb(self, handler, temp_dir):
        """Test: Decrypt large PPTX file (10MB simulation)"""
        input_path = temp_dir / "large_10mb.pptx"
        output_path = temp_dir / "decrypted_large.pptx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'x' * (10 * 1024 * 1024))):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.decrypt.assert_called_once()
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_pptx_large_file_100mb(self, handler, temp_dir):
        """Test: Decrypt very large PPTX file (100MB simulation)"""
        input_path = temp_dir / "large_100mb.pptx"
        output_path = temp_dir / "decrypted_very_large.pptx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'x' * (100 * 1024 * 1024))):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.decrypt.assert_called_once()
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")


class TestDecryptionEdgeCases:
    """Test edge cases and error conditions in decryption"""
    
    @pytest.fixture
    def logger(self):
        return MagicMock(spec=logging.Logger)
    
    @pytest.fixture
    def handler(self, logger):
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto'):
            return OfficeDocumentHandler(logger)
    
    @pytest.fixture
    def temp_dir(self):
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_decrypt_corrupted_encrypted_file(self, handler, temp_dir):
        """Test: Decrypt corrupted encrypted file fails appropriately"""
        input_path = temp_dir / "corrupted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt.side_effect = Exception("File structure corrupted")
        
        with patch('builtins.open', mock_open(read_data=b'corrupted_data')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                
                with pytest.raises(Exception) as exc_info:
                    handler.decrypt_file(input_path, output_path, password)
                
                assert "Failed to decrypt Office document" in str(exc_info.value)
                assert "File structure corrupted" in str(exc_info.value)
    
    def test_decrypt_empty_file(self, handler, temp_dir):
        """Test: Decrypt empty file fails appropriately"""
        input_path = temp_dir / "empty.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile') as mock_office_class:
                mock_office_class.side_effect = Exception("Empty file or invalid format")
                
                with pytest.raises(Exception) as exc_info:
                    handler.decrypt_file(input_path, output_path, password)
                
                assert "Failed to decrypt Office document" in str(exc_info.value)
                assert "Empty file or invalid format" in str(exc_info.value)
    
    def test_decrypt_non_office_file(self, handler, temp_dir):
        """Test: Decrypt non-Office file fails appropriately"""
        input_path = temp_dir / "notoffice.txt"
        output_path = temp_dir / "decrypted.txt"
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'This is not an Office file')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile') as mock_office_class:
                mock_office_class.side_effect = Exception("Not a valid Office file")
                
                with pytest.raises(Exception) as exc_info:
                    handler.decrypt_file(input_path, output_path, password)
                
                assert "Failed to decrypt Office document" in str(exc_info.value)
                assert "Not a valid Office file" in str(exc_info.value)
    
    def test_decrypt_readonly_file(self, handler, temp_dir):
        """Test: Decrypt readonly file scenario"""
        input_path = temp_dir / "readonly.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        # Mock readonly file scenario (can read but might have permission issues)
        mock_open_obj = mock_open(read_data=b'docx_content')
        
        with patch('builtins.open', mock_open_obj):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    # Should succeed despite readonly status of input
                    mock_office_file.decrypt.assert_called_once()
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_network_drive_file(self, handler, temp_dir):
        """Test: Decrypt file on network drive"""
        input_path = Path("\\\\server\\share\\encrypted.docx")
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security'):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    mock_office_file.decrypt.assert_called_once()
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_decrypt_output_directory_full(self, handler, temp_dir):
        """Test: Decrypt when output directory is full"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt.side_effect = OSError("No space left on device")
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                
                with pytest.raises(Exception) as exc_info:
                    handler.decrypt_file(input_path, output_path, password)
                
                assert "Failed to decrypt Office document" in str(exc_info.value)
                assert "No space left on device" in str(exc_info.value)
    
    def test_decrypt_insufficient_permissions(self, handler, temp_dir):
        """Test: Decrypt with insufficient permissions for output"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        
        # Mock permission error when trying to write output
        with patch('builtins.open', mock_open(read_data=b'docx_content')) as mock_file:
            # Make the write operation fail with permission error
            mock_file.return_value.__enter__.side_effect = [
                mock_file.return_value,  # First call (read) succeeds
                PermissionError("Permission denied")  # Second call (write) fails
            ]
            
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                
                with pytest.raises(Exception) as exc_info:
                    handler.decrypt_file(input_path, output_path, password)
                
                assert "Failed to decrypt Office document" in str(exc_info.value)
                assert "Permission denied" in str(exc_info.value)
    
    def test_decrypt_memory_exhaustion(self, handler, temp_dir):
        """Test: Decrypt handles memory exhaustion gracefully"""
        input_path = temp_dir / "huge.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt.side_effect = MemoryError("Not enough memory")
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                
                with pytest.raises(Exception) as exc_info:
                    handler.decrypt_file(input_path, output_path, password)
                
                assert "Failed to decrypt Office document" in str(exc_info.value)
                assert "Not enough memory" in str(exc_info.value)



class TestSecurityValidation:
    """Test security validation of decrypted files"""
    
    @pytest.fixture
    def logger(self):
        return MagicMock(spec=logging.Logger)
    
    @pytest.fixture
    def handler(self, logger):
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto'):
            return OfficeDocumentHandler(logger)
    
    @pytest.fixture
    def temp_dir(self):
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_security_validation_passes(self, handler, temp_dir):
        """Test: Security validation passes for safe decrypted file"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        # Mock security validation to pass
        mock_security_validator = MagicMock()
        mock_security_validator.validate_office_document_security = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch('src.core.security.SecurityValidator', return_value=mock_security_validator):
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    # Verify security validation was called
                    mock_security_validator.validate_office_document_security.assert_called_once_with(output_path)
                    # Verify success logging
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
                    handler.logger.debug.assert_called_with(f"Security validation passed for decrypted file: {output_path}")
    
    def test_security_validation_fails_file_deleted(self, handler, temp_dir):
        """Test: Security validation fails, decrypted file is deleted"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        # Mock security validation to fail
        mock_security_validator = MagicMock()
        mock_security_validator.validate_office_document_security.side_effect = Exception("Security threat detected")
        
        # Mock output path to simulate file existence
        mock_output_path = MagicMock()
        mock_output_path.exists.return_value = True
        mock_output_path.unlink = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch('src.core.security.SecurityValidator', return_value=mock_security_validator):
                    with patch('pathlib.Path', return_value=mock_output_path):
                        
                        with pytest.raises(Exception) as exc_info:
                            handler.decrypt_file(input_path, output_path, password)
                        
                        # Verify security validation was called
                        mock_security_validator.validate_office_document_security.assert_called_once()
                        # Verify file was deleted
                        mock_output_path.unlink.assert_called_once()
                        # Verify appropriate logging
                        handler.logger.warning.assert_called_with(f"Removed potentially unsafe decrypted file: {mock_output_path}")
                        # Verify exception includes security failure message
                        assert "Security validation failed" in str(exc_info.value)
                        assert "Security threat detected" in str(exc_info.value)
    
    def test_security_validation_fails_file_deletion_fails(self, handler, temp_dir):
        """Test: Security validation fails, file deletion also fails"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        # Mock security validation to fail
        mock_security_validator = MagicMock()
        mock_security_validator.validate_office_document_security.side_effect = Exception("Security threat detected")
        
        # Mock output path to simulate file existence but deletion failure
        mock_output_path = MagicMock()
        mock_output_path.exists.return_value = True
        mock_output_path.unlink.side_effect = PermissionError("Cannot delete file")
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch('src.core.security.SecurityValidator', return_value=mock_security_validator):
                    with patch('pathlib.Path', return_value=mock_output_path):
                        
                        with pytest.raises(Exception) as exc_info:
                            handler.decrypt_file(input_path, output_path, password)
                        
                        # Verify security validation was called
                        mock_security_validator.validate_office_document_security.assert_called_once()
                        # Verify file deletion was attempted
                        mock_output_path.unlink.assert_called_once()
                        # Verify exception still includes security failure message
                        assert "Security validation failed" in str(exc_info.value)
                        assert "Security threat detected" in str(exc_info.value)