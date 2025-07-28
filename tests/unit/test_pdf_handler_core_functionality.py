"""
PDF Handler Core Functionality Tests

This module tests the core PDF handler functionality that exists in the current
implementation: password testing, encryption, and decryption operations.

These tests focus on increasing coverage for the actual implemented methods.
"""

import pytest
import logging
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import io

# Import the PDF handler class
from fastpass.core.crypto_handlers.pdf_handler import PDFHandler


class TestPDFHandlerCoreFunctionality:
    """Test PDF handler core functionality"""

    @pytest.fixture
    def pdf_handler(self):
        """Create PDF handler for testing"""
        logger = logging.getLogger('test_pdf_core')
        return PDFHandler(logger)

    @pytest.fixture
    def mock_pdf_reader(self):
        """Create mock PDF reader"""
        with patch('fastpass.core.crypto_handlers.pdf_handler.PyPDF2.PdfReader') as mock:
            yield mock

    @pytest.fixture
    def mock_pdf_writer(self):
        """Create mock PDF writer"""
        with patch('fastpass.core.crypto_handlers.pdf_handler.PyPDF2.PdfWriter') as mock:
            yield mock

    # Password Testing Tests (8 tests)
    
    def test_password_test_encrypted_correct(self, pdf_handler, mock_pdf_reader):
        """Test password testing with correct password"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1  # Success with user password
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("encrypted.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            result = pdf_handler.test_password(test_file, "correct_password")
            
        assert result is True
        mock_reader.decrypt.assert_called_once_with("correct_password")

    def test_password_test_encrypted_incorrect(self, pdf_handler, mock_pdf_reader):
        """Test password testing with incorrect password"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 0  # Failure
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("encrypted.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            result = pdf_handler.test_password(test_file, "wrong_password")
            
        assert result is False
        mock_reader.decrypt.assert_called_once_with("wrong_password")

    def test_password_test_unencrypted(self, pdf_handler, mock_pdf_reader):
        """Test password testing on unencrypted PDF"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = False
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("unencrypted.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            result = pdf_handler.test_password(test_file, "any_password")
            
        assert result is True
        mock_reader.decrypt.assert_not_called()

    def test_password_test_owner_password(self, pdf_handler, mock_pdf_reader):
        """Test password testing with owner password"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 2  # Success with owner password
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("encrypted.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            result = pdf_handler.test_password(test_file, "owner_password")
            
        assert result is True

    def test_password_test_file_error(self, pdf_handler, mock_pdf_reader):
        """Test password testing with file read error"""
        mock_pdf_reader.side_effect = Exception("File read error")
        
        test_file = Path("error.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            result = pdf_handler.test_password(test_file, "password")
            
        assert result is False

    def test_password_test_permission_error(self, pdf_handler):
        """Test password testing with permission error"""
        test_file = Path("no_permission.pdf")
        
        with patch('builtins.open', side_effect=PermissionError("Access denied")):
            result = pdf_handler.test_password(test_file, "password")
            
        assert result is False

    def test_password_test_file_not_found(self, pdf_handler):
        """Test password testing with file not found"""
        test_file = Path("nonexistent.pdf")
        
        with patch('builtins.open', side_effect=FileNotFoundError("File not found")):
            result = pdf_handler.test_password(test_file, "password")
            
        assert result is False

    def test_password_test_unicode_password(self, pdf_handler, mock_pdf_reader):
        """Test password testing with Unicode password"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("encrypted.pdf")
        unicode_password = "пароль密码🔒"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            result = pdf_handler.test_password(test_file, unicode_password)
            
        assert result is True
        mock_reader.decrypt.assert_called_once_with(unicode_password)

    # Encryption Tests (6 tests)
    
    def test_encrypt_basic_pdf(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test basic PDF encryption"""
        # Setup mocks
        mock_reader = MagicMock()
        mock_reader.pages = [MagicMock(), MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("input.pdf")
        output_file = Path("output.pdf")
        password = "test_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            pdf_handler.encrypt_file(input_file, output_file, password)
            
        # Verify encryption process
        assert mock_writer.add_page.call_count == 2
        mock_writer.encrypt.assert_called_once_with(
            user_password=password,
            owner_password=password,
            use_128bit=True
        )
        mock_writer.write.assert_called_once()

    def test_encrypt_empty_pdf(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test encryption of PDF with no pages"""
        mock_reader = MagicMock()
        mock_reader.pages = []  # No pages
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("empty.pdf")
        output_file = Path("empty_encrypted.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            pdf_handler.encrypt_file(input_file, output_file, password)
            
        # Verify no pages added but encryption still called
        mock_writer.add_page.assert_not_called()
        mock_writer.encrypt.assert_called_once()
        mock_writer.write.assert_called_once()

    def test_encrypt_file_read_error(self, pdf_handler):
        """Test encryption with file read error"""
        input_file = Path("unreadable.pdf")
        output_file = Path("output.pdf")
        password = "password"
        
        with patch('builtins.open', side_effect=PermissionError("Access denied")):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.encrypt_file(input_file, output_file, password)
            
        assert "Failed to encrypt PDF" in str(exc_info.value)

    def test_encrypt_pypdf2_error(self, pdf_handler, mock_pdf_reader):
        """Test encryption with PyPDF2 error"""
        mock_pdf_reader.side_effect = Exception("PyPDF2 error")
        
        input_file = Path("input.pdf")
        output_file = Path("output.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.encrypt_file(input_file, output_file, password)
            
        assert "Failed to encrypt PDF" in str(exc_info.value)

    def test_encrypt_output_write_error(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test encryption with output write error"""
        mock_reader = MagicMock()
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_writer.write.side_effect = PermissionError("Cannot write to output")
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("input.pdf")
        output_file = Path("readonly_output.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.encrypt_file(input_file, output_file, password)
            
        assert "Failed to encrypt PDF" in str(exc_info.value)

    def test_encrypt_special_characters_password(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test encryption with special characters in password"""
        mock_reader = MagicMock()
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("input.pdf")
        output_file = Path("output.pdf")
        special_password = "P@ssw0rd!#$%^&*()"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            pdf_handler.encrypt_file(input_file, output_file, special_password)
            
        mock_writer.encrypt.assert_called_once_with(
            user_password=special_password,
            owner_password=special_password,
            use_128bit=True
        )

    # Decryption Tests (6 tests)
    
    def test_decrypt_encrypted_pdf(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption of encrypted PDF"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1  # Success
        mock_reader.pages = [MagicMock(), MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("encrypted.pdf")
        output_file = Path("decrypted.pdf")
        password = "correct_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            pdf_handler.decrypt_file(input_file, output_file, password)
            
        mock_reader.decrypt.assert_called_once_with(password)
        assert mock_writer.add_page.call_count == 2
        mock_writer.write.assert_called_once()

    def test_decrypt_unencrypted_pdf(self, pdf_handler, mock_pdf_reader):
        """Test decryption of unencrypted PDF (should copy)"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = False
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("unencrypted.pdf")
        output_file = Path("copied.pdf")
        password = "any_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with patch('shutil.copy2') as mock_copy:
                pdf_handler.decrypt_file(input_file, output_file, password)
                
        mock_copy.assert_called_once_with(input_file, output_file)
        mock_reader.decrypt.assert_not_called()

    def test_decrypt_wrong_password(self, pdf_handler, mock_pdf_reader):
        """Test decryption with wrong password"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 0  # Failure
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("encrypted.pdf")
        output_file = Path("decrypted.pdf")
        password = "wrong_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.decrypt_file(input_file, output_file, password)
            
        assert "Incorrect password" in str(exc_info.value)

    def test_decrypt_file_read_error(self, pdf_handler):
        """Test decryption with file read error"""
        input_file = Path("unreadable.pdf")
        output_file = Path("output.pdf")
        password = "password"
        
        with patch('builtins.open', side_effect=PermissionError("Access denied")):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.decrypt_file(input_file, output_file, password)
            
        assert "Failed to decrypt PDF" in str(exc_info.value)

    def test_decrypt_pypdf2_error(self, pdf_handler, mock_pdf_reader):
        """Test decryption with PyPDF2 error"""
        mock_pdf_reader.side_effect = Exception("PyPDF2 error")
        
        input_file = Path("input.pdf")
        output_file = Path("output.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.decrypt_file(input_file, output_file, password)
            
        assert "Failed to decrypt PDF" in str(exc_info.value)

    def test_decrypt_output_write_error(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption with output write error"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_writer.write.side_effect = PermissionError("Cannot write output")
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("encrypted.pdf")
        output_file = Path("readonly_output.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.decrypt_file(input_file, output_file, password)
            
        assert "Failed to decrypt PDF" in str(exc_info.value)

    # Cleanup Tests (2 tests)
    
    def test_cleanup_basic(self, pdf_handler):
        """Test basic cleanup functionality"""
        # Cleanup should not raise any errors
        pdf_handler.cleanup()
        
        # Handler should remain functional
        assert pdf_handler.logger is not None
        assert pdf_handler.encryption_method == 'AES-256'

    def test_cleanup_multiple_calls(self, pdf_handler):
        """Test multiple cleanup calls"""
        # Multiple cleanup calls should be safe
        pdf_handler.cleanup()
        pdf_handler.cleanup()
        pdf_handler.cleanup()
        
        # Handler should remain functional
        assert pdf_handler.logger is not None
        assert pdf_handler.encryption_method == 'AES-256'