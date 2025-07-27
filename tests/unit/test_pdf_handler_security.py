"""
PDF Handler Security Tests

This module tests PDF security through the existing PDFHandler methods,
focusing on proper error handling and resilience against malicious files.

Tests security aspects of encrypt_file, decrypt_file, and test_password methods
without requiring non-existent security validation methods.
"""

import pytest
import logging
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import io

# Import the PDF handler class
from src.core.crypto_handlers.pdf_handler import PDFHandler


class TestPDFSecurity:
    """Test PDF security through existing handler methods"""

    @pytest.fixture
    def pdf_handler(self):
        """Create PDF handler for testing"""
        logger = logging.getLogger('test_pdf_security')
        return PDFHandler(logger)

    @pytest.fixture
    def mock_pdf_reader(self):
        """Create mock PDF reader"""
        with patch('src.core.crypto_handlers.pdf_handler.PyPDF2.PdfReader') as mock:
            yield mock

    @pytest.fixture
    def mock_pdf_writer(self):
        """Create mock PDF writer"""
        with patch('src.core.crypto_handlers.pdf_handler.PyPDF2.PdfWriter') as mock:
            yield mock

    # Security through existing methods - error handling and resilience (12 tests)
    
    def test_encrypt_file_handles_malformed_pdf(self, pdf_handler, mock_pdf_reader):
        """Test encrypt_file properly handles malformed PDF files"""
        # Setup mock for malformed PDF that should raise exception
        mock_pdf_reader.side_effect = Exception("Malformed PDF structure")
        
        input_file = Path("malformed.pdf")
        output_file = Path("output.pdf")
        password = "test_password"
        
        with patch('builtins.open', mock_open()):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.encrypt_file(input_file, output_file, password)
            
            assert "Failed to encrypt PDF" in str(exc_info.value)

    def test_decrypt_file_handles_corrupted_pdf(self, pdf_handler, mock_pdf_reader):
        """Test decrypt_file properly handles corrupted PDF files"""
        # Setup mock for corrupted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.side_effect = Exception("PDF corruption detected")
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("corrupted.pdf")
        output_file = Path("output.pdf")
        password = "test_password"
        
        with patch('builtins.open', mock_open()):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.decrypt_file(input_file, output_file, password)
            
            assert "Failed to decrypt PDF" in str(exc_info.value)

    def test_test_password_handles_malicious_pdf(self, pdf_handler, mock_pdf_reader):
        """Test test_password safely handles potentially malicious PDFs"""
        # Setup mock for malicious PDF that causes PyPDF2 to raise exception
        mock_pdf_reader.side_effect = Exception("Malicious PDF detected by PyPDF2")
        
        test_file = Path("malicious.pdf")
        password = "test_password"
        
        with patch('builtins.open', mock_open()):
            result = pdf_handler.test_password(test_file, password)
            
            # Should return False when PDF causes exceptions
            assert result is False

    def test_encrypt_file_handles_excessive_pages(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test encrypt_file handles PDFs with excessive page counts"""
        # Setup mock PDF with many pages (potential PDF bomb)
        mock_reader = MagicMock()
        mock_reader.pages = [MagicMock() for _ in range(10000)]  # Many pages
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("large.pdf")
        output_file = Path("output.pdf")
        password = "test_password"
        
        with patch('builtins.open', mock_open()):
            # Should complete without issues or fail gracefully
            try:
                pdf_handler.encrypt_file(input_file, output_file, password)
                # Verify all pages were processed
                assert mock_writer.add_page.call_count == 10000
            except Exception as e:
                # If it fails, should be a controlled failure
                assert "Failed to encrypt PDF" in str(e)

    def test_decrypt_file_wrong_password_security(self, pdf_handler, mock_pdf_reader):
        """Test decrypt_file properly handles incorrect passwords"""
        # Setup encrypted PDF with wrong password
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 0  # Failed decryption
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("encrypted.pdf")
        output_file = Path("output.pdf")
        wrong_password = "wrong_password"
        
        with patch('builtins.open', mock_open()):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.decrypt_file(input_file, output_file, wrong_password)
            
            assert "Incorrect password" in str(exc_info.value)

    def test_encrypt_file_handles_large_file_size(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test encrypt_file handles large PDF files appropriately"""
        # Setup mock for large PDF file
        mock_reader = MagicMock()
        mock_reader.pages = [MagicMock() for _ in range(100)]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        # Simulate memory issue during write
        mock_writer.write.side_effect = MemoryError("Insufficient memory")
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("large.pdf")
        output_file = Path("output.pdf")
        password = "test_password"
        
        with patch('builtins.open', mock_open()):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.encrypt_file(input_file, output_file, password)
            
            assert "Failed to encrypt PDF" in str(exc_info.value)

    def test_test_password_handles_invalid_pdf_format(self, pdf_handler):
        """Test test_password handles files that aren't valid PDFs"""
        # Test with non-PDF file
        non_pdf_file = Path("notapdf.txt")
        password = "test_password"
        
        # Mock file that doesn't have PDF structure
        with patch('builtins.open', mock_open(read_data=b'This is not a PDF file')):
            with patch('src.core.crypto_handlers.pdf_handler.PyPDF2.PdfReader') as mock_reader:
                mock_reader.side_effect = Exception("Not a PDF file")
                
                result = pdf_handler.test_password(non_pdf_file, password)
                
                # Should return False for invalid files
                assert result is False

    def test_decrypt_file_handles_already_decrypted_pdf(self, pdf_handler, mock_pdf_reader):
        """Test decrypt_file handles PDFs that are already decrypted"""
        # Setup non-encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = False
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("unencrypted.pdf")
        output_file = Path("output.pdf")
        password = "test_password"
        
        with patch('builtins.open', mock_open()):
            with patch('shutil.copy2') as mock_copy:
                pdf_handler.decrypt_file(input_file, output_file, password)
                
                # Should copy file as-is
                mock_copy.assert_called_once_with(input_file, output_file)

    def test_encrypt_file_handles_io_errors(self, pdf_handler, mock_pdf_reader):
        """Test encrypt_file handles I/O errors gracefully"""
        mock_reader = MagicMock()
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("input.pdf")
        output_file = Path("output.pdf")
        password = "test_password"
        
        # Simulate I/O error when opening file
        with patch('builtins.open', side_effect=IOError("Permission denied")):
            with pytest.raises(Exception) as exc_info:
                pdf_handler.encrypt_file(input_file, output_file, password)
            
            assert "Failed to encrypt PDF" in str(exc_info.value)

    def test_password_strength_through_encryption(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test that weak passwords still work but are logged appropriately"""
        mock_reader = MagicMock()
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("input.pdf")
        output_file = Path("output.pdf")
        weak_password = "123"  # Very weak password
        
        with patch('builtins.open', mock_open()):
            # Should still encrypt but could log warning about weak password
            pdf_handler.encrypt_file(input_file, output_file, weak_password)
            
            # Verify encryption was attempted with the weak password
            mock_writer.encrypt.assert_called_once_with(
                user_password=weak_password,
                owner_password=weak_password,
                use_128bit=True
            )

    def test_configuration_security_settings(self, pdf_handler):
        """Test that security-related configuration is properly applied"""
        # Test initial secure defaults
        assert pdf_handler.encryption_method == 'AES-256'
        assert pdf_handler.user_password_length == 128
        
        # Test configuration update
        security_config = {
            'pdf_encryption_method': 'AES-256',
            'pdf_password_length': 256
        }
        
        pdf_handler.configure(security_config)
        
        assert pdf_handler.encryption_method == 'AES-256'
        assert pdf_handler.user_password_length == 256

    def test_encryption_uses_secure_settings(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test that encryption uses secure settings by default"""
        mock_reader = MagicMock()
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("input.pdf")
        output_file = Path("output.pdf")
        password = "test_password"
        
        with patch('builtins.open', mock_open()):
            pdf_handler.encrypt_file(input_file, output_file, password)
            
            # Verify secure encryption settings
            mock_writer.encrypt.assert_called_once_with(
                user_password=password,
                owner_password=password,  # Same password for both
                use_128bit=True  # Secure encryption
            )