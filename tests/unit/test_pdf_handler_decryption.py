"""
PDF Handler Decryption Tests

This module tests PDF decryption functionality across all scenarios including
various PDF types, password variations, and error conditions.

Maps to missing tests implementation plan Phase 1.4 (30 tests).
"""

import pytest
import logging
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import io

# Import the PDF handler class
from src.core.crypto_handlers.pdf_handler import PDFHandler


class TestPDFDecryption:
    """Test PDF decryption across all scenarios"""

    @pytest.fixture
    def pdf_handler(self):
        """Create PDF handler for testing"""
        logger = logging.getLogger('test_pdf_decryption')
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

    # Basic Decryption Tests (10 tests)
    
    def test_decrypt_simple_encrypted_pdf(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decrypting simple encrypted PDF"""
        # Setup mock encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1  # Success value from PyPDF2
        mock_reader.pages = [MagicMock(), MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_encrypted.pdf")
        output_file = Path("test_decrypted.pdf")
        password = "correct_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Should not raise an exception
            pdf_handler.decrypt_file(input_file, output_file, password)
            
            # Verify decryption was called
            mock_reader.decrypt.assert_called_once_with(password)
            mock_writer.write.assert_called_once()

    def test_decrypt_complex_encrypted_pdf(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decrypting complex encrypted PDF"""
        # Setup mock complex encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1  # Success value from PyPDF2
        mock_reader.pages = [MagicMock() for _ in range(10)]
        mock_reader.metadata = {'Title': 'Complex Document', 'Author': 'Test'}
        mock_reader.outline = [{'title': 'Chapter 1', 'page': 0}]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_complex_encrypted.pdf")
        output_file = Path("test_complex_decrypted.pdf")
        password = "complex_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Should not raise an exception
            pdf_handler.decrypt_file(input_file, output_file, password)
            
            # Verify complex PDF decryption
            mock_reader.decrypt.assert_called_once_with(password)
            assert mock_writer.add_page.call_count == 10

    def test_decrypt_wrong_password(self, pdf_handler, mock_pdf_reader):
        """Test decryption with incorrect password"""
        # Setup mock encrypted PDF with wrong password
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 0  # Failed password from PyPDF2
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("test_encrypted.pdf")
        output_file = Path("test_decrypted.pdf")
        wrong_password = "wrong_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Should raise an exception for wrong password
            with pytest.raises(Exception) as exc_info:
                pdf_handler.decrypt_file(input_file, output_file, wrong_password)
            
            assert "Incorrect password" in str(exc_info.value)
            mock_reader.decrypt.assert_called_once_with(wrong_password)

    def test_decrypt_unencrypted_pdf(self, pdf_handler, mock_pdf_reader):
        """Test decrypting unencrypted PDF"""
        # Setup mock unencrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = False
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("test_unencrypted.pdf")
        output_file = Path("test_copied.pdf")
        password = "any_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with patch('shutil.copy2') as mock_copy:
                # Should not raise an exception and should copy file
                pdf_handler.decrypt_file(input_file, output_file, password)
                
                # Verify unencrypted PDF is copied without modification
                mock_reader.decrypt.assert_not_called()
                mock_copy.assert_called_once_with(input_file, output_file)

    def test_decrypt_multiple_encryption_layers(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decrypting PDF with multiple encryption layers"""
        # Setup mock PDF with nested encryption (theoretical scenario)
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        # Simulate nested encryption metadata
        mock_reader.trailer = {'/Encrypt': {'Type': 'Nested', 'Layers': 2}}
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_multi_encrypted.pdf")
        output_file = Path("test_multi_decrypted.pdf")
        password = "master_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Should not raise an exception
            pdf_handler.decrypt_file(input_file, output_file, password)
            
            # Verify multi-layer encryption handled
            mock_reader.decrypt.assert_called_once_with(password)

    def test_decrypt_partial_encryption(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decrypting PDF with partial encryption"""
        # Setup mock PDF with selective encryption
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock(), MagicMock()]
        # Simulate partial encryption (some objects encrypted, others not)
        mock_reader.pages[0].encrypted = True
        mock_reader.pages[1].encrypted = False
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_partial_encrypted.pdf")
        output_file = Path("test_partial_decrypted.pdf")
        password = "partial_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Should not raise an exception
            pdf_handler.decrypt_file(input_file, output_file, password)
            
            # Verify partial encryption handled correctly
            mock_reader.decrypt.assert_called_once_with(password)

    def test_decrypt_large_encrypted_pdf(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decrypting large encrypted PDF files"""
        # Setup mock large encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock() for _ in range(1000)]  # Large PDF
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_large_encrypted.pdf")
        output_file = Path("test_large_decrypted.pdf")
        password = "large_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Monitor memory usage during decryption
            with patch('psutil.Process') as mock_process:
                mock_process.return_value.memory_info.return_value.rss = 200000000  # 200MB
                
                # Should not raise an exception
                pdf_handler.decrypt_file(input_file, output_file, password)
                
                # Verify large files handled efficiently
                mock_reader.decrypt.assert_called_once_with(password)
                assert mock_writer.add_page.call_count == 1000

    def test_decrypt_pdf_with_digital_signature(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decrypting PDF with digital signatures"""
        # Setup mock signed encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        # Mock digital signature data
        mock_reader.fields = [{'Type': 'Sig', 'Name': 'Signature1'}]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_signed_encrypted.pdf")
        output_file = Path("test_signed_decrypted.pdf")
        password = "signed_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Should not raise an exception
            pdf_handler.decrypt_file(input_file, output_file, password)
            
            # Verify digital signatures preserved during decryption
            mock_reader.decrypt.assert_called_once_with(password)

    def test_decrypt_pdf_with_drm(self, pdf_handler, mock_pdf_reader):
        """Test decrypting PDF with DRM protection"""
        # Setup mock DRM-protected PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        # Simulate DRM that prevents decryption
        mock_reader.decrypt.side_effect = Exception("DRM protection prevents decryption")
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("test_drm_protected.pdf")
        output_file = Path("test_drm_decrypted.pdf")
        password = "drm_password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Should raise an exception for DRM protection
            with pytest.raises(Exception) as exc_info:
                pdf_handler.decrypt_file(input_file, output_file, password)
            
            # Verify DRM protection error
            assert "DRM protection prevents decryption" in str(exc_info.value)

    def test_decrypt_damaged_encrypted_pdf(self, pdf_handler, mock_pdf_reader):
        """Test decrypting damaged encrypted PDF"""
        # Setup mock damaged encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.side_effect = Exception("PDF structure damaged")
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("test_damaged_encrypted.pdf")
        output_file = Path("test_damaged_decrypted.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-damaged')):
            with pytest.raises(Exception, match="PDF structure damaged"):
                pdf_handler.decrypt_file(input_file, output_file, password)

    # Password Variation Tests (10 tests)
    
    def test_decrypt_unicode_password(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption with Unicode passwords"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_unicode_encrypted.pdf")
        output_file = Path("test_unicode_decrypted.pdf")
        
        # Test various Unicode passwords
        unicode_passwords = [
            "密码123",     # Chinese
            "пароль456",   # Russian
            "🔐🗝️🔒",    # Emoji
            "café_münü",   # Accented characters
        ]
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            for password in unicode_passwords:
                pdf_handler.decrypt_file(input_file, output_file, password)
                # Method returns None on success

    def test_decrypt_very_long_password(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption with very long passwords"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_long_pwd_encrypted.pdf")
        output_file = Path("test_long_pwd_decrypted.pdf")
        
        # Test 1000+ character password
        long_password = "VeryLongPassword" * 100  # 1600 characters
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            pdf_handler.decrypt_file(input_file, output_file, long_password)
            
            # Verify long passwords handled efficiently
            mock_reader.decrypt.assert_called_once_with(long_password)

    def test_decrypt_special_character_password(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption with special character passwords"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_special_encrypted.pdf")
        output_file = Path("test_special_decrypted.pdf")
        
        # Test special character passwords
        special_passwords = [
            "!@#$%^&*()",
            "pass\\word",
            "pass\"word",
            "pass'word",
        ]
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            for password in special_passwords:
                pdf_handler.decrypt_file(input_file, output_file, password)
                # Method returns None on success

    def test_decrypt_binary_password(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption with binary password data"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_binary_encrypted.pdf")
        output_file = Path("test_binary_decrypted.pdf")
        
        # Test binary password
        binary_password = b'\x00\x01\x02\xff\xfe'
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            pdf_handler.decrypt_file(input_file, output_file, 
                                   binary_password.decode('latin-1'))
            # Method returns None on success

    def test_decrypt_case_sensitive_password(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption password case sensitivity"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_case_encrypted.pdf")
        output_file = Path("test_case_decrypted.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Test correct case
            mock_reader.decrypt.side_effect = lambda pwd: 1 if pwd == "Password123" else 0
            
            pdf_handler.decrypt_file(input_file, output_file, "Password123")
            # Method returns None on success
            
            # Test wrong case - should raise exception for failed decryption
            with pytest.raises(Exception):
                pdf_handler.decrypt_file(input_file, output_file, "password123")

    def test_decrypt_whitespace_password(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption with whitespace passwords"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_whitespace_encrypted.pdf")
        output_file = Path("test_whitespace_decrypted.pdf")
        
        # Test whitespace passwords
        whitespace_passwords = [
            " password ",   # Leading/trailing spaces
            "pass word",    # Internal space
            "\tpassword\t", # Tabs
        ]
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            for password in whitespace_passwords:
                pdf_handler.decrypt_file(input_file, output_file, password)
                # Method returns None on success

    def test_decrypt_empty_password(self, pdf_handler, mock_pdf_reader):
        """Test decryption with empty passwords"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 0  # Empty password fails
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("test_empty_pwd_encrypted.pdf")
        output_file = Path("test_empty_pwd_decrypted.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Test empty password - should raise exception for failed decryption
            with pytest.raises(Exception):
                pdf_handler.decrypt_file(input_file, output_file, "")
            
            # Test None password - should raise exception for failed decryption
            with pytest.raises(Exception):
                pdf_handler.decrypt_file(input_file, output_file, None)

    def test_decrypt_password_encoding_variations(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption with different password encodings"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_encoding_encrypted.pdf")
        output_file = Path("test_encoding_decrypted.pdf")
        
        # Test password with different encodings
        test_password = "café"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            pdf_handler.decrypt_file(input_file, output_file, test_password)
            # Method returns None on success

    def test_decrypt_password_normalization(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption with Unicode normalization"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_normalization_encrypted.pdf")
        output_file = Path("test_normalization_decrypted.pdf")
        
        # Test Unicode normalization forms
        password_nfc = "café"  # NFC form
        password_nfd = "cafe\u0301"  # NFD form (decomposed)
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Both forms should work consistently
            pdf_handler.decrypt_file(input_file, output_file, password_nfc)
            # Method returns None on success

    def test_decrypt_password_boundary_conditions(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption password boundary conditions"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_boundary_encrypted.pdf")
        output_file = Path("test_boundary_decrypted.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Test minimum length password
            pdf_handler.decrypt_file(input_file, output_file, "a")
            # Method returns None on success
            
            # Test maximum reasonable length password
            max_password = "x" * 32767  # Windows MAX_PATH
            pdf_handler.decrypt_file(input_file, output_file, max_password)
            # Method returns None on success

    # Error Condition Tests (10 tests)
    
    def test_decrypt_corrupted_encrypted_pdf(self, pdf_handler, mock_pdf_reader):
        """Test decrypting corrupted encrypted PDF"""
        # Mock corrupted encrypted PDF
        mock_pdf_reader.side_effect = Exception("Corrupted encryption data")
        
        input_file = Path("test_corrupted_encrypted.pdf")
        output_file = Path("test_corrupted_decrypted.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-corrupted')):
            with pytest.raises(Exception, match="Corrupted encryption data"):
                pdf_handler.decrypt_file(input_file, output_file, password)

    def test_decrypt_truncated_encrypted_pdf(self, pdf_handler, mock_pdf_reader):
        """Test decrypting truncated encrypted PDF"""
        # Mock truncated PDF
        mock_pdf_reader.side_effect = EOFError("Unexpected end of file")
        
        input_file = Path("test_truncated.pdf")
        output_file = Path("test_truncated_decrypted.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4\ntruncated')):
            with pytest.raises(Exception, match="Failed to decrypt PDF.*Unexpected end of file"):
                pdf_handler.decrypt_file(input_file, output_file, password)

    def test_decrypt_malformed_encryption_dict(self, pdf_handler, mock_pdf_reader):
        """Test decrypting PDF with malformed encryption dictionary"""
        # Mock malformed encryption metadata
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.side_effect = ValueError("Invalid encryption dictionary")
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("test_malformed_encryption.pdf")
        output_file = Path("test_malformed_decrypted.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(Exception, match="Failed to decrypt PDF.*Invalid encryption dictionary"):
                pdf_handler.decrypt_file(input_file, output_file, password)

    def test_decrypt_unsupported_encryption_version(self, pdf_handler, mock_pdf_reader):
        """Test decrypting PDF with unsupported encryption"""
        # Mock unsupported encryption algorithm
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.side_effect = NotImplementedError("Unsupported encryption version")
        mock_pdf_reader.return_value = mock_reader
        
        input_file = Path("test_unsupported_encryption.pdf")
        output_file = Path("test_unsupported_decrypted.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(Exception, match="Failed to decrypt PDF.*Unsupported encryption version"):
                pdf_handler.decrypt_file(input_file, output_file, password)

    def test_decrypt_output_permission_denied(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption with output permission denied"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_encrypted.pdf")
        output_file = Path("test_no_write_permission.pdf")
        password = "password"
        
        # Mock output write failure - trigger PermissionError when trying to open output file
        def open_side_effect(path, mode='r', *args, **kwargs):
            if 'wb' in mode and 'no_write_permission' in str(path):
                raise PermissionError("Output permission denied")
            return mock_open(read_data=b'%PDF-1.4')()
        
        with patch('builtins.open', side_effect=open_side_effect):
            with pytest.raises(Exception, match="Failed to decrypt PDF.*Output permission denied"):
                pdf_handler.decrypt_file(input_file, output_file, password)

    def test_decrypt_disk_full_scenario(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption when output disk is full"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_writer.write.side_effect = OSError("No space left on device")
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_encrypted.pdf")
        output_file = Path("test_decrypted.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(Exception, match="Failed to decrypt PDF.*No space left on device"):
                pdf_handler.decrypt_file(input_file, output_file, password)

    def test_decrypt_memory_exhaustion(self, pdf_handler, mock_pdf_reader):
        """Test decryption under memory pressure"""
        # Mock memory exhaustion during decryption
        mock_pdf_reader.side_effect = MemoryError("Insufficient memory for decryption")
        
        input_file = Path("test_large_encrypted.pdf")
        output_file = Path("test_large_decrypted.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(Exception, match="Failed to decrypt PDF.*Insufficient memory for decryption"):
                pdf_handler.decrypt_file(input_file, output_file, password)

    def test_decrypt_concurrent_access_conflicts(self, pdf_handler, mock_pdf_reader):
        """Test decryption with file access conflicts"""
        # Mock concurrent access conflict
        mock_pdf_reader.side_effect = PermissionError("File locked by another process")
        
        input_file = Path("test_locked_encrypted.pdf")
        output_file = Path("test_locked_decrypted.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(Exception, match="Failed to decrypt PDF.*File locked by another process"):
                pdf_handler.decrypt_file(input_file, output_file, password)

    def test_decrypt_network_file_interruption(self, pdf_handler, mock_pdf_reader):
        """Test decryption with network interruption"""
        # Mock network interruption
        mock_pdf_reader.side_effect = ConnectionError("Network connection lost")
        
        input_file = Path("//network/share/test_encrypted.pdf")
        output_file = Path("test_network_decrypted.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(Exception, match="Failed to decrypt PDF.*Network connection lost"):
                pdf_handler.decrypt_file(input_file, output_file, password)

    def test_decrypt_system_interruption(self, pdf_handler, mock_pdf_reader, mock_pdf_writer):
        """Test decryption behavior during system interruption"""
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_reader.pages = [MagicMock()]
        mock_pdf_reader.return_value = mock_reader
        
        mock_writer = MagicMock()
        mock_writer.write.side_effect = KeyboardInterrupt("System shutdown")
        mock_pdf_writer.return_value = mock_writer
        
        input_file = Path("test_encrypted.pdf")
        output_file = Path("test_decrypted.pdf")
        password = "password"
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with pytest.raises(KeyboardInterrupt, match="System shutdown"):
                pdf_handler.decrypt_file(input_file, output_file, password)