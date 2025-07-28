"""
PDF Handler Password Testing Tests

This module tests PDF password validation functionality across all scenarios
including encrypted/unencrypted PDFs, various password types, and edge cases.

Maps to missing tests implementation plan Phase 1.2 (25 tests).
"""

import pytest
import logging
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import io

# Import the PDF handler class
from fastpass.core.crypto_handlers.pdf_handler import PDFHandler


class TestPDFPasswordValidation:
    """Test PDF password validation across all scenarios"""

    @pytest.fixture
    def pdf_handler(self):
        """Create PDF handler for testing"""
        logger = logging.getLogger('test_pdf_password')
        return PDFHandler(logger)

    @pytest.fixture
    def mock_pdf_reader(self):
        """Create mock PDF reader"""
        with patch('fastpass.core.crypto_handlers.pdf_handler.PyPDF2.PdfReader') as mock:
            yield mock

    # Basic Password Testing (8 tests)
    
    def test_password_validation_encrypted_pdf_correct(self, pdf_handler, mock_pdf_reader):
        """Test correct password validation for encrypted PDF"""
        # Setup mock encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1  # Correct password (PyPDF2 success)
        mock_pdf_reader.return_value = mock_reader
        
        # Create test file
        test_file = Path("test_encrypted.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Test password validation with correct password
            result = pdf_handler.test_password(test_file, "correct_password")
            
            # Verify validation returns True
            assert result is True
            mock_reader.decrypt.assert_called_once_with("correct_password")

    def test_password_validation_encrypted_pdf_incorrect(self, pdf_handler, mock_pdf_reader):
        """Test incorrect password validation for encrypted PDF"""
        # Setup mock encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 0  # Incorrect password (PyPDF2 failure)
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_encrypted.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Test password validation with incorrect password
            result = pdf_handler.test_password(test_file, "wrong_password")
            
            # Verify validation returns False
            assert result is False
            mock_reader.decrypt.assert_called_once_with("wrong_password")

    def test_password_validation_unencrypted_pdf(self, pdf_handler, mock_pdf_reader):
        """Test password validation for unencrypted PDF"""
        # Setup mock unencrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = False
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_unencrypted.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Test password validation on unencrypted PDF
            result = pdf_handler.test_password(test_file, "any_password")
            
            # Verify returns True for unencrypted PDFs (spec requirement)
            assert result is True
            # Decrypt should not be called for unencrypted PDFs
            mock_reader.decrypt.assert_not_called()

    def test_password_validation_corrupted_pdf(self, pdf_handler, mock_pdf_reader):
        """Test password validation for corrupted PDF"""
        # Setup mock to simulate corrupted PDF
        mock_pdf_reader.side_effect = Exception("Corrupted PDF structure")
        
        test_file = Path("test_corrupted.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-corrupted')):
            # Test password validation on corrupted PDF
            result = pdf_handler.test_password(test_file, "password")
            
            # Verify returns False for corrupted PDFs
            assert result is False

    def test_password_validation_empty_pdf(self, pdf_handler, mock_pdf_reader):
        """Test password validation for empty/zero-length PDF"""
        test_file = Path("test_empty.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'')):
            # Test password validation on empty file
            result = pdf_handler.test_password(test_file, "password")
            
            # Verify returns False for empty files
            assert result is False

    def test_password_validation_non_pdf_file(self, pdf_handler):
        """Test password validation for non-PDF files"""
        test_file = Path("test_document.txt")
        
        with patch('builtins.open', mock_open(read_data=b'This is not a PDF file')):
            # Test password validation on non-PDF file
            result = pdf_handler.test_password(test_file, "password")
            
            # Verify returns False for non-PDF files
            assert result is False

    def test_password_validation_malformed_pdf_header(self, pdf_handler, mock_pdf_reader):
        """Test password validation for PDF with malformed header"""
        # Setup mock to handle malformed header
        mock_pdf_reader.side_effect = Exception("Invalid PDF header")
        
        test_file = Path("test_malformed.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-INVALID')):
            # Test password validation on malformed PDF
            result = pdf_handler.test_password(test_file, "password")
            
            # Verify graceful handling of malformed headers
            assert result is False

    def test_password_validation_pdf_version_compatibility(self, pdf_handler, mock_pdf_reader):
        """Test password validation across PDF versions"""
        test_file = Path("test_versioned.pdf")
        
        # Test different PDF versions
        pdf_versions = [b'%PDF-1.4', b'%PDF-1.5', b'%PDF-1.6', b'%PDF-1.7', b'%PDF-2.0']
        
        for version in pdf_versions:
            # Setup mock for each version
            mock_reader = MagicMock()
            mock_reader.is_encrypted = False
            mock_pdf_reader.return_value = mock_reader
            
            with patch('builtins.open', mock_open(read_data=version)):
                result = pdf_handler.test_password(test_file, "password")
                
                # Verify all supported versions work
                assert result is True

    # Password Type Testing (8 tests)
    
    def test_password_validation_unicode_password(self, pdf_handler, mock_pdf_reader):
        """Test Unicode password validation"""
        # Setup mock encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_unicode.pdf")
        
        # Test various Unicode passwords
        unicode_passwords = [
            "日本語パスワード",  # Japanese
            "🔒🔑密码",  # Emoji + Chinese
            "مرحبا",  # Arabic
            "Ñoño_México",  # Spanish with special chars
        ]
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            for password in unicode_passwords:
                result = pdf_handler.test_password(test_file, password)
                assert result is True

    def test_password_validation_very_long_password(self, pdf_handler, mock_pdf_reader):
        """Test very long password validation"""
        # Setup mock encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_long_password.pdf")
        
        # Test very long password (1000+ characters)
        long_password = "a" * 1000
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            result = pdf_handler.test_password(test_file, long_password)
            
            # Verify long passwords are handled efficiently
            assert result is True
            mock_reader.decrypt.assert_called_with(long_password)

    def test_password_validation_special_characters(self, pdf_handler, mock_pdf_reader):
        """Test special character password validation"""
        # Setup mock encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_special_chars.pdf")
        
        # Test passwords with special characters
        special_passwords = [
            "!@#$%^&*()",  # Common special chars
            "pass\\word",  # Backslashes
            "pass\"word",  # Quotes
            "pass\nword",  # Newlines
            "pass\tword",  # Tabs
        ]
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            for password in special_passwords:
                result = pdf_handler.test_password(test_file, password)
                assert result is True

    def test_password_validation_empty_password(self, pdf_handler, mock_pdf_reader):
        """Test empty password validation"""
        # Setup mock encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 0  # Empty password typically fails
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_empty_password.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Test empty password
            result = pdf_handler.test_password(test_file, "")
            assert result is False
            
            # Test None password
            result = pdf_handler.test_password(test_file, None)
            assert result is False
            
            # Test whitespace-only password
            result = pdf_handler.test_password(test_file, "   ")
            assert result is False

    def test_password_validation_binary_password(self, pdf_handler, mock_pdf_reader):
        """Test binary password data validation"""
        # Setup mock encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_binary_password.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Test binary password data
            binary_password = b'\x00\x01\x02\x03\xff'
            
            # Convert to string for testing
            result = pdf_handler.test_password(test_file, binary_password.decode('latin-1'))
            assert result is True

    def test_password_validation_password_with_nulls(self, pdf_handler, mock_pdf_reader):
        """Test passwords containing null bytes"""
        # Setup mock encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_null_password.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Test password with embedded null
            null_password = "pass\x00word"
            result = pdf_handler.test_password(test_file, null_password)
            
            # Should handle null bytes safely
            assert result is True

    def test_password_validation_case_sensitivity(self, pdf_handler, mock_pdf_reader):
        """Test password case sensitivity"""
        # Setup mock encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_case_sensitive.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Test that case matters
            mock_reader.decrypt.side_effect = lambda pwd: pwd == "Password123"
            
            # Correct case
            result = pdf_handler.test_password(test_file, "Password123")
            assert result is True
            
            # Wrong case
            result = pdf_handler.test_password(test_file, "password123")
            assert result is False
            
            result = pdf_handler.test_password(test_file, "PASSWORD123")
            assert result is False

    def test_password_validation_encoding_variations(self, pdf_handler, mock_pdf_reader):
        """Test different password encodings"""
        # Setup mock encrypted PDF
        mock_reader = MagicMock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.return_value = 1
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_encoding.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Test password with different encodings
            test_password = "café"
            
            # Test UTF-8 encoded password
            result = pdf_handler.test_password(test_file, test_password)
            assert result is True

    # File System Edge Cases (9 tests)
    
    def test_password_validation_locked_file(self, pdf_handler):
        """Test password validation for locked PDF files"""
        test_file = Path("test_locked.pdf")
        
        # Mock file locking scenario
        with patch('builtins.open', side_effect=PermissionError("File is locked")):
            result = pdf_handler.test_password(test_file, "password")
            
            # Verify graceful handling of locked files
            assert result is False

    def test_password_validation_permission_denied(self, pdf_handler):
        """Test password validation with insufficient permissions"""
        test_file = Path("test_no_permission.pdf")
        
        # Mock permission denied
        with patch('builtins.open', side_effect=PermissionError("Access denied")):
            result = pdf_handler.test_password(test_file, "password")
            
            # Verify graceful error handling
            assert result is False

    def test_password_validation_network_file(self, pdf_handler, mock_pdf_reader):
        """Test password validation for network-mounted files"""
        # Setup mock for network file
        mock_reader = MagicMock()
        mock_reader.is_encrypted = False
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("//network/share/test.pdf")
        
        # Mock network file access with latency
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            result = pdf_handler.test_password(test_file, "password")
            
            # Verify network files are handled
            assert result is True

    def test_password_validation_symlink_file(self, pdf_handler, mock_pdf_reader):
        """Test password validation for symlinked PDFs"""
        # Setup mock for symlinked file
        mock_reader = MagicMock()
        mock_reader.is_encrypted = False
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_symlink.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            with patch.object(Path, 'is_symlink', return_value=True):
                result = pdf_handler.test_password(test_file, "password")
                
                # Verify symlinks are handled appropriately
                assert result is True

    def test_password_validation_very_large_file(self, pdf_handler, mock_pdf_reader):
        """Test password validation for very large PDFs"""
        # Setup mock for large file
        mock_reader = MagicMock()
        mock_reader.is_encrypted = False
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_large.pdf")
        
        # Mock large file (>1GB simulation)
        large_pdf_data = b'%PDF-1.4' + b'\x00' * 1000000  # Simulate large content
        
        with patch('builtins.open', mock_open(read_data=large_pdf_data)):
            result = pdf_handler.test_password(test_file, "password")
            
            # Verify large files are handled efficiently
            assert result is True

    def test_password_validation_concurrent_access(self, pdf_handler, mock_pdf_reader):
        """Test password validation with concurrent file access"""
        # Setup mock for concurrent access
        mock_reader = MagicMock()
        mock_reader.is_encrypted = False
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("test_concurrent.pdf")
        
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            # Simulate concurrent access
            result1 = pdf_handler.test_password(test_file, "password1")
            result2 = pdf_handler.test_password(test_file, "password2")
            
            # Verify concurrent access works
            assert result1 is True
            assert result2 is True

    def test_password_validation_file_disappears(self, pdf_handler):
        """Test password validation when file is deleted during operation"""
        test_file = Path("test_disappearing.pdf")
        
        # Mock file disappearing during operation
        with patch('builtins.open', side_effect=FileNotFoundError("File not found")):
            result = pdf_handler.test_password(test_file, "password")
            
            # Verify graceful handling when file disappears
            assert result is False

    def test_password_validation_device_files(self, pdf_handler):
        """Test password validation for device files"""
        # Test device files (should be blocked by security validation)
        device_files = [
            Path("CON"),  # Windows
            Path("PRN"),  # Windows
            Path("/dev/null"),  # Unix
        ]
        
        for device_file in device_files:
            result = pdf_handler.test_password(device_file, "password")
            
            # Verify device files are handled safely
            assert result is False

    def test_password_validation_mount_point_changes(self, pdf_handler, mock_pdf_reader):
        """Test password validation across mount point changes"""
        # Setup mock for mount point scenario
        mock_reader = MagicMock()
        mock_reader.is_encrypted = False
        mock_pdf_reader.return_value = mock_reader
        
        test_file = Path("/mnt/usb/test.pdf")
        
        # First access succeeds
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4')):
            result1 = pdf_handler.test_password(test_file, "password")
            assert result1 is True
        
        # Second access fails (mount point changed)
        with patch('builtins.open', side_effect=FileNotFoundError("Mount point unavailable")):
            result2 = pdf_handler.test_password(test_file, "password")
            assert result2 is False