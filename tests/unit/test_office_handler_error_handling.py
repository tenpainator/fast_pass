"""
Office Handler Unit Tests - Error Handling and Edge Cases (12 tests)
Tests msoffcrypto import failures, file format edge cases, and complex document features
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import logging
from io import BytesIO

# Import modules under test
from src.core.crypto_handlers.office_handler import OfficeDocumentHandler
from src.exceptions import FileFormatError, ProcessingError, SecurityViolationError


class TestOfficeHandlerLibraryErrors:
    """Test library dependency and version compatibility errors"""
    
    def test_msoffcrypto_library_unavailable(self):
        """
        Test: OfficeDocumentHandler raises ImportError when msoffcrypto is unavailable
        
        This simulates the scenario where msoffcrypto-tool package is not installed
        or fails to import, which should prevent Office handler from initializing.
        """
        logger = MagicMock()
        
        # Mock the module-level msoffcrypto import to be None
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', None):
            with pytest.raises(ImportError, match="msoffcrypto-tool is required"):
                OfficeDocumentHandler(logger)
    
    def test_msoffcrypto_version_incompatibility(self):
        """
        Test: OfficeDocumentHandler handles version incompatibility gracefully
        
        Tests behavior when msoffcrypto is available but has incompatible API
        or missing required methods/attributes.
        """
        logger = MagicMock()
        
        # Create a mock msoffcrypto that raises AttributeError when OfficeFile is accessed
        mock_msoffcrypto = MagicMock()
        mock_msoffcrypto.OfficeFile.side_effect = AttributeError("OfficeFile not found in this version")
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            handler = OfficeDocumentHandler(logger)
            
            test_file = Path("test.docx")
            
            # Should fail when trying to use OfficeFile and return False
            with patch('builtins.open', mock_open(read_data=b'fake_data')):
                result = handler.test_password(test_file, "password")
                assert result is False


class TestOfficeFileFormatEdgeCases:
    """Test various Office file format edge cases and unsupported scenarios"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.logger = MagicMock()
        
        # Mock msoffcrypto to be available
        mock_msoffcrypto = MagicMock()
        mock_office_file = MagicMock()
        mock_msoffcrypto.OfficeFile.return_value = mock_office_file
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            self.handler = OfficeDocumentHandler(self.logger)
    
    def test_office_file_format_version_unsupported(self):
        """
        Test: Handler gracefully handles unsupported Office file format versions
        
        Tests scenarios where Office files are too old/new or use unsupported
        format variations that msoffcrypto cannot process.
        """
        test_file = Path("unsupported.docx")
        
        # Mock file operations to simulate format version issues
        mock_msoffcrypto = MagicMock()
        mock_office_file = MagicMock()
        
        # Simulate unsupported format error from msoffcrypto
        mock_office_file.is_encrypted.side_effect = ValueError("Unsupported file format version")
        mock_msoffcrypto.OfficeFile.return_value = mock_office_file
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            with patch('builtins.open', mock_open(read_data=b'fake_office_data')):
                result = self.handler.test_password(test_file, "password")
                # Should return False when format is unsupported
                assert result is False
    
    def test_office_file_macro_enabled_handling(self):
        """
        Test: Handler properly processes macro-enabled Office documents (.docm, .xlsm, .pptm)
        
        Macro-enabled files have different internal structure but should still
        be processable for encryption/decryption operations.
        """
        test_file = Path("document.docm")
        
        # Mock successful processing of macro-enabled file
        mock_msoffcrypto = MagicMock()
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.return_value = None
        mock_office_file.decrypt.return_value = None
        mock_msoffcrypto.OfficeFile.return_value = mock_office_file
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            with patch('builtins.open', mock_open(read_data=b'macro_enabled_content')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp_file = MagicMock()
                    mock_temp_file.read.return_value = b'decrypted_data'
                    mock_temp_file.seek.return_value = None
                    mock_temp_context = MagicMock()
                    mock_temp_context.__enter__.return_value = mock_temp_file
                    mock_temp_context.__exit__.return_value = None
                    mock_temp.return_value = mock_temp_context
                    
                    # Create new handler instance with mocked msoffcrypto
                    logger = MagicMock()
                    handler = OfficeDocumentHandler(logger)
                    result = handler.test_password(test_file, "password")
                    assert result is True
    
    def test_office_file_template_handling(self):
        """
        Test: Handler processes Office template files (.dotx, .xltx, .potx)
        
        Template files have special properties and metadata that may affect
        encryption/decryption operations.
        """
        test_file = Path("template.dotx")
        
        # Mock template file processing
        mock_msoffcrypto = MagicMock()
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = False
        mock_msoffcrypto.OfficeFile.return_value = mock_office_file
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            with patch('builtins.open', mock_open(read_data=b'template_content')):
                result = self.handler.test_password(test_file, "password")
                # Unencrypted template should return True
                assert result is True
    
    def test_office_file_with_embedded_objects(self):
        """
        Test: Handler processes Office files containing embedded objects
        
        Files with embedded Excel charts, images, or other objects have
        complex internal structure that may affect crypto operations.
        """
        test_file = Path("with_objects.xlsx")
        
        # Mock file with embedded objects causing processing complexity
        mock_msoffcrypto = MagicMock()
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        
        # Simulate complex file processing that may timeout or fail
        mock_office_file.load_key.side_effect = Exception("Complex file structure processing failed")
        mock_msoffcrypto.OfficeFile.return_value = mock_office_file
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            with patch('builtins.open', mock_open(read_data=b'complex_file_with_objects')):
                result = self.handler.test_password(test_file, "password")
                # Should handle errors gracefully
                assert result is False
    
    def test_office_file_with_external_links(self):
        """
        Test: Handler processes Office files with external data connections
        
        Files with external links to databases, web services, or other files
        may have special security considerations during processing.
        """
        test_file = Path("with_links.xlsx")
        
        # Mock successful processing despite external links
        mock_msoffcrypto = MagicMock()
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.return_value = None
        mock_office_file.decrypt.return_value = None
        mock_msoffcrypto.OfficeFile.return_value = mock_office_file
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            with patch('builtins.open', mock_open(read_data=b'file_with_external_links')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp_file = MagicMock()
                    mock_temp_file.read.return_value = b'decrypted_data'
                    mock_temp_file.seek.return_value = None
                    mock_temp_context = MagicMock()
                    mock_temp_context.__enter__.return_value = mock_temp_file
                    mock_temp_context.__exit__.return_value = None
                    mock_temp.return_value = mock_temp_context
                    
                    # Create new handler instance with mocked msoffcrypto
                    logger = MagicMock()
                    handler = OfficeDocumentHandler(logger)
                    result = handler.test_password(test_file, "correct_password")
                    assert result is True
    
    def test_office_file_password_protected_sheets(self):
        """
        Test: Handler manages Excel files with individual sheet password protection
        
        Excel workbooks can have both file-level and sheet-level password protection,
        creating complex scenarios for decryption operations.
        """
        test_file = Path("protected_sheets.xlsx")
        
        # Mock Excel file with multiple protection levels
        mock_msoffcrypto = MagicMock()
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        
        # Simulate sheet-level protection affecting decryption
        mock_office_file.load_key.return_value = None
        mock_office_file.decrypt.side_effect = Exception("Sheet protection prevents full decryption")
        mock_msoffcrypto.OfficeFile.return_value = mock_office_file
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            with patch('builtins.open', mock_open(read_data=b'sheet_protected_file')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp.__enter__.return_value = MagicMock()
                    
                    result = self.handler.test_password(test_file, "password")
                    # Should handle sheet protection errors gracefully
                    assert result is False
    
    def test_office_file_digital_signature(self):
        """
        Test: Handler processes digitally signed Office documents
        
        Digitally signed documents have additional security metadata that
        may be affected by encryption/decryption operations.
        """
        test_file = Path("signed.docx")
        
        # Mock signed document processing
        mock_msoffcrypto = MagicMock()
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = False
        mock_msoffcrypto.OfficeFile.return_value = mock_office_file
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            with patch('builtins.open', mock_open(read_data=b'digitally_signed_content')):
                result = self.handler.test_password(test_file, "password")
                # Should handle signed documents normally
                assert result is True
    
    def test_office_file_drm_protected(self):
        """
        Test: Handler detects and appropriately handles DRM-protected Office files
        
        DRM-protected files use different encryption mechanisms that may not
        be compatible with standard password-based encryption tools.
        """
        test_file = Path("drm_protected.docx")
        
        # Mock DRM protection detection
        mock_msoffcrypto = MagicMock()
        mock_office_file = MagicMock()
        
        # Simulate DRM protection error
        mock_office_file.is_encrypted.side_effect = Exception("DRM protection detected")
        mock_msoffcrypto.OfficeFile.return_value = mock_office_file
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            with patch('builtins.open', mock_open(read_data=b'drm_protected_content')):
                result = self.handler.test_password(test_file, "password")
                # Should handle DRM protection gracefully
                assert result is False
    
    def test_office_file_readonly_recommended(self):
        """
        Test: Handler processes files marked as "Read-Only Recommended"
        
        Files with read-only recommendations have special metadata that
        should not interfere with encryption/decryption operations.
        """
        test_file = Path("readonly_recommended.xlsx")
        
        # Mock read-only recommended file
        mock_msoffcrypto = MagicMock()
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key.return_value = None
        mock_office_file.decrypt.return_value = None
        mock_msoffcrypto.OfficeFile.return_value = mock_office_file
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            with patch('builtins.open', mock_open(read_data=b'readonly_recommended_content')):
                with patch('tempfile.NamedTemporaryFile') as mock_temp:
                    mock_temp_file = MagicMock()
                    mock_temp_file.read.return_value = b'decrypted_data'
                    mock_temp_file.seek.return_value = None
                    mock_temp_context = MagicMock()
                    mock_temp_context.__enter__.return_value = mock_temp_file
                    mock_temp_context.__exit__.return_value = None
                    mock_temp.return_value = mock_temp_context
                    
                    # Create new handler instance with mocked msoffcrypto
                    logger = MagicMock()
                    handler = OfficeDocumentHandler(logger)
                    result = handler.test_password(test_file, "password")
                    assert result is True
    
    def test_office_file_structure_damaged(self):
        """
        Test: Handler gracefully handles Office files with damaged internal structure
        
        Corrupted ZIP archives or damaged XML content within Office files
        should be detected and handled without crashing the application.
        """
        test_file = Path("damaged.pptx")
        
        # Mock damaged file structure
        mock_msoffcrypto = MagicMock()
        
        # Simulate file structure damage during OfficeFile initialization
        mock_msoffcrypto.OfficeFile.side_effect = Exception("Corrupted ZIP archive")
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            with patch('builtins.open', mock_open(read_data=b'corrupted_zip_data')):
                result = self.handler.test_password(test_file, "password")
                # Should handle corruption gracefully
                assert result is False


class TestOfficeHandlerErrorMessageSanitization:
    """Test error message sanitization and security features"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.logger = MagicMock()
        
        # Mock msoffcrypto to be available
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', MagicMock()):
            self.handler = OfficeDocumentHandler(self.logger)
    
    def test_sanitize_error_message_empty_input(self):
        """
        Test: _sanitize_error_message handles empty and None inputs
        """
        # Create new handler instance with mocked msoffcrypto
        logger = MagicMock()
        mock_msoffcrypto = MagicMock()
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            handler = OfficeDocumentHandler(logger)
            
            # Test None input
            result = handler._sanitize_error_message(None)
            assert result == "Unknown error"
            
            # Test empty string
            result = handler._sanitize_error_message("")
            assert result == "Unknown error"
            
            # Test whitespace only - strips to empty string
            result = handler._sanitize_error_message("   ")
            assert result == ""
    
    def test_sanitize_error_message_length_truncation(self):
        """
        Test: _sanitize_error_message truncates very long error messages
        """
        # Create a message longer than 200 characters
        long_message = "A" * 250
        
        result = self.handler._sanitize_error_message(long_message)
        
        # Should be truncated to 200 characters plus "..."
        assert len(result) == 203
        assert result.endswith("...")
        assert result.startswith("A" * 200)
    
    def test_sanitize_error_message_normal_length(self):
        """
        Test: _sanitize_error_message preserves normal-length messages
        """
        normal_message = "This is a normal error message"
        
        result = self.handler._sanitize_error_message(normal_message)
        
        # Should be preserved as-is
        assert result == normal_message
    
    def test_sanitize_error_message_strips_whitespace(self):
        """
        Test: _sanitize_error_message strips leading and trailing whitespace
        """
        message_with_whitespace = "  Error message with whitespace  \n\t"
        
        result = self.handler._sanitize_error_message(message_with_whitespace)
        
        # Should strip whitespace
        assert result == "Error message with whitespace"


class TestOfficeHandlerSecurityValidation:
    """Test security validation and path checking"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.logger = MagicMock()
        
        # Mock msoffcrypto to be available
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', MagicMock()):
            self.handler = OfficeDocumentHandler(self.logger)
    
    def test_validate_path_security_hardened_invalid_path(self):
        """
        Test: _validate_path_security_hardened raises SecurityViolationError for invalid paths
        """
        # Create new handler instance with mocked msoffcrypto
        logger = MagicMock()
        mock_msoffcrypto = MagicMock()
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            handler = OfficeDocumentHandler(logger)
            
            # Mock SecurityValidator to raise SecurityViolationError
            mock_validator = MagicMock()
            mock_validator.validate_file_path.side_effect = SecurityViolationError("Path traversal attempt")
            
            with patch('src.core.security.SecurityValidator', return_value=mock_validator):
                with patch.object(Path, 'exists', return_value=True):
                    with patch.object(Path, 'is_file', return_value=True):
                        with pytest.raises(SecurityViolationError):
                            test_path = Path("../../etc/passwd")
                            handler._validate_path_security_hardened(test_path)
    
    def test_encrypt_file_secure_legacy_format_prevention(self):
        """
        Test: encrypt_file_secure prevents encryption of legacy Office formats
        """
        # Create a test legacy format file
        legacy_file = Path("document.doc")
        output_file = Path("output.doc")
        
        # Mock FastPassConfig.LEGACY_FORMATS to include .doc
        with patch('src.utils.config.FastPassConfig') as mock_config:
            mock_config.LEGACY_FORMATS = ['.doc', '.xls', '.ppt']
            
            with pytest.raises(FileFormatError, match="Legacy Office format .doc supports decryption only"):
                self.handler.encrypt_file(legacy_file, output_file, "password")
    
    def test_encrypt_file_secure_password_validation(self):
        """
        Test: encrypt_file_secure validates password security requirements
        """
        # Create new handler instance with mocked msoffcrypto
        logger = MagicMock()
        mock_msoffcrypto = MagicMock()
        
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto', mock_msoffcrypto):
            handler = OfficeDocumentHandler(logger)
            
            # Use temporary directory for testing to avoid security validation failures
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                input_file = temp_path / "test.docx"
                output_file = temp_path / "output.docx"
                
                # Create the input file
                input_file.touch()
                
                # Test password too long
                long_password = "a" * 1025
                with pytest.raises(ValueError, match="Password exceeds maximum length"):
                    handler.encrypt_file(input_file, output_file, long_password)
                
                # Test password with null byte
                null_password = "password\x00injection"
                with pytest.raises(ValueError, match="Null byte in password"):
                    handler.encrypt_file(input_file, output_file, null_password)