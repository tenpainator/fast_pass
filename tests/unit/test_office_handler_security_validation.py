"""
FastPass Office Handler Security Validation Tests
Tests the security validation functionality in office_handler.py
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from src.core.crypto_handlers.office_handler import OfficeDocumentHandler


class TestSecurityValidation:
    """Test security validation of decrypted files"""
    
    @pytest.fixture
    def handler(self):
        """Create OfficeDocumentHandler instance for testing"""
        logger = MagicMock()
        with patch('src.core.crypto_handlers.office_handler.msoffcrypto'):
            handler = OfficeDocumentHandler(logger)
            return handler
    
    @pytest.fixture
    def temp_dir(self, tmp_path):
        """Create temporary directory for test files"""
        return tmp_path
    
    def test_security_validation_passes(self, handler, temp_dir):
        """Test: Security validation passes successfully"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security') as mock_validate:
                    mock_validate.return_value = None  # Security validation passes
                    
                    handler.decrypt_file(input_path, output_path, password)
                    
                    # Verify security validation was called
                    mock_validate.assert_called_once_with(output_path)
                    handler.logger.info.assert_called_with(f"Successfully decrypted {input_path.name}")
    
    def test_security_validation_fails_file_deleted(self, handler, tmp_path):
        """Test: Security validation fails, decrypted file is deleted"""
        input_path = tmp_path / "encrypted.docx"
        output_path = tmp_path / "decrypted.docx"
        password = "password"
        
        # Create real input file
        input_path.write_bytes(b'fake_docx_content')
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        # Create the output file to simulate successful decryption before validation
        def side_effect(*args, **kwargs):
            output_path.write_bytes(b'decrypted_content')
            return mock_open(read_data=b'docx_content')()
        
        with patch('builtins.open', side_effect=side_effect):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security') as mock_validate:
                    mock_validate.side_effect = Exception("Security threat detected")
                    
                    with pytest.raises(Exception) as exc_info:
                        handler.decrypt_file(input_path, output_path, password)
                    
                    # Verify security validation was called
                    mock_validate.assert_called_once_with(output_path)
                    # Verify the output file was deleted due to security failure
                    assert not output_path.exists(), "Output file should have been deleted after security validation failure"
                    # Verify exception message
                    assert "Failed to decrypt Office document" in str(exc_info.value)
    
    def test_security_validation_fails_file_deletion_fails(self, handler, temp_dir):
        """Test: Security validation fails, file deletion also fails"""
        input_path = temp_dir / "encrypted.docx"
        output_path = temp_dir / "decrypted.docx"
        password = "password"
        
        mock_office_file = MagicMock()
        mock_office_file.is_encrypted.return_value = True
        mock_office_file.load_key = MagicMock()
        mock_office_file.decrypt = MagicMock()
        
        with patch('builtins.open', mock_open(read_data=b'docx_content')):
            with patch('src.core.crypto_handlers.office_handler.msoffcrypto.OfficeFile', return_value=mock_office_file):
                with patch.object(handler, '_validate_decrypted_file_security') as mock_validate:
                    mock_validate.side_effect = Exception("Security threat detected")
                    
                    with pytest.raises(Exception) as exc_info:
                        handler.decrypt_file(input_path, output_path, password)
                    
                    # Verify security validation was called
                    mock_validate.assert_called_once_with(output_path)
                    # Verify exception message
                    assert "Failed to decrypt Office document" in str(exc_info.value)
    
    def test_validate_decrypted_file_security_method(self, handler, temp_dir):
        """Test: _validate_decrypted_file_security method directly"""
        test_file = temp_dir / "test.docx"
        test_file.write_text("test content")
        
        # Test successful validation
        with patch('src.core.security.SecurityValidator') as mock_validator_class:
            mock_validator = MagicMock()
            mock_validator.validate_office_document_security.return_value = None
            mock_validator_class.return_value = mock_validator
            
            # Should not raise exception
            handler._validate_decrypted_file_security(test_file)
            
            # Verify SecurityValidator was created and called
            mock_validator_class.assert_called_once_with(handler.logger)
            mock_validator.validate_office_document_security.assert_called_once_with(test_file)
            
    def test_validate_decrypted_file_security_fails_and_deletes(self, handler, temp_dir):
        """Test: _validate_decrypted_file_security fails and deletes file"""
        test_file = temp_dir / "test.docx"
        test_file.write_text("test content")
        
        # Test validation failure
        with patch('src.core.security.SecurityValidator') as mock_validator_class:
            mock_validator = MagicMock()
            mock_validator.validate_office_document_security.side_effect = Exception("Security threat")
            mock_validator_class.return_value = mock_validator
            
            with pytest.raises(Exception) as exc_info:
                handler._validate_decrypted_file_security(test_file)
            
            # Verify file was deleted
            assert not test_file.exists()
            # Verify exception message
            assert "Security validation failed" in str(exc_info.value)
            # Verify warning was logged
            handler.logger.warning.assert_called()
            
    def test_validate_decrypted_file_security_deletion_fails(self, handler, temp_dir):
        """Test: _validate_decrypted_file_security fails, file deletion also fails"""
        test_file = temp_dir / "test.docx"
        test_file.write_text("test content")
        
        # Test validation failure with deletion failure
        with patch('src.core.security.SecurityValidator') as mock_validator_class:
            with patch('pathlib.Path.unlink') as mock_unlink:
                mock_validator = MagicMock()
                mock_validator.validate_office_document_security.side_effect = Exception("Security threat")
                mock_validator_class.return_value = mock_validator
                mock_unlink.side_effect = PermissionError("Cannot delete")
                
                with pytest.raises(Exception) as exc_info:
                    handler._validate_decrypted_file_security(test_file)
                
                # Verify deletion was attempted
                mock_unlink.assert_called_once()
                # Verify exception message
                assert "Security validation failed" in str(exc_info.value)