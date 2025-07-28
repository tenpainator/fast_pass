"""
Library Interface Tests
Tests for the FastPass library interface (DocumentProcessor)
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import logging

# Import library interface
from fastpass import DocumentProcessor, ProcessingResult, encrypt_file, decrypt_file, is_password_protected
from fastpass.exceptions import FastPassError, SecurityViolationError, FileFormatError, PasswordError


class TestDocumentProcessorInitialization:
    """Test DocumentProcessor initialization"""
    
    def test_processor_init_default(self):
        """Test default initialization"""
        processor = DocumentProcessor()
        
        assert processor.logger is not None
        assert processor.config is not None
        assert processor.password_manager is not None
        assert processor.security_validator is not None
        assert processor.file_validator is not None
        assert processor._crypto_handlers is not None
        assert processor.temp_files_created == []
    
    def test_processor_init_with_custom_logger(self):
        """Test initialization with custom logger"""
        custom_logger = logging.getLogger("test_logger")
        processor = DocumentProcessor(logger=custom_logger)
        
        assert processor.logger is custom_logger
    
    def test_processor_init_with_custom_config(self):
        """Test initialization with custom config"""
        custom_config = {"test_key": "test_value"}
        processor = DocumentProcessor(config=custom_config)
        
        assert processor.config is custom_config
    
    @patch('fastpass.core.document_processor.OfficeDocumentHandler')
    @patch('fastpass.core.document_processor.PDFHandler')
    def test_processor_init_crypto_handlers(self, mock_pdf_handler, mock_office_handler):
        """Test crypto handlers initialization"""
        processor = DocumentProcessor()
        
        # Should attempt to initialize both handlers
        mock_office_handler.assert_called_once()
        mock_pdf_handler.assert_called_once()


class TestDocumentProcessorFileOperations:
    """Test DocumentProcessor file operations"""
    
    @pytest.fixture
    def processor(self):
        """Create a DocumentProcessor instance for testing"""
        return DocumentProcessor()
    
    @pytest.fixture
    def sample_file(self):
        """Create a temporary test file"""
        with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as f:
            f.write(b'test content')
            yield Path(f.name)
        # Cleanup
        Path(f.name).unlink(missing_ok=True)
    
    def test_encrypt_file_basic(self, processor, sample_file):
        """Test basic file encryption"""
        with patch.object(processor, '_process_file') as mock_process:
            mock_result = ProcessingResult(
                success=True,
                input_file=sample_file,
                operation='encrypt',
                message='File encrypted successfully'
            )
            mock_process.return_value = mock_result
            
            result = processor.encrypt_file(sample_file, "password123")
            
            assert result.success is True
            assert result.input_file == sample_file
            assert result.operation == 'encrypt'
            mock_process.assert_called_once_with(sample_file, 'encrypt', ['password123'], None)
    
    def test_decrypt_file_basic(self, processor, sample_file):
        """Test basic file decryption"""
        with patch.object(processor, '_process_file') as mock_process:
            mock_result = ProcessingResult(
                success=True,
                input_file=sample_file,
                operation='decrypt',
                message='File decrypted successfully'
            )
            mock_process.return_value = mock_result
            
            result = processor.decrypt_file(sample_file, ["password1", "password2"])
            
            assert result.success is True
            assert result.input_file == sample_file
            assert result.operation == 'decrypt'
            mock_process.assert_called_once_with(sample_file, 'decrypt', ['password1', 'password2'], None)
    
    def test_is_password_protected_true(self, processor, sample_file):
        """Test password protection check - protected file"""
        with patch.object(processor.security_validator, 'validate_file_path'), \
             patch.object(processor.file_validator, 'validate_file') as mock_validate:
            
            mock_manifest = Mock()
            mock_manifest.is_encrypted = True
            mock_validate.return_value = mock_manifest
            
            result = processor.is_password_protected(sample_file)
            
            assert result is True
    
    def test_is_password_protected_false(self, processor, sample_file):
        """Test password protection check - unprotected file"""
        with patch.object(processor.security_validator, 'validate_file_path'), \
             patch.object(processor.file_validator, 'validate_file') as mock_validate:
            
            mock_manifest = Mock()
            mock_manifest.is_encrypted = False
            mock_validate.return_value = mock_manifest
            
            result = processor.is_password_protected(sample_file)
            
            assert result is False
    
    def test_is_password_protected_exception(self, processor, sample_file):
        """Test password protection check - exception handling"""
        with patch.object(processor, '_process_file') as mock_process:
            mock_process.side_effect = Exception("Test error")
            
            result = processor.is_password_protected(sample_file)
            
            assert result is False
    
    def test_get_file_info(self, processor, sample_file):
        """Test file information retrieval"""
        with patch.object(processor.security_validator, 'validate_file_path'), \
             patch.object(processor.file_validator, 'validate_file') as mock_validate:
            
            mock_manifest = Mock()
            mock_manifest.path = sample_file
            mock_manifest.size = 1024
            mock_manifest.format = '.docx'
            mock_manifest.crypto_tool = 'msoffcrypto'
            mock_manifest.supported = True
            mock_validate.return_value = mock_manifest
            
            with patch.object(processor, 'is_password_protected', return_value=True):
                info = processor.get_file_info(sample_file)
            
            assert info['path'] == str(sample_file)
            assert info['size'] == 1024
            assert info['format'] == '.docx'
            assert info['crypto_tool'] == 'msoffcrypto'
            assert info['supported'] is True
            assert info['is_password_protected'] is True


class TestDocumentProcessorContextManager:
    """Test DocumentProcessor context manager functionality"""
    
    def test_context_manager_cleanup(self):
        """Test context manager calls cleanup"""
        with patch('fastpass.core.document_processor.DocumentProcessor.cleanup') as mock_cleanup:
            with DocumentProcessor() as processor:
                assert processor is not None
            mock_cleanup.assert_called_once()
    
    def test_cleanup_temp_files(self):
        """Test cleanup removes temporary files"""
        processor = DocumentProcessor()
        
        # Create mock temp files
        temp_file1 = Mock()
        temp_file1.exists.return_value = True
        temp_file2 = Mock()
        temp_file2.exists.return_value = False
        
        processor.temp_files_created = [temp_file1, temp_file2]
        
        processor.cleanup()
        
        temp_file1.unlink.assert_called_once()
        temp_file2.unlink.assert_not_called()
        assert processor.temp_files_created == []


class TestConvenienceFunctions:
    """Test convenience functions"""
    
    @pytest.fixture
    def sample_file(self):
        """Create a temporary test file"""
        with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as f:
            f.write(b'test content')
            yield Path(f.name)
        Path(f.name).unlink(missing_ok=True)
    
    def test_encrypt_file_convenience(self, sample_file):
        """Test encrypt_file convenience function"""
        with patch('fastpass.core.document_processor.DocumentProcessor') as MockProcessor:
            mock_processor = MockProcessor.return_value.__enter__.return_value
            mock_result = ProcessingResult(
                success=True,
                input_file=sample_file,
                operation='encrypt'
            )
            mock_processor.encrypt_file.return_value = mock_result
            
            result = encrypt_file(sample_file, "password123")
            
            assert result.success is True
            mock_processor.encrypt_file.assert_called_once_with(sample_file, "password123", None)
    
    def test_decrypt_file_convenience(self, sample_file):
        """Test decrypt_file convenience function"""
        with patch('fastpass.core.document_processor.DocumentProcessor') as MockProcessor:
            mock_processor = MockProcessor.return_value.__enter__.return_value
            mock_result = ProcessingResult(
                success=True,
                input_file=sample_file,
                operation='decrypt'
            )
            mock_processor.decrypt_file.return_value = mock_result
            
            result = decrypt_file(sample_file, ["password1", "password2"])
            
            assert result.success is True
            mock_processor.decrypt_file.assert_called_once_with(sample_file, ["password1", "password2"], None)
    
    def test_is_password_protected_convenience(self, sample_file):
        """Test is_password_protected convenience function"""
        with patch('fastpass.core.document_processor.DocumentProcessor') as MockProcessor:
            mock_processor = MockProcessor.return_value.__enter__.return_value
            mock_processor.is_password_protected.return_value = True
            
            result = is_password_protected(sample_file)
            
            assert result is True
            mock_processor.is_password_protected.assert_called_once_with(sample_file)


class TestProcessingResult:
    """Test ProcessingResult dataclass"""
    
    def test_processing_result_creation(self):
        """Test ProcessingResult creation"""
        input_file = Path("test.docx")
        output_file = Path("test_encrypted.docx")
        
        result = ProcessingResult(
            success=True,
            input_file=input_file,
            output_file=output_file,
            operation="encrypt",
            message="Success",
            error=None,
            passwords_tried=1,
            processing_time=1.5
        )
        
        assert result.success is True
        assert result.input_file == input_file
        assert result.output_file == output_file
        assert result.operation == "encrypt"
        assert result.message == "Success"
        assert result.error is None
        assert result.passwords_tried == 1
        assert result.processing_time == 1.5
    
    def test_processing_result_defaults(self):
        """Test ProcessingResult default values"""
        input_file = Path("test.docx")
        
        result = ProcessingResult(
            success=False,
            input_file=input_file
        )
        
        assert result.success is False
        assert result.input_file == input_file
        assert result.output_file is None
        assert result.operation == ""
        assert result.message == ""
        assert result.error is None
        assert result.passwords_tried == 0
        assert result.processing_time == 0.0


class TestLibraryImports:
    """Test library imports work correctly"""
    
    def test_main_imports(self):
        """Test main library imports"""
        import fastpass
        
        # Test main classes are available
        assert hasattr(fastpass, 'DocumentProcessor')
        assert hasattr(fastpass, 'ProcessingResult')
        assert hasattr(fastpass, 'PasswordManager')
        
        # Test convenience functions are available
        assert hasattr(fastpass, 'encrypt_file')
        assert hasattr(fastpass, 'decrypt_file')
        assert hasattr(fastpass, 'is_password_protected')
        
        # Test exceptions are available
        assert hasattr(fastpass, 'FastPassError')
        assert hasattr(fastpass, 'SecurityViolationError')
        assert hasattr(fastpass, 'FileFormatError')
        assert hasattr(fastpass, 'PasswordError')
        
        # Test config is available
        assert hasattr(fastpass, 'FastPassConfig')
    
    def test_direct_imports(self):
        """Test direct imports from fastpass"""
        from fastpass import DocumentProcessor, ProcessingResult, encrypt_file
        from fastpass import SecurityViolationError, FastPassError
        
        # Should be able to use imported classes/functions
        assert DocumentProcessor is not None
        assert ProcessingResult is not None
        assert encrypt_file is not None
        assert SecurityViolationError is not None
        assert FastPassError is not None
    
    def test_exception_inheritance(self):
        """Test exception inheritance hierarchy"""
        from fastpass.exceptions import (
            FastPassError, SecurityViolationError, FileFormatError,
            PasswordError, ProcessingError
        )
        
        # All exceptions should inherit from FastPassError
        assert issubclass(SecurityViolationError, FastPassError)
        assert issubclass(FileFormatError, FastPassError)
        assert issubclass(PasswordError, FastPassError)
        assert issubclass(ProcessingError, FastPassError)


class TestLibraryErrorHandling:
    """Test library error handling"""
    
    def test_security_violation_propagation(self):
        """Test security violations are properly propagated"""
        processor = DocumentProcessor()
        
        with patch.object(processor.security_validator, 'validate_file_path') as mock_validate:
            mock_validate.side_effect = SecurityViolationError("Path not allowed")
            
            result = processor._process_file("../../../etc/passwd", "encrypt", ["password"], None)
            
            assert result.success is False
            assert "Path not allowed" in result.error
    
    def test_file_format_error_propagation(self):
        """Test file format errors are properly propagated"""
        processor = DocumentProcessor()
        
        with patch.object(processor.security_validator, 'validate_file_path'), \
             patch.object(processor.file_validator, 'validate_file') as mock_validate:
            mock_validate.side_effect = FileFormatError("Unsupported format")
            
            result = processor._process_file("test.xyz", "encrypt", ["password"], None)
            
            assert result.success is False
            assert "Unsupported format" in result.error


class TestLibraryLogging:
    """Test library logging behavior"""
    
    def test_library_mode_logging(self):
        """Test library mode has minimal logging"""
        from fastpass.utils.logger import setup_logger
        
        logger = setup_logger(library_mode=True)
        
        # Should be set to ERROR level to minimize output
        assert logger.level == logging.ERROR
        # Should have no handlers to avoid interfering with calling application
        assert len(logger.handlers) == 0
    
    def test_non_library_mode_logging(self):
        """Test non-library mode has normal logging"""
        from fastpass.utils.logger import setup_logger
        
        logger = setup_logger(library_mode=False)
        
        # Should have normal INFO level
        assert logger.level == logging.INFO
        # Should have handlers for console output
        assert len(logger.handlers) > 0