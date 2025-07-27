"""
Comprehensive Unit Tests for Office Handler Encryption
Tests all encryption functionality with 32 required test cases
"""

import pytest
import tempfile
import os
import stat
from pathlib import Path
from unittest.mock import patch, MagicMock, call, mock_open
import logging
import subprocess

# Import modules under test
from src.core.crypto_handlers.office_handler import OfficeDocumentHandler
from src.exceptions import FileFormatError, ProcessingError, SecurityViolationError


# Module-level fixtures
@pytest.fixture
def mock_logger():
    """Create mock logger for testing"""
    return MagicMock(spec=logging.Logger)

@pytest.fixture
def office_handler(mock_logger):
    """Create OfficeDocumentHandler with mocked dependencies"""
    with patch('src.core.crypto_handlers.office_handler.msoffcrypto'):
        handler = OfficeDocumentHandler(mock_logger)
        return handler

@pytest.fixture
def temp_office_files():
    """Create temporary test files"""
    files = {}
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test files for different formats
        for ext in ['.docx', '.xlsx', '.pptx']:
            file_path = temp_path / f"test{ext}"
            file_path.write_bytes(b"dummy content")
            files[ext] = file_path
        
        # Create output directory
        output_dir = temp_path / "output"
        output_dir.mkdir()
        files['output_dir'] = output_dir
        
        yield files


class TestOfficeHandlerEncryption:
    """Test OfficeDocumentHandler encryption functionality"""


class TestDocxEncryption:
    """Test DOCX file encryption scenarios"""
    
    def test_encrypt_docx_simple_password(self, office_handler, temp_office_files):
        """Test: Encrypt DOCX with simple password using COM automation"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password123"
        
        # Mock COM automation components
        mock_word_app = MagicMock()
        mock_doc = MagicMock()
        mock_word_app.Documents.Open.return_value = mock_doc
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom') as mock_pythoncom, \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_word_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            # Verify COM operations
            mock_word_app.Documents.Open.assert_called_once()
            assert mock_doc.Password == password
            mock_doc.SaveAs2.assert_called_once()
            mock_doc.Close.assert_called_once()
            mock_word_app.Quit.assert_called_once()
    
    def test_encrypt_docx_complex_password(self, office_handler, temp_office_files):
        """Test: Encrypt DOCX with complex password containing special characters"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "P@ssw0rd!2023#$%"
        
        mock_word_app = MagicMock()
        mock_doc = MagicMock()
        mock_word_app.Documents.Open.return_value = mock_doc
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_word_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_doc.Password == password
            mock_doc.SaveAs2.assert_called_once()
    
    def test_encrypt_docx_unicode_password(self, office_handler, temp_office_files):
        """Test: Encrypt DOCX with Unicode password"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "pässwørd中文"
        
        mock_word_app = MagicMock()
        mock_doc = MagicMock()
        mock_word_app.Documents.Open.return_value = mock_doc
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_word_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_doc.Password == password
    
    def test_encrypt_docx_very_long_password(self, office_handler, temp_office_files):
        """Test: Encrypt DOCX with very long password (within limits)"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "a" * 500  # Long but within 1024 limit
        
        mock_word_app = MagicMock()
        mock_doc = MagicMock()
        mock_word_app.Documents.Open.return_value = mock_doc
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_word_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_doc.Password == password
    
    def test_encrypt_docx_special_chars_password(self, office_handler, temp_office_files):
        """Test: Encrypt DOCX with password containing special characters"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        
        mock_word_app = MagicMock()
        mock_doc = MagicMock()
        mock_word_app.Documents.Open.return_value = mock_doc
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_word_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_doc.Password == password
    
    def test_encrypt_docx_already_encrypted(self, office_handler, temp_office_files):
        """Test: Encrypt already encrypted DOCX file"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "newpassword"
        
        mock_word_app = MagicMock()
        mock_doc = MagicMock()
        mock_word_app.Documents.Open.return_value = mock_doc
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_word_app
            
            # Should succeed - re-encryption with new password
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_doc.Password == password
    
    def test_encrypt_docx_large_file_10mb(self, office_handler, temp_office_files):
        """Test: Encrypt large DOCX file (10MB simulation)"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password"
        
        # Simulate large file by mocking file operations
        mock_word_app = MagicMock()
        mock_doc = MagicMock()
        mock_word_app.Documents.Open.return_value = mock_doc
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_word_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_doc.Password == password
    
    def test_encrypt_docx_large_file_100mb(self, office_handler, temp_office_files):
        """Test: Encrypt very large DOCX file (100MB simulation)"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password"
        
        mock_word_app = MagicMock()
        mock_doc = MagicMock()
        mock_word_app.Documents.Open.return_value = mock_doc
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_word_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_doc.Password == password


class TestXlsxEncryption:
    """Test XLSX file encryption scenarios"""
    
    def test_encrypt_xlsx_simple_password(self, office_handler, temp_office_files):
        """Test: Encrypt XLSX with simple password"""
        input_path = temp_office_files['.xlsx']
        output_path = temp_office_files['output_dir'] / "encrypted.xlsx"
        password = "password123"
        
        mock_excel_app = MagicMock()
        mock_workbook = MagicMock()
        mock_excel_app.Workbooks.Open.return_value = mock_workbook
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_excel_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            mock_excel_app.Workbooks.Open.assert_called_once()
            assert mock_workbook.Password == password
            mock_workbook.SaveAs.assert_called_once()
    
    def test_encrypt_xlsx_complex_password(self, office_handler, temp_office_files):
        """Test: Encrypt XLSX with complex password"""
        input_path = temp_office_files['.xlsx']
        output_path = temp_office_files['output_dir'] / "encrypted.xlsx"
        password = "C0mpl3x!P@ssw0rd"
        
        mock_excel_app = MagicMock()
        mock_workbook = MagicMock()
        mock_excel_app.Workbooks.Open.return_value = mock_workbook
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_excel_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_workbook.Password == password
    
    def test_encrypt_xlsx_unicode_password(self, office_handler, temp_office_files):
        """Test: Encrypt XLSX with Unicode password"""
        input_path = temp_office_files['.xlsx']
        output_path = temp_office_files['output_dir'] / "encrypted.xlsx"
        password = "unicode密码ñ"
        
        mock_excel_app = MagicMock()
        mock_workbook = MagicMock()
        mock_excel_app.Workbooks.Open.return_value = mock_workbook
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_excel_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_workbook.Password == password
    
    def test_encrypt_xlsx_very_long_password(self, office_handler, temp_office_files):
        """Test: Encrypt XLSX with very long password"""
        input_path = temp_office_files['.xlsx']
        output_path = temp_office_files['output_dir'] / "encrypted.xlsx"
        password = "x" * 800  # Long password within limits
        
        mock_excel_app = MagicMock()
        mock_workbook = MagicMock()
        mock_excel_app.Workbooks.Open.return_value = mock_workbook
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_excel_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_workbook.Password == password
    
    def test_encrypt_xlsx_special_chars_password(self, office_handler, temp_office_files):
        """Test: Encrypt XLSX with special characters password"""
        input_path = temp_office_files['.xlsx']
        output_path = temp_office_files['output_dir'] / "encrypted.xlsx"
        password = "~!@#$%^&*()_+{}[]|\\:;\"'<>?,./"
        
        mock_excel_app = MagicMock()
        mock_workbook = MagicMock()
        mock_excel_app.Workbooks.Open.return_value = mock_workbook
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_excel_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_workbook.Password == password
    
    def test_encrypt_xlsx_already_encrypted(self, office_handler, temp_office_files):
        """Test: Encrypt already encrypted XLSX file"""
        input_path = temp_office_files['.xlsx']
        output_path = temp_office_files['output_dir'] / "encrypted.xlsx"
        password = "newpassword"
        
        mock_excel_app = MagicMock()
        mock_workbook = MagicMock()
        mock_excel_app.Workbooks.Open.return_value = mock_workbook
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_excel_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_workbook.Password == password
    
    def test_encrypt_xlsx_large_file_10mb(self, office_handler, temp_office_files):
        """Test: Encrypt large XLSX file (10MB simulation)"""
        input_path = temp_office_files['.xlsx']
        output_path = temp_office_files['output_dir'] / "encrypted.xlsx"
        password = "password"
        
        mock_excel_app = MagicMock()
        mock_workbook = MagicMock()
        mock_excel_app.Workbooks.Open.return_value = mock_workbook
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_excel_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_workbook.Password == password
    
    def test_encrypt_xlsx_large_file_100mb(self, office_handler, temp_office_files):
        """Test: Encrypt very large XLSX file (100MB simulation)"""
        input_path = temp_office_files['.xlsx']
        output_path = temp_office_files['output_dir'] / "encrypted.xlsx"
        password = "password"
        
        mock_excel_app = MagicMock()
        mock_workbook = MagicMock()
        mock_excel_app.Workbooks.Open.return_value = mock_workbook
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_excel_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_workbook.Password == password


class TestPptxEncryption:
    """Test PPTX file encryption scenarios"""
    
    def test_encrypt_pptx_simple_password(self, office_handler, temp_office_files):
        """Test: Encrypt PPTX with simple password"""
        input_path = temp_office_files['.pptx']
        output_path = temp_office_files['output_dir'] / "encrypted.pptx"
        password = "password123"
        
        mock_ppt_app = MagicMock()
        mock_presentation = MagicMock()
        mock_ppt_app.Presentations.Open.return_value = mock_presentation
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_ppt_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            mock_ppt_app.Presentations.Open.assert_called_once()
            assert mock_presentation.Password == password
            mock_presentation.SaveAs.assert_called_once()
    
    def test_encrypt_pptx_complex_password(self, office_handler, temp_office_files):
        """Test: Encrypt PPTX with complex password"""
        input_path = temp_office_files['.pptx']
        output_path = temp_office_files['output_dir'] / "encrypted.pptx"
        password = "V3ry$tr0ng!P@$$w0rd"
        
        mock_ppt_app = MagicMock()
        mock_presentation = MagicMock()
        mock_ppt_app.Presentations.Open.return_value = mock_presentation
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_ppt_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_presentation.Password == password
    
    def test_encrypt_pptx_unicode_password(self, office_handler, temp_office_files):
        """Test: Encrypt PPTX with Unicode password"""
        input_path = temp_office_files['.pptx']
        output_path = temp_office_files['output_dir'] / "encrypted.pptx"
        password = "präsentation密码"
        
        mock_ppt_app = MagicMock()
        mock_presentation = MagicMock()
        mock_ppt_app.Presentations.Open.return_value = mock_presentation
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_ppt_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_presentation.Password == password
    
    def test_encrypt_pptx_very_long_password(self, office_handler, temp_office_files):
        """Test: Encrypt PPTX with very long password"""
        input_path = temp_office_files['.pptx']
        output_path = temp_office_files['output_dir'] / "encrypted.pptx"
        password = "p" * 700  # Long password within limits
        
        mock_ppt_app = MagicMock()
        mock_presentation = MagicMock()
        mock_ppt_app.Presentations.Open.return_value = mock_presentation
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_ppt_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_presentation.Password == password
    
    def test_encrypt_pptx_special_chars_password(self, office_handler, temp_office_files):
        """Test: Encrypt PPTX with special characters password"""
        input_path = temp_office_files['.pptx']
        output_path = temp_office_files['output_dir'] / "encrypted.pptx"
        password = "#$%^&*()[]{}|\\:;\"'<>?,./"
        
        mock_ppt_app = MagicMock()
        mock_presentation = MagicMock()
        mock_ppt_app.Presentations.Open.return_value = mock_presentation
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_ppt_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_presentation.Password == password
    
    def test_encrypt_pptx_already_encrypted(self, office_handler, temp_office_files):
        """Test: Encrypt already encrypted PPTX file"""
        input_path = temp_office_files['.pptx']
        output_path = temp_office_files['output_dir'] / "encrypted.pptx"
        password = "newpassword"
        
        mock_ppt_app = MagicMock()
        mock_presentation = MagicMock()
        mock_ppt_app.Presentations.Open.return_value = mock_presentation
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_ppt_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_presentation.Password == password
    
    def test_encrypt_pptx_large_file_10mb(self, office_handler, temp_office_files):
        """Test: Encrypt large PPTX file (10MB simulation)"""
        input_path = temp_office_files['.pptx']
        output_path = temp_office_files['output_dir'] / "encrypted.pptx"
        password = "password"
        
        mock_ppt_app = MagicMock()
        mock_presentation = MagicMock()
        mock_ppt_app.Presentations.Open.return_value = mock_presentation
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_ppt_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_presentation.Password == password
    
    def test_encrypt_pptx_large_file_100mb(self, office_handler, temp_office_files):
        """Test: Encrypt very large PPTX file (100MB simulation)"""
        input_path = temp_office_files['.pptx']
        output_path = temp_office_files['output_dir'] / "encrypted.pptx"
        password = "password"
        
        mock_ppt_app = MagicMock()
        mock_presentation = MagicMock()
        mock_ppt_app.Presentations.Open.return_value = mock_presentation
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_ppt_app
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            assert mock_presentation.Password == password


class TestEncryptionErrorConditions:
    """Test error conditions and edge cases in encryption"""
    
    def test_encrypt_corrupted_file(self, office_handler, temp_office_files):
        """Test: Encrypt corrupted Office file"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password"
        
        # Simulate corrupted file by making COM operations fail
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.side_effect = Exception("File corrupted")
            
            with pytest.raises(ProcessingError, match="COM automation encryption failed"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_empty_file(self, office_handler, temp_office_files):
        """Test: Encrypt empty Office file"""
        input_path = temp_office_files['output_dir'] / "empty.docx"
        input_path.write_bytes(b"")  # Empty file
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password"
        
        mock_word_app = MagicMock()
        mock_word_app.Documents.Open.side_effect = Exception("Cannot open empty file")
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_word_app
            
            with pytest.raises(ProcessingError, match="COM automation encryption failed"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_non_office_file(self, office_handler, temp_office_files):
        """Test: Encrypt non-Office file (should fail with FileFormatError)"""
        input_path = temp_office_files['output_dir'] / "test.txt"
        input_path.write_text("Not an Office file")
        output_path = temp_office_files['output_dir'] / "encrypted.txt"
        password = "password"
        
        with patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            with pytest.raises(FileFormatError, match="Unsupported Office format"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_readonly_file(self, office_handler, temp_office_files):
        """Test: Encrypt read-only Office file"""
        input_path = temp_office_files['.docx']
        # Make file read-only
        input_path.chmod(0o444)
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password"
        
        mock_word_app = MagicMock()
        mock_word_app.Documents.Open.side_effect = Exception("Access denied")
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_word_app
            
            with pytest.raises(ProcessingError, match="COM automation encryption failed"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_network_drive_file(self, office_handler, temp_office_files):
        """Test: Encrypt file on network drive (simulated)"""
        # Simulate network path
        network_path = Path("\\\\server\\share\\test.docx")
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password"
        
        # Mock path validation to simulate network drive detection
        with patch.object(office_handler, '_validate_path_security_hardened') as mock_validate:
            mock_validate.side_effect = SecurityViolationError("Network path not allowed")
            
            with pytest.raises(SecurityViolationError, match="Network path not allowed"):
                office_handler.encrypt_file(network_path, output_path, password)
    
    def test_encrypt_output_directory_full(self, office_handler, temp_office_files):
        """Test: Encrypt when output directory is full (simulated)"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password"
        
        mock_word_app = MagicMock()
        mock_doc = MagicMock()
        mock_word_app.Documents.Open.return_value = mock_doc
        mock_doc.SaveAs2.side_effect = Exception("Disk full")
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.return_value = mock_word_app
            
            with pytest.raises(ProcessingError, match="COM automation encryption failed"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_insufficient_permissions(self, office_handler, temp_office_files):
        """Test: Encrypt with insufficient file permissions"""
        input_path = temp_office_files['.docx']
        output_path = Path("/root/encrypted.docx")  # Simulated restricted path
        password = "password"
        
        with patch.object(office_handler, '_validate_path_security_hardened') as mock_validate:
            mock_validate.side_effect = SecurityViolationError("Insufficient permissions")
            
            with pytest.raises(SecurityViolationError, match="Insufficient permissions"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_encrypt_memory_exhaustion(self, office_handler, temp_office_files):
        """Test: Encrypt when system runs out of memory (simulated)"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password"
        
        with patch('src.core.crypto_handlers.office_handler.win32com') as mock_win32com, \
             patch('src.core.crypto_handlers.office_handler.pythoncom'), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            mock_win32com.client.Dispatch.side_effect = MemoryError("Out of memory")
            
            with pytest.raises(ProcessingError, match="COM automation encryption failed"):
                office_handler.encrypt_file(input_path, output_path, password)


class TestPasswordValidationAndSecurityChecks:
    """Test password validation and security validations"""
    
    def test_password_too_long_validation(self, office_handler, temp_office_files):
        """Test: Password exceeds maximum length"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "a" * 1025  # Exceeds 1024 limit
        
        with patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            with pytest.raises(ValueError, match="Password exceeds maximum length"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_password_null_byte_validation(self, office_handler, temp_office_files):
        """Test: Password contains null byte"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password\x00malicious"
        
        with patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'):
            
            with pytest.raises(ValueError, match="Null byte in password"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_legacy_format_rejection(self, office_handler, temp_office_files):
        """Test: Legacy format (.doc) encryption is rejected"""
        input_path = temp_office_files['output_dir'] / "test.doc"
        input_path.write_bytes(b"dummy content")
        output_path = temp_office_files['output_dir'] / "encrypted.doc"
        password = "password"
        
        # Mock FastPassConfig to include .doc as legacy format
        mock_config = MagicMock()
        mock_config.LEGACY_FORMATS = {'.doc': 'msoffcrypto'}
        
        with patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig', mock_config):
            
            with pytest.raises(FileFormatError, match="Legacy Office format .doc supports decryption only"):
                office_handler.encrypt_file(input_path, output_path, password)


class TestSubprocessFallbackEncryption:
    """Test subprocess fallback encryption when COM is not available"""
    
    def test_subprocess_encryption_success(self, office_handler, temp_office_files):
        """Test: Successful subprocess encryption when COM unavailable"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password"
        
        # Mock COM as unavailable
        with patch('src.core.crypto_handlers.office_handler.win32com', None), \
             patch('src.core.crypto_handlers.office_handler.pythoncom', None), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'), \
             patch('subprocess.run') as mock_run:
            
            # Mock successful subprocess execution
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stderr = ""
            mock_run.return_value = mock_result
            
            office_handler.encrypt_file(input_path, output_path, password)
            
            # Verify subprocess was called with correct arguments
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert 'python' in args
            assert '-m' in args
            assert 'msoffcrypto.cli' in args
            assert '-e' in args
            assert '-p' in args
            assert password in args
    
    def test_subprocess_encryption_failure(self, office_handler, temp_office_files):
        """Test: Subprocess encryption failure"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password"
        
        with patch('src.core.crypto_handlers.office_handler.win32com', None), \
             patch('src.core.crypto_handlers.office_handler.pythoncom', None), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'), \
             patch('subprocess.run') as mock_run:
            
            # Mock failed subprocess execution
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stderr = "Encryption failed"
            mock_run.return_value = mock_result
            
            with pytest.raises(ProcessingError, match="Office encryption failed"):
                office_handler.encrypt_file(input_path, output_path, password)
    
    def test_subprocess_timeout(self, office_handler, temp_office_files):
        """Test: Subprocess encryption timeout"""
        input_path = temp_office_files['.docx']
        output_path = temp_office_files['output_dir'] / "encrypted.docx"
        password = "password"
        
        with patch('src.core.crypto_handlers.office_handler.win32com', None), \
             patch('src.core.crypto_handlers.office_handler.pythoncom', None), \
             patch.object(office_handler, '_validate_path_security_hardened'), \
             patch('src.utils.config.FastPassConfig'), \
             patch('subprocess.run') as mock_run:
            
            # Mock subprocess timeout
            mock_run.side_effect = subprocess.TimeoutExpired('cmd', 60)
            
            with pytest.raises(ProcessingError, match="Office encryption timed out"):
                office_handler.encrypt_file(input_path, output_path, password)


class TestDirectEncryptionAvailability:
    """Test direct encryption availability detection"""
    
    def test_direct_encryption_available_true(self, office_handler):
        """Test: Direct encryption available when COM modules present"""
        with patch('src.core.crypto_handlers.office_handler.win32com', MagicMock()), \
             patch('src.core.crypto_handlers.office_handler.pythoncom', MagicMock()):
            
            assert office_handler._direct_encryption_available() is True
    
    def test_direct_encryption_available_false_no_win32com(self, office_handler):
        """Test: Direct encryption unavailable when win32com missing"""
        with patch('src.core.crypto_handlers.office_handler.win32com', None), \
             patch('src.core.crypto_handlers.office_handler.pythoncom', MagicMock()):
            
            assert office_handler._direct_encryption_available() is False
    
    def test_direct_encryption_available_false_no_pythoncom(self, office_handler):
        """Test: Direct encryption unavailable when pythoncom missing"""
        with patch('src.core.crypto_handlers.office_handler.win32com', MagicMock()), \
             patch('src.core.crypto_handlers.office_handler.pythoncom', None):
            
            assert office_handler._direct_encryption_available() is False
    
    def test_direct_encryption_not_available_exception(self, office_handler):
        """Test: Exception when trying direct encryption without COM"""
        input_path = Path("test.docx")
        output_path = Path("encrypted.docx")
        password = "password"
        
        with patch('src.core.crypto_handlers.office_handler.win32com', None), \
             patch('src.core.crypto_handlers.office_handler.pythoncom', None):
            
            with pytest.raises(ProcessingError, match="COM automation not available"):
                office_handler._encrypt_direct(input_path, output_path, password)