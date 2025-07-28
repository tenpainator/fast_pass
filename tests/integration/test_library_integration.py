"""
Library Integration Tests
End-to-end tests for the FastPass library interface using real files
"""

import pytest
import tempfile
from pathlib import Path
import shutil

# Import library interface
from fastpass import DocumentProcessor, encrypt_file, decrypt_file, is_password_protected
from fastpass.exceptions import SecurityViolationError, FileFormatError


class TestLibraryRealFileOperations:
    """Test library operations with real files"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests"""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    @pytest.fixture
    def sample_pdf(self, temp_dir):
        """Copy valid PDF file for testing"""
        source_pdf = Path("c:/Dev/fastpass/tests/fixtures/sample_files/clean/sample.pdf")
        pdf_file = temp_dir / "test_document.pdf"
        
        # Copy the valid PDF fixture
        shutil.copy2(source_pdf, pdf_file)
        return pdf_file
    
    def test_encrypt_decrypt_cycle_pdf(self, sample_pdf, temp_dir):
        """Test complete encrypt->decrypt cycle with PDF"""
        password = "test123"
        
        # Test with DocumentProcessor class
        with DocumentProcessor() as processor:
            # Check file is not initially protected
            assert not processor.is_password_protected(sample_pdf)
            
            # Encrypt the file
            encrypt_result = processor.encrypt_file(sample_pdf, password)
            
            # Encryption should succeed
            assert encrypt_result.success
            assert encrypt_result.operation == 'encrypt'
            assert encrypt_result.input_file == sample_pdf
            
            # File should now be protected
            assert processor.is_password_protected(sample_pdf)
            
            # Decrypt the file
            decrypt_result = processor.decrypt_file(sample_pdf, [password])
            
            # Decryption should succeed
            assert decrypt_result.success
            assert decrypt_result.operation == 'decrypt'
            assert decrypt_result.input_file == sample_pdf
            
            # File should no longer be protected
            assert not processor.is_password_protected(sample_pdf)
    
    def test_convenience_functions_pdf(self, sample_pdf):
        """Test convenience functions with PDF"""
        password = "convenience123"
        
        # Check initial state
        assert not is_password_protected(sample_pdf)
        
        # Encrypt using convenience function
        encrypt_result = encrypt_file(sample_pdf, password)
        assert encrypt_result.success
        
        # Check protection state
        assert is_password_protected(sample_pdf)
        
        # Decrypt using convenience function
        decrypt_result = decrypt_file(sample_pdf, [password])
        assert decrypt_result.success
        
        # Check final state
        assert not is_password_protected(sample_pdf)
    
    def test_wrong_password_handling(self, sample_pdf):
        """Test handling of wrong passwords"""
        correct_password = "correct123"
        wrong_passwords = ["wrong1", "wrong2", "wrong3"]
        
        # Encrypt file first
        encrypt_result = encrypt_file(sample_pdf, correct_password)
        assert encrypt_result.success
        
        # Try to decrypt with wrong passwords
        decrypt_result = decrypt_file(sample_pdf, wrong_passwords)
        assert not decrypt_result.success
        assert "password" in decrypt_result.error.lower()
        
        # File should still be protected
        assert is_password_protected(sample_pdf)
        
        # Decrypt with correct password should work
        correct_result = decrypt_file(sample_pdf, [correct_password])
        assert correct_result.success
    
    def test_multiple_password_attempts(self, sample_pdf):
        """Test trying multiple passwords including correct one"""
        correct_password = "correct123"
        password_list = ["wrong1", "wrong2", correct_password, "wrong3"]
        
        # Encrypt file first
        encrypt_result = encrypt_file(sample_pdf, correct_password)
        assert encrypt_result.success
        
        # Try to decrypt with password list including correct one
        decrypt_result = decrypt_file(sample_pdf, password_list)
        assert decrypt_result.success
        assert decrypt_result.passwords_tried > 1  # Should have tried multiple passwords
    
    def test_file_info_retrieval(self, sample_pdf):
        """Test file information retrieval"""
        password = "info123"
        
        with DocumentProcessor() as processor:
            # Get info for unencrypted file
            info = processor.get_file_info(sample_pdf)
            assert info['path'] == str(sample_pdf)
            assert info['format'] == '.pdf'
            assert info['crypto_tool'] == 'PyPDF2'
            assert info['supported'] is True
            assert info['is_password_protected'] is False
            
            # Encrypt file
            processor.encrypt_file(sample_pdf, password)
            
            # Get info for encrypted file
            info_encrypted = processor.get_file_info(sample_pdf)
            assert info_encrypted['is_password_protected'] is True
    
    def test_output_directory_specification(self, sample_pdf, temp_dir):
        """Test specifying output directory"""
        password = "output123"
        output_dir = temp_dir / "output"
        output_dir.mkdir()
        
        with DocumentProcessor() as processor:
            # Encrypt to specific output directory
            result = processor.encrypt_file(sample_pdf, password, output_dir)
            
            assert result.success
            # Output file should be in specified directory
            assert result.output_file is not None
            assert result.output_file.parent == output_dir
            
            # Original file should be unchanged
            original_content = sample_pdf.read_bytes()
            # Output file should exist and be different
            assert result.output_file.exists()
            output_content = result.output_file.read_bytes()
            assert original_content != output_content
    
    def test_unsupported_file_format(self, temp_dir):
        """Test handling of unsupported file formats"""
        unsupported_file = temp_dir / "test.xyz"
        unsupported_file.write_text("This is not a supported format")
        
        with DocumentProcessor() as processor:
            # Should handle unsupported format gracefully
            result = processor.encrypt_file(unsupported_file, "password")
            
            assert not result.success
            assert "format" in result.error.lower() or "unsupported" in result.error.lower()
    
    def test_nonexistent_file_handling(self):
        """Test handling of nonexistent files"""
        nonexistent_file = Path("does_not_exist.pdf")
        
        with DocumentProcessor() as processor:
            result = processor.encrypt_file(nonexistent_file, "password")
            
            assert not result.success
            assert result.error is not None
    
    def test_security_violation_handling(self):
        """Test handling of security violations"""
        # Try to access a file outside allowed directories
        system_file = Path("../../../etc/passwd")  # Unix system file
        
        with DocumentProcessor() as processor:
            result = processor.encrypt_file(system_file, "password")
            
            assert not result.success
            assert result.error is not None
    
    def test_processor_reuse(self, sample_pdf):
        """Test reusing the same processor instance"""
        password1 = "first123"
        password2 = "second123"
        
        processor = DocumentProcessor()
        
        try:
            # First operation
            result1 = processor.encrypt_file(sample_pdf, password1)
            assert result1.success
            
            # Second operation with same processor
            result2 = processor.decrypt_file(sample_pdf, [password1])
            assert result2.success
            
            # Third operation
            result3 = processor.encrypt_file(sample_pdf, password2)
            assert result3.success
            
            # Fourth operation  
            result4 = processor.decrypt_file(sample_pdf, [password2])
            assert result4.success
            
        finally:
            processor.cleanup()
    
    def test_temp_file_cleanup(self, sample_pdf):
        """Test temporary file cleanup"""
        password = "cleanup123"
        
        processor = DocumentProcessor()
        
        # Perform operations that might create temp files
        result1 = processor.encrypt_file(sample_pdf, password)
        assert result1.success
        
        result2 = processor.decrypt_file(sample_pdf, [password])
        assert result2.success
        
        # Check that temp files list is tracked
        temp_count_before = len(processor.temp_files_created)
        
        # Cleanup should clear temp files
        processor.cleanup()
        
        assert len(processor.temp_files_created) == 0
    
    def test_error_recovery(self, sample_pdf, temp_dir):
        """Test error recovery and continued operations"""
        password = "recovery123"
        
        processor = DocumentProcessor()
        
        try:
            # Successful operation
            result1 = processor.encrypt_file(sample_pdf, password)
            assert result1.success
            
            # Failed operation (wrong password)
            result2 = processor.decrypt_file(sample_pdf, ["wrong_password"])
            assert not result2.success
            
            # Successful operation after failure
            result3 = processor.decrypt_file(sample_pdf, [password])
            assert result3.success
            
            # Another successful operation
            result4 = processor.encrypt_file(sample_pdf, password)
            assert result4.success
            
        finally:
            processor.cleanup()


class TestLibraryPerformance:
    """Test library performance characteristics"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests"""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    @pytest.fixture
    def large_pdf(self, temp_dir):
        """Copy valid PDF file for performance testing"""
        source_pdf = Path("c:/Dev/fastpass/tests/fixtures/sample_files/clean/sample.pdf")
        pdf_file = temp_dir / "large_test.pdf"
        
        # Copy the valid PDF fixture
        shutil.copy2(source_pdf, pdf_file)
        return pdf_file
    
    def test_processing_time_tracking(self, large_pdf):
        """Test that processing time is tracked"""
        password = "timing123"
        
        with DocumentProcessor() as processor:
            result = processor.encrypt_file(large_pdf, password)
            
            assert result.success
            assert result.processing_time > 0
            assert isinstance(result.processing_time, float)
    
    def test_multiple_operations_performance(self, large_pdf):
        """Test performance of multiple operations"""
        password = "multi123"
        
        processor = DocumentProcessor()
        
        try:
            # Measure multiple operations
            total_time = 0
            num_operations = 3
            
            for i in range(num_operations):
                if i % 2 == 0:
                    result = processor.encrypt_file(large_pdf, f"{password}_{i}")
                else:
                    result = processor.decrypt_file(large_pdf, [f"{password}_{i-1}"])
                
                assert result.success
                total_time += result.processing_time
            
            # Average time should be reasonable
            avg_time = total_time / num_operations
            assert avg_time < 10.0  # Should be less than 10 seconds per operation
            
        finally:
            processor.cleanup()


class TestLibraryThreadSafety:
    """Test library thread safety considerations"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests"""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_separate_processor_instances(self, temp_dir):
        """Test that separate processor instances don't interfere"""
        # Create two test files
        file1 = temp_dir / "file1.pdf"
        file2 = temp_dir / "file2.pdf"
        
        source_pdf = Path("c:/Dev/fastpass/tests/fixtures/sample_files/clean/sample.pdf")
        shutil.copy2(source_pdf, file1)
        shutil.copy2(source_pdf, file2)
        
        # Create two separate processors
        processor1 = DocumentProcessor()
        processor2 = DocumentProcessor()
        
        try:
            # Operate on different files with different processors
            result1 = processor1.encrypt_file(file1, "password1")
            result2 = processor2.encrypt_file(file2, "password2")
            
            assert result1.success
            assert result2.success
            
            # Each processor should track its own temp files
            assert len(processor1.temp_files_created) >= 0
            assert len(processor2.temp_files_created) >= 0
            
            # Processors should have separate configurations
            assert processor1.config is not processor2.config
            # Loggers may be shared (same name), but processors should be separate instances
            assert processor1 is not processor2
            
        finally:
            processor1.cleanup()
            processor2.cleanup()