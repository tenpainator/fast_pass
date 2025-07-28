"""PDF document encryption/decryption handler using PyPDF2."""

import logging
from pathlib import Path
from typing import Dict, Any

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None


class PDFHandler:
    """PDF document encryption/decryption handler using PyPDF2."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
        if PyPDF2 is None:
            raise ImportError("PyPDF2 is required for PDF document processing")
        
        self.encryption_method = 'AES-256'
        self.user_password_length = 128
        
        self.logger.debug("PDF handler initialized")
    
    def configure(self, config: Dict[str, Any]) -> None:
        """Configure PDF handler settings."""
        self.encryption_method = config.get('pdf_encryption_method', self.encryption_method)
        self.user_password_length = config.get('pdf_password_length', self.user_password_length)
    
    def test_password(self, file_path: Path, password: str) -> bool:
        """Test if password works for PDF document."""
        try:
            with open(file_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                
                if not pdf_reader.is_encrypted:
                    return True
                
                # Try to decrypt with password
                result = pdf_reader.decrypt(password)
                
                # PyPDF2 returns: 0=Failed, 1=User password, 2=Owner password
                return result > 0
                
        except Exception as e:
            self.logger.debug(f"Password test failed for {file_path}: {e}")
            return False
    
    def encrypt_file(self, input_path: Path, output_path: Path, password: str) -> None:
        """Encrypt PDF file with password."""
        try:
            with open(input_path, 'rb') as input_file:
                pdf_reader = PyPDF2.PdfReader(input_file)
                pdf_writer = PyPDF2.PdfWriter()
                
                # Copy all pages from input to output
                for page_num in range(len(pdf_reader.pages)):
                    page = pdf_reader.pages[page_num]
                    pdf_writer.add_page(page)
                
                # Encrypt the PDF with password
                pdf_writer.encrypt(
                    user_password=password,
                    owner_password=password,  # Use same password for both
                    use_128bit=True
                )
                
                # Write encrypted PDF to output file
                with open(output_path, 'wb') as output_file:
                    pdf_writer.write(output_file)
                
                self.logger.info(f"Successfully encrypted {input_path.name}")
                
        except Exception as e:
            raise Exception(f"Failed to encrypt PDF {input_path}: {e}")
    
    def decrypt_file(self, input_path: Path, output_path: Path, password: str) -> None:
        try:
            with open(input_path, 'rb') as input_file:
                pdf_reader = PyPDF2.PdfReader(input_file)
                
                if not pdf_reader.is_encrypted:
                    # PDF is not encrypted, just copy it
                    import shutil
                    shutil.copy2(input_path, output_path)
                    self.logger.info(f"PDF {input_path.name} was not encrypted, copied as-is")
                    return
                
                # Decrypt with password
                decrypt_result = pdf_reader.decrypt(password)
                if decrypt_result == 0:
                    raise Exception(f"Incorrect password for PDF {input_path}")
                
                # Create writer and copy all pages
                pdf_writer = PyPDF2.PdfWriter()
                
                for page_num in range(len(pdf_reader.pages)):
                    page = pdf_reader.pages[page_num]
                    pdf_writer.add_page(page)
                
                # Write decrypted PDF to output file
                with open(output_path, 'wb') as output_file:
                    pdf_writer.write(output_file)
                
                self.logger.info(f"Successfully decrypted {input_path.name}")
                
        except Exception as e:
            raise Exception(f"Failed to decrypt PDF {input_path}: {e}")
    
    def cleanup(self) -> None:
        # PDF handler doesn't maintain persistent resources
        pass