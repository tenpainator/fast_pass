"""
FastPass Office Document Handler
Maps to: C1c_Office, C2a_Config - msoffcrypto-tool integration
"""

# A1a: Load System Tools
import logging
from pathlib import Path
from typing import Dict, Any
import tempfile
import shutil

try:
    import msoffcrypto
except ImportError:
    msoffcrypto = None


class OfficeDocumentHandler:
    """
    Microsoft Office document encryption/decryption handler
    Uses msoffcrypto-tool for crypto operations
    """
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
        if msoffcrypto is None:
            raise ImportError("msoffcrypto-tool is required for Office document processing")
        
        # C2a_Config: Configure Office Settings
        self.timeout = 30
        self.encryption_algorithm = 'AES-256'
        
        self.logger.debug("Office document handler initialized")
    
    def configure(self, config: Dict[str, Any]) -> None:
        """
        C2a: Configure Office Handler
        Set Office-specific configuration options
        """
        self.timeout = config.get('office_timeout', self.timeout)
        
        # Log experimental encryption warning
        if config.get('debug', False):
            self.logger.warning(
                "Office document encryption is EXPERIMENTAL. "
                "Decryption is fully supported."
            )
    
    def test_password(self, file_path: Path, password: str) -> bool:
        """
        Test if password works for Office document
        Returns True if password is correct, False otherwise
        """
        try:
            with open(file_path, 'rb') as f:
                office_file = msoffcrypto.OfficeFile(f)
                
                if not office_file.is_encrypted():
                    # File is not encrypted, so any password "works" for decryption
                    return True
                
                # Try to load with password
                office_file.load_key(password=password)
                
                # Try to decrypt a small portion to verify password
                with tempfile.NamedTemporaryFile() as temp_file:
                    office_file.decrypt(temp_file)
                    temp_file.seek(0)
                    # If we can read some data, password is correct
                    data = temp_file.read(100)
                    return len(data) > 0
                    
        except Exception as e:
            self.logger.debug(f"Password test failed for {file_path}: {e}")
            return False
    
    def encrypt_file(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        Encrypt Office document with password
        Note: This is experimental functionality
        """
        
        # Log experimental warning
        self.logger.warning(
            f"EXPERIMENTAL: Encrypting {input_path.name} with Office encryption"
        )
        
        try:
            # For Office encryption, we need to use a different approach
            # msoffcrypto-tool primarily supports decryption
            # For encryption, we would need to use Office automation or other tools
            
            # This is a placeholder implementation
            # In a real implementation, you might use:
            # - Office COM automation (Windows only)
            # - LibreOffice command line tools
            # - Or other encryption methods
            
            raise NotImplementedError(
                "Office document encryption is not yet implemented. "
                "Use Microsoft Office or LibreOffice to encrypt documents manually."
            )
            
        except Exception as e:
            raise Exception(f"Failed to encrypt Office document {input_path}: {e}")
    
    def decrypt_file(self, input_path: Path, output_path: Path, password: str) -> None:
        """
        Decrypt Office document with password
        Full decryption support using msoffcrypto-tool
        """
        try:
            with open(input_path, 'rb') as f:
                office_file = msoffcrypto.OfficeFile(f)
                
                if not office_file.is_encrypted():
                    # File is not encrypted, just copy it
                    shutil.copy2(input_path, output_path)
                    self.logger.info(f"File {input_path.name} was not encrypted, copied as-is")
                    return
                
                # Load the password
                office_file.load_key(password=password)
                
                # Decrypt to output file
                with open(output_path, 'wb') as output_file:
                    office_file.decrypt(output_file)
                
                self.logger.info(f"Successfully decrypted {input_path.name}")
                
        except Exception as e:
            raise Exception(f"Failed to decrypt Office document {input_path}: {e}")
    
    def cleanup(self) -> None:
        """
        E2d: Call Handler Cleanup
        Clean up any handler-specific resources
        """
        # Office handler doesn't maintain persistent resources
        pass