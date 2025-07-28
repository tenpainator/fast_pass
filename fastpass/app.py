"""FastPass main application class."""

import sys
import atexit
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import logging

from fastpass.utils.config import FastPassConfig
from fastpass.utils.logger import sanitize_error_message


class FastPassApplication:
    """Main FastPass application orchestrating the complete processing workflow."""
    
    def __init__(self, args, logger: logging.Logger, config: Dict[str, Any]):
        self.args = args
        self.logger = logger
        self.config = config
        
        # Initialize tracking lists
        self.temp_files_created = []
        self.processing_results = {}
        
        # Record operation start time
        self.operation_start_time = datetime.now()
        
        # Initialize password manager
        from fastpass.core.password.password_manager import PasswordManager
        self.password_manager = PasswordManager(
            cli_passwords=getattr(args, 'password', []) or []
        )
        
        # Set application state flags
        self.ready_for_processing = True
        self.cleanup_required = True
        
        self.logger.debug('FastPass application initialized')
        
        # Register cleanup handler
        atexit.register(self._emergency_cleanup)
    
    def run(self) -> int:
        """Execute the main processing workflow."""
        try:
            # Check crypto tool availability
            self._check_crypto_tools()
            
            # Security and file validation
            validated_files = self._perform_security_and_file_validation()
            
            # Setup crypto handlers
            crypto_handlers = self._setup_crypto_tools_and_configuration(validated_files)
            
            # Process files
            processing_results = self._process_files_with_crypto_operations(
                validated_files, crypto_handlers
            )
            
            # Cleanup and report results
            exit_code = self._cleanup_and_generate_final_report(processing_results)
            
            return exit_code
            
        except SecurityViolationError as e:
            self.logger.error(f"Security violation: {sanitize_error_message(str(e))}")
            return 3
        except FileFormatError as e:
            self.logger.error(f"File format error: {sanitize_error_message(str(e))}")
            return 1
        except CryptoToolError as e:
            self.logger.error(f"Crypto tool error: {sanitize_error_message(str(e))}")
            return 1
        except PasswordError as e:
            self.logger.error(f"Password error: {sanitize_error_message(str(e))}")
            return 4
        except ProcessingError as e:
            self.logger.error(f"Processing error: {sanitize_error_message(str(e))}")
            self._cleanup_partial_processing_on_failure()
            return 1
        except Exception as e:
            self.logger.error(f"Unexpected error: {sanitize_error_message(str(e))}")
            self._emergency_cleanup()
            return 2
    
    def _check_crypto_tools(self) -> None:
        """Verify required crypto tools are available."""
        crypto_tools = {}
        missing_tools = []
        
        try:
            import msoffcrypto
            crypto_tools['msoffcrypto'] = True
            self.logger.debug("Office document tool available")
        except ImportError:
            missing_tools.append('msoffcrypto-tool')
            self.logger.warning("msoffcrypto-tool not available")
        
        try:
            import PyPDF2
            crypto_tools['PyPDF2'] = True
            self.logger.debug("PDF processing tool available")
        except ImportError:
            missing_tools.append('PyPDF2')
            self.logger.warning("PyPDF2 not available")
        
        if missing_tools:
            raise CryptoToolError(f"Missing required tools: {missing_tools}")
        
        self.crypto_tools = crypto_tools
    
    def _perform_security_and_file_validation(self) -> List:
        """Perform security checks and file validation."""
        from fastpass.core.security import SecurityValidator
        from fastpass.core.file_handler import FileValidator
        
        security_validator = SecurityValidator(self.logger)
        file_validator = FileValidator(self.logger, self.config)
        
        # Validate output directory if specified
        if hasattr(self.args, 'output_dir') and self.args.output_dir:
            validated_output_dir = security_validator.validate_output_directory(self.args.output_dir)
            self.args.output_dir = validated_output_dir
        
        # Determine input file
        if hasattr(self.args, 'input') and self.args.input:
            files_to_process = [self.args.input]
        else:
            raise ValueError("No input file specified")
        
        validated_files = []
        
        # Process each file
        for file_path in files_to_process:
            try:
                security_validator.validate_file_path(file_path)
                file_manifest = file_validator.validate_file(file_path, allow_unsupported=True)
                validated_files.append(file_manifest)
                
            except SecurityViolationError as e:
                self.logger.error(f"Security validation failed for {file_path}: {e}")
            except FileFormatError as e:
                self.logger.error(f"File format validation failed for {file_path}: {e}")
        
        if not validated_files:
            raise FileFormatError("No valid files found to process")
        
        self.logger.info(f"Validated {len(validated_files)} files for processing")
        return validated_files
    
    def _setup_crypto_tools_and_configuration(self, validated_files: List) -> Dict:
        """Initialize and configure crypto handlers."""
        from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
        from fastpass.core.crypto_handlers.pdf_handler import PDFHandler
        
        # Determine required tools and initialize handlers
        required_tools = set(manifest.crypto_tool for manifest in validated_files)
        crypto_handlers = {}
        
        if 'msoffcrypto' in required_tools:
            crypto_handlers['msoffcrypto'] = OfficeDocumentHandler(self.logger)
        
        if 'PyPDF2' in required_tools:
            crypto_handlers['PyPDF2'] = PDFHandler(self.logger)
        
        # Configure handlers
        for handler in crypto_handlers.values():
            handler.configure(self.config)
        
        self.logger.debug(f"Initialized {len(crypto_handlers)} crypto handlers")
        return crypto_handlers
    
    def _process_files_with_crypto_operations(self, validated_files: List, crypto_handlers: Dict) -> Dict:
        """Process files using appropriate crypto handlers."""
        from fastpass.core.file_handler import FileProcessor
        
        processor = FileProcessor(
            logger=self.logger,
            config=self.config,
            password_manager=self.password_manager,
            crypto_handlers=crypto_handlers,
            temp_files_created=self.temp_files_created
        )
        
        operation = self.args.operation
        
        return processor.process_files(validated_files, operation, self.args.output_dir)
    
    def _cleanup_and_generate_final_report(self, processing_results: Dict) -> int:
        """Clean up resources and generate final report."""
        from fastpass.core.file_handler import ResultsReporter
        
        # Calculate processing metrics and generate report
        reporter = ResultsReporter(self.logger, self.operation_start_time)
        
        # Cleanup resources
        self._perform_cleanup()
        
        # Clear sensitive data
        self._clear_sensitive_data()
        
        # Generate report and determine exit code
        return reporter.generate_report(processing_results)
    
    def _perform_cleanup(self) -> None:
        """Clean up temporary files."""
        for temp_file in self.temp_files_created:
            try:
                if temp_file.exists():
                    temp_file.unlink()
                    self.logger.debug(f"Cleaned up temp file: {temp_file}")
            except Exception as e:
                self.logger.warning(f"Failed to remove temp file {temp_file}: {e}")
    
    def _clear_sensitive_data(self) -> None:
        """Clear sensitive data from memory."""
        if hasattr(self, 'password_manager'):
            self.password_manager.clear_passwords()
            del self.password_manager
        
        if hasattr(self.args, 'password'):
            self.args.password = None
        
        # Force garbage collection
        import gc
        gc.collect()
    
    def _cleanup_partial_processing_on_failure(self) -> None:
        """Cleanup when processing fails partway through."""
        self._perform_cleanup()
    
    def _emergency_cleanup(self) -> None:
        """Emergency cleanup for unexpected termination."""
        try:
            self._perform_cleanup()
        except Exception:
            pass

# Import exception classes
from fastpass.exceptions import (
    SecurityViolationError, FileFormatError, CryptoToolError, 
    PasswordError, FileProcessingError, ProcessingError
)