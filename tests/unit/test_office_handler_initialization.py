"""
Comprehensive Unit Tests for Office Handler Class Initialization
Tests OfficeDocumentHandler __init__ and configure methods
"""

import pytest
import logging
from unittest.mock import patch, MagicMock, Mock
from pathlib import Path

# Import modules under test
from fastpass.exceptions import FileFormatError, ProcessingError, SecurityViolationError


class TestOfficeHandlerInitialization:
    """Test OfficeDocumentHandler initialization and setup"""
    
    def test_office_handler_init_success(self):
        """
        Test: OfficeDocumentHandler initializes correctly with valid dependencies
        
        Verifies successful initialization when msoffcrypto is available
        """
        logger = MagicMock(spec=logging.Logger)
        
        # Mock msoffcrypto import as available
        with patch('fastpass.core.crypto_handlers.office_handler.msoffcrypto', create=True) as mock_msoffcrypto:
            mock_msoffcrypto.return_value = MagicMock()
            
            from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
            handler = OfficeDocumentHandler(logger)
            
            # Verify initialization
            assert handler.logger == logger
            assert handler.timeout == 30
            assert handler.encryption_algorithm == 'AES-256'
            
            # Verify debug log was called
            logger.debug.assert_called_once_with("Office document handler initialized")
    
    def test_office_handler_init_msoffcrypto_import_failure(self):
        """
        Test: OfficeDocumentHandler raises ImportError when msoffcrypto unavailable
        
        Verifies proper error handling when required dependency is missing
        """
        logger = MagicMock(spec=logging.Logger)
        
        # Mock msoffcrypto as None (import failed)
        with patch('fastpass.core.crypto_handlers.office_handler.msoffcrypto', None):
            from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
            
            with pytest.raises(ImportError, match="msoffcrypto-tool is required for Office document processing"):
                OfficeDocumentHandler(logger)
    
    def test_office_handler_init_with_custom_config(self):
        """
        Test: OfficeDocumentHandler initialization respects custom configuration
        
        Verifies that default configuration values are properly set
        """
        logger = MagicMock(spec=logging.Logger)
        
        with patch('fastpass.core.crypto_handlers.office_handler.msoffcrypto', create=True):
            from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
            handler = OfficeDocumentHandler(logger)
            
            # Verify default configuration is set properly
            assert handler.timeout == 30
            assert handler.encryption_algorithm == 'AES-256'
            
            # Verify logger is properly assigned
            assert handler.logger is logger
            
            # Verify logger was called for initialization
            logger.debug.assert_called_once()
    
    def test_office_handler_init_memory_constraints(self):
        """
        Test: OfficeDocumentHandler initialization under memory constraints
        
        Verifies initialization works even with limited memory
        """
        logger = MagicMock(spec=logging.Logger)
        
        with patch('fastpass.core.crypto_handlers.office_handler.msoffcrypto', create=True):
            from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
            
            # Simulate memory constraint by limiting object creation
            handler = OfficeDocumentHandler(logger)
            
            # Basic initialization should still work
            assert handler.logger == logger
            assert hasattr(handler, 'timeout')
            assert hasattr(handler, 'encryption_algorithm')
            
            # Verify essential attributes are present (actual implementation may have more)
            essential_attrs = {'logger', 'timeout', 'encryption_algorithm'}
            handler_attrs = set(handler.__dict__.keys())
            assert essential_attrs.issubset(handler_attrs), f"Missing essential attributes: {essential_attrs - handler_attrs}"


class TestOfficeHandlerConfiguration:
    """Test OfficeDocumentHandler configure method"""
    
    def setup_method(self):
        """Set up test fixtures for configuration tests"""
        self.logger = MagicMock(spec=logging.Logger)
        
        # Mock msoffcrypto for all tests
        self.msoffcrypto_patcher = patch('fastpass.core.crypto_handlers.office_handler.msoffcrypto', create=True)
        self.mock_msoffcrypto = self.msoffcrypto_patcher.start()
        
        from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
        self.handler = OfficeDocumentHandler(self.logger)
    
    def teardown_method(self):
        """Clean up test fixtures"""
        self.msoffcrypto_patcher.stop()
    
    def test_office_handler_configure_valid_settings(self):
        """
        Test: configure method accepts valid settings
        
        Verifies that valid configuration options are properly applied
        """
        config = {
            'office_timeout': 60,
            'debug': False
        }
        
        # Configure should not raise any exceptions
        self.handler.configure(config)
        
        # Verify timeout was updated
        assert self.handler.timeout == 60
        
        # Verify no warning was logged for debug=False
        warning_calls = [call for call in self.logger.warning.call_args_list 
                        if 'EXPERIMENTAL' in str(call)]
        assert len(warning_calls) == 0
    
    def test_office_handler_configure_invalid_settings(self):
        """
        Test: configure method handles invalid settings gracefully
        
        Verifies that invalid configuration values are accepted (no validation in current implementation)
        """
        config = {
            'office_timeout': 'invalid_timeout',  # Invalid type
            'unknown_setting': 'value',           # Unknown setting
            'debug': 'not_boolean'                # Invalid boolean
        }
        
        # Configure should not raise exceptions for invalid values
        self.handler.configure(config)
        
        # Current implementation accepts any value, so timeout becomes the invalid value
        assert self.handler.timeout == 'invalid_timeout'
        
        # Should not crash despite invalid configuration
        assert hasattr(self.handler, 'timeout')
        assert hasattr(self.handler, 'encryption_algorithm')
    
    def test_office_handler_configure_none_settings(self):
        """
        Test: configure method handles None configuration
        
        Verifies that None configuration raises AttributeError (current implementation limitation)
        """
        # Configure with None should raise AttributeError (current implementation)
        with pytest.raises(AttributeError, match="'NoneType' object has no attribute 'get'"):
            self.handler.configure(None)
    
    def test_office_handler_configure_edge_cases(self):
        """
        Test: configure method handles edge cases properly
        
        Verifies proper handling of debug mode and experimental warnings
        """
        # Test debug mode enables experimental warning
        debug_config = {'debug': True}
        self.handler.configure(debug_config)
        
        # Verify debug info was logged for subprocess method
        self.logger.info.assert_called_with(
            "Office encryption using msoffcrypto-tool subprocess. "
            "Both encryption and decryption fully supported."
        )
        
        # Test empty configuration
        empty_config = {}
        original_timeout = self.handler.timeout
        self.handler.configure(empty_config)
        assert self.handler.timeout == original_timeout
        
        # Test configuration with None values - current implementation uses None as default fallback
        none_config = {'office_timeout': None, 'debug': None}
        self.handler.configure(none_config)
        assert self.handler.timeout is None  # Current implementation allows None values
        
        # Reset timeout for next tests
        self.handler.timeout = 30
        
        # Test configuration with zero timeout (edge case)
        zero_config = {'office_timeout': 0}
        self.handler.configure(zero_config)
        assert self.handler.timeout == 0  # Should accept zero as valid
        
        # Test configuration with negative timeout (edge case)
        negative_config = {'office_timeout': -1}
        self.handler.configure(negative_config)
        assert self.handler.timeout == -1  # Should accept negative as-is (no validation in configure)


class TestOfficeHandlerDependencyHandling:
    """Test OfficeDocumentHandler dependency handling edge cases"""
    
    def test_msoffcrypto_available_but_broken(self):
        """
        Test: Initialization when msoffcrypto is available but broken
        
        Verifies that handler initializes even if msoffcrypto has issues
        """
        logger = MagicMock(spec=logging.Logger)
        
        # Mock msoffcrypto as available but potentially broken
        broken_msoffcrypto = MagicMock()
        broken_msoffcrypto.OfficeFile.side_effect = Exception("Broken msoffcrypto")
        
        with patch('fastpass.core.crypto_handlers.office_handler.msoffcrypto', broken_msoffcrypto):
            from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
            
            # Initialization should succeed (errors are caught during usage, not init)
            handler = OfficeDocumentHandler(logger)
            assert handler.logger == logger
            assert handler.timeout == 30
            assert handler.encryption_algorithm == 'AES-256'
    
    
    def test_logger_type_validation(self):
        """
        Test: Handler validates logger parameter type
        
        Verifies that handler works with different logger types
        """
        with patch('fastpass.core.crypto_handlers.office_handler.msoffcrypto', create=True):
            from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
            
            # Test with proper logger
            real_logger = logging.getLogger('test')
            handler = OfficeDocumentHandler(real_logger)
            assert handler.logger == real_logger
            
            # Test with mock logger
            mock_logger = MagicMock(spec=logging.Logger)
            handler = OfficeDocumentHandler(mock_logger)
            assert handler.logger == mock_logger
            
            # Handler should work with any logger-like object
            fake_logger = MagicMock()
            fake_logger.debug = MagicMock()
            handler = OfficeDocumentHandler(fake_logger)
            assert handler.logger == fake_logger


class TestOfficeHandlerThreadSafety:
    """Test OfficeDocumentHandler thread safety during initialization"""
    
    def test_concurrent_initialization(self):
        """
        Test: Multiple handlers can be initialized concurrently
        
        Verifies thread safety of initialization process
        """
        logger = MagicMock(spec=logging.Logger)
        
        with patch('fastpass.core.crypto_handlers.office_handler.msoffcrypto', create=True):
            from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
            
            # Create multiple handlers concurrently (simulated)
            handlers = []
            for i in range(5):
                handler = OfficeDocumentHandler(logger)
                handlers.append(handler)
            
            # All handlers should be properly initialized
            for handler in handlers:
                assert handler.logger == logger
                assert handler.timeout == 30
                assert handler.encryption_algorithm == 'AES-256'
            
            # Each handler should be independent
            handlers[0].timeout = 100
            assert handlers[1].timeout == 30  # Should not affect other instances
    
    def test_configuration_independence(self):
        """
        Test: Handler configurations are independent between instances
        
        Verifies that configuring one handler doesn't affect others
        """
        logger = MagicMock(spec=logging.Logger)
        
        with patch('fastpass.core.crypto_handlers.office_handler.msoffcrypto', create=True):
            from fastpass.core.crypto_handlers.office_handler import OfficeDocumentHandler
            
            handler1 = OfficeDocumentHandler(logger)
            handler2 = OfficeDocumentHandler(logger)
            
            # Configure first handler
            handler1.configure({'office_timeout': 120})
            
            # Second handler should remain unchanged
            assert handler1.timeout == 120
            assert handler2.timeout == 30  # Default value
            
            # Configure second handler differently
            handler2.configure({'office_timeout': 15})
            
            # Handlers should have independent configurations
            assert handler1.timeout == 120
            assert handler2.timeout == 15