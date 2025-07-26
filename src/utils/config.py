"""
FastPass Configuration Management System
Maps to: CONFIGURATION MANAGEMENT SYSTEM from flowchart
"""

# A1a: Load System Tools
import json
import os
from pathlib import Path
from typing import Dict, Any
import argparse


class FastPassConfig:
    """Configuration management with multiple sources and precedence"""
    
    # CONFIGURATION MANAGEMENT SYSTEM constants
    VERSION = "1.0.0"
    MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB
    TEMP_DIR_PREFIX = "fastpass_"
    SECURE_FILE_PERMISSIONS = 0o600
    SUPPORTED_FORMATS = {
        '.docx': 'msoffcrypto',
        '.xlsx': 'msoffcrypto', 
        '.pptx': 'msoffcrypto',
        '.docm': 'msoffcrypto',
        '.xlsm': 'msoffcrypto',
        '.pptm': 'msoffcrypto',
        '.dotx': 'msoffcrypto',
        '.xltx': 'msoffcrypto',
        '.potx': 'msoffcrypto',
        '.pdf': 'PyPDF2'
    }
    
    # Configuration file locations (in order of precedence)
    CONFIG_LOCATIONS = [
        Path.home() / '.fastpass' / 'config.json',  # User config
        Path.cwd() / 'fastpass.json',               # Project config
        Path(__file__).parent.parent / 'config.json'  # Default config
    ]
    
    @classmethod
    def load_configuration(cls, cli_args: argparse.Namespace) -> Dict[str, Any]:
        """Load configuration from multiple sources with precedence"""
        config = cls._get_default_config()
        
        # 1. Load from config files (lowest precedence)
        for config_path in cls.CONFIG_LOCATIONS:
            if config_path.exists():
                try:
                    with open(config_path, 'r') as f:
                        file_config = json.load(f)
                        config.update(file_config)
                except (json.JSONDecodeError, IOError) as e:
                    print(f"Warning: Could not load config from {config_path}: {e}")
        
        # 2. Load from environment variables
        env_config = cls._load_from_environment()
        config.update(env_config)
        
        # 3. Override with CLI arguments (highest precedence)
        cli_config = cls._extract_cli_config(cli_args)
        config.update(cli_config)
        
        return config
    
    @classmethod
    def _get_default_config(cls) -> Dict[str, Any]:
        """Default configuration values"""
        return {
            'max_file_size': cls.MAX_FILE_SIZE,
            'temp_dir_prefix': cls.TEMP_DIR_PREFIX,
            'secure_permissions': cls.SECURE_FILE_PERMISSIONS,
            'supported_formats': cls.SUPPORTED_FORMATS.copy(),
            'debug': False,
            'verify': False,
            'dry_run': False
        }
    
    @classmethod
    def _load_from_environment(cls) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        env_config = {}
        
        # Check for FASTPASS_* environment variables
        if os.getenv('FASTPASS_DEBUG'):
            env_config['debug'] = os.getenv('FASTPASS_DEBUG').lower() in ('1', 'true', 'yes')
        
        if os.getenv('FASTPASS_MAX_FILE_SIZE'):
            try:
                env_config['max_file_size'] = int(os.getenv('FASTPASS_MAX_FILE_SIZE'))
            except ValueError:
                pass
        
        return env_config
    
    @classmethod
    def _extract_cli_config(cls, cli_args: argparse.Namespace) -> Dict[str, Any]:
        """Extract configuration from CLI arguments"""
        cli_config = {}
        
        if hasattr(cli_args, 'debug') and cli_args.debug:
            cli_config['debug'] = True
        
        if hasattr(cli_args, 'verify') and cli_args.verify:
            cli_config['verify'] = True
            
        if hasattr(cli_args, 'dry_run') and cli_args.dry_run:
            cli_config['dry_run'] = True
        
        return cli_config