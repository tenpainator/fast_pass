"""
FastPass Logging Configuration
Maps to: A3a-A3e Enhanced Logging Setup with TTY Detection
"""

# A1a: Load System Tools
import logging
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional


def setup_logger(name: str = "fastpass", 
                debug: bool = False, 
                log_file: Optional[Path] = None) -> logging.Logger:
    """
    A3a: Configure Console and File Logging
    Detect TTY for appropriate log formatting
    Set up both console and optional file logging
    """
    logger = logging.getLogger(name)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Set log level
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    
    # A3b: Set Up TTY-Aware Progress Tracking
    # TTY: Full timestamp format for console display
    # Non-TTY: Simple format for file redirection
    is_tty = sys.stdout.isatty()
    
    if is_tty:
        # A3c: Initialize Multi-Handler Logger - TTY format
        console_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        date_format = "%Y-%m-%d %H:%M:%S"
    else:
        # Non-TTY: Simple format for file redirection
        console_format = "[%(levelname)s] %(message)s"
        date_format = None
    
    # Create console handler for INFO and DEBUG messages (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.addFilter(lambda record: record.levelno < logging.ERROR)
    console_formatter = logging.Formatter(console_format, datefmt=date_format)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Create separate handler for ERROR messages (stderr)
    error_handler = logging.StreamHandler(sys.stderr)
    error_handler.setLevel(logging.ERROR)
    error_formatter = logging.Formatter(console_format, datefmt=date_format)
    error_handler.setFormatter(error_formatter)
    logger.addHandler(error_handler)
    
    # A3c: Add file handler if --log-file specified
    if log_file:
        try:
            # Ensure log directory exists
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file)
            file_format = "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s"
            file_formatter = logging.Formatter(file_format, datefmt="%Y-%m-%d %H:%M:%S")
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not create log file {log_file}: {e}")
    
    # A3e: Record Program Startup with Config
    logger.debug(f"FastPass logger initialized (TTY: {is_tty})")
    
    return logger


def sanitize_error_message(message: str) -> str:
    """
    E3a: Sanitize Error Messages
    Apply sanitize_error_message() to all errors
    Remove paths, passwords, sensitive patterns
    """
    import re
    
    # E3a_Sanitize: Pattern-Based Sanitization
    # Remove password=<value>, IP addresses, email addresses
    sanitized = message
    
    # Remove password patterns
    sanitized = re.sub(r'password[=:\s]+[^\s,]+', 'password=<REDACTED>', sanitized, flags=re.IGNORECASE)
    
    # Remove file paths (keep just filename)
    sanitized = re.sub(r'[A-Za-z]:[\\\/][^\\\/\s]*[\\\/]([^\\\/\s]+)', r'<path>/\1', sanitized)
    sanitized = re.sub(r'\/[^\/\s]*\/([^\/\s]+)', r'<path>/\1', sanitized)
    
    # Remove potential IP addresses
    sanitized = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<IP_ADDRESS>', sanitized)
    
    # Remove email addresses
    sanitized = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '<EMAIL>', sanitized)
    
    return sanitized