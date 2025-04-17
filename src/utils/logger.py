#!/usr/bin/env python3
# ADONIS Logging Utility

import os
import sys
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path

def setup_logger(level=logging.INFO, log_dir=None):
    """
    Set up the application logger with console and file outputs.
    
    Args:
        level: Logging level (default: INFO)
        log_dir: Directory to store log files (default: ~/.adonis/logs)
    """
    if log_dir is None:
        log_dir = os.path.expanduser("~/.adonis/logs")
        
    # Create log directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    # Create a root logger
    root_logger = logging.getLogger("adonis")
    root_logger.setLevel(level)
    root_logger.handlers = []  # Remove any existing handlers
    
    # Create formatters
    console_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # Create file handler
    log_file = os.path.join(log_dir, f"adonis_{datetime.now().strftime('%Y%m%d')}.log")
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    # Set permissions on log directory
    try:
        os.chmod(log_dir, 0o700)  # Restrict access to user only
    except:
        pass  # Ignore permission errors
    
    # Log startup message
    root_logger.info(f"ADONIS Logger initialized at {datetime.now().isoformat()}")
    root_logger.info(f"Logging to: {log_file}")
    
    return root_logger

class ModuleLogger:
    """
    Custom logger class for ADONIS modules with additional context.
    """
    
    def __init__(self, module_name):
        """
        Initialize a module logger.
        
        Args:
            module_name: Name of the module
        """
        self.logger = logging.getLogger(f"adonis.module.{module_name}")
        self.module_name = module_name
    
    def debug(self, message, **kwargs):
        """Log debug message with module context."""
        self.logger.debug(f"[{self.module_name}] {message}", **kwargs)
    
    def info(self, message, **kwargs):
        """Log info message with module context."""
        self.logger.info(f"[{self.module_name}] {message}", **kwargs)
    
    def warning(self, message, **kwargs):
        """Log warning message with module context."""
        self.logger.warning(f"[{self.module_name}] {message}", **kwargs)
    
    def error(self, message, **kwargs):
        """Log error message with module context."""
        self.logger.error(f"[{self.module_name}] {message}", **kwargs)
    
    def critical(self, message, **kwargs):
        """Log critical message with module context."""
        self.logger.critical(f"[{self.module_name}] {message}", **kwargs)
    
    def exception(self, message, **kwargs):
        """Log exception with module context."""
        self.logger.exception(f"[{self.module_name}] {message}", **kwargs)