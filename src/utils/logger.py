#!/usr/bin/env python3
# ADONIS - Logger utility

import os
import sys
import logging
import datetime
from logging.handlers import RotatingFileHandler
from typing import Optional

# Default log format
DEFAULT_LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
DEFAULT_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Default logs directory
DEFAULT_LOGS_DIR = os.path.expanduser('~/.adonis/logs')


def setup_logging(level=logging.INFO, log_file: Optional[str] = None, 
                 format_str: Optional[str] = None, date_format: Optional[str] = None,
                 max_size: int = 10485760, backup_count: int = 5) -> None:
    """
    Set up logging configuration for the application.
    
    Args:
        level: Logging level (default: INFO)
        log_file: Path to log file (default: timestamped file in default logs directory)
        format_str: Log message format string
        date_format: Date format string
        max_size: Maximum log file size in bytes before rotation (default: 10MB)
        backup_count: Number of backup log files to keep (default: 5)
    """
    # Use default formats if not specified
    if format_str is None:
        format_str = DEFAULT_LOG_FORMAT
    if date_format is None:
        date_format = DEFAULT_DATE_FORMAT
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear existing handlers if any
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(format_str, date_format)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Create file handler if log_file is specified or use default location
    if log_file is None:
        # Create default logs directory if it doesn't exist
        os.makedirs(DEFAULT_LOGS_DIR, exist_ok=True)
        
        # Create timestamped log file
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(DEFAULT_LOGS_DIR, f'adonis_{timestamp}.log')
    else:
        # Ensure directory exists
        log_dir = os.path.dirname(os.path.abspath(log_file))
        os.makedirs(log_dir, exist_ok=True)
    
    # Add file handler
    try:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
        # Log the location of the log file
        logging.info(f"Logging to file: {log_file}")
    except Exception as e:
        logging.error(f"Failed to set up log file: {str(e)}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)