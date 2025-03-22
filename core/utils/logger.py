import logging
import os
from pathlib import Path
from datetime import datetime
from logging.handlers import RotatingFileHandler
import sys
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init()

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels"""
    
    COLORS = {
        'DEBUG': Fore.BLUE,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }

    def format(self, record):
        # Add color to the level name if it's a console handler
        if hasattr(self, 'is_console') and self.is_console:
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = f"{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}"
        
        return super().format(record)

def setup_logging(name: str = "ReconBuddy", log_dir: str = None) -> logging.Logger:
    """
    Set up logging configuration
    
    Args:
        name: Logger name
        log_dir: Directory to store log files
    
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    # Create formatters
    console_formatter = ColoredFormatter(
        '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_formatter.is_console = True
    
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s - %(pathname)s:%(lineno)d',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)
    
    # Set up file logging if directory is provided
    if log_dir:
        log_dir = Path(log_dir)
        os.makedirs(log_dir, exist_ok=True)
        
        # Main log file with rotation
        main_log = log_dir / f"{name.lower()}.log"
        file_handler = RotatingFileHandler(
            main_log,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)
        
        # Error log file with rotation
        error_log = log_dir / f"{name.lower()}_error.log"
        error_handler = RotatingFileHandler(
            error_log,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        error_handler.setFormatter(file_formatter)
        error_handler.setLevel(logging.ERROR)
        
        # Add file handlers
        logger.addHandler(file_handler)
        logger.addHandler(error_handler)
    
    # Add console handler
    logger.addHandler(console_handler)
    
    return logger

def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger instance. If it doesn't exist, create one.
    
    Args:
        name: Logger name (optional)
    
    Returns:
        Logger instance
    """
    if name is None:
        name = "ReconBuddy"
    
    logger = logging.getLogger(name)
    
    # If logger is not configured, set it up
    if not logger.handlers:
        log_dir = os.getenv("RECONBUDDY_HOME")
        if log_dir:
            log_dir = Path(log_dir) / "logs"
        setup_logging(name, log_dir)
    
    return logger

# Exception handler decorator
def handle_exceptions(logger=None):
    """
    Decorator to handle and log exceptions
    
    Args:
        logger: Logger instance (optional)
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger(func.__module__)
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Log the error with traceback
                logger.exception(
                    f"Error in {func.__name__}: {str(e)}"
                )
                raise
        return wrapper
    return decorator 