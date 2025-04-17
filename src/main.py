#!/usr/bin/env python3
# ADONIS - Main entry point

import os
import sys
import argparse
import logging
import signal
from typing import Dict, List, Any, Optional

# Add src directory to path for imports to work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.version import VERSION
from src.core.application import AdonisApp
from src.utils.logger import setup_logging


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=f"ADONIS - AI-powered Debugging and Offensive Network Integrated Suite (v{VERSION})"
    )

    # General options
    parser.add_argument('-v', '--version', action='store_true', help='Show version information')
    parser.add_argument('-c', '--config', help='Path to configuration file', default=None)
    parser.add_argument('--no-gui', action='store_true', help='Run in command-line mode without GUI')
    
    # Logging options
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        default='INFO', help='Set logging level')
    parser.add_argument('--log-file', help='Path to log file', default=None)
    
    # Module-specific options
    parser.add_argument('--module', help='Run a specific module directly')
    parser.add_argument('--module-args', help='Arguments for the specified module')
    
    # Other options
    parser.add_argument('--no-ai', action='store_true', help='Disable AI assistant')
    parser.add_argument('--data-dir', help='Path to data directory', default=None)
    
    return parser.parse_args()


def signal_handler(sig, frame):
    """Handle interrupt signals."""
    print("\nExiting ADONIS...")
    sys.exit(0)


def main():
    """Main entry point for ADONIS."""
    # Register signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Show version and exit if requested
    if args.version:
        print(f"ADONIS version {VERSION}")
        print("AI-powered Debugging and Offensive Network Integrated Suite")
        print("Copyright (c) 2025 ADONIS Team")
        return 0
    
    # Set up logging
    log_level = getattr(logging, args.log_level)
    setup_logging(log_level, args.log_file)
    logger = logging.getLogger("adonis")
    
    # Show startup message
    logger.info(f"Starting ADONIS v{VERSION}")
    
    # Create application configuration
    config_options = {}
    
    if args.config:
        config_options["config_file"] = args.config
        
    if args.data_dir:
        config_options["data_dir"] = args.data_dir
    
    if args.no_ai:
        config_options["ai_assistant.enabled"] = False
    
    # Create and initialize the main application
    try:
        app = AdonisApp(config_options)
        if not app.initialize():
            logger.error("Failed to initialize ADONIS")
            return 1
            
        logger.info("ADONIS initialized successfully")
        
        # Run a specific module if requested
        if args.module:
            # This would run a specific module in CLI mode
            module_args = args.module_args.split() if args.module_args else []
            success = app.run_module(args.module, module_args)
            app.shutdown()
            return 0 if success else 1
        
        # Start the application with GUI or CLI mode
        if args.no_gui:
            # Command-line mode
            app.run_cli()
            app.shutdown()
        else:
            # GUI mode
            from src.ui.main_window import launch_ui
            result = launch_ui(app)
            app.shutdown()
            return result
            
    except Exception as e:
        logger.exception(f"Error running ADONIS: {str(e)}")
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())