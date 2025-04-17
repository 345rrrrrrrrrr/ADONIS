#!/usr/bin/env python3
# ADONIS - AI-powered Debugging and Offensive Network Integrated Suite
# Main application entry point

import os
import sys
import argparse
import logging
from pathlib import Path

# Import core components
from core.application import AdonisApp
from core.config import Config
from utils.logger import setup_logger

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="ADONIS - AI-powered Debugging and Offensive Network Integrated Suite"
    )
    
    parser.add_argument("--config", type=str, help="Path to configuration file")
    parser.add_argument("--setup", action="store_true", help="Run initial setup wizard")
    parser.add_argument("--safe", action="store_true", help="Start in safe mode (minimal modules)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI assistant")
    
    return parser.parse_args()

def main():
    """Main entry point for ADONIS application."""
    args = parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logger(log_level)
    logger = logging.getLogger("adonis")
    
    logger.info("Starting ADONIS...")
    
    # Load configuration
    config_path = args.config or os.path.expanduser("~/.adonis/config/adonis.yml")
    config = Config(config_path)
    
    # Check for first-time setup
    if args.setup or not os.path.exists(config_path):
        logger.info("Running setup wizard...")
        from core.setup import SetupWizard
        wizard = SetupWizard(config)
        wizard.run()
    
    # Initialize and start the application
    app = AdonisApp(
        config=config,
        safe_mode=args.safe,
        enable_ai=not args.no_ai
    )
    
    try:
        exit_code = app.run()
        logger.info(f"ADONIS exited with code: {exit_code}")
        return exit_code
    except KeyboardInterrupt:
        logger.info("ADONIS terminated by user")
        return 0
    except Exception as e:
        logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())