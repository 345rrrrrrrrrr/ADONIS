#!/usr/bin/env python3
# ADONIS Core Application Class

import logging
import signal
import time
from typing import Dict, List, Any, Optional

from core.module_manager import ModuleManager
from core.user_manager import UserManager
from core.api_server import APIServer
from core.workflow import WorkflowManager, network_scan_to_packet_capture, terminal_command_to_packet_capture

class AdonisApp:
    """
    Main application class for ADONIS platform. 
    Handles module loading, user authentication, and overall application lifecycle.
    """
    
    def __init__(self, config, safe_mode=False, enable_ai=True):
        """
        Initialize the ADONIS application.
        
        Args:
            config: Configuration object
            safe_mode: If True, only load essential modules
            enable_ai: If True, enable the AI assistant
        """
        self.logger = logging.getLogger("adonis.core")
        self.config = config
        self.safe_mode = safe_mode
        self.enable_ai = enable_ai
        self.running = False
        
        # Initialize components
        self.module_manager = ModuleManager(self)
        self.user_manager = UserManager(self)
        self.api_server = APIServer(self)
        self.workflow_manager = WorkflowManager(self)
        
        # Initialize AI Assistant if enabled
        self.ai_assistant = None
        if enable_ai:
            try:
                from ai.assistant import AIAssistant
                self.ai_assistant = AIAssistant(self)
                self.logger.info("AI Assistant initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize AI Assistant: {str(e)}")
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
    
    def run(self) -> int:
        """
        Run the application main loop.
        
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        self.logger.info("Initializing ADONIS...")
        
        # Perform system checks
        if not self._run_system_checks():
            self.logger.error("System checks failed. Exiting.")
            return 1
        
        # Initialize user authentication
        if not self.user_manager.initialize():
            self.logger.error("Failed to initialize user management system. Exiting.")
            return 1
        
        # Load modules
        module_list = ["core"] 
        if not self.safe_mode:
            module_list.extend([
                "debugger", 
                "network_scanner", 
                "terminal", 
                "packet_analyzer", 
                "memory_editor"
            ])
        
        self.logger.info(f"Loading modules: {', '.join(module_list)}")
        if not self.module_manager.load_modules(module_list):
            self.logger.error("Failed to load all required modules. Exiting.")
            return 1
        
        # Register cross-module workflows
        self._register_workflows()
        
        # Start the API server
        if not self.api_server.start():
            self.logger.error("Failed to start API server. Exiting.")
            return 1
        
        # Start the application main loop
        self.running = True
        self.logger.info("ADONIS is ready")
        
        try:
            while self.running:
                # Main application loop
                time.sleep(0.1)  # Reduce CPU usage in the main loop
                
                # Process pending tasks
                self.module_manager.process_tasks()
                
                # Check system health
                self._monitor_system_health()
        except Exception as e:
            self.logger.error(f"Error in main loop: {str(e)}", exc_info=True)
            return 1
        finally:
            self._shutdown()
        
        return 0
    
    def _register_workflows(self):
        """Register cross-module workflows."""
        self.logger.info("Registering cross-module workflows...")
        
        # Network scan to packet capture workflow
        self.workflow_manager.register_workflow(
            "network_scan_to_packet_capture",
            "Start a packet capture based on network scan results",
            ["network_scanner", "packet_analyzer"],
            network_scan_to_packet_capture
        )
        
        # Terminal command with packet capture workflow
        self.workflow_manager.register_workflow(
            "terminal_command_to_packet_capture",
            "Run a terminal command while capturing related network traffic",
            ["terminal", "packet_analyzer"],
            terminal_command_to_packet_capture
        )
        
        # Log registered workflows
        available_workflows = self.workflow_manager.get_available_workflows()
        self.logger.info(f"Registered {len(available_workflows)} workflows")
    
    def _run_system_checks(self) -> bool:
        """
        Perform system checks to ensure the application can run properly.
        
        Returns:
            True if all checks passed, False otherwise
        """
        self.logger.info("Running system checks...")
        
        # Check system requirements
        import psutil
        import os
        
        # Check available RAM
        available_ram = psutil.virtual_memory().available / (1024 * 1024)  # Convert to MB
        min_ram = self.config.get("system.requirements.min_ram_mb", 1024)  # 1GB default
        
        if available_ram < min_ram:
            self.logger.warning(f"Low memory: {available_ram:.0f} MB available, {min_ram} MB recommended")
        
        # Check available disk space
        app_dir = self.config.get("system.paths.data_dir", "~/.adonis/data")
        app_dir = os.path.expanduser(app_dir)  # Properly expand the ~ character
        
        # Create directory if it doesn't exist
        try:
            os.makedirs(app_dir, exist_ok=True)
            
            # Now check disk usage
            disk_usage = psutil.disk_usage(app_dir)
            available_disk_gb = disk_usage.free / (1024 * 1024 * 1024)  # Convert to GB
            min_disk_gb = self.config.get("system.requirements.min_disk_gb", 5)  # 5GB default
            
            if available_disk_gb < min_disk_gb:
                self.logger.warning(f"Low disk space: {available_disk_gb:.1f} GB available, {min_disk_gb} GB recommended")
                
        except Exception as e:
            self.logger.warning(f"Could not check disk space: {str(e)}")
        
        # Additional system checks can be added here
        
        # For now, just return True; in production, we might fail if critical checks fail
        return True
    
    def _monitor_system_health(self) -> None:
        """
        Monitor system health and resource usage.
        """
        # This would be called periodically to check system resources and module health
        # For now, this is a placeholder
        pass
    
    def _shutdown(self) -> None:
        """
        Perform a clean shutdown of the application.
        """
        self.logger.info("Shutting down ADONIS...")
        
        # Stop all modules in reverse order
        self.module_manager.unload_all()
        
        # Stop the API server
        self.api_server.stop()
        
        # Shutdown the AI assistant if enabled
        if self.ai_assistant:
            self.ai_assistant.shutdown()
        
        self.logger.info("ADONIS shutdown complete")
    
    def _handle_signal(self, signum, frame):
        """
        Handle system signals for clean shutdown.
        """
        signal_name = {signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(signum, str(signum))
        self.logger.info(f"Received signal {signal_name}, shutting down...")
        self.running = False