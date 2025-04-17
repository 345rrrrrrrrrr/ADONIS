#!/usr/bin/env python3
# ADONIS Core Module

import logging
import os
import sys
import psutil
from typing import Dict, Any

from core.module_manager import Module

class CoreModule(Module):
    """
    Core module for ADONIS platform.
    Handles system status, resource monitoring, and other core functions.
    """
    
    def __init__(self, app, name="core"):
        super().__init__(app, name)
        self.logger = logging.getLogger("adonis.module.core")
        self.system_info = {}
        self.resource_usage = {}
        self.monitor_interval = 5  # seconds
        self.last_monitor_time = 0
        
    def initialize(self) -> bool:
        """Initialize the core module."""
        self.logger.info("Initializing Core Module")
        
        # Collect system information
        self._collect_system_info()
        
        # Initial resource usage check
        self._update_resource_usage()
        
        self.initialized = True
        return True
    
    def shutdown(self) -> None:
        """Clean up resources when shutting down."""
        self.logger.info("Shutting down Core Module")
    
    def process_tasks(self) -> None:
        """Process core module tasks, including resource monitoring."""
        import time
        current_time = time.time()
        
        # Update resource usage at the specified interval
        if current_time - self.last_monitor_time >= self.monitor_interval:
            self._update_resource_usage()
            self.last_monitor_time = current_time
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the module and system."""
        status = super().get_status()
        status.update({
            "system_info": self.system_info,
            "resource_usage": self.resource_usage
        })
        return status
    
    def _collect_system_info(self) -> None:
        """Collect system information."""
        self.logger.debug("Collecting system information")
        
        try:
            import platform
            
            self.system_info = {
                "hostname": platform.node(),
                "os": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                },
                "python": {
                    "version": platform.python_version(),
                    "implementation": platform.python_implementation(),
                },
                "hardware": {
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                    "cpu_cores": psutil.cpu_count(logical=False),
                    "logical_cpus": psutil.cpu_count(logical=True),
                    "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                }
            }
            
            # Add additional system information
            try:
                import distro
                self.system_info["os"]["distribution"] = distro.name(pretty=True)
            except ImportError:
                pass
                
        except Exception as e:
            self.logger.error(f"Error collecting system information: {str(e)}")
    
    def _update_resource_usage(self) -> None:
        """Update current resource usage statistics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=None)
            cpu_freq = psutil.cpu_freq()
            if cpu_freq:
                cpu_freq_current = cpu_freq.current
            else:
                cpu_freq_current = 0
                
            # Memory usage
            vm = psutil.virtual_memory()
            memory_usage = {
                "total_gb": round(vm.total / (1024**3), 2),
                "available_gb": round(vm.available / (1024**3), 2),
                "used_gb": round(vm.used / (1024**3), 2),
                "percent": vm.percent
            }
            
            # Disk usage for the application data directory
            app_dir = self.app.config.get("system.paths.data_dir", "~/.adonis/data")
            app_dir = os.path.expanduser(app_dir)
            if os.path.exists(app_dir):
                du = psutil.disk_usage(app_dir)
                disk_usage = {
                    "total_gb": round(du.total / (1024**3), 2),
                    "free_gb": round(du.free / (1024**3), 2),
                    "used_gb": round(du.used / (1024**3), 2),
                    "percent": du.percent
                }
            else:
                disk_usage = {
                    "error": f"Path does not exist: {app_dir}"
                }
            
            # Network usage
            net_io = psutil.net_io_counters()
            network_usage = {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv
            }
            
            # Process information for our application
            process = psutil.Process(os.getpid())
            process_info = {
                "pid": process.pid,
                "cpu_percent": process.cpu_percent(interval=None),
                "memory_percent": process.memory_percent(),
                "memory_mb": round(process.memory_info().rss / (1024**2), 2),
                "threads": process.num_threads(),
                "open_files": len(process.open_files()),
                "connections": len(process.connections())
            }
            
            # Update the resource usage dictionary
            self.resource_usage = {
                "timestamp": import time; time.time(),
                "cpu": {
                    "percent": cpu_percent,
                    "freq_mhz": cpu_freq_current
                },
                "memory": memory_usage,
                "disk": disk_usage,
                "network": network_usage,
                "process": process_info
            }
        
        except Exception as e:
            self.logger.error(f"Error updating resource usage: {str(e)}")
    
    def get_available_modules(self) -> Dict[str, Any]:
        """
        Get information about available modules.
        
        Returns:
            Dictionary of module information
        """
        return self.app.module_manager.get_module_status()
    
    def get_system_info(self) -> Dict[str, Any]:
        """
        Get system information.
        
        Returns:
            Dictionary of system information
        """
        return self.system_info
    
    def get_resource_usage(self) -> Dict[str, Any]:
        """
        Get current resource usage.
        
        Returns:
            Dictionary of resource usage information
        """
        # Update resource usage before returning
        self._update_resource_usage()
        return self.resource_usage