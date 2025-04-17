#!/usr/bin/env python3
# ADONIS Module Manager

import importlib
import logging
import os
import sys
import time
from typing import Dict, List, Any, Optional

class Module:
    """Base class for all ADONIS modules."""
    
    def __init__(self, app, name):
        self.app = app
        self.name = name
        self.logger = logging.getLogger(f"adonis.module.{name}")
        self.config = app.config.get_module_config(name)
        self.enabled = True
        self.initialized = False
    
    def initialize(self) -> bool:
        """Initialize the module. Return True if successful."""
        self.initialized = True
        return True
    
    def shutdown(self) -> None:
        """Clean up resources when shutting down."""
        pass
    
    def process_tasks(self) -> None:
        """Process any pending tasks for this module."""
        pass
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the module."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "initialized": self.initialized
        }

class ModuleManager:
    """
    Manages loading, initialization, and communication between modules.
    """
    
    def __init__(self, app):
        self.app = app
        self.logger = logging.getLogger("adonis.core.module_manager")
        self.modules: Dict[str, Module] = {}
        self.module_paths = [
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules"),
            os.path.expanduser("~/.adonis/modules")
        ]
    
    def load_modules(self, module_names: List[str]) -> bool:
        """
        Load and initialize the specified modules.
        
        Args:
            module_names: List of module names to load
            
        Returns:
            True if all modules were loaded successfully
        """
        success = True
        
        for name in module_names:
            if name in self.modules:
                self.logger.warning(f"Module '{name}' is already loaded")
                continue
                
            try:
                # Try to import the module
                if name == "core":
                    # Core module is a special case
                    from core.core_module import CoreModule
                    module_class = CoreModule
                else:
                    # For regular modules, dynamically import them
                    module_path = f"modules.{name}.{name}_module"
                    module = importlib.import_module(module_path)
                    module_class_name = ''.join(word.capitalize() for word in name.split('_')) + 'Module'
                    module_class = getattr(module, module_class_name)
                
                # Create an instance of the module
                instance = module_class(self.app, name)
                
                # Initialize the module
                self.logger.info(f"Initializing module: {name}")
                if instance.initialize():
                    self.modules[name] = instance
                    self.logger.info(f"Module '{name}' loaded successfully")
                else:
                    self.logger.error(f"Failed to initialize module: {name}")
                    success = False
                    
            except Exception as e:
                self.logger.error(f"Error loading module '{name}': {str(e)}", exc_info=True)
                success = False
        
        return success
    
    def unload_module(self, name: str) -> bool:
        """
        Unload and clean up a module.
        
        Args:
            name: Name of the module to unload
            
        Returns:
            True if the module was unloaded successfully
        """
        if name not in self.modules:
            self.logger.warning(f"Module '{name}' is not loaded")
            return False
            
        try:
            # Shutdown the module
            self.logger.info(f"Shutting down module: {name}")
            self.modules[name].shutdown()
            
            # Remove the module from the loaded modules
            del self.modules[name]
            self.logger.info(f"Module '{name}' unloaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error unloading module '{name}': {str(e)}", exc_info=True)
            return False
    
    def unload_all(self) -> None:
        """Unload all modules in reverse order of loading."""
        # Create a list of module names and reverse it
        module_names = list(self.modules.keys())
        module_names.reverse()
        
        for name in module_names:
            self.unload_module(name)
    
    def get_module(self, name: str) -> Optional[Module]:
        """Get a loaded module by name."""
        return self.modules.get(name)
    
    def get_all_modules(self) -> Dict[str, Module]:
        """Get all loaded modules."""
        return self.modules.copy()
    
    def process_tasks(self) -> None:
        """Process tasks for all loaded modules."""
        for module in self.modules.values():
            if module.enabled:
                module.process_tasks()
    
    def get_module_status(self) -> List[Dict[str, Any]]:
        """Get status information for all modules."""
        return [module.get_status() for module in self.modules.values()]