#!/usr/bin/env python3
# ADONIS Configuration System

import os
import yaml
import logging
from typing import Dict, Any, Optional

class Config:
    """
    Configuration manager for ADONIS.
    Handles loading, saving, and accessing configuration settings.
    """
    
    def __init__(self, config_path):
        """
        Initialize the configuration system.
        
        Args:
            config_path: Path to the main configuration file
        """
        self.logger = logging.getLogger("adonis.core.config")
        self.config_path = os.path.expanduser(config_path)
        self.config_dir = os.path.dirname(self.config_path)
        self.config_data = {}
        
        # Create config directory if it doesn't exist
        if not os.path.exists(self.config_dir):
            try:
                os.makedirs(self.config_dir, mode=0o700, exist_ok=True)
                self.logger.info(f"Created configuration directory: {self.config_dir}")
            except Exception as e:
                self.logger.error(f"Failed to create config directory: {str(e)}")
        
        # Load configuration
        self.load()
    
    def load(self) -> bool:
        """
        Load configuration from file.
        
        Returns:
            True if configuration was loaded successfully
        """
        # If config file doesn't exist, create a default one
        if not os.path.exists(self.config_path):
            self.logger.info(f"Configuration file not found: {self.config_path}")
            self.config_data = self._create_default_config()
            return self.save()
        
        # Load existing config file
        try:
            with open(self.config_path, 'r') as f:
                self.config_data = yaml.safe_load(f) or {}
            self.logger.info(f"Configuration loaded from {self.config_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {str(e)}")
            self.config_data = self._create_default_config()
            return False
    
    def save(self) -> bool:
        """
        Save configuration to file.
        
        Returns:
            True if configuration was saved successfully
        """
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config_data, f, default_flow_style=False)
            self.logger.info(f"Configuration saved to {self.config_path}")
            
            # Set secure permissions on config file
            os.chmod(self.config_path, 0o600)
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {str(e)}")
            return False
    
    def get(self, key, default=None):
        """
        Get a configuration value by key.
        
        Args:
            key: The configuration key (dot notation for nested keys)
            default: Default value if key doesn't exist
            
        Returns:
            The configuration value or default if not found
        """
        # Handle dot notation for nested keys
        keys = key.split('.')
        value = self.config_data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
                
        return value
    
    def set(self, key, value) -> None:
        """
        Set a configuration value.
        
        Args:
            key: The configuration key (dot notation for nested keys)
            value: The value to set
        """
        # Handle dot notation for nested keys
        keys = key.split('.')
        data = self.config_data
        
        # Navigate to the innermost dict
        for k in keys[:-1]:
            if k not in data or not isinstance(data[k], dict):
                data[k] = {}
            data = data[k]
                
        # Set the value
        data[keys[-1]] = value
    
    def get_module_config(self, module_name):
        """
        Get configuration for a specific module.
        
        Args:
            module_name: Name of the module
            
        Returns:
            Module configuration dict
        """
        return self.get(f'modules.{module_name}', {})
    
    def _create_default_config(self) -> Dict[str, Any]:
        """
        Create default configuration.
        
        Returns:
            Default configuration dict
        """
        # Create basic default configuration
        return {
            'system': {
                'version': '0.1.0',
                'paths': {
                    'data_dir': os.path.expanduser('~/.adonis/data'),
                    'logs_dir': os.path.expanduser('~/.adonis/logs'),
                    'plugins_dir': os.path.expanduser('~/.adonis/plugins'),
                },
                'security': {
                    'encryption_key_file': os.path.expanduser('~/.adonis/keys/encryption.key'),
                    'session_timeout_minutes': 30,
                    'require_auth': True,
                    'allow_remote': False,
                },
                'requirements': {
                    'min_ram_mb': 1024,
                    'min_disk_gb': 5,
                }
            },
            'ui': {
                'theme': 'dark',
                'show_welcome_screen': True,
                'font_size': 'medium',
                'enable_animations': True,
                'layout': 'default',
            },
            'modules': {
                'core': {
                    'enabled': True,
                },
                'debugger': {
                    'enabled': True,
                    'default_options': {
                        'disassembly_format': 'intel',
                        'follow_forks': False,
                    }
                },
                'network_scanner': {
                    'enabled': True,
                    'default_options': {
                        'timing_template': 3,
                        'max_scan_hosts': 1024,
                        'max_scan_ports': 1024,
                    }
                },
                'terminal': {
                    'enabled': True,
                    'shell': '/bin/bash',
                    'history_size': 1000,
                    'enable_autosuggestions': True,
                },
                'packet_analyzer': {
                    'enabled': True,
                    'capture_buffer_mb': 100,
                    'default_filter': '',
                    'resolve_names': True,
                },
                'memory_editor': {
                    'enabled': True,
                    'read_only_mode': True,
                    'backup_values': True,
                }
            },
            'ai_assistant': {
                'enabled': True,
                'model': 'local',
                'log_conversations': False,
                'privacy_mode': True,
            },
            'api': {
                'enabled': False,
                'port': 8000,
                'host': '127.0.0.1',
                'require_auth': True,
            },
            'logging': {
                'level': 'info',
                'max_files': 10,
                'max_size_mb': 10,
            }
        }