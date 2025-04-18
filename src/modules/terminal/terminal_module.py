#!/usr/bin/env python3
# ADONIS Terminal Module

import logging
import os
import json
import threading
import time
import subprocess
import shlex
import pty
import select
import signal
import fcntl
import termios
import struct
import sys
from typing import Dict, List, Any, Optional, Callable

from core.module_manager import Module

class TerminalModule(Module):
    """
    Terminal module for ADONIS.
    Provides terminal/shell access with history, environment management, and scripting.
    """
    
    def __init__(self, app, name="terminal"):
        super().__init__(app, name)
        self.logger = logging.getLogger("adonis.module.terminal")
        self.active_terminals = {}
        self.terminal_history = []
        self.environment_vars = {}
        self.terminal_count = 0
        self.max_history = 100
        
    def initialize(self) -> bool:
        """Initialize the terminal module."""
        self.logger.info("Initializing Terminal Module")
        
        # Create necessary directories
        history_dir = os.path.expanduser(
            self.app.config.get("system.paths.data_dir", "~/.adonis/data") + "/terminal"
        )
        os.makedirs(history_dir, exist_ok=True)
        
        # Load environment variables from config
        self._load_environment_vars()
        
        # Load history from file
        self._load_history()
        
        # Module successfully initialized
        self.initialized = True
        return True
        
    def shutdown(self) -> None:
        """Clean up resources when shutting down."""
        self.logger.info("Shutting down Terminal Module")
        
        # Stop all active terminals
        terminal_ids = list(self.active_terminals.keys())
        for terminal_id in terminal_ids:
            self.stop_terminal(terminal_id)
            
        # Save history to file
        self._save_history()
    
    def process_tasks(self) -> None:
        """Process any pending tasks for this module."""
        # Check status of active terminals and read any available output
        for terminal_id, terminal_info in list(self.active_terminals.items()):
            if not self._is_terminal_alive(terminal_id):
                self._handle_terminal_exit(terminal_id)
            else:
                # Read any available output
                self._read_terminal_output(terminal_id)
    
    def _load_environment_vars(self) -> None:
        """Load environment variables from configuration."""
        # Get system environment
        self.environment_vars = dict(os.environ)
        
        # Add/override with config values
        config_env = self.config.get("environment", {})
        self.environment_vars.update(config_env)
        
        # Ensure PATH is set
        if "PATH" not in self.environment_vars:
            self.environment_vars["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    
    def _load_history(self) -> None:
        """Load command history from file."""
        history_file = os.path.expanduser(
            self.app.config.get("system.paths.data_dir", "~/.adonis/data") + "/terminal/history.json"
        )
        
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r') as f:
                    self.terminal_history = json.load(f)
                    self.logger.info(f"Loaded {len(self.terminal_history)} history entries")
            except Exception as e:
                self.logger.error(f"Error loading terminal history: {str(e)}")
                self.terminal_history = []
        else:
            self.terminal_history = []
    
    def _save_history(self) -> None:
        """Save command history to file."""
        history_file = os.path.expanduser(
            self.app.config.get("system.paths.data_dir", "~/.adonis/data") + "/terminal/history.json"
        )
        
        try:
            with open(history_file, 'w') as f:
                json.dump(self.terminal_history[-self.max_history:], f)
                self.logger.info(f"Saved {len(self.terminal_history[-self.max_history:])} history entries")
        except Exception as e:
            self.logger.error(f"Error saving terminal history: {str(e)}")
    
    def start_terminal(self, shell: str = None, working_dir: str = None, 
                       env_vars: Dict[str, str] = None, 
                       callback: Callable = None) -> str:
        """
        Start a new terminal session.
        
        Args:
            shell: Shell to use (e.g., "bash", "zsh"). If None, use system default.
            working_dir: Working directory. If None, use home directory.
            env_vars: Additional environment variables.
            callback: Function to call when terminal exits.
            
        Returns:
            Terminal ID for tracking
        """
        if not self.initialized:
            self.logger.error("Cannot start terminal: Module not initialized")
            return ""
        
        # Generate terminal ID
        self.terminal_count += 1
        terminal_id = f"term_{int(time.time())}_{self.terminal_count}"
        
        # Determine shell
        if not shell:
            shell = os.environ.get("SHELL", "/bin/bash")
        
        # Determine working directory
        if not working_dir:
            working_dir = os.path.expanduser("~")
        
        try:
            # Create environment
            terminal_env = self.environment_vars.copy()
            if env_vars:
                terminal_env.update(env_vars)
            
            # Start the terminal in a pseudo-terminal
            master, slave = pty.openpty()
            
            # Set non-blocking mode on the master
            flags = fcntl.fcntl(master, fcntl.F_GETFL)
            fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            # Start the shell process
            process = subprocess.Popen(
                [shell],
                stdin=slave,
                stdout=slave,
                stderr=slave,
                start_new_session=True,
                env=terminal_env,
                cwd=working_dir
            )
            
            # Close the slave fd as it's now owned by the subprocess
            os.close(slave)
            
            # Record terminal information
            terminal_info = {
                "id": terminal_id,
                "start_time": time.time(),
                "shell": shell,
                "working_dir": working_dir,
                "process": process,
                "master_fd": master,
                "env": terminal_env,
                "output_buffer": b"",
                "exit_code": None,
                "status": "running",
                "callback": callback
            }
            
            self.active_terminals[terminal_id] = terminal_info
            
            self.logger.info(f"Started terminal {terminal_id} using {shell}")
            return terminal_id
            
        except Exception as e:
            self.logger.error(f"Error starting terminal: {str(e)}")
            return ""
    
    def stop_terminal(self, terminal_id: str) -> bool:
        """
        Stop a terminal session.
        
        Args:
            terminal_id: ID of the terminal to stop
            
        Returns:
            True if the terminal was stopped successfully
        """
        if terminal_id not in self.active_terminals:
            self.logger.warning(f"Cannot stop terminal {terminal_id}: not found")
            return False
            
        terminal_info = self.active_terminals[terminal_id]
        
        # Send SIGTERM to process group
        try:
            os.killpg(os.getpgid(terminal_info["process"].pid), signal.SIGTERM)
            
            # Give it a chance to terminate gracefully
            for _ in range(10):  # Wait up to 1 second
                if not self._is_terminal_alive(terminal_id):
                    break
                time.sleep(0.1)
                
            # If still running, force kill
            if self._is_terminal_alive(terminal_id):
                os.killpg(os.getpgid(terminal_info["process"].pid), signal.SIGKILL)
                
            # Clean up
            self._handle_terminal_exit(terminal_id)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping terminal {terminal_id}: {str(e)}")
            return False
    
    def send_input(self, terminal_id: str, input_text: str) -> bool:
        """
        Send input to a terminal session.
        
        Args:
            terminal_id: ID of the terminal
            input_text: Text to send to the terminal
            
        Returns:
            True if the input was sent successfully
        """
        if terminal_id not in self.active_terminals:
            self.logger.warning(f"Cannot send input to terminal {terminal_id}: not found")
            return False
            
        terminal_info = self.active_terminals[terminal_id]
        
        if not self._is_terminal_alive(terminal_id):
            self.logger.warning(f"Cannot send input to terminal {terminal_id}: process is not running")
            return False
            
        try:
            # Add input to history if it ends with newline
            if input_text.endswith('\n') and input_text.strip():
                command = input_text.strip()
                self._add_to_history(command)
                
            # Convert to bytes and send to the pty
            os.write(terminal_info["master_fd"], input_text.encode())
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending input to terminal {terminal_id}: {str(e)}")
            return False
    
    def read_output(self, terminal_id: str, max_size: int = None) -> bytes:
        """
        Read output from a terminal session.
        
        Args:
            terminal_id: ID of the terminal
            max_size: Maximum number of bytes to read
            
        Returns:
            Output bytes or empty bytes if no output available
        """
        if terminal_id not in self.active_terminals:
            self.logger.warning(f"Cannot read from terminal {terminal_id}: not found")
            return b""
            
        terminal_info = self.active_terminals[terminal_id]
        
        if max_size is not None and max_size <= 0:
            return b""
            
        # Return buffered output
        output = terminal_info["output_buffer"]
        
        if max_size is not None and len(output) > max_size:
            # Keep the extra bytes in the buffer for the next read
            terminal_info["output_buffer"] = output[max_size:]
            return output[:max_size]
        else:
            # Return all buffered output
            terminal_info["output_buffer"] = b""
            return output
    
    def get_terminal_status(self, terminal_id: str) -> Dict[str, Any]:
        """
        Get status of a terminal session.
        
        Args:
            terminal_id: ID of the terminal
            
        Returns:
            Dictionary with terminal status information
        """
        if terminal_id in self.active_terminals:
            terminal_info = self.active_terminals[terminal_id].copy()
            # Remove items that can't be serialized
            if "process" in terminal_info:
                terminal_info["process_pid"] = terminal_info["process"].pid
                del terminal_info["process"]
            if "master_fd" in terminal_info:
                del terminal_info["master_fd"]
            if "callback" in terminal_info:
                del terminal_info["callback"]
            if "output_buffer" in terminal_info:
                terminal_info["output_available"] = len(terminal_info["output_buffer"]) > 0
                del terminal_info["output_buffer"]
            return terminal_info
        else:
            return {"id": terminal_id, "status": "not_found"}
    
    def get_environment(self, terminal_id: str = None) -> Dict[str, str]:
        """
        Get environment variables for a terminal or the default environment.
        
        Args:
            terminal_id: ID of the terminal. If None, return default environment.
            
        Returns:
            Dictionary of environment variables
        """
        if terminal_id is not None and terminal_id in self.active_terminals:
            return self.active_terminals[terminal_id]["env"].copy()
        else:
            return self.environment_vars.copy()
    
    def set_environment_var(self, name: str, value: str, terminal_id: str = None) -> bool:
        """
        Set an environment variable.
        
        Args:
            name: Name of the variable
            value: Value to set
            terminal_id: ID of the terminal. If None, set in default environment.
            
        Returns:
            True if successful
        """
        if terminal_id is not None and terminal_id in self.active_terminals:
            self.active_terminals[terminal_id]["env"][name] = value
            return True
        else:
            self.environment_vars[name] = value
            return True
    
    def resize_terminal(self, terminal_id: str, rows: int, cols: int) -> bool:
        """
        Resize a terminal session.
        
        Args:
            terminal_id: ID of the terminal
            rows: Number of rows
            cols: Number of columns
            
        Returns:
            True if successful
        """
        if terminal_id not in self.active_terminals:
            self.logger.warning(f"Cannot resize terminal {terminal_id}: not found")
            return False
            
        terminal_info = self.active_terminals[terminal_id]
        
        try:
            # Set terminal size
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(terminal_info["master_fd"], termios.TIOCSWINSZ, winsize)
            return True
        except Exception as e:
            self.logger.error(f"Error resizing terminal {terminal_id}: {str(e)}")
            return False
    
    def get_terminal_history(self) -> List[str]:
        """
        Get command history.
        
        Returns:
            List of historical commands
        """
        return self.terminal_history.copy()
    
    def execute_script(self, terminal_id: str, script: str) -> bool:
        """
        Execute a script in a terminal session.
        
        Args:
            terminal_id: ID of the terminal
            script: Script content
            
        Returns:
            True if successful
        """
        if terminal_id not in self.active_terminals:
            self.logger.warning(f"Cannot execute script in terminal {terminal_id}: not found")
            return False
            
        lines = script.splitlines()
        for line in lines:
            if not self.send_input(terminal_id, line + '\n'):
                return False
                
        return True
    
    def _is_terminal_alive(self, terminal_id: str) -> bool:
        """
        Check if a terminal process is still running.
        
        Args:
            terminal_id: ID of the terminal
            
        Returns:
            True if the terminal is still running
        """
        if terminal_id not in self.active_terminals:
            return False
            
        terminal_info = self.active_terminals[terminal_id]
        
        return terminal_info["process"].poll() is None
    
    def _read_terminal_output(self, terminal_id: str) -> None:
        """
        Read output from a terminal's pty.
        
        Args:
            terminal_id: ID of the terminal
        """
        if terminal_id not in self.active_terminals:
            return
            
        terminal_info = self.active_terminals[terminal_id]
        
        try:
            # Try to read from the pty
            ready, _, _ = select.select([terminal_info["master_fd"]], [], [], 0)
            
            if terminal_info["master_fd"] in ready:
                try:
                    data = os.read(terminal_info["master_fd"], 4096)
                    if data:
                        terminal_info["output_buffer"] += data
                except OSError:
                    # No data available or other error
                    pass
                    
        except Exception as e:
            self.logger.error(f"Error reading from terminal {terminal_id}: {str(e)}")
    
    def _handle_terminal_exit(self, terminal_id: str) -> None:
        """
        Handle a terminal process exiting.
        
        Args:
            terminal_id: ID of the terminal
        """
        if terminal_id not in self.active_terminals:
            return
            
        terminal_info = self.active_terminals[terminal_id]
        
        # Get exit code
        exit_code = terminal_info["process"].poll()
        
        # Read any remaining output
        self._read_terminal_output(terminal_id)
        
        # Update terminal info
        terminal_info["status"] = "exited"
        terminal_info["exit_code"] = exit_code
        terminal_info["end_time"] = time.time()
        
        # Close the pty master
        try:
            os.close(terminal_info["master_fd"])
        except OSError:
            pass
            
        # Call the callback if provided
        if terminal_info["callback"]:
            try:
                terminal_info["callback"](terminal_id, exit_code)
            except Exception as e:
                self.logger.error(f"Error in terminal callback: {str(e)}")
        
        # Keep the terminal info for history, but remove process and fd references
        del terminal_info["process"]
        del terminal_info["master_fd"]
        
        self.logger.info(f"Terminal {terminal_id} exited with code {exit_code}")
    
    def _add_to_history(self, command: str) -> None:
        """
        Add a command to history.
        
        Args:
            command: Command to add
        """
        # Don't add empty commands or duplicates of the last command
        if not command or (self.terminal_history and self.terminal_history[-1] == command):
            return
            
        self.terminal_history.append(command)
        
        # Trim history if too long
        if len(self.terminal_history) > self.max_history:
            self.terminal_history = self.terminal_history[-self.max_history:]