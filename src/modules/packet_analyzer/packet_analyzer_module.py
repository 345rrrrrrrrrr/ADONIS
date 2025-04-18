#!/usr/bin/env python3
# ADONIS Packet Analyzer Module

import logging
import os
import json
import threading
import time
import subprocess
from typing import Dict, List, Any, Optional, Callable

from core.module_manager import Module

class PacketAnalyzerModule(Module):
    """
    Packet Analyzer module for ADONIS.
    Provides packet capture and analysis capabilities inspired by Wireshark.
    """
    
    def __init__(self, app, name="packet_analyzer"):
        super().__init__(app, name)
        self.logger = logging.getLogger("adonis.module.packet_analyzer")
        self.active_captures = {}
        self.capture_results = {}
        self.capture_history = []
        self.capture_count = 0
        self.max_history = 100
        self.dependencies_checked = False
        self.available_interfaces = []
        
    def initialize(self) -> bool:
        """Initialize the packet analyzer module."""
        self.logger.info("Initializing Packet Analyzer Module")
        
        # Check for required dependencies
        if not self._check_dependencies():
            self.logger.error("Missing required dependencies for Packet Analyzer Module")
            return False
            
        # Create necessary directories
        results_dir = os.path.expanduser(
            self.app.config.get("system.paths.data_dir", "~/.adonis/data") + "/packet_analyzer"
        )
        os.makedirs(results_dir, exist_ok=True)
        
        # Get available network interfaces
        self._refresh_interfaces()
        
        # Load capture filters
        self._load_capture_filters()
        
        # Module successfully initialized
        self.initialized = True
        return True
        
    def shutdown(self) -> None:
        """Clean up resources when shutting down."""
        self.logger.info("Shutting down Packet Analyzer Module")
        
        # Stop all active captures
        for capture_id in list(self.active_captures.keys()):
            self.stop_capture(capture_id)
    
    def process_tasks(self) -> None:
        """Process any pending tasks for this module."""
        # Check status of active captures
        for capture_id, capture_info in list(self.active_captures.items()):
            if capture_info["process"] is not None:
                if capture_info["process"].poll() is not None:
                    # Capture has completed
                    self._handle_capture_completion(capture_id)
    
    def _check_dependencies(self) -> bool:
        """
        Check if required dependencies are installed.
        
        Returns:
            True if all dependencies are present
        """
        if self.dependencies_checked:
            return True
            
        # Check for tcpdump (command-line packet analyzer)
        try:
            result = subprocess.run(
                ["tcpdump", "--version"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            if result.returncode == 0:
                self.logger.info(f"Found tcpdump: {result.stdout.splitlines()[0].strip()}")
            else:
                self.logger.warning("tcpdump check returned non-zero exit code")
                return False
        except FileNotFoundError:
            self.logger.error("tcpdump not found in PATH")
            return False
        except Exception as e:
            self.logger.error(f"Error checking for tcpdump: {str(e)}")
            return False
            
        # Check for tshark (terminal version of Wireshark)
        try:
            result = subprocess.run(
                ["tshark", "--version"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            if result.returncode == 0:
                self.logger.info(f"Found tshark: {result.stdout.splitlines()[0].strip()}")
            else:
                self.logger.warning("tshark check returned non-zero exit code")
                return False
        except FileNotFoundError:
            self.logger.error("tshark not found in PATH")
            return False
        except Exception as e:
            self.logger.error(f"Error checking for tshark: {str(e)}")
            return False
            
        self.dependencies_checked = True
        return True
    
    def _refresh_interfaces(self) -> None:
        """Refresh the list of available network interfaces."""
        try:
            # Use tshark to list interfaces
            result = subprocess.run(
                ["tshark", "-D"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            
            if result.returncode == 0:
                interfaces = []
                for line in result.stdout.splitlines():
                    # Format is usually: 1. eth0 (Network interface)
                    parts = line.split(".", 1)
                    if len(parts) == 2:
                        # Extract interface name
                        interface_info = parts[1].strip()
                        # Further extract just the interface name
                        interface_name = interface_info.split()[0]
                        interfaces.append({
                            "name": interface_name,
                            "description": interface_info
                        })
                self.available_interfaces = interfaces
                self.logger.info(f"Found {len(interfaces)} network interfaces")
            else:
                self.logger.warning("Failed to get network interfaces")
        except Exception as e:
            self.logger.error(f"Error refreshing interfaces: {str(e)}")
    
    def _load_capture_filters(self) -> None:
        """Load predefined capture filters."""
        # Default capture filters
        self.capture_filters = {
            "http": {
                "name": "HTTP Traffic",
                "description": "Capture HTTP packets",
                "filter": "tcp port 80 or tcp port 443"
            },
            "dns": {
                "name": "DNS Traffic",
                "description": "Capture DNS queries and responses",
                "filter": "udp port 53 or tcp port 53"
            },
            "ssh": {
                "name": "SSH Traffic",
                "description": "Capture SSH connections",
                "filter": "tcp port 22"
            },
            "icmp": {
                "name": "ICMP Traffic",
                "description": "Capture ping and other ICMP traffic",
                "filter": "icmp or icmp6"
            },
            "arp": {
                "name": "ARP Traffic",
                "description": "Capture ARP requests and responses",
                "filter": "arp"
            },
            "dhcp": {
                "name": "DHCP Traffic",
                "description": "Capture DHCP requests and responses",
                "filter": "udp port 67 or udp port 68"
            }
        }
        
        # Load custom filters from config
        custom_filters = self.config.get("capture_filters", {})
        self.capture_filters.update(custom_filters)
    
    def get_interfaces(self) -> List[Dict[str, str]]:
        """
        Get list of available network interfaces.
        
        Returns:
            List of interface information dictionaries
        """
        return self.available_interfaces.copy()
    
    def get_capture_filters(self) -> Dict[str, Dict[str, str]]:
        """
        Get available capture filters.
        
        Returns:
            Dictionary of capture filters
        """
        return self.capture_filters.copy()
    
    def start_capture(self, interface: str, options: Dict[str, Any] = None, callback: Callable = None) -> str:
        """
        Start a new packet capture session.
        
        Args:
            interface: Network interface name to capture on
            options: Capture options
            callback: Function to call when capture completes
            
        Returns:
            Capture ID for tracking
        """
        if not self.initialized:
            self.logger.error("Cannot start capture: Module not initialized")
            return ""
        
        if not options:
            options = {}
        
        # Check if interface exists
        if not any(iface["name"] == interface for iface in self.available_interfaces):
            self.logger.error(f"Interface {interface} not found")
            return ""
        
        # Generate capture ID
        self.capture_count += 1
        capture_id = f"capture_{int(time.time())}_{self.capture_count}"
        
        # Prepare output files
        output_dir = os.path.expanduser(
            self.app.config.get("system.paths.data_dir", "~/.adonis/data") + "/packet_analyzer"
        )
        pcap_output = f"{output_dir}/{capture_id}.pcap"
        
        # Build tshark command
        cmd = ["tshark"]
        cmd.extend(["-i", interface])
        cmd.extend(["-w", pcap_output])
        
        # Add capture filter if specified
        capture_filter = None
        if "filter" in options:
            capture_filter = options["filter"]
        elif "filter_name" in options and options["filter_name"] in self.capture_filters:
            capture_filter = self.capture_filters[options["filter_name"]]["filter"]
        
        if capture_filter:
            cmd.extend(["-f", capture_filter])
        
        # Add duration limit
        duration = options.get("duration", 60)  # Default: 60 seconds
        cmd.extend(["-a", f"duration:{duration}"])
        
        # Add packet count limit if specified
        if "packet_limit" in options:
            cmd.extend(["-c", str(options["packet_limit"])])
        
        # Set ring buffer if continuous capture
        if options.get("ring_buffer", False):
            filesize = options.get("filesize_mb", 10)
            cmd.extend(["-b", f"filesize:{filesize}", "-b", "files:5"])
        
        self.logger.info(f"Starting capture {capture_id} with command: {' '.join(cmd)}")
        
        try:
            # Start the capture process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Record capture information
            capture_info = {
                "id": capture_id,
                "start_time": time.time(),
                "interface": interface,
                "options": options,
                "filter": capture_filter,
                "status": "running",
                "process": process,
                "output_file": pcap_output,
                "callback": callback
            }
            
            self.active_captures[capture_id] = capture_info
            
            # Add to history
            self.capture_history.append({
                "id": capture_id,
                "start_time": capture_info["start_time"],
                "interface": interface,
                "filter": capture_filter,
                "status": "running"
            })
            
            # Trim capture history if needed
            if len(self.capture_history) > self.max_history:
                self.capture_history = self.capture_history[-self.max_history:]
            
            return capture_id
            
        except Exception as e:
            self.logger.error(f"Error starting capture: {str(e)}")
            return ""
    
    def stop_capture(self, capture_id: str) -> bool:
        """
        Stop a running packet capture.
        
        Args:
            capture_id: ID of the capture to stop
            
        Returns:
            True if capture was stopped successfully
        """
        if capture_id not in self.active_captures:
            self.logger.warning(f"Cannot stop capture {capture_id}: not found")
            return False
            
        capture_info = self.active_captures[capture_id]
        
        # Terminate the process
        if capture_info["process"] and capture_info["process"].poll() is None:
            try:
                capture_info["process"].terminate()
                capture_info["process"].wait(timeout=5)
                self.logger.info(f"Capture {capture_id} terminated")
            except subprocess.TimeoutExpired:
                capture_info["process"].kill()
                self.logger.warning(f"Capture {capture_id} killed after timeout")
            except Exception as e:
                self.logger.error(f"Error stopping capture {capture_id}: {str(e)}")
                return False
        
        # Update capture status
        capture_info["status"] = "stopped"
        capture_info["end_time"] = time.time()
        
        # Update history
        for capture in self.capture_history:
            if capture["id"] == capture_id:
                capture["status"] = "stopped"
                capture["end_time"] = time.time()
                break
        
        # Process the completed capture
        self._handle_capture_completion(capture_id)
        
        return True
    
    def get_capture_status(self, capture_id: str) -> Dict[str, Any]:
        """
        Get status of a capture.
        
        Args:
            capture_id: ID of the capture
            
        Returns:
            Dictionary with capture status information
        """
        if capture_id in self.active_captures:
            capture_info = self.active_captures[capture_id].copy()
            # Remove process object from the result
            if "process" in capture_info:
                del capture_info["process"]
            if "callback" in capture_info:
                del capture_info["callback"]
            return capture_info
        elif capture_id in self.capture_results:
            return self.capture_results[capture_id]
        else:
            for capture in self.capture_history:
                if capture["id"] == capture_id:
                    return capture
                    
        return {"id": capture_id, "status": "not_found"}
    
    def get_capture_history(self) -> List[Dict[str, Any]]:
        """
        Get history of all packet captures.
        
        Returns:
            List of capture history entries
        """
        return self.capture_history.copy()
    
    def analyze_capture(self, capture_id: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze a packet capture file.
        
        Args:
            capture_id: ID of the capture to analyze
            options: Analysis options
            
        Returns:
            Dictionary with analysis results
        """
        if not options:
            options = {}
            
        # Find the capture file
        capture_file = None
        
        if capture_id in self.capture_results:
            capture_file = self.capture_results[capture_id].get("output_file")
        else:
            for capture in self.capture_history:
                if capture["id"] == capture_id:
                    output_dir = os.path.expanduser(
                        self.app.config.get("system.paths.data_dir", "~/.adonis/data") + "/packet_analyzer"
                    )
                    capture_file = f"{output_dir}/{capture_id}.pcap"
                    break
        
        if not capture_file or not os.path.exists(capture_file):
            return {"error": f"Capture file for {capture_id} not found"}
            
        try:
            # Build tshark command for analysis
            cmd = ["tshark", "-r", capture_file]
            
            # Add display filter if specified
            if "display_filter" in options:
                cmd.extend(["-Y", options["display_filter"]])
                
            # Add stats option if specified
            if options.get("stats", False):
                cmd.extend(["-z", "io,stat,1"])
                
            # Add packet limit if specified
            if "limit" in options:
                cmd.extend(["-c", str(options["limit"])])
                
            # Set output format to JSON if requested
            if options.get("format", "text") == "json":
                cmd.extend(["-T", "json"])
                
            # Run the command
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            output = result.stdout
            
            if options.get("format", "text") == "json":
                try:
                    return json.loads(output)
                except json.JSONDecodeError:
                    return {"error": "Failed to parse JSON output", "raw": output}
            else:
                # Process text output
                packets = []
                lines = output.splitlines()
                for line in lines:
                    if line.strip():
                        packets.append(line)
                        
                return {
                    "id": capture_id,
                    "packets": packets,
                    "count": len(packets)
                }
                
        except Exception as e:
            self.logger.error(f"Error analyzing capture: {str(e)}")
            return {"error": str(e)}
    
    def _handle_capture_completion(self, capture_id: str) -> None:
        """
        Handle completion of a packet capture.
        
        Args:
            capture_id: ID of the completed capture
        """
        # Skip if not in active captures
        if capture_id not in self.active_captures:
            return
            
        capture_info = self.active_captures[capture_id]
        process = capture_info["process"]
        
        # Get return code
        return_code = process.poll()
        
        # Read output
        stdout, stderr = process.communicate()
        
        # Determine status if not already set
        if capture_info.get("status") != "stopped":
            if return_code == 0:
                status = "completed"
            else:
                status = "failed"
            
            # Update capture info
            capture_info["status"] = status
            capture_info["end_time"] = time.time()
            
        # Add more details
        capture_info["return_code"] = return_code
        capture_info["stderr"] = stderr
        
        # Get basic stats about the capture
        stats = self._get_capture_stats(capture_info["output_file"])
        capture_info["stats"] = stats
        
        # Save to capture results
        self.capture_results[capture_id] = capture_info.copy()
        
        # Update capture history
        for capture in self.capture_history:
            if capture["id"] == capture_id:
                capture["status"] = capture_info["status"]
                if "end_time" in capture_info:
                    capture["end_time"] = capture_info["end_time"]
                if "packet_count" in stats:
                    capture["packet_count"] = stats["packet_count"]
                break
                
        # Remove the process object
        if "process" in capture_info:
            del capture_info["process"]
            
        # Call the callback if provided
        if capture_info["callback"]:
            try:
                capture_info["callback"](capture_id, capture_info["status"], stats)
            except Exception as e:
                self.logger.error(f"Error in capture callback: {str(e)}")
                
        # Remove from active captures
        del self.active_captures[capture_id]
        
        self.logger.info(f"Capture {capture_id} {capture_info['status']}")
    
    def _get_capture_stats(self, capture_file: str) -> Dict[str, Any]:
        """
        Get basic statistics for a capture file.
        
        Args:
            capture_file: Path to the capture file
            
        Returns:
            Dictionary with basic statistics
        """
        stats = {}
        
        if not os.path.exists(capture_file):
            return stats
            
        try:
            # Get packet count
            cmd = ["capinfos", "-c", capture_file]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Number of packets" in line:
                        parts = line.split(":")
                        if len(parts) == 2:
                            stats["packet_count"] = int(parts[1].strip())
            
            # Get capture duration
            cmd = ["capinfos", "-u", capture_file]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Capture duration" in line:
                        parts = line.split(":")
                        if len(parts) == 2:
                            duration_str = parts[1].strip().split()[0]
                            try:
                                stats["duration"] = float(duration_str)
                            except ValueError:
                                pass
            
            # Get capture size
            stats["file_size"] = os.path.getsize(capture_file)
            
        except Exception as e:
            self.logger.error(f"Error getting capture stats: {str(e)}")
            
        return stats
    
    def export_capture(self, capture_id: str, format: str = "pcap", options: Dict[str, Any] = None) -> str:
        """
        Export a packet capture to a different format.
        
        Args:
            capture_id: ID of the capture to export
            format: Target format (pcap, pcapng, csv, txt, json, etc.)
            options: Export options
            
        Returns:
            Path to the exported file or error message
        """
        if not options:
            options = {}
            
        # Find the capture file
        capture_file = None
        
        if capture_id in self.capture_results:
            capture_file = self.capture_results[capture_id].get("output_file")
        else:
            for capture in self.capture_history:
                if capture["id"] == capture_id:
                    output_dir = os.path.expanduser(
                        self.app.config.get("system.paths.data_dir", "~/.adonis/data") + "/packet_analyzer"
                    )
                    capture_file = f"{output_dir}/{capture_id}.pcap"
                    break
        
        if not capture_file or not os.path.exists(capture_file):
            return f"Capture file for {capture_id} not found"
            
        try:
            # Prepare output file
            output_dir = os.path.expanduser(
                self.app.config.get("system.paths.data_dir", "~/.adonis/data") + "/packet_analyzer/exports"
            )
            os.makedirs(output_dir, exist_ok=True)
            
            export_file = f"{output_dir}/{capture_id}.{format}"
            
            # Build export command
            if format in ["pcap", "pcapng"]:
                cmd = ["editcap", capture_file, export_file]
            elif format in ["txt", "csv", "json", "psml", "pdml"]:
                cmd = ["tshark", "-r", capture_file, "-T", format, "-w", export_file]
                
                # Add display filter if specified
                if "display_filter" in options:
                    cmd.extend(["-Y", options["display_filter"]])
            else:
                return f"Unsupported export format: {format}"
            
            # Run the export command
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                return export_file
            else:
                return f"Export failed: {result.stderr}"
            
        except Exception as e:
            self.logger.error(f"Error exporting capture: {str(e)}")
            return f"Export error: {str(e)}"