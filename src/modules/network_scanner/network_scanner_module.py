#!/usr/bin/env python3
# ADONIS Network Scanner Module

import logging
import os
import json
import threading
import time
import ipaddress
import subprocess
from typing import Dict, List, Any, Optional, Callable

from core.module_manager import Module

class NetworkScannerModule(Module):
    """
    Network Scanner module for ADONIS.
    Provides network scanning capabilities inspired by nmap.
    """
    
    def __init__(self, app, name="network_scanner"):
        super().__init__(app, name)
        self.logger = logging.getLogger("adonis.module.network_scanner")
        self.active_scans = {}
        self.scan_results = {}
        self.scan_history = []
        self.scan_count = 0
        self.max_history = 100
        self.dependencies_checked = False
        
    def initialize(self) -> bool:
        """Initialize the network scanner module."""
        self.logger.info("Initializing Network Scanner Module")
        
        # Check for required dependencies
        if not self._check_dependencies():
            self.logger.error("Missing required dependencies for Network Scanner Module")
            return False
            
        # Create necessary directories
        results_dir = os.path.expanduser(
            self.app.config.get("system.paths.data_dir", "~/.adonis/data") + "/network_scanner"
        )
        os.makedirs(results_dir, exist_ok=True)
        
        # Load scan profiles
        self._load_scan_profiles()
        
        # Module successfully initialized
        self.initialized = True
        return True
        
    def shutdown(self) -> None:
        """Clean up resources when shutting down."""
        self.logger.info("Shutting down Network Scanner Module")
        
        # Stop all active scans
        for scan_id in list(self.active_scans.keys()):
            self.stop_scan(scan_id)
    
    def process_tasks(self) -> None:
        """Process any pending tasks for this module."""
        # Check status of active scans
        for scan_id, scan_info in list(self.active_scans.items()):
            if scan_info["process"] is not None:
                if scan_info["process"].poll() is not None:
                    # Scan has completed
                    self._handle_scan_completion(scan_id)
    
    def _check_dependencies(self) -> bool:
        """
        Check if required dependencies are installed.
        
        Returns:
            True if all dependencies are present
        """
        if self.dependencies_checked:
            return True
            
        # Check for nmap
        try:
            result = subprocess.run(
                ["nmap", "--version"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            if result.returncode == 0:
                self.logger.info(f"Found nmap: {result.stdout.splitlines()[0].strip()}")
            else:
                self.logger.warning("nmap check returned non-zero exit code")
                return False
        except FileNotFoundError:
            self.logger.error("nmap not found in PATH")
            return False
        except Exception as e:
            self.logger.error(f"Error checking for nmap: {str(e)}")
            return False
            
        self.dependencies_checked = True
        return True
    
    def _load_scan_profiles(self) -> None:
        """Load predefined scan profiles."""
        # Default scan profiles
        self.scan_profiles = {
            "quick": {
                "name": "Quick Scan",
                "description": "Fast scan of most common ports",
                "args": ["-F", "--open"]
            },
            "comprehensive": {
                "name": "Comprehensive Scan",
                "description": "Detailed scan of all ports with service detection",
                "args": ["-p-", "-sV", "-O", "--open"]
            },
            "stealth": {
                "name": "Stealth Scan",
                "description": "More discrete SYN scan with minimal packets",
                "args": ["-sS", "-T2", "--open"]
            },
            "vuln": {
                "name": "Vulnerability Scan",
                "description": "Scan for common vulnerabilities",
                "args": ["--script", "vuln", "-sV", "--open"]
            }
        }
        
        # Load custom profiles from config
        custom_profiles = self.config.get("scan_profiles", {})
        self.scan_profiles.update(custom_profiles)
    
    def start_scan(self, targets: List[str], options: Dict[str, Any] = None, callback: Callable = None) -> str:
        """
        Start a new network scan.
        
        Args:
            targets: List of target IPs, hostnames, or CIDR ranges
            options: Scan options
            callback: Function to call when scan completes
            
        Returns:
            Scan ID for tracking the scan
        """
        if not self.initialized:
            self.logger.error("Cannot start scan: Module not initialized")
            return ""
        
        if not options:
            options = {}
        
        # Generate scan ID
        self.scan_count += 1
        scan_id = f"scan_{int(time.time())}_{self.scan_count}"
        
        # Validate targets
        validated_targets = self._validate_targets(targets)
        if not validated_targets:
            self.logger.error("No valid targets specified")
            return ""
        
        # Apply profile if specified
        profile = options.get("profile", "quick")
        if profile in self.scan_profiles:
            profile_args = self.scan_profiles[profile]["args"]
        else:
            profile_args = self.scan_profiles["quick"]["args"]
        
        # Prepare output files
        output_dir = os.path.expanduser(
            self.app.config.get("system.paths.data_dir", "~/.adonis/data") + "/network_scanner"
        )
        xml_output = f"{output_dir}/{scan_id}.xml"
        
        # Build nmap command
        cmd = ["nmap"]
        cmd.extend(profile_args)
        
        # Add additional arguments from options
        timing = options.get("timing", 3)
        cmd.extend([f"-T{timing}"])
        
        # Service scan if requested
        if options.get("service_detection", False):
            cmd.extend(["-sV"])
        
        # OS detection if requested
        if options.get("os_detection", False):
            cmd.extend(["-O"])
            
        # Add output format
        cmd.extend(["-oX", xml_output])
        
        # Add targets
        cmd.extend(validated_targets)
        
        self.logger.info(f"Starting scan {scan_id} with command: {' '.join(cmd)}")
        
        try:
            # Start the scan process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Record scan information
            scan_info = {
                "id": scan_id,
                "start_time": time.time(),
                "targets": validated_targets,
                "options": options,
                "profile": profile,
                "status": "running",
                "process": process,
                "output_file": xml_output,
                "callback": callback
            }
            
            self.active_scans[scan_id] = scan_info
            
            # Add to history
            self.scan_history.append({
                "id": scan_id,
                "start_time": scan_info["start_time"],
                "targets": validated_targets,
                "profile": profile,
                "status": "running"
            })
            
            # Trim scan history if needed
            if len(self.scan_history) > self.max_history:
                self.scan_history = self.scan_history[-self.max_history:]
            
            return scan_id
            
        except Exception as e:
            self.logger.error(f"Error starting scan: {str(e)}")
            return ""
    
    def stop_scan(self, scan_id: str) -> bool:
        """
        Stop a running scan.
        
        Args:
            scan_id: ID of the scan to stop
            
        Returns:
            True if the scan was stopped successfully
        """
        if scan_id not in self.active_scans:
            self.logger.warning(f"Cannot stop scan {scan_id}: not found")
            return False
            
        scan_info = self.active_scans[scan_id]
        
        # Terminate the process
        if scan_info["process"] and scan_info["process"].poll() is None:
            try:
                scan_info["process"].terminate()
                scan_info["process"].wait(timeout=5)
                self.logger.info(f"Scan {scan_id} terminated")
            except subprocess.TimeoutExpired:
                scan_info["process"].kill()
                self.logger.warning(f"Scan {scan_id} killed after timeout")
            except Exception as e:
                self.logger.error(f"Error stopping scan {scan_id}: {str(e)}")
                return False
        
        # Update scan status
        scan_info["status"] = "stopped"
        
        # Update history
        for scan in self.scan_history:
            if scan["id"] == scan_id:
                scan["status"] = "stopped"
                scan["end_time"] = time.time()
                break
        
        # Remove from active scans
        del self.active_scans[scan_id]
        
        return True
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Get status of a scan.
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            Dictionary with scan status information
        """
        if scan_id in self.active_scans:
            scan_info = self.active_scans[scan_id].copy()
            # Remove process object from the result
            if "process" in scan_info:
                del scan_info["process"]
            if "callback" in scan_info:
                del scan_info["callback"]
            return scan_info
        elif scan_id in self.scan_results:
            return self.scan_results[scan_id]
        else:
            for scan in self.scan_history:
                if scan["id"] == scan_id:
                    return scan
                    
        return {"id": scan_id, "status": "not_found"}
    
    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """
        Get results of a completed scan.
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            Dictionary with scan results
        """
        if scan_id in self.scan_results:
            return self.scan_results[scan_id]
        else:
            return {"id": scan_id, "status": "not_found"}
    
    def get_scan_history(self) -> List[Dict[str, Any]]:
        """
        Get history of all scans.
        
        Returns:
            List of scan history entries
        """
        return self.scan_history.copy()
    
    def _handle_scan_completion(self, scan_id: str) -> None:
        """
        Handle completion of a scan.
        
        Args:
            scan_id: ID of the completed scan
        """
        scan_info = self.active_scans[scan_id]
        process = scan_info["process"]
        
        # Get return code
        return_code = process.poll()
        
        # Read output
        stdout, stderr = process.communicate()
        
        # Determine status
        if return_code == 0:
            status = "completed"
        else:
            status = "failed"
            
        # Update scan info
        scan_info["status"] = status
        scan_info["end_time"] = time.time()
        scan_info["return_code"] = return_code
        scan_info["stderr"] = stderr
        
        # Parse results if available
        results = {}
        if os.path.exists(scan_info["output_file"]):
            try:
                results = self._parse_nmap_xml(scan_info["output_file"])
            except Exception as e:
                self.logger.error(f"Error parsing scan results: {str(e)}")
                
        scan_info["results"] = results
        
        # Save to scan results
        self.scan_results[scan_id] = scan_info.copy()
        
        # Update scan history
        for scan in self.scan_history:
            if scan["id"] == scan_id:
                scan["status"] = status
                scan["end_time"] = scan_info["end_time"]
                if "host_count" in results:
                    scan["host_count"] = results["host_count"]
                break
                
        # Remove the process object
        if "process" in scan_info:
            del scan_info["process"]
            
        # Call the callback if provided
        if scan_info["callback"]:
            try:
                scan_info["callback"](scan_id, status, results)
            except Exception as e:
                self.logger.error(f"Error in scan callback: {str(e)}")
                
        # Remove from active scans
        del self.active_scans[scan_id]
        
        self.logger.info(f"Scan {scan_id} {status}")
    
    def _parse_nmap_xml(self, xml_file: str) -> Dict[str, Any]:
        """
        Parse nmap XML output file.
        
        Args:
            xml_file: Path to XML output file
            
        Returns:
            Dictionary with parsed scan results
        """
        try:
            # Import required libraries only when needed
            import xml.etree.ElementTree as ET
            
            # Parse the XML file
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Extract scan information
            scan_info = {}
            
            # Get nmaprun attributes
            if "start" in root.attrib:
                scan_info["start_timestamp"] = int(root.attrib["start"])
            if "version" in root.attrib:
                scan_info["nmap_version"] = root.attrib["version"]
                
            # Get scan args
            args_elem = root.find("./scaninfo")
            if args_elem is not None:
                scan_info["scan_type"] = args_elem.attrib.get("type", "")
                scan_info["protocol"] = args_elem.attrib.get("protocol", "")
                
            # Get hosts
            hosts = []
            host_count = 0
            
            for host_elem in root.findall("./host"):
                host = {}
                
                # Get host status
                status = host_elem.find("./status")
                if status is not None:
                    host["status"] = status.attrib.get("state", "unknown")
                
                # Skip hosts that are not "up"
                if host.get("status") != "up":
                    continue
                    
                host_count += 1
                
                # Get addresses (IP and MAC)
                host["addresses"] = {}
                for addr in host_elem.findall("./address"):
                    addr_type = addr.attrib.get("addrtype")
                    if addr_type:
                        host["addresses"][addr_type] = addr.attrib.get("addr", "")
                        
                # Get hostnames
                hostnames_elem = host_elem.find("./hostnames")
                if hostnames_elem is not None:
                    host["hostnames"] = []
                    for hostname in hostnames_elem.findall("./hostname"):
                        host["hostnames"].append(hostname.attrib.get("name", ""))
                
                # Get OS detection
                os_elem = host_elem.find("./os")
                if os_elem is not None:
                    os_matches = []
                    for osmatch in os_elem.findall("./osmatch"):
                        os_matches.append({
                            "name": osmatch.attrib.get("name", ""),
                            "accuracy": osmatch.attrib.get("accuracy", ""),
                        })
                    if os_matches:
                        host["os"] = os_matches
                
                # Get ports/services
                ports_elem = host_elem.find("./ports")
                if ports_elem is not None:
                    host["ports"] = []
                    for port in ports_elem.findall("./port"):
                        port_info = {
                            "protocol": port.attrib.get("protocol", ""),
                            "portid": port.attrib.get("portid", ""),
                        }
                        
                        # Get port state
                        state = port.find("./state")
                        if state is not None:
                            port_info["state"] = state.attrib.get("state", "")
                        
                        # Get service info
                        service = port.find("./service")
                        if service is not None:
                            port_info["service"] = {
                                "name": service.attrib.get("name", ""),
                                "product": service.attrib.get("product", ""),
                                "version": service.attrib.get("version", ""),
                                "extrainfo": service.attrib.get("extrainfo", ""),
                            }
                            
                        # Get scripts
                        scripts = []
                        for script in port.findall("./script"):
                            scripts.append({
                                "id": script.attrib.get("id", ""),
                                "output": script.attrib.get("output", "")
                            })
                        if scripts:
                            port_info["scripts"] = scripts
                            
                        host["ports"].append(port_info)
                
                hosts.append(host)
                
            # Return the parsed results
            return {
                "info": scan_info,
                "hosts": hosts,
                "host_count": host_count
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing nmap XML: {str(e)}")
            return {"error": str(e)}
    
    def _validate_targets(self, targets: List[str]) -> List[str]:
        """
        Validate and normalize target specifications.
        
        Args:
            targets: List of target specifications
            
        Returns:
            List of validated targets
        """
        valid_targets = []
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
                
            try:
                # Check if it's a valid IP address
                ipaddress.ip_address(target)
                valid_targets.append(target)
                continue
            except ValueError:
                pass
                
            try:
                # Check if it's a valid CIDR range
                ipaddress.ip_network(target, strict=False)
                valid_targets.append(target)
                continue
            except ValueError:
                pass
                
            # Check if it might be a hostname (very basic check)
            if self._is_valid_hostname(target):
                valid_targets.append(target)
                continue
                
        return valid_targets
        
    def _is_valid_hostname(self, hostname: str) -> bool:
        """
        Check if a string might be a valid hostname.
        
        Args:
            hostname: Hostname string to check
            
        Returns:
            True if the hostname appears valid
        """
        import re
        
        # Simple validation pattern for hostnames
        pattern = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
        
        return re.match(pattern, hostname) is not None