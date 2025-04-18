#!/usr/bin/env python3
# ADONIS Cross-Module Workflow Manager

import logging
from typing import Dict, List, Any, Optional, Callable

class WorkflowManager:
    """
    Manages workflows that span across multiple ADONIS modules.
    Enables cooperation between different tools for complex analysis tasks.
    """
    
    def __init__(self, app):
        """Initialize the workflow manager."""
        self.app = app
        self.logger = logging.getLogger("adonis.core.workflow")
        self.registered_workflows = {}
        self.active_workflows = {}
        self.workflow_count = 0
        
    def register_workflow(self, name: str, description: str, 
                          modules: List[str], workflow_func: Callable) -> bool:
        """
        Register a new workflow.
        
        Args:
            name: Unique name for the workflow
            description: Description of what the workflow does
            modules: List of module names required for this workflow
            workflow_func: Function to execute the workflow
            
        Returns:
            True if registration was successful
        """
        if name in self.registered_workflows:
            self.logger.warning(f"Workflow '{name}' is already registered")
            return False
            
        self.registered_workflows[name] = {
            "name": name,
            "description": description,
            "modules": modules,
            "function": workflow_func
        }
        
        self.logger.info(f"Registered workflow: {name}")
        return True
    
    def get_available_workflows(self) -> List[Dict[str, Any]]:
        """
        Get list of available workflows.
        
        Returns:
            List of workflow information dictionaries
        """
        result = []
        for name, workflow in self.registered_workflows.items():
            # Check if all required modules are loaded
            modules_available = True
            for module_name in workflow["modules"]:
                if not self.app.module_manager.get_module(module_name):
                    modules_available = False
                    break
                    
            if modules_available:
                result.append({
                    "name": workflow["name"],
                    "description": workflow["description"],
                    "modules": workflow["modules"]
                })
                
        return result
    
    def start_workflow(self, name: str, params: Dict[str, Any] = None) -> str:
        """
        Start a workflow.
        
        Args:
            name: Name of the registered workflow
            params: Parameters for the workflow
            
        Returns:
            Workflow ID for tracking
        """
        if name not in self.registered_workflows:
            self.logger.error(f"Cannot start workflow '{name}': not registered")
            return ""
            
        workflow = self.registered_workflows[name]
        
        # Check if all required modules are loaded
        for module_name in workflow["modules"]:
            if not self.app.module_manager.get_module(module_name):
                self.logger.error(f"Cannot start workflow '{name}': module '{module_name}' not available")
                return ""
        
        # Generate workflow ID
        self.workflow_count += 1
        workflow_id = f"workflow_{name}_{self.workflow_count}"
        
        # Start the workflow
        try:
            # Store active workflow info
            self.active_workflows[workflow_id] = {
                "id": workflow_id,
                "name": name,
                "params": params or {},
                "status": "running"
            }
            
            # Execute workflow function
            result = workflow["function"](self.app, workflow_id, params or {})
            
            # Update workflow status
            if not result:
                self.active_workflows[workflow_id]["status"] = "failed"
                return ""
                
            return workflow_id
            
        except Exception as e:
            self.logger.error(f"Error starting workflow '{name}': {str(e)}")
            if workflow_id in self.active_workflows:
                self.active_workflows[workflow_id]["status"] = "failed"
                self.active_workflows[workflow_id]["error"] = str(e)
            return ""
    
    def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """
        Get status of a workflow.
        
        Args:
            workflow_id: ID of the workflow
            
        Returns:
            Dictionary with workflow status information
        """
        if workflow_id in self.active_workflows:
            return self.active_workflows[workflow_id].copy()
        else:
            return {"id": workflow_id, "status": "not_found"}
    
    def update_workflow_status(self, workflow_id: str, status: str, data: Any = None) -> bool:
        """
        Update the status of an active workflow.
        
        Args:
            workflow_id: ID of the workflow
            status: New status
            data: Optional data to associate with the workflow
            
        Returns:
            True if successful
        """
        if workflow_id not in self.active_workflows:
            self.logger.warning(f"Cannot update workflow {workflow_id}: not found")
            return False
            
        self.active_workflows[workflow_id]["status"] = status
        if data is not None:
            self.active_workflows[workflow_id]["data"] = data
            
        return True
    
    def stop_workflow(self, workflow_id: str) -> bool:
        """
        Stop an active workflow.
        
        Args:
            workflow_id: ID of the workflow
            
        Returns:
            True if successful
        """
        if workflow_id not in self.active_workflows:
            self.logger.warning(f"Cannot stop workflow {workflow_id}: not found")
            return False
            
        self.active_workflows[workflow_id]["status"] = "stopped"
        return True


# Define some useful cross-module workflows

def network_scan_to_packet_capture(app, workflow_id, params):
    """
    Start a packet capture after a network scan identifies interesting targets.
    
    Args:
        app: Application instance
        workflow_id: Workflow ID
        params: Parameters including scan results and capture options
        
    Returns:
        True if successful
    """
    logger = logging.getLogger("adonis.workflow.network_to_packet")
    network_scanner = app.module_manager.get_module("network_scanner")
    packet_analyzer = app.module_manager.get_module("packet_analyzer")
    
    if not network_scanner or not packet_analyzer:
        logger.error("Required modules not available")
        return False
    
    # Get scan results
    scan_id = params.get("scan_id")
    if not scan_id:
        logger.error("No scan_id provided")
        return False
    
    scan_results = network_scanner.get_scan_results(scan_id)
    if "error" in scan_results:
        logger.error(f"Error retrieving scan results: {scan_results.get('error')}")
        return False
    
    # Find hosts with open ports
    targets = []
    for host in scan_results.get("results", {}).get("hosts", []):
        if host.get("status") == "up" and "addresses" in host:
            ip = host["addresses"].get("ipv4", "")
            if ip:
                targets.append(ip)
    
    if not targets:
        logger.warning("No active targets found in scan results")
        return False
    
    # Get target interface
    interface = params.get("interface")
    if not interface:
        # Try to find a suitable interface
        interfaces = packet_analyzer.get_interfaces()
        if interfaces:
            interface = interfaces[0]["name"]
        else:
            logger.error("No suitable interface found")
            return False
    
    # Prepare capture options
    capture_options = {
        "duration": params.get("duration", 60),
        "filter": f"host {' or host '.join(targets)}"
    }
    
    # Add other options
    if "packet_limit" in params:
        capture_options["packet_limit"] = params["packet_limit"]
    if "ring_buffer" in params:
        capture_options["ring_buffer"] = params["ring_buffer"]
    if "filesize_mb" in params:
        capture_options["filesize_mb"] = params["filesize_mb"]
    
    # Start the capture
    def capture_callback(capture_id, status, stats):
        app.workflow_manager.update_workflow_status(
            workflow_id, 
            "completed" if status == "completed" else "failed",
            {
                "scan_id": scan_id,
                "capture_id": capture_id,
                "stats": stats
            }
        )
    
    capture_id = packet_analyzer.start_capture(
        interface,
        capture_options,
        callback=capture_callback
    )
    
    if not capture_id:
        logger.error("Failed to start packet capture")
        return False
    
    # Update workflow status
    app.workflow_manager.update_workflow_status(
        workflow_id, 
        "running",
        {
            "scan_id": scan_id,
            "capture_id": capture_id,
            "targets": targets
        }
    )
    
    logger.info(f"Started packet capture for {len(targets)} targets from scan {scan_id}")
    return True


def terminal_command_to_packet_capture(app, workflow_id, params):
    """
    Run a terminal command and capture related network traffic.
    
    Args:
        app: Application instance
        workflow_id: Workflow ID
        params: Parameters including command and capture options
        
    Returns:
        True if successful
    """
    logger = logging.getLogger("adonis.workflow.terminal_to_packet")
    terminal_module = app.module_manager.get_module("terminal")
    packet_analyzer = app.module_manager.get_module("packet_analyzer")
    
    if not terminal_module or not packet_analyzer:
        logger.error("Required modules not available")
        return False
    
    # Get command
    command = params.get("command")
    if not command:
        logger.error("No command provided")
        return False
    
    # Get target interface
    interface = params.get("interface")
    if not interface:
        # Try to find a suitable interface
        interfaces = packet_analyzer.get_interfaces()
        if interfaces:
            interface = interfaces[0]["name"]
        else:
            logger.error("No suitable interface found")
            return False
    
    # Prepare capture options
    capture_options = {
        "duration": params.get("duration", 60)
    }
    
    # Add filter if provided
    if "filter" in params:
        capture_options["filter"] = params["filter"]
    
    # Start the capture
    capture_id = packet_analyzer.start_capture(
        interface,
        capture_options
    )
    
    if not capture_id:
        logger.error("Failed to start packet capture")
        return False
    
    # Start terminal
    terminal_id = terminal_module.start_terminal()
    if not terminal_id:
        logger.error("Failed to start terminal")
        packet_analyzer.stop_capture(capture_id)
        return False
    
    # Update workflow status
    app.workflow_manager.update_workflow_status(
        workflow_id, 
        "running",
        {
            "terminal_id": terminal_id,
            "capture_id": capture_id,
            "command": command
        }
    )
    
    # Execute command in terminal
    if not terminal_module.send_input(terminal_id, f"{command}\n"):
        logger.error("Failed to send command to terminal")
        terminal_module.stop_terminal(terminal_id)
        packet_analyzer.stop_capture(capture_id)
        app.workflow_manager.update_workflow_status(workflow_id, "failed")
        return False
    
    # Set up a timer to stop the capture after command finishes
    # In a real implementation, this would be more sophisticated
    import threading
    def finish_workflow():
        # Wait for capture to complete
        import time
        time.sleep(capture_options["duration"])
        
        # Stop terminal if still running
        terminal_module.stop_terminal(terminal_id)
        
        # Update workflow status
        app.workflow_manager.update_workflow_status(
            workflow_id, 
            "completed",
            {
                "terminal_id": terminal_id,
                "capture_id": capture_id,
                "command": command
            }
        )
    
    threading.Thread(target=finish_workflow, daemon=True).start()
    
    logger.info(f"Started command '{command}' with packet capture")
    return True