#!/usr/bin/env python3
# ADONIS Memory Editor Module

import os
import sys
import time
import logging
import platform
from typing import Dict, List, Any, Optional, Union, Tuple, BinaryIO
import struct
import tempfile
import json

from core.module_manager import Module

# Import platform-specific memory access libraries
if platform.system() == "Windows":
    # For Windows
    try:
        import win32process
        import win32api
        import win32con
        import pywintypes
    except ImportError:
        pass
elif platform.system() == "Linux":
    # For Linux
    try:
        import psutil
        import ctypes
        import ptrace
    except ImportError:
        pass
elif platform.system() == "Darwin":
    # For MacOS
    try:
        import psutil
    except ImportError:
        pass

class MemoryEditorModule(Module):
    """
    Memory Editor Module for ADONIS.
    
    Provides functionality to examine and modify process memory.
    Supports attaching to processes, reading/writing memory, and searching for patterns.
    """
    
    def __init__(self, app, name="memory_editor"):
        """Initialize Memory Editor module."""
        super().__init__(app, name)
        self.attached_processes = {}
        self.memory_snapshots = {}
        self.snapshot_counter = 0
        
        # Platform information
        self.platform = platform.system()
        self.logger.info(f"Memory Editor initializing on {self.platform}")
        
        # Check for required dependencies
        self._check_dependencies()
    
    def initialize(self) -> bool:
        """Initialize the Memory Editor module."""
        self.logger.info("Initializing Memory Editor module...")
        
        # Validate permissions to access memory
        if not self._validate_permissions():
            self.logger.warning("Memory Editor may have limited functionality due to permission issues")
            # Don't fail initialization, just warn the user
        
        return True
    
    def shutdown(self) -> None:
        """Clean up resources when shutting down."""
        self.logger.info("Shutting down Memory Editor module...")
        
        # Detach from any attached processes
        processes = list(self.attached_processes.keys())
        for process_id in processes:
            self.detach_process(process_id)
        
        # Clean up temporary files from snapshots
        self._cleanup_snapshots()
    
    def _check_dependencies(self) -> None:
        """Check for required dependencies based on the platform."""
        missing_deps = []
        
        if self.platform == "Windows":
            for module_name in ["win32process", "win32api", "win32con"]:
                if module_name not in sys.modules:
                    missing_deps.append(module_name)
                    
        elif self.platform == "Linux":
            for module_name in ["psutil", "ctypes"]:
                if module_name not in sys.modules:
                    missing_deps.append(module_name)
                    
        elif self.platform == "Darwin":  # MacOS
            for module_name in ["psutil"]:
                if module_name not in sys.modules:
                    missing_deps.append(module_name)
        
        if missing_deps:
            self.logger.warning(f"Missing dependencies for full Memory Editor functionality: {', '.join(missing_deps)}")
            self.logger.warning("Some features may be limited or unavailable")
    
    def _validate_permissions(self) -> bool:
        """Validate that we have sufficient permissions to access process memory."""
        try:
            if self.platform == "Windows":
                # Check if we're running with admin rights
                try:
                    return win32api.GetCurrentProcess() and True
                except Exception:
                    return False
                    
            elif self.platform == "Linux":
                # Check if we can read /proc/self/mem or if we're root
                try:
                    return os.access("/proc/self/mem", os.R_OK) or os.geteuid() == 0
                except Exception:
                    return False
                    
            elif self.platform == "Darwin":
                # Check if we're root on MacOS
                try:
                    return os.geteuid() == 0
                except Exception:
                    return False
            else:
                # Unsupported platform
                return False
                
        except Exception as e:
            self.logger.error(f"Error validating permissions: {str(e)}")
            return False
    
    def list_processes(self, filter_text: str = "") -> List[Dict[str, Any]]:
        """
        List running processes with optional filtering.
        
        Args:
            filter_text: Optional text to filter process names
            
        Returns:
            List of dictionaries containing process information
        """
        result = []
        
        try:
            import psutil
            
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'memory_percent', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    name = proc_info.get('name', '')
                    cmdline = " ".join(proc_info.get('cmdline', []))
                    
                    # Apply filter if provided
                    if filter_text and filter_text.lower() not in name.lower() and filter_text.lower() not in cmdline.lower():
                        continue
                    
                    result.append({
                        "pid": proc_info.get('pid', 0),
                        "name": name,
                        "user": proc_info.get('username', ''),
                        "cmdline": cmdline,
                        "mem": proc_info.get('memory_percent', 0),
                        "cpu": proc_info.get('cpu_percent', 0)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                    
        except Exception as e:
            self.logger.error(f"Error listing processes: {str(e)}")
        
        return result
    
    def attach_process(self, pid: int) -> Optional[str]:
        """
        Attach to a specific process for memory manipulation.
        
        Args:
            pid: Process ID to attach to
            
        Returns:
            Process ID string if successful, None otherwise
        """
        if str(pid) in self.attached_processes:
            return str(pid)
        
        try:
            if self.platform == "Windows":
                # Windows process attachment
                try:
                    process_handle = win32api.OpenProcess(
                        win32con.PROCESS_VM_READ | win32con.PROCESS_VM_WRITE | win32con.PROCESS_VM_OPERATION,
                        False,
                        pid
                    )
                    if process_handle:
                        self.attached_processes[str(pid)] = {
                            "handle": process_handle,
                            "pid": pid,
                            "attached_time": time.time()
                        }
                        self.logger.info(f"Attached to process {pid}")
                        return str(pid)
                except pywintypes.error as e:
                    self.logger.error(f"Error attaching to process {pid}: {str(e)}")
                    return None
                    
            elif self.platform == "Linux":
                # Linux process attachment
                try:
                    # Check if process exists
                    if not os.path.exists(f"/proc/{pid}"):
                        self.logger.error(f"Process {pid} does not exist")
                        return None
                    
                    # Check if we have permissions to access the process
                    if not os.access(f"/proc/{pid}/mem", os.R_OK):
                        self.logger.error(f"No permission to access process {pid}")
                        return None
                    
                    self.attached_processes[str(pid)] = {
                        "pid": pid,
                        "attached_time": time.time()
                    }
                    self.logger.info(f"Attached to process {pid}")
                    return str(pid)
                except Exception as e:
                    self.logger.error(f"Error attaching to process {pid}: {str(e)}")
                    return None
                    
            elif self.platform == "Darwin":
                # MacOS process attachment (limited functionality)
                try:
                    # Check if process exists using psutil
                    if psutil.pid_exists(pid):
                        self.attached_processes[str(pid)] = {
                            "pid": pid,
                            "attached_time": time.time()
                        }
                        self.logger.info(f"Attached to process {pid} (limited functionality on MacOS)")
                        return str(pid)
                    else:
                        self.logger.error(f"Process {pid} does not exist")
                        return None
                except Exception as e:
                    self.logger.error(f"Error attaching to process {pid}: {str(e)}")
                    return None
            else:
                self.logger.error(f"Unsupported platform: {self.platform}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error attaching to process {pid}: {str(e)}")
            return None
        
        return None
    
    def detach_process(self, process_id: str) -> bool:
        """
        Detach from a previously attached process.
        
        Args:
            process_id: Process ID string to detach from
            
        Returns:
            True if successful, False otherwise
        """
        if process_id not in self.attached_processes:
            self.logger.error(f"Process {process_id} is not attached")
            return False
        
        try:
            process = self.attached_processes[process_id]
            
            if self.platform == "Windows":
                # Windows process detachment
                try:
                    if "handle" in process:
                        win32api.CloseHandle(process["handle"])
                except pywintypes.error as e:
                    self.logger.error(f"Error detaching from process {process_id}: {str(e)}")
            
            # Remove from attached processes
            del self.attached_processes[process_id]
            self.logger.info(f"Detached from process {process_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error detaching from process {process_id}: {str(e)}")
            return False
    
    def get_process_status(self, process_id: str) -> Dict[str, Any]:
        """
        Get information about an attached process.
        
        Args:
            process_id: Process ID string
            
        Returns:
            Dictionary containing process information
        """
        if process_id not in self.attached_processes:
            return {"error": "Process is not attached"}
        
        try:
            import psutil
            
            pid = self.attached_processes[process_id]["pid"]
            
            try:
                proc = psutil.Process(pid)
                info = {
                    "pid": pid,
                    "name": proc.name(),
                    "user": proc.username(),
                    "cpu": proc.cpu_percent(),
                    "mem": proc.memory_percent(),
                    "status": proc.status(),
                    "create_time": proc.create_time(),
                    "cmdline": " ".join(proc.cmdline())
                }
                
                return {"info": info}
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Process may have terminated
                if process_id in self.attached_processes:
                    self.detach_process(process_id)
                return {"error": "Process no longer exists"}
                
        except Exception as e:
            self.logger.error(f"Error getting process status: {str(e)}")
            return {"error": str(e)}
    
    def get_process_memory_map(self, process_id: str) -> List[Dict[str, Any]]:
        """
        Get memory map of an attached process.
        
        Args:
            process_id: Process ID string
            
        Returns:
            List of dictionaries containing memory region information
        """
        if process_id not in self.attached_processes:
            return []
        
        result = []
        
        try:
            import psutil
            
            pid = self.attached_processes[process_id]["pid"]
            
            try:
                proc = psutil.Process(pid)
                memory_maps = []
                
                if self.platform in ["Linux", "Darwin"]:
                    # Get memory maps on Linux/MacOS
                    memory_maps = proc.memory_maps(grouped=False)
                    
                    for mmap in memory_maps:
                        try:
                            addr_range = mmap.addr.split('-')
                            start_addr = int(addr_range[0], 16)
                            end_addr = int(addr_range[1], 16)
                            
                            result.append({
                                "start_address": start_addr,
                                "end_address": end_addr,
                                "permissions": mmap.perms,
                                "path": mmap.path,
                                "size": end_addr - start_addr,
                                "type": self._determine_region_type(mmap.path, mmap.perms)
                            })
                        except Exception:
                            continue
                            
                elif self.platform == "Windows":
                    # Limited memory mapping on Windows
                    import win32process
                    import win32con
                    handle = self.attached_processes[process_id].get("handle")
                    if handle:
                        # This is simplified and would need more work for full memory mapping
                        # on Windows; the actual implementation would require using VirtualQueryEx
                        memory_info = proc.memory_info()
                        result.append({
                            "start_address": 0x10000,  # Base address is typically user space start
                            "end_address": 0x10000 + memory_info.rss,  # Approximate
                            "permissions": "rwx",  # Default
                            "path": proc.exe(),
                            "size": memory_info.rss,
                            "type": "process"
                        })
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Process may have terminated
                if process_id in self.attached_processes:
                    self.detach_process(process_id)
                
        except Exception as e:
            self.logger.error(f"Error getting process memory map: {str(e)}")
        
        return result
    
    def _determine_region_type(self, path: str, perms: str) -> str:
        """
        Determine the type of memory region based on path and permissions.
        
        Args:
            path: Path associated with memory region
            perms: Permission string (e.g., 'rwxp')
            
        Returns:
            String describing the region type (heap, stack, etc.)
        """
        if '[heap]' in path:
            return 'heap'
        elif '[stack]' in path:
            return 'stack'
        elif not path:
            return 'anonymous'
        elif '.so' in path or '.dll' in path or '.dylib' in path:
            return 'library'
        elif perms.startswith('r-x'):
            return 'code'
        elif perms.startswith('rw-'):
            return 'data'
        else:
            return 'other'
    
    def read_memory(self, process_id: str, address: int, size: int) -> Dict[str, Any]:
        """
        Read memory from a specific address in the process.
        
        Args:
            process_id: Process ID string
            address: Memory address to read from
            size: Number of bytes to read
            
        Returns:
            Dictionary containing read data or error
        """
        if process_id not in self.attached_processes:
            return {"error": "Process is not attached"}
        
        try:
            if self.platform == "Windows":
                # Windows memory reading
                handle = self.attached_processes[process_id].get("handle")
                if not handle:
                    return {"error": "Invalid process handle"}
                
                try:
                    import win32process
                    import ctypes
                    from ctypes import wintypes
                    
                    buffer = ctypes.create_string_buffer(size)
                    bytes_read = wintypes.DWORD(0)
                    
                    result = ctypes.windll.kernel32.ReadProcessMemory(
                        handle,
                        ctypes.c_void_p(address),
                        buffer,
                        size,
                        ctypes.byref(bytes_read)
                    )
                    
                    if result:
                        return {"data": buffer.raw[:bytes_read.value]}
                    else:
                        error_code = ctypes.windll.kernel32.GetLastError()
                        return {"error": f"Memory read failed with error code {error_code}"}
                        
                except Exception as e:
                    return {"error": f"Error reading memory: {str(e)}"}
                    
            elif self.platform == "Linux":
                # Linux memory reading
                pid = self.attached_processes[process_id]["pid"]
                
                try:
                    # Open /proc/[pid]/mem
                    with open(f"/proc/{pid}/mem", "rb") as mem_file:
                        # Seek to the address
                        mem_file.seek(address)
                        # Read the data
                        data = mem_file.read(size)
                        return {"data": data}
                except IOError as e:
                    return {"error": f"Memory read failed: {str(e)}"}
                    
            elif self.platform == "Darwin":
                # MacOS memory reading (limited functionality)
                return {"error": "Memory reading not fully supported on MacOS"}
                
            else:
                return {"error": f"Unsupported platform: {self.platform}"}
                
        except Exception as e:
            self.logger.error(f"Error reading memory: {str(e)}")
            return {"error": str(e)}
    
    def write_memory(self, process_id: str, address: int, data: Union[bytes, str, int, float], data_type: str = "byte") -> Dict[str, Any]:
        """
        Write data to a specific address in the process memory.
        
        Args:
            process_id: Process ID string
            address: Memory address to write to
            data: Data to write (bytes, string, int, float)
            data_type: Type of data ("byte", "string", "int", "float")
            
        Returns:
            Dictionary indicating success or error
        """
        if process_id not in self.attached_processes:
            return {"error": "Process is not attached"}
        
        try:
            # Convert data to bytes based on type
            if data_type == "string":
                if isinstance(data, str):
                    byte_data = data.encode('utf-8')
                else:
                    byte_data = bytes(data)
            elif data_type == "int":
                byte_data = struct.pack("i", data)
            elif data_type == "float":
                byte_data = struct.pack("f", data)
            else:
                # Assume already bytes or convert from list
                if isinstance(data, list):
                    byte_data = bytes(data)
                elif isinstance(data, str):
                    # Try to convert hex string to bytes
                    byte_data = bytes.fromhex(data.replace(" ", ""))
                else:
                    byte_data = data
            
            if self.platform == "Windows":
                # Windows memory writing
                handle = self.attached_processes[process_id].get("handle")
                if not handle:
                    return {"error": "Invalid process handle"}
                
                try:
                    import ctypes
                    from ctypes import wintypes
                    
                    size = len(byte_data)
                    bytes_written = wintypes.DWORD(0)
                    
                    result = ctypes.windll.kernel32.WriteProcessMemory(
                        handle,
                        ctypes.c_void_p(address),
                        byte_data,
                        size,
                        ctypes.byref(bytes_written)
                    )
                    
                    if result:
                        return {"success": True, "bytes_written": bytes_written.value}
                    else:
                        error_code = ctypes.windll.kernel32.GetLastError()
                        return {"error": f"Memory write failed with error code {error_code}"}
                        
                except Exception as e:
                    return {"error": f"Error writing memory: {str(e)}"}
                    
            elif self.platform == "Linux":
                # Linux memory writing
                pid = self.attached_processes[process_id]["pid"]
                
                try:
                    # Open /proc/[pid]/mem
                    with open(f"/proc/{pid}/mem", "wb+") as mem_file:
                        # Seek to the address
                        mem_file.seek(address)
                        # Write the data
                        bytes_written = mem_file.write(byte_data)
                        return {"success": True, "bytes_written": bytes_written}
                except IOError as e:
                    return {"error": f"Memory write failed: {str(e)}"}
                    
            elif self.platform == "Darwin":
                # MacOS memory writing (limited functionality)
                return {"error": "Memory writing not fully supported on MacOS"}
                
            else:
                return {"error": f"Unsupported platform: {self.platform}"}
                
        except Exception as e:
            self.logger.error(f"Error writing memory: {str(e)}")
            return {"error": str(e)}
    
    def search_memory(self, process_id: str, pattern: Any, pattern_type: str = "byte", region_type: str = "all") -> Dict[str, Any]:
        """
        Search for a pattern in process memory.
        
        Args:
            process_id: Process ID string
            pattern: Pattern to search for (bytes, string, int, float)
            pattern_type: Type of pattern ("byte", "string", "int", "float")
            region_type: Type of memory region to search ("all", "heap", "stack", "data")
            
        Returns:
            Dictionary containing search results or error
        """
        if process_id not in self.attached_processes:
            return {"error": "Process is not attached"}
        
        # Convert pattern to bytes based on type
        try:
            if pattern_type == "string":
                if isinstance(pattern, str):
                    byte_pattern = pattern.encode('utf-8')
                else:
                    byte_pattern = bytes(pattern)
            elif pattern_type == "int":
                byte_pattern = struct.pack("i", pattern)
            elif pattern_type == "float":
                byte_pattern = struct.pack("f", pattern)
            else:
                # Assume already bytes
                if isinstance(pattern, list):
                    byte_pattern = bytes(pattern)
                elif isinstance(pattern, str):
                    # Try to convert hex string to bytes
                    byte_pattern = bytes.fromhex(pattern.replace(" ", ""))
                else:
                    byte_pattern = pattern
        except Exception as e:
            return {"error": f"Error converting pattern: {str(e)}"}
        
        # Get memory maps
        memory_maps = self.get_process_memory_map(process_id)
        
        # Filter by region type if specified
        if region_type != "all":
            memory_maps = [region for region in memory_maps if region.get("type") == region_type]
        
        results = []
        
        # Search in each memory region
        for region in memory_maps:
            start_addr = region["start_address"]
            end_addr = region["end_address"]
            size = end_addr - start_addr
            
            # Skip regions that are too large or too small
            if size > 100 * 1024 * 1024:  # Skip regions larger than 100MB
                continue
                
            # Read memory from region
            read_result = self.read_memory(process_id, start_addr, size)
            
            if "data" in read_result:
                memory_data = read_result["data"]
                
                # Search for pattern
                offset = 0
                while True:
                    offset = memory_data.find(byte_pattern, offset)
                    if offset == -1:
                        break
                    
                    # Found a match
                    address = start_addr + offset
                    results.append({
                        "address": address,
                        "region": {
                            "start": start_addr,
                            "end": end_addr,
                            "permissions": region.get("permissions", ""),
                            "name": region.get("path", "")
                        }
                    })
                    
                    offset += 1  # Move to next byte to find next occurrence
        
        return {
            "process_id": process_id,
            "pattern_type": pattern_type,
            "matches": len(results),
            "results": results
        }
    
    def create_memory_snapshot(self, process_id: str, region_type: str = "all") -> Dict[str, Any]:
        """
        Create a snapshot of process memory for later analysis.
        
        Args:
            process_id: Process ID string
            region_type: Type of memory region to snapshot ("all", "heap", "stack", "data")
            
        Returns:
            Dictionary containing snapshot info or error
        """
        if process_id not in self.attached_processes:
            return {"error": "Process is not attached"}
        
        try:
            # Get memory maps
            memory_maps = self.get_process_memory_map(process_id)
            
            # Filter by region type if specified
            if region_type != "all":
                memory_maps = [region for region in memory_maps if region.get("type") == region_type]
            
            # Create a temporary file for the snapshot
            snapshot_file = tempfile.NamedTemporaryFile(delete=False, suffix='.adonis_snapshot')
            snapshot_path = snapshot_file.name
            
            # Get process info
            process_info = self.get_process_status(process_id)
            
            # Create snapshot metadata
            self.snapshot_counter += 1
            snapshot_id = f"{process_id}_{int(time.time())}_{self.snapshot_counter}"
            
            snapshot = {
                "snapshot_id": snapshot_id,
                "process_id": process_id,
                "timestamp": time.time(),
                "region_type": region_type,
                "region_count": len(memory_maps),
                "process_info": process_info.get("info", {}),
                "snapshot_path": snapshot_path,
                "regions": []
            }
            
            # Save memory data for each region
            for region in memory_maps:
                start_addr = region["start_address"]
                end_addr = region["end_address"]
                size = end_addr - start_addr
                
                # Skip regions that are too large
                if size > 100 * 1024 * 1024:  # Skip regions larger than 100MB
                    continue
                    
                # Read memory from region
                read_result = self.read_memory(process_id, start_addr, size)
                
                if "data" in read_result:
                    memory_data = read_result["data"]
                    
                    # Store region info
                    region_info = {
                        "start_address": start_addr,
                        "end_address": end_addr,
                        "size": size,
                        "permissions": region.get("permissions", ""),
                        "type": region.get("type", ""),
                        "path": region.get("path", ""),
                        "offset": snapshot_file.tell()  # Position in the file
                    }
                    
                    # Write memory data to file
                    snapshot_file.write(memory_data)
                    
                    # Add region to snapshot
                    snapshot["regions"].append(region_info)
            
            # Close the file
            snapshot_file.close()
            
            # Save snapshot metadata
            self.memory_snapshots[snapshot_id] = snapshot
            
            # Return snapshot info
            return {
                "snapshot_id": snapshot_id,
                "process_id": process_id,
                "timestamp": snapshot["timestamp"],
                "region_count": len(snapshot["regions"])
            }
            
        except Exception as e:
            self.logger.error(f"Error creating memory snapshot: {str(e)}")
            return {"error": str(e)}
    
    def compare_snapshots(self, snapshot_id1: str, snapshot_id2: str) -> Dict[str, Any]:
        """
        Compare two memory snapshots and find differences.
        
        Args:
            snapshot_id1: First snapshot ID
            snapshot_id2: Second snapshot ID
            
        Returns:
            Dictionary containing differences or error
        """
        if snapshot_id1 not in self.memory_snapshots:
            return {"error": f"Snapshot {snapshot_id1} not found"}
            
        if snapshot_id2 not in self.memory_snapshots:
            return {"error": f"Snapshot {snapshot_id2} not found"}
            
        try:
            snapshot1 = self.memory_snapshots[snapshot_id1]
            snapshot2 = self.memory_snapshots[snapshot_id2]
            
            # Check if snapshots are from the same process
            if snapshot1["process_id"] != snapshot2["process_id"]:
                return {"error": "Cannot compare snapshots from different processes"}
            
            differences = []
            
            # Open snapshot files
            with open(snapshot1["snapshot_path"], "rb") as file1, open(snapshot2["snapshot_path"], "rb") as file2:
                # Compare regions
                for region1 in snapshot1["regions"]:
                    # Find matching region in snapshot2
                    matching_regions = [r for r in snapshot2["regions"] 
                                      if r["start_address"] == region1["start_address"] and 
                                         r["end_address"] == region1["end_address"]]
                    
                    if not matching_regions:
                        # Region doesn't exist in snapshot2
                        differences.append({
                            "type": "removed_region",
                            "region": region1
                        })
                        continue
                    
                    region2 = matching_regions[0]
                    
                    # Read data from both snapshots
                    file1.seek(region1["offset"])
                    file2.seek(region2["offset"])
                    
                    size = region1["size"]
                    data1 = file1.read(size)
                    data2 = file2.read(size)
                    
                    # Compare data
                    if data1 != data2:
                        # Find specific differences
                        region_diffs = []
                        
                        # Compare byte by byte (with a limit to avoid too many differences)
                        max_diffs = 100
                        diff_count = 0
                        
                        for i in range(min(len(data1), len(data2))):
                            if data1[i] != data2[i]:
                                address = region1["start_address"] + i
                                region_diffs.append({
                                    "address": address,
                                    "value1": data1[i],
                                    "value2": data2[i]
                                })
                                
                                diff_count += 1
                                if diff_count >= max_diffs:
                                    break
                        
                        differences.append({
                            "type": "modified_region",
                            "region": region1,
                            "diff_count": diff_count,
                            "differences": region_diffs
                        })
                
                # Check for new regions in snapshot2
                for region2 in snapshot2["regions"]:
                    matching_regions = [r for r in snapshot1["regions"] 
                                      if r["start_address"] == region2["start_address"] and 
                                         r["end_address"] == region2["end_address"]]
                    
                    if not matching_regions:
                        # Region doesn't exist in snapshot1
                        differences.append({
                            "type": "new_region",
                            "region": region2
                        })
            
            return {
                "snapshot1": snapshot_id1,
                "snapshot2": snapshot_id2,
                "process_id": snapshot1["process_id"],
                "differences_count": len(differences),
                "differences": differences
            }
            
        except Exception as e:
            self.logger.error(f"Error comparing snapshots: {str(e)}")
            return {"error": str(e)}
    
    def delete_snapshot(self, snapshot_id: str) -> bool:
        """
        Delete a memory snapshot.
        
        Args:
            snapshot_id: Snapshot ID to delete
            
        Returns:
            True if successful, False otherwise
        """
        if snapshot_id not in self.memory_snapshots:
            self.logger.error(f"Snapshot {snapshot_id} not found")
            return False
        
        try:
            snapshot = self.memory_snapshots[snapshot_id]
            
            # Delete snapshot file
            if os.path.exists(snapshot["snapshot_path"]):
                os.unlink(snapshot["snapshot_path"])
            
            # Remove snapshot from list
            del self.memory_snapshots[snapshot_id]
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting snapshot {snapshot_id}: {str(e)}")
            return False
    
    def _cleanup_snapshots(self) -> None:
        """Delete all snapshot files when shutting down."""
        for snapshot_id, snapshot in self.memory_snapshots.items():
            try:
                if "snapshot_path" in snapshot and os.path.exists(snapshot["snapshot_path"]):
                    os.unlink(snapshot["snapshot_path"])
            except Exception as e:
                self.logger.error(f"Error cleaning up snapshot {snapshot_id}: {str(e)}")