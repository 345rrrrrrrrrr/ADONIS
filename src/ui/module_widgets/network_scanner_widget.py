#!/usr/bin/env python3
# ADONIS - Network Scanner Widget

import os
import json
import logging
import time
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox,
    QCheckBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox, QFileDialog, QProgressBar,
    QGroupBox, QSplitter, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QIcon


class NetworkScannerWidget(QWidget):
    """
    Widget for the Network Scanner module.
    Provides a UI for scanning networks and viewing results.
    """
    
    def __init__(self, app, parent=None):
        """Initialize the Network Scanner widget."""
        super().__init__(parent)
        self.app = app
        self.logger = logging.getLogger("adonis.ui.network_scanner")
        self.module = None
        self.current_scan_id = None
        self.scan_timer = None
        self.scan_results = {}
        self.unsaved_changes = False
        
        # Get the network scanner module instance
        if hasattr(self.app, 'module_manager'):
            self.module = self.app.module_manager.get_module("network_scanner")
        
        if not self.module:
            self.logger.warning("Network Scanner module not found")
        
        self._setup_ui()
        
        # Start a timer to periodically check scan status
        self.scan_timer = QTimer(self)
        self.scan_timer.timeout.connect(self._update_scan_status)
        self.scan_timer.start(1000)  # Update every second
    
    def _setup_ui(self):
        """Set up the UI components."""
        # Main layout
        layout = QVBoxLayout(self)
        
        # Create splitter for resizable sections
        splitter = QSplitter(Qt.Vertical)
        
        # Upper section - Scan controls
        upper_widget = QWidget()
        upper_layout = QVBoxLayout(upper_widget)
        
        # Scan settings
        settings_group = QGroupBox("Scan Settings")
        settings_layout = QGridLayout(settings_group)
        
        # Target input
        settings_layout.addWidget(QLabel("Target(s):"), 0, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP address, hostname, or CIDR range (e.g., 192.168.1.0/24)")
        settings_layout.addWidget(self.target_input, 0, 1, 1, 3)
        
        # Scan profile
        settings_layout.addWidget(QLabel("Scan Profile:"), 1, 0)
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["quick", "comprehensive", "stealth", "vuln"])
        settings_layout.addWidget(self.profile_combo, 1, 1)
        
        # Timing
        settings_layout.addWidget(QLabel("Timing:"), 1, 2)
        self.timing_combo = QComboBox()
        self.timing_combo.addItems(["1 (Sneaky)", "2 (Polite)", "3 (Normal)", "4 (Aggressive)", "5 (Insane)"])
        self.timing_combo.setCurrentIndex(2)  # Default to "Normal"
        settings_layout.addWidget(self.timing_combo, 1, 3)
        
        # Options
        settings_layout.addWidget(QLabel("Options:"), 2, 0)
        self.service_detection_check = QCheckBox("Service Detection")
        settings_layout.addWidget(self.service_detection_check, 2, 1)
        self.os_detection_check = QCheckBox("OS Detection")
        settings_layout.addWidget(self.os_detection_check, 2, 2)
        
        upper_layout.addWidget(settings_group)
        
        # Button row
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self._on_start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self._on_stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch(1)
        
        self.save_button = QPushButton("Save Results")
        self.save_button.clicked.connect(self._on_save_results)
        self.save_button.setEnabled(False)
        button_layout.addWidget(self.save_button)
        
        upper_layout.addLayout(button_layout)
        
        # Progress section
        progress_layout = QHBoxLayout()
        
        self.status_label = QLabel("Ready")
        progress_layout.addWidget(self.status_label)
        
        progress_layout.addStretch(1)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p% (Estimating...)")
        progress_layout.addWidget(self.progress_bar, 2)
        
        upper_layout.addLayout(progress_layout)
        
        # Add upper widget to splitter
        splitter.addWidget(upper_widget)
        
        # Lower section - Results
        lower_widget = QWidget()
        lower_layout = QVBoxLayout(lower_widget)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        
        # Hosts tab
        self.hosts_table = QTableWidget(0, 5)  # Rows will be added as found
        self.hosts_table.setHorizontalHeaderLabels(["IP Address", "Hostname", "Status", "OS", "Ports"])
        self.hosts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.hosts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_tabs.addTab(self.hosts_table, "Hosts")
        
        # Ports tab
        self.ports_table = QTableWidget(0, 6)
        self.ports_table.setHorizontalHeaderLabels(["IP Address", "Port", "Protocol", "State", "Service", "Version"])
        self.ports_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ports_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_tabs.addTab(self.ports_table, "Ports")
        
        # Raw output tab
        self.raw_output = QTextEdit()
        self.raw_output.setReadOnly(True)
        self.raw_output.setFont(QFont("Consolas", 10))
        self.results_tabs.addTab(self.raw_output, "Raw Output")
        
        lower_layout.addWidget(self.results_tabs)
        
        # Add lower widget to splitter
        splitter.addWidget(lower_widget)
        
        # Set initial splitter sizes
        splitter.setSizes([200, 400])  # Adjust these values as needed
        
        # Add splitter to layout
        layout.addWidget(splitter)
        
        self.setLayout(layout)
    
    def _on_start_scan(self):
        """Handle start scan button click."""
        # Check if module is available
        if not self.module:
            QMessageBox.critical(
                self,
                "Module Error",
                "Network Scanner module is not available."
            )
            return
        
        # Get scan parameters
        targets = self._parse_targets(self.target_input.text())
        if not targets:
            QMessageBox.warning(
                self,
                "Invalid Target",
                "Please enter at least one valid target."
            )
            return
        
        # Get scan profile
        profile = self.profile_combo.currentText()
        
        # Get timing
        timing_text = self.timing_combo.currentText()
        timing = int(timing_text[0])  # Extract first character (the number)
        
        # Get options
        options = {
            "profile": profile,
            "timing": timing,
            "service_detection": self.service_detection_check.isChecked(),
            "os_detection": self.os_detection_check.isChecked()
        }
        
        # Clear previous results
        self._clear_results()
        
        # Update UI
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.save_button.setEnabled(False)
        self.status_label.setText("Scanning...")
        self.progress_bar.setValue(0)
        
        # Start the scan
        try:
            scan_id = self.module.start_scan(targets, options, self._on_scan_complete)
            if scan_id:
                self.current_scan_id = scan_id
                self.logger.info(f"Started scan with ID: {scan_id}")
            else:
                self._show_error("Failed to start scan.")
        except Exception as e:
            self._show_error(f"Error starting scan: {str(e)}")
    
    def _on_stop_scan(self):
        """Handle stop scan button click."""
        if not self.module or not self.current_scan_id:
            return
        
        try:
            if self.module.stop_scan(self.current_scan_id):
                self.status_label.setText("Scan stopped by user")
                self.scan_button.setEnabled(True)
                self.stop_button.setEnabled(False)
        except Exception as e:
            self._show_error(f"Error stopping scan: {str(e)}")
    
    def _on_save_results(self):
        """Handle save results button click."""
        if not self.scan_results:
            return
        
        # Ask for save location
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Scan Results",
            os.path.expanduser("~/scan_results.json"),
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
            
            self.status_label.setText(f"Results saved to {file_path}")
            self.unsaved_changes = False
        except Exception as e:
            self._show_error(f"Error saving results: {str(e)}")
    
    def _on_scan_complete(self, scan_id, status, results):
        """Handle scan completion callback."""
        self.logger.info(f"Scan {scan_id} completed with status: {status}")
        
        # Update UI on the UI thread
        self.status_label.setText(f"Scan {status}")
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        if status == "completed":
            # Save results
            self.scan_results = results
            
            # Enable save button
            self.save_button.setEnabled(True)
            self.unsaved_changes = True
            
            # Display results
            self._display_results(results)
            
            # Complete the progress bar
            self.progress_bar.setValue(100)
        else:
            self.progress_bar.setValue(0)
    
    def _update_scan_status(self):
        """Update the scan status and progress."""
        if not self.module or not self.current_scan_id:
            return
        
        try:
            scan_info = self.module.get_scan_status(self.current_scan_id)
            if not scan_info:
                return
                
            status = scan_info.get("status")
            
            # Update status label
            if status == "running":
                elapsed = time.time() - scan_info.get("start_time", time.time())
                self.status_label.setText(f"Scanning... ({elapsed:.1f}s)")
                
                # Update progress bar with a pulsing effect since we don't know the exact progress
                current_progress = self.progress_bar.value()
                new_progress = (current_progress + 5) % 95  # Keep between 0-95%
                self.progress_bar.setValue(new_progress)
            
            elif status == "completed":
                # This will be handled by the callback
                pass
                
            elif status in ["stopped", "failed"]:
                self.status_label.setText(f"Scan {status}")
                self.scan_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                self.progress_bar.setValue(0)
                
        except Exception as e:
            self.logger.error(f"Error updating scan status: {str(e)}")
    
    def _display_results(self, results):
        """Display scan results in the UI."""
        # Clear existing results
        self.hosts_table.setRowCount(0)
        self.ports_table.setRowCount(0)
        self.raw_output.clear()
        
        # Display raw output first
        self.raw_output.setPlainText(json.dumps(results, indent=2))
        
        # Check if results are valid
        if not results or not isinstance(results, dict) or "hosts" not in results:
            return
        
        # Display hosts
        hosts = results.get("hosts", [])
        self.hosts_table.setRowCount(len(hosts))
        
        for i, host in enumerate(hosts):
            # IP Address
            ip = host.get("addresses", {}).get("ipv4", "")
            self.hosts_table.setItem(i, 0, QTableWidgetItem(ip))
            
            # Hostname
            hostnames = host.get("hostnames", [])
            hostname = hostnames[0] if hostnames else ""
            self.hosts_table.setItem(i, 1, QTableWidgetItem(hostname))
            
            # Status
            status = host.get("status", "")
            self.hosts_table.setItem(i, 2, QTableWidgetItem(status))
            
            # OS
            os_matches = host.get("os", [])
            os_name = os_matches[0].get("name", "") if os_matches else ""
            self.hosts_table.setItem(i, 3, QTableWidgetItem(os_name))
            
            # Ports summary
            ports = host.get("ports", [])
            ports_summary = f"{len(ports)} open" if ports else "None"
            self.hosts_table.setItem(i, 4, QTableWidgetItem(ports_summary))
            
            # Display ports in ports tab
            for port in ports:
                row = self.ports_table.rowCount()
                self.ports_table.insertRow(row)
                
                # IP Address
                self.ports_table.setItem(row, 0, QTableWidgetItem(ip))
                
                # Port
                port_id = port.get("portid", "")
                self.ports_table.setItem(row, 1, QTableWidgetItem(port_id))
                
                # Protocol
                protocol = port.get("protocol", "")
                self.ports_table.setItem(row, 2, QTableWidgetItem(protocol))
                
                # State
                state = port.get("state", "")
                self.ports_table.setItem(row, 3, QTableWidgetItem(state))
                
                # Service and Version
                service = port.get("service", {})
                service_name = service.get("name", "")
                version = f"{service.get('product', '')} {service.get('version', '')}".strip()
                
                self.ports_table.setItem(row, 4, QTableWidgetItem(service_name))
                self.ports_table.setItem(row, 5, QTableWidgetItem(version))
    
    def _clear_results(self):
        """Clear all results from the UI."""
        self.hosts_table.setRowCount(0)
        self.ports_table.setRowCount(0)
        self.raw_output.clear()
        self.scan_results = {}
    
    def _parse_targets(self, target_text):
        """Parse target input into a list of targets."""
        if not target_text.strip():
            return []
        
        # Split by commas and whitespace
        targets = [t.strip() for t in target_text.split(",")]
        
        # Remove empty items
        targets = [t for t in targets if t]
        
        return targets
    
    def _show_error(self, message):
        """Display an error message and update UI."""
        self.logger.error(message)
        QMessageBox.critical(self, "Error", message)
        
        # Reset UI
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Error")
        self.progress_bar.setValue(0)
    
    def has_unsaved_changes(self):
        """Check if there are unsaved scan results."""
        return self.unsaved_changes
    
    def save(self):
        """Save the current scan results."""
        if self.unsaved_changes:
            self._on_save_results()
    
    def save_as(self):
        """Save the current scan results to a new file."""
        self._on_save_results()
    
    def load_file(self, file_path):
        """Load scan results from a file."""
        try:
            with open(file_path, 'r') as f:
                results = json.load(f)
            
            self.scan_results = results
            self._display_results(results)
            self.save_button.setEnabled(True)
            self.status_label.setText(f"Loaded results from {file_path}")
            
            return True
        except Exception as e:
            self._show_error(f"Error loading file: {str(e)}")
            return False
    
    def cleanup(self):
        """Clean up resources when closing."""
        # Stop any active scan
        if self.module and self.current_scan_id:
            try:
                self.module.stop_scan(self.current_scan_id)
            except:
                pass
        
        # Stop the timer
        if self.scan_timer:
            self.scan_timer.stop()