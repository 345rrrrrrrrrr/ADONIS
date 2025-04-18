#!/usr/bin/env python3
# ADONIS Packet Analyzer Widget

import os
import time
from typing import Dict, List, Any, Optional, Callable

from PyQt5.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QTextEdit, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QLineEdit, QCheckBox, QSpinBox, QGroupBox, QFileDialog,
    QMessageBox
)

class PacketAnalyzerWidget(QWidget):
    """
    Widget for the Packet Analyzer module.
    Provides UI elements for capturing and analyzing network packets.
    """
    
    # Signals
    captureStarted = pyqtSignal(str)  # Emits capture ID when started
    captureStopped = pyqtSignal(str)  # Emits capture ID when stopped
    captureCompleted = pyqtSignal(str, dict)  # Emits capture ID and stats
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.app = None
        self.module = None
        self.active_capture_id = None
        self.current_view_capture = None
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.setInterval(1000)  # Update every second
        
        self.init_ui()
    
    def set_app(self, app):
        """Set the application instance."""
        self.app = app
        
        # Get module reference
        if self.app:
            self.module = self.app.module_manager.get_module("packet_analyzer")
            if self.module:
                self.refresh_interfaces()
                self.status_timer.start()
    
    def init_ui(self):
        """Initialize the user interface."""
        main_layout = QVBoxLayout()
        
        # Split the widget into control area and display area
        splitter = QSplitter(Qt.Vertical)
        
        # Control area
        control_widget = QWidget()
        control_layout = QVBoxLayout(control_widget)
        
        # Interface selection
        interface_layout = QHBoxLayout()
        interface_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(200)
        interface_layout.addWidget(self.interface_combo)
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_interfaces)
        interface_layout.addWidget(self.refresh_btn)
        control_layout.addLayout(interface_layout)
        
        # Capture options
        options_group = QGroupBox("Capture Options")
        options_layout = QVBoxLayout(options_group)
        
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.filter_combo = QComboBox()
        self.filter_combo.setEditable(True)
        filter_layout.addWidget(self.filter_combo)
        options_layout.addLayout(filter_layout)
        
        options_row = QHBoxLayout()
        
        options_row.addWidget(QLabel("Duration (s):"))
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(1, 3600)
        self.duration_spin.setValue(60)
        options_row.addWidget(self.duration_spin)
        
        options_row.addWidget(QLabel("Packet limit:"))
        self.packet_limit_spin = QSpinBox()
        self.packet_limit_spin.setRange(0, 1000000)
        self.packet_limit_spin.setValue(0)
        self.packet_limit_spin.setSpecialValueText("No limit")
        options_row.addWidget(self.packet_limit_spin)
        
        options_row.addWidget(QLabel("Ring buffer:"))
        self.ring_buffer_check = QCheckBox()
        options_row.addWidget(self.ring_buffer_check)
        
        options_row.addWidget(QLabel("File size (MB):"))
        self.filesize_spin = QSpinBox()
        self.filesize_spin.setRange(1, 1000)
        self.filesize_spin.setValue(10)
        options_row.addWidget(self.filesize_spin)
        
        options_row.addStretch()
        options_layout.addLayout(options_row)
        
        control_layout.addWidget(options_group)
        
        # Capture control buttons
        buttons_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        buttons_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        buttons_layout.addWidget(self.stop_btn)
        
        self.analyze_btn = QPushButton("Analyze Selected")
        self.analyze_btn.clicked.connect(self.analyze_selected)
        self.analyze_btn.setEnabled(False)
        buttons_layout.addWidget(self.analyze_btn)
        
        self.export_btn = QPushButton("Export Selected")
        self.export_btn.clicked.connect(self.export_selected)
        self.export_btn.setEnabled(False)
        buttons_layout.addWidget(self.export_btn)
        
        control_layout.addLayout(buttons_layout)
        
        # Status area
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        self.status_label = QLabel("Ready")
        status_layout.addWidget(self.status_label)
        
        status_layout.addWidget(QLabel("Packets:"))
        self.packet_count_label = QLabel("0")
        status_layout.addWidget(self.packet_count_label)
        
        status_layout.addWidget(QLabel("Duration:"))
        self.duration_label = QLabel("00:00:00")
        status_layout.addWidget(self.duration_label)
        
        status_layout.addStretch()
        control_layout.addLayout(status_layout)
        
        # Add control widget to splitter
        splitter.addWidget(control_widget)
        
        # Display area with tabs
        self.tab_widget = QTabWidget()
        
        # History tab
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(7)
        self.history_table.setHorizontalHeaderLabels([
            "ID", "Start Time", "Interface", "Filter", "Status", 
            "Packets", "Duration"
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.itemSelectionChanged.connect(self.selection_changed)
        self.tab_widget.addTab(self.history_table, "Capture History")
        
        # Packet view tab
        self.packet_view = QWidget()
        packet_layout = QVBoxLayout(self.packet_view)
        
        # Filter for packet view
        filter_packet_layout = QHBoxLayout()
        filter_packet_layout.addWidget(QLabel("Display Filter:"))
        self.display_filter_edit = QLineEdit()
        filter_packet_layout.addWidget(self.display_filter_edit)
        self.apply_filter_btn = QPushButton("Apply")
        self.apply_filter_btn.clicked.connect(self.apply_display_filter)
        filter_packet_layout.addWidget(self.apply_filter_btn)
        packet_layout.addLayout(filter_packet_layout)
        
        # Packet list
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"
        ])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        packet_layout.addWidget(self.packet_table)
        
        # Packet details
        packet_details_layout = QVBoxLayout()
        packet_details_layout.addWidget(QLabel("Packet Details:"))
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        packet_details_layout.addWidget(self.packet_details)
        packet_layout.addLayout(packet_details_layout)
        
        self.tab_widget.addTab(self.packet_view, "Packet View")
        
        # Add tab widget to splitter
        splitter.addWidget(self.tab_widget)
        
        # Set initial splitter sizes (1:3 ratio)
        splitter.setSizes([100, 300])
        
        # Add splitter to main layout
        main_layout.addWidget(splitter)
        self.setLayout(main_layout)
        
        # Initialize filter presets
        self._init_filter_presets()
    
    def _init_filter_presets(self):
        """Initialize filter presets."""
        # Will be populated when module is set
        self.filter_combo.clear()
        self.filter_combo.addItem("", "")  # Empty default
        # Other filters will be added when module is set
    
    def refresh_interfaces(self):
        """Refresh the list of network interfaces."""
        if not self.module:
            return
            
        current_text = self.interface_combo.currentText()
        self.interface_combo.clear()
        
        # Get interfaces from module
        interfaces = self.module.get_interfaces()
        for iface in interfaces:
            self.interface_combo.addItem(f"{iface['name']} - {iface['description']}", iface['name'])
        
        # Try to restore previous selection
        if current_text:
            index = self.interface_combo.findText(current_text)
            if index >= 0:
                self.interface_combo.setCurrentIndex(index)
        
        # Load filters
        self._load_filters()
    
    def _load_filters(self):
        """Load capture filters from module."""
        if not self.module:
            return
            
        self.filter_combo.clear()
        self.filter_combo.addItem("", "")  # Empty default
        
        # Get filters from module
        filters = self.module.get_capture_filters()
        for filter_id, filter_info in filters.items():
            self.filter_combo.addItem(
                f"{filter_info['name']} - {filter_info['description']}",
                filter_info['filter']
            )
    
    def update_status(self):
        """Update status display."""
        if not self.module:
            return
            
        # Update history table
        self.refresh_history()
        
        # Update active capture status if any
        if self.active_capture_id:
            status = self.module.get_capture_status(self.active_capture_id)
            
            if status["status"] != "running":
                # Capture completed or stopped
                self.active_capture_id = None
                self.stop_btn.setEnabled(False)
                self.start_btn.setEnabled(True)
                self.status_label.setText(f"Capture {status['status']}")
                
                # Emit signal
                self.captureCompleted.emit(status["id"], status.get("stats", {}))
            else:
                # Capture still running
                elapsed = time.time() - status["start_time"]
                hours = int(elapsed // 3600)
                minutes = int((elapsed % 3600) // 60)
                seconds = int(elapsed % 60)
                self.duration_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
    
    def refresh_history(self):
        """Refresh the capture history table."""
        if not self.module:
            return
            
        history = self.module.get_capture_history()
        
        # Save current selection
        selected_rows = [item.row() for item in self.history_table.selectedItems()]
        selected_id = None
        if selected_rows:
            selected_id = self.history_table.item(selected_rows[0], 0).text()
        
        # Clear table
        self.history_table.setRowCount(0)
        
        # Add history items
        for i, entry in enumerate(history):
            self.history_table.insertRow(i)
            
            # ID
            self.history_table.setItem(i, 0, QTableWidgetItem(entry["id"]))
            
            # Start time
            start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry["start_time"]))
            self.history_table.setItem(i, 1, QTableWidgetItem(start_time))
            
            # Interface
            self.history_table.setItem(i, 2, QTableWidgetItem(entry.get("interface", "")))
            
            # Filter
            self.history_table.setItem(i, 3, QTableWidgetItem(entry.get("filter", "")))
            
            # Status
            self.history_table.setItem(i, 4, QTableWidgetItem(entry.get("status", "")))
            
            # Packet count
            packet_count = entry.get("packet_count", "")
            self.history_table.setItem(i, 5, QTableWidgetItem(str(packet_count) if packet_count else ""))
            
            # Duration
            if "end_time" in entry and "start_time" in entry:
                duration = entry["end_time"] - entry["start_time"]
                duration_str = f"{int(duration)}s"
                self.history_table.setItem(i, 6, QTableWidgetItem(duration_str))
            else:
                self.history_table.setItem(i, 6, QTableWidgetItem(""))
        
        # Restore selection
        if selected_id:
            for i in range(self.history_table.rowCount()):
                if self.history_table.item(i, 0).text() == selected_id:
                    self.history_table.selectRow(i)
                    break
    
    def selection_changed(self):
        """Handle selection change in history table."""
        selected_rows = [item.row() for item in self.history_table.selectedItems()]
        
        if selected_rows:
            row = selected_rows[0]
            capture_id = self.history_table.item(row, 0).text()
            status = self.history_table.item(row, 4).text()
            
            # Enable/disable buttons based on status
            self.analyze_btn.setEnabled(status in ["completed", "stopped"])
            self.export_btn.setEnabled(status in ["completed", "stopped"])
            
            # Store selected capture ID
            self.current_view_capture = capture_id
        else:
            # No selection
            self.analyze_btn.setEnabled(False)
            self.export_btn.setEnabled(False)
            self.current_view_capture = None
    
    def start_capture(self):
        """Start a packet capture."""
        if not self.module:
            QMessageBox.warning(self, "Module Not Available", 
                               "Packet Analyzer module is not available.")
            return
        
        # Get interface
        interface = self.interface_combo.currentData()
        if not interface:
            QMessageBox.warning(self, "No Interface", 
                               "Please select a network interface.")
            return
        
        # Get filter
        filter_text = self.filter_combo.currentData()
        if not filter_text and self.filter_combo.currentText():
            # Use custom text if no preset is selected
            filter_text = self.filter_combo.currentText()
        
        # Prepare options
        options = {
            "duration": self.duration_spin.value(),
            "filter": filter_text
        }
        
        # Add packet limit if set
        if self.packet_limit_spin.value() > 0:
            options["packet_limit"] = self.packet_limit_spin.value()
        
        # Add ring buffer settings if enabled
        if self.ring_buffer_check.isChecked():
            options["ring_buffer"] = True
            options["filesize_mb"] = self.filesize_spin.value()
        
        # Start capture
        capture_id = self.module.start_capture(
            interface, 
            options=options,
            callback=self._capture_completed_callback
        )
        
        if capture_id:
            # Update UI
            self.status_label.setText(f"Capturing on {interface}")
            self.packet_count_label.setText("0")
            self.duration_label.setText("00:00:00")
            self.active_capture_id = capture_id
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            
            # Emit signal
            self.captureStarted.emit(capture_id)
        else:
            QMessageBox.warning(self, "Capture Failed", 
                               "Failed to start packet capture.")
    
    def stop_capture(self):
        """Stop the active packet capture."""
        if not self.module or not self.active_capture_id:
            return
            
        if self.module.stop_capture(self.active_capture_id):
            self.status_label.setText("Capture stopped")
            self.stop_btn.setEnabled(False)
            self.start_btn.setEnabled(True)
            
            # Emit signal
            self.captureStopped.emit(self.active_capture_id)
            self.active_capture_id = None
    
    def analyze_selected(self):
        """Analyze the selected capture."""
        if not self.module or not self.current_view_capture:
            return
            
        # Switch to packet view tab
        self.tab_widget.setCurrentWidget(self.packet_view)
        
        # Clear previous data
        self.packet_table.setRowCount(0)
        self.packet_details.clear()
        
        # Get display filter
        display_filter = self.display_filter_edit.text()
        
        # Set up options
        options = {
            "format": "text",
            "limit": 1000  # Limit to 1000 packets for performance
        }
        
        if display_filter:
            options["display_filter"] = display_filter
        
        # Analyze the capture
        results = self.module.analyze_capture(self.current_view_capture, options)
        
        if "error" in results:
            QMessageBox.warning(self, "Analysis Error", 
                               f"Error analyzing capture: {results['error']}")
            return
            
        # Display packets in table
        packets = results.get("packets", [])
        self.packet_table.setRowCount(len(packets))
        
        for i, packet in enumerate(packets):
            # Split packet line into fields
            # Format typically: "1 0.000000 192.168.1.1 → 192.168.1.2 TCP 74 443 → 52986 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
            parts = packet.split()
            
            if len(parts) >= 7:
                # Packet number
                self.packet_table.setItem(i, 0, QTableWidgetItem(parts[0]))
                
                # Time
                self.packet_table.setItem(i, 1, QTableWidgetItem(parts[1]))
                
                # Source
                self.packet_table.setItem(i, 2, QTableWidgetItem(parts[2]))
                
                # Destination (skip arrow character)
                self.packet_table.setItem(i, 3, QTableWidgetItem(parts[4]))
                
                # Protocol
                self.packet_table.setItem(i, 4, QTableWidgetItem(parts[5]))
                
                # Length
                self.packet_table.setItem(i, 5, QTableWidgetItem(parts[6]))
                
                # Info - rest of the line
                info = " ".join(parts[7:])
                self.packet_table.setItem(i, 6, QTableWidgetItem(info))
            else:
                # Just put the whole line in the info column if parsing fails
                self.packet_table.setItem(i, 0, QTableWidgetItem(str(i+1)))
                self.packet_table.setItem(i, 6, QTableWidgetItem(packet))
                
        # Update status
        self.packet_count_label.setText(str(results.get("count", 0)))
    
    def apply_display_filter(self):
        """Apply the display filter to the current view."""
        if self.current_view_capture:
            self.analyze_selected()
    
    def export_selected(self):
        """Export the selected capture."""
        if not self.module or not self.current_view_capture:
            return
            
        # Ask for export format
        formats = ["pcap", "pcapng", "txt", "csv", "json"]
        format_dialog = QDialog(self)
        format_dialog.setWindowTitle("Export Format")
        format_layout = QVBoxLayout(format_dialog)
        
        format_layout.addWidget(QLabel("Select export format:"))
        format_combo = QComboBox()
        for fmt in formats:
            format_combo.addItem(fmt)
        format_layout.addWidget(format_combo)
        
        buttons = QHBoxLayout()
        ok_btn = QPushButton("Export")
        ok_btn.clicked.connect(format_dialog.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(format_dialog.reject)
        buttons.addWidget(ok_btn)
        buttons.addWidget(cancel_btn)
        format_layout.addLayout(buttons)
        
        if format_dialog.exec_() == QDialog.Accepted:
            selected_format = format_combo.currentText()
            
            # Export the capture
            result = self.module.export_capture(
                self.current_view_capture,
                format=selected_format
            )
            
            if result and not result.startswith("Export"):
                QMessageBox.information(self, "Export Complete", 
                                      f"Capture exported to:\n{result}")
            else:
                QMessageBox.warning(self, "Export Failed", 
                                   f"Failed to export capture: {result}")
    
    def _capture_completed_callback(self, capture_id: str, status: str, stats: Dict[str, Any]):
        """Callback for when a capture is completed."""
        # This will be called from the module's thread, so use signals to update UI
        self.captureCompleted.emit(capture_id, stats)
        
        # Refresh the history table on next timer tick
        pass  # The timer will handle the refresh