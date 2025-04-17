#!/usr/bin/env python3
# ADONIS Packet Analyzer Widget

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                           QPushButton, QTextEdit, QTableWidget, QTableWidgetItem, 
                           QComboBox, QSplitter, QToolBar, QAction, QHeaderView)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QSize
from PyQt5.QtGui import QIcon, QFont

class PacketAnalyzerWidget(QWidget):
    """
    Widget for the packet analyzer module of ADONIS.
    Provides an interface for analyzing network traffic.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.module = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.main_layout = QVBoxLayout(self)
        
        # Create toolbar
        self.toolbar = QToolBar()
        self.toolbar.setIconSize(QSize(24, 24))
        
        self.action_start = QAction(QIcon.fromTheme("media-record"), "Start Capture", self)
        self.action_stop = QAction(QIcon.fromTheme("media-playback-stop"), "Stop Capture", self)
        self.action_clear = QAction(QIcon.fromTheme("edit-clear"), "Clear", self)
        self.action_save = QAction(QIcon.fromTheme("document-save"), "Save Capture", self)
        self.action_load = QAction(QIcon.fromTheme("document-open"), "Load Capture", self)
        self.action_analyze = QAction(QIcon.fromTheme("document-properties"), "Analyze", self)
        
        self.toolbar.addAction(self.action_start)
        self.toolbar.addAction(self.action_stop)
        self.toolbar.addAction(self.action_clear)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.action_save)
        self.toolbar.addAction(self.action_load)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.action_analyze)
        
        self.main_layout.addWidget(self.toolbar)
        
        # Filter controls
        self.filter_layout = QHBoxLayout()
        
        self.interface_label = QLabel("Interface:")
        self.interface_combo = QComboBox()
        
        self.filter_label = QLabel("Filter:")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter capture filter (e.g., tcp port 80)")
        self.apply_button = QPushButton("Apply")
        
        self.filter_layout.addWidget(self.interface_label)
        self.filter_layout.addWidget(self.interface_combo, 1)
        self.filter_layout.addWidget(self.filter_label)
        self.filter_layout.addWidget(self.filter_input, 3)
        self.filter_layout.addWidget(self.apply_button)
        
        self.main_layout.addLayout(self.filter_layout)
        
        # Splitter for packet list and details
        self.main_splitter = QSplitter(Qt.Vertical)
        
        # Packet list table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"
        ])
        self.packet_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        
        # Packet details pane
        self.packet_details = QTextEdit()
        self.packet_details.setFont(QFont("Monospace", 10))
        self.packet_details.setReadOnly(True)
        
        # Add widgets to splitter
        self.main_splitter.addWidget(self.packet_table)
        self.main_splitter.addWidget(self.packet_details)
        
        # Set splitter sizes
        self.main_splitter.setStretchFactor(0, 2)
        self.main_splitter.setStretchFactor(1, 1)
        
        # Status bar
        self.status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.packet_count_label = QLabel("Packets: 0")
        self.status_layout.addWidget(self.status_label, 1)  # Stretch factor
        self.status_layout.addWidget(self.packet_count_label)
        
        # Add widgets to the main layout
        self.main_layout.addWidget(self.main_splitter, 1)  # Stretch factor
        self.main_layout.addLayout(self.status_layout)
        
        # Connect signals
        self.action_start.triggered.connect(self.on_start_capture)
        self.action_stop.triggered.connect(self.on_stop_capture)
        self.action_clear.triggered.connect(self.on_clear_capture)
        self.action_save.triggered.connect(self.on_save_capture)
        self.action_load.triggered.connect(self.on_load_capture)
        self.action_analyze.triggered.connect(self.on_analyze)
        self.apply_button.clicked.connect(self.on_apply_filter)
        self.packet_table.itemSelectionChanged.connect(self.on_packet_selected)
        
        # Disable buttons initially
        self.action_stop.setEnabled(False)
        self.action_save.setEnabled(False)
        self.action_analyze.setEnabled(False)
    
    def set_module(self, module):
        """
        Set the module instance associated with this widget.
        
        Args:
            module: Packet analyzer module instance
        """
        self.module = module
        
        # Connect signals from the module
        if hasattr(module, "packet_received_signal"):
            module.packet_received_signal.connect(self.on_packet_received)
            
        if hasattr(module, "capture_status_changed_signal"):
            module.capture_status_changed_signal.connect(self.on_capture_status_changed)
            
        if hasattr(module, "interfaces_updated_signal"):
            module.interfaces_updated_signal.connect(self.on_interfaces_updated)
            
        # Request available interfaces
        if hasattr(module, "get_interfaces"):
            interfaces = module.get_interfaces()
            self.update_interfaces(interfaces)
    
    def update_interfaces(self, interfaces):
        """
        Update the interface dropdown with available network interfaces.
        
        Args:
            interfaces: List of network interfaces
        """
        self.interface_combo.clear()
        
        for interface in interfaces:
            name = interface.get("name", "")
            description = interface.get("description", "")
            display_name = f"{name} - {description}" if description else name
            self.interface_combo.addItem(display_name, userData=name)
    
    def on_interfaces_updated(self, interfaces):
        """
        Handle updated interface list.
        
        Args:
            interfaces: List of network interfaces
        """
        self.update_interfaces(interfaces)
    
    def on_packet_selected(self):
        """Handle packet selection in the table."""
        selected = self.packet_table.selectedItems()
        
        if not selected:
            return
            
        row = selected[0].row()
        packet_id = int(self.packet_table.item(row, 0).text())
        
        if self.module and hasattr(self.module, "get_packet_details"):
            details = self.module.get_packet_details(packet_id)
            self.packet_details.setText(details)
    
    def on_packet_received(self, packet_data):
        """
        Handle a new packet received from the module.
        
        Args:
            packet_data: Dictionary with packet information
        """
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        # Fill row with packet data
        self.packet_table.setItem(row, 0, QTableWidgetItem(str(packet_data.get("id", row))))
        self.packet_table.setItem(row, 1, QTableWidgetItem(packet_data.get("time", "")))
        self.packet_table.setItem(row, 2, QTableWidgetItem(packet_data.get("src", "")))
        self.packet_table.setItem(row, 3, QTableWidgetItem(packet_data.get("dst", "")))
        self.packet_table.setItem(row, 4, QTableWidgetItem(packet_data.get("proto", "")))
        self.packet_table.setItem(row, 5, QTableWidgetItem(str(packet_data.get("len", 0))))
        self.packet_table.setItem(row, 6, QTableWidgetItem(packet_data.get("info", "")))
        
        # Update packet count
        self.packet_count_label.setText(f"Packets: {row + 1}")
        
        # Auto-scroll to bottom if not browsing
        if not self.packet_table.selectedItems():
            self.packet_table.scrollToBottom()
    
    def on_capture_status_changed(self, is_capturing, status_message):
        """
        Handle capture status changes.
        
        Args:
            is_capturing: Whether the module is actively capturing
            status_message: Status message to display
        """
        self.action_start.setEnabled(not is_capturing)
        self.action_stop.setEnabled(is_capturing)
        self.interface_combo.setEnabled(not is_capturing)
        self.filter_input.setEnabled(not is_capturing)
        self.apply_button.setEnabled(not is_capturing)
        
        self.action_save.setEnabled(self.packet_table.rowCount() > 0)
        self.action_analyze.setEnabled(self.packet_table.rowCount() > 0)
        
        self.status_label.setText(status_message)
    
    @pyqtSlot()
    def on_start_capture(self):
        """Handle start capture button click."""
        interface = self.interface_combo.currentData()
        filter_text = self.filter_input.text().strip()
        
        if not interface:
            self.status_label.setText("Error: No interface selected")
            return
        
        if self.module and hasattr(self.module, "start_capture"):
            success = self.module.start_capture(interface, filter_text)
            if not success:
                self.status_label.setText("Error: Failed to start capture")
    
    @pyqtSlot()
    def on_stop_capture(self):
        """Handle stop capture button click."""
        if self.module and hasattr(self.module, "stop_capture"):
            self.module.stop_capture()
    
    @pyqtSlot()
    def on_clear_capture(self):
        """Handle clear capture button click."""
        # Clear the table and details
        self.packet_table.setRowCount(0)
        self.packet_details.clear()
        self.packet_count_label.setText("Packets: 0")
        
        # Update button states
        self.action_save.setEnabled(False)
        self.action_analyze.setEnabled(False)
        
        # Clear in module if applicable
        if self.module and hasattr(self.module, "clear_capture"):
            self.module.clear_capture()
    
    @pyqtSlot()
    def on_save_capture(self):
        """Handle save capture button click."""
        from PyQt5.QtWidgets import QFileDialog
        
        if not self.module:
            return
            
        # Get save file path
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Packet Capture",
            "",
            "PCAP Files (*.pcap);;All Files (*)"
        )
        
        if file_path and hasattr(self.module, "save_capture"):
            success = self.module.save_capture(file_path)
            
            if success:
                self.status_label.setText(f"Saved capture to {file_path}")
            else:
                self.status_label.setText("Error saving capture")
    
    @pyqtSlot()
    def on_load_capture(self):
        """Handle load capture button click."""
        from PyQt5.QtWidgets import QFileDialog
        
        if not self.module:
            return
            
        # Get load file path
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Packet Capture",
            "",
            "PCAP Files (*.pcap);;All Files (*)"
        )
        
        if file_path and hasattr(self.module, "load_capture"):
            # Clear existing data
            self.on_clear_capture()
            
            success = self.module.load_capture(file_path)
            
            if success:
                self.status_label.setText(f"Loaded capture from {file_path}")
            else:
                self.status_label.setText("Error loading capture")
    
    @pyqtSlot()
    def on_analyze(self):
        """Handle analyze button click."""
        if self.module and hasattr(self.module, "analyze_capture"):
            results = self.module.analyze_capture()
            
            # Show analysis results
            from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QDialogButtonBox
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Packet Analysis")
            dialog.resize(600, 400)
            
            layout = QVBoxLayout(dialog)
            
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setFont(QFont("Monospace", 10))
            text_edit.setText(results)
            
            button_box = QDialogButtonBox(QDialogButtonBox.Ok)
            button_box.accepted.connect(dialog.accept)
            
            layout.addWidget(text_edit)
            layout.addWidget(button_box)
            
            dialog.exec_()
    
    @pyqtSlot()
    def on_apply_filter(self):
        """Handle apply filter button click."""
        filter_text = self.filter_input.text().strip()
        
        if self.module and hasattr(self.module, "set_filter"):
            self.module.set_filter(filter_text)