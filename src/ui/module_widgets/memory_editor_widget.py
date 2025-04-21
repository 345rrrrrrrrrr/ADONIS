#!/usr/bin/env python3
# ADONIS Memory Editor Widget

import os
import sys
import time
from typing import Dict, List, Any, Optional, Union, Tuple
import struct
import binascii
import logging

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QTableWidget, QTableWidgetItem, QComboBox, 
    QTabWidget, QSplitter, QTreeWidget, QTreeWidgetItem,
    QGroupBox, QTextEdit, QSpinBox, QHeaderView, QMenu,
    QAction, QToolBar, QStatusBar, QMessageBox, QApplication,
    QDialog, QFileDialog, QCheckBox, QRadioButton, QButtonGroup
)
from PyQt5.QtGui import QFont, QColor, QBrush, QIcon, QTextCursor
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QByteArray, QBuffer

from ui.utils import create_action
from core.core_module import Module

class MemoryEditorWidget(QWidget):
    """
    Memory Editor Widget for examining and modifying process memory.
    
    Features:
    - Process list and attachment
    - Memory map visualization
    - Memory viewing/editing in hex
    - Memory search functionality
    - Memory snapshot comparison
    """
    
    def __init__(self, app, parent=None):
        """Initialize Memory Editor widget."""
        super().__init__(parent)
        self.app = app
        self.logger = logging.getLogger(__name__)
        
        # Get the memory editor module instance
        self.memory_module = self.app.get_module('memory_editor')
        if not self.memory_module:
            self.logger.error("Memory Editor module not found!")
        
        # Widget state
        self.current_process_id = None
        self.attached_processes = {}
        self.memory_regions = []
        self.current_memory_view = {
            "address": 0,
            "size": 1024,
            "region": None
        }
        self.search_results = []
        self.snapshots = {}
        
        # Initialize UI
        self.init_ui()
        
        # Setup update timer for process list
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_process_list)
        self.update_timer.start(5000)  # Update every 5 seconds
        
        # Initial process list load
        self.update_process_list()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.layout = QVBoxLayout(self)
        
        # Create main splitter
        self.main_splitter = QSplitter(Qt.Horizontal)
        
        # Left side: Process and region controls
        self.control_widget = QWidget()
        self.control_layout = QVBoxLayout(self.control_widget)
        
        # Process section
        self.process_group = QGroupBox("Processes")
        self.process_layout = QVBoxLayout(self.process_group)
        
        # Process filter
        self.filter_layout = QHBoxLayout()
        self.filter_label = QLabel("Filter:")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter process name to filter...")
        self.filter_input.textChanged.connect(self.update_process_list)
        self.filter_layout.addWidget(self.filter_label)
        self.filter_layout.addWidget(self.filter_input)
        
        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(4)
        self.process_table.setHorizontalHeaderLabels(["PID", "Name", "User", "Memory"])
        self.process_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.process_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.process_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.process_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.process_table.itemSelectionChanged.connect(self.on_process_selected)
        
        # Process buttons
        self.process_buttons_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.update_process_list)
        self.attach_button = QPushButton("Attach")
        self.attach_button.clicked.connect(self.attach_to_process)
        self.attach_button.setEnabled(False)
        self.detach_button = QPushButton("Detach")
        self.detach_button.clicked.connect(self.detach_from_process)
        self.detach_button.setEnabled(False)
        self.process_buttons_layout.addWidget(self.refresh_button)
        self.process_buttons_layout.addWidget(self.attach_button)
        self.process_buttons_layout.addWidget(self.detach_button)
        
        # Add to process layout
        self.process_layout.addLayout(self.filter_layout)
        self.process_layout.addWidget(self.process_table)
        self.process_layout.addLayout(self.process_buttons_layout)
        
        # Memory regions section
        self.regions_group = QGroupBox("Memory Regions")
        self.regions_layout = QVBoxLayout(self.regions_group)
        
        # Region filter
        self.region_filter_layout = QHBoxLayout()
        self.region_filter_label = QLabel("Filter:")
        self.region_filter_input = QLineEdit()
        self.region_filter_input.setPlaceholderText("Filter regions...")
        self.region_type_combo = QComboBox()
        self.region_type_combo.addItems(["All", "Heap", "Stack", "Code", "Data", "Library"])
        self.region_type_combo.currentTextChanged.connect(self.filter_memory_regions)
        self.region_filter_input.textChanged.connect(self.filter_memory_regions)
        self.region_filter_layout.addWidget(self.region_filter_label)
        self.region_filter_layout.addWidget(self.region_filter_input)
        self.region_filter_layout.addWidget(self.region_type_combo)
        
        # Memory regions table
        self.regions_table = QTableWidget()
        self.regions_table.setColumnCount(5)
        self.regions_table.setHorizontalHeaderLabels(
            ["Start Address", "End Address", "Size", "Permissions", "Type"]
        )
        self.regions_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.regions_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.regions_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.regions_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.regions_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.regions_table.itemSelectionChanged.connect(self.on_region_selected)
        self.regions_table.itemDoubleClicked.connect(self.view_memory_region)
        
        # Add to regions layout
        self.regions_layout.addLayout(self.region_filter_layout)
        self.regions_layout.addWidget(self.regions_table)
        
        # Add to control layout
        self.control_layout.addWidget(self.process_group)
        self.control_layout.addWidget(self.regions_group)
        
        # Right side: Tabbed interface for different views
        self.tab_widget = QTabWidget()
        
        # Memory viewer tab
        self.memory_tab = QWidget()
        self.memory_layout = QVBoxLayout(self.memory_tab)
        
        # Memory navigation
        self.memory_nav_layout = QHBoxLayout()
        self.address_label = QLabel("Address:")
        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("Enter address (hex)...")
        self.address_input.returnPressed.connect(self.go_to_address)
        self.go_button = QPushButton("Go")
        self.go_button.clicked.connect(self.go_to_address)
        self.prev_button = QPushButton("Previous")
        self.prev_button.clicked.connect(self.go_to_previous_page)
        self.next_button = QPushButton("Next")
        self.next_button.clicked.connect(self.go_to_next_page)
        
        self.memory_nav_layout.addWidget(self.address_label)
        self.memory_nav_layout.addWidget(self.address_input)
        self.memory_nav_layout.addWidget(self.go_button)
        self.memory_nav_layout.addWidget(self.prev_button)
        self.memory_nav_layout.addWidget(self.next_button)
        
        # Memory display
        self.memory_display = HexEditor(self)
        self.memory_display.dataChanged.connect(self.on_memory_data_changed)
        
        # Add to memory layout
        self.memory_layout.addLayout(self.memory_nav_layout)
        self.memory_layout.addWidget(self.memory_display)
        
        # Search tab
        self.search_tab = QWidget()
        self.search_layout = QVBoxLayout(self.search_tab)
        
        # Search controls
        self.search_controls_layout = QVBoxLayout()
        
        # Search type and input
        self.search_type_layout = QHBoxLayout()
        self.search_type_label = QLabel("Search Type:")
        self.search_type_combo = QComboBox()
        self.search_type_combo.addItems(["Bytes", "Text", "Integer", "Float"])
        self.search_type_combo.currentTextChanged.connect(self.on_search_type_changed)
        
        self.search_input_label = QLabel("Search Value:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search value...")
        
        self.search_type_layout.addWidget(self.search_type_label)
        self.search_type_layout.addWidget(self.search_type_combo)
        self.search_type_layout.addWidget(self.search_input_label)
        self.search_type_layout.addWidget(self.search_input)
        
        # Search region options
        self.search_region_layout = QHBoxLayout()
        self.search_region_label = QLabel("Search In:")
        self.search_region_combo = QComboBox()
        self.search_region_combo.addItems(["All", "Heap", "Stack", "Data"])
        
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.search_memory)
        
        self.search_region_layout.addWidget(self.search_region_label)
        self.search_region_layout.addWidget(self.search_region_combo)
        self.search_region_layout.addWidget(self.search_button)
        
        # Search results table
        self.search_results_table = QTableWidget()
        self.search_results_table.setColumnCount(3)
        self.search_results_table.setHorizontalHeaderLabels(["Address", "Region", "Preview"])
        self.search_results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.search_results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.search_results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.search_results_table.itemDoubleClicked.connect(self.view_search_result)
        
        # Add to search layout
        self.search_layout.addLayout(self.search_type_layout)
        self.search_layout.addLayout(self.search_region_layout)
        self.search_layout.addWidget(self.search_results_table)
        
        # Snapshots tab
        self.snapshot_tab = QWidget()
        self.snapshot_layout = QVBoxLayout(self.snapshot_tab)
        
        # Snapshot controls
        self.snapshot_buttons_layout = QHBoxLayout()
        self.create_snapshot_button = QPushButton("Create Snapshot")
        self.create_snapshot_button.clicked.connect(self.create_snapshot)
        self.compare_snapshots_button = QPushButton("Compare Snapshots")
        self.compare_snapshots_button.clicked.connect(self.compare_snapshots)
        self.delete_snapshot_button = QPushButton("Delete Snapshot")
        self.delete_snapshot_button.clicked.connect(self.delete_snapshot)
        
        self.snapshot_buttons_layout.addWidget(self.create_snapshot_button)
        self.snapshot_buttons_layout.addWidget(self.compare_snapshots_button)
        self.snapshot_buttons_layout.addWidget(self.delete_snapshot_button)
        
        # Snapshots table
        self.snapshots_table = QTableWidget()
        self.snapshots_table.setColumnCount(4)
        self.snapshots_table.setHorizontalHeaderLabels(["Snapshot ID", "Process ID", "Timestamp", "Regions"])
        self.snapshots_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.snapshots_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.snapshots_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.snapshots_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        
        # Snapshot comparison view
        self.snapshot_diff_layout = QVBoxLayout()
        self.snapshot_diff_label = QLabel("Snapshot Differences:")
        
        self.snapshot_diff_table = QTableWidget()
        self.snapshot_diff_table.setColumnCount(5)
        self.snapshot_diff_table.setHorizontalHeaderLabels(["Type", "Address", "Region", "Value 1", "Value 2"])
        self.snapshot_diff_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.snapshot_diff_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.snapshot_diff_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.snapshot_diff_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.snapshot_diff_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.snapshot_diff_table.itemDoubleClicked.connect(self.view_snapshot_diff)
        
        # Add to snapshot layout
        self.snapshot_layout.addLayout(self.snapshot_buttons_layout)
        self.snapshot_layout.addWidget(self.snapshots_table)
        self.snapshot_layout.addWidget(self.snapshot_diff_label)
        self.snapshot_layout.addWidget(self.snapshot_diff_table)
        
        # Add tabs
        self.tab_widget.addTab(self.memory_tab, "Memory Viewer")
        self.tab_widget.addTab(self.search_tab, "Memory Search")
        self.tab_widget.addTab(self.snapshot_tab, "Memory Snapshots")
        
        # Add widgets to splitter
        self.main_splitter.addWidget(self.control_widget)
        self.main_splitter.addWidget(self.tab_widget)
        
        # Set default splitter sizes
        self.main_splitter.setSizes([300, 700])
        
        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.showMessage("Memory Editor ready")
        
        # Add to main layout
        self.layout.addWidget(self.main_splitter)
        self.layout.addWidget(self.status_bar)
    
    def update_process_list(self):
        """Update the list of running processes."""
        if not self.memory_module:
            return
            
        filter_text = self.filter_input.text()
        
        # Get process list from memory editor module
        processes = self.memory_module.list_processes(filter_text)
        
        # Clear current table
        self.process_table.setRowCount(0)
        
        # Add processes to table
        row = 0
        for proc in processes:
            self.process_table.insertRow(row)
            self.process_table.setItem(row, 0, QTableWidgetItem(str(proc["pid"])))
            self.process_table.setItem(row, 1, QTableWidgetItem(proc["name"]))
            self.process_table.setItem(row, 2, QTableWidgetItem(proc["user"]))
            self.process_table.setItem(row, 3, QTableWidgetItem(f"{proc['mem']:.2f}%"))
            
            # Highlight attached processes
            if str(proc["pid"]) in self.attached_processes:
                for col in range(4):
                    item = self.process_table.item(row, col)
                    item.setBackground(QBrush(QColor("#e6f7ff")))
            
            row += 1
    
    def on_process_selected(self):
        """Handle process selection event."""
        selected_items = self.process_table.selectedItems()
        if not selected_items:
            self.attach_button.setEnabled(False)
            self.detach_button.setEnabled(False)
            return
        
        row = selected_items[0].row()
        pid = self.process_table.item(row, 0).text()
        
        if pid in self.attached_processes:
            self.attach_button.setEnabled(False)
            self.detach_button.setEnabled(True)
        else:
            self.attach_button.setEnabled(True)
            self.detach_button.setEnabled(False)
    
    def attach_to_process(self):
        """Attach to the selected process."""
        selected_items = self.process_table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        pid = self.process_table.item(row, 0).text()
        name = self.process_table.item(row, 1).text()
        
        # Attach to process using the memory editor module
        result = self.memory_module.attach_process(int(pid))
        
        if result:
            self.current_process_id = pid
            self.attached_processes[pid] = {
                "pid": pid,
                "name": name,
                "attached_time": time.time()
            }
            
            self.status_bar.showMessage(f"Attached to process {name} (PID: {pid})")
            
            # Update process table colors
            self.update_process_list()
            
            # Update button states
            self.attach_button.setEnabled(False)
            self.detach_button.setEnabled(True)
            
            # Refresh memory regions
            self.refresh_memory_regions()
        else:
            QMessageBox.warning(
                self, 
                "Attach Failed", 
                f"Failed to attach to process {name} (PID: {pid}). "
                "This might be due to insufficient permissions or process protection."
            )
    
    def detach_from_process(self):
        """Detach from the current process."""
        selected_items = self.process_table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        pid = self.process_table.item(row, 0).text()
        name = self.process_table.item(row, 1).text()
        
        # Detach from process using the memory editor module
        result = self.memory_module.detach_process(pid)
        
        if result:
            if pid == self.current_process_id:
                self.current_process_id = None
            
            if pid in self.attached_processes:
                del self.attached_processes[pid]
            
            self.status_bar.showMessage(f"Detached from process {name} (PID: {pid})")
            
            # Update process table colors
            self.update_process_list()
            
            # Update button states
            self.attach_button.setEnabled(True)
            self.detach_button.setEnabled(False)
            
            # Clear memory regions
            self.regions_table.setRowCount(0)
            self.memory_regions = []
            
            # Clear memory display
            self.memory_display.clear_data()
        else:
            QMessageBox.warning(
                self, 
                "Detach Failed", 
                f"Failed to detach from process {name} (PID: {pid})."
            )
    
    def refresh_memory_regions(self):
        """Refresh the memory regions for the current process."""
        if not self.current_process_id or self.current_process_id not in self.attached_processes:
            return
        
        # Get memory map from memory editor module
        self.memory_regions = self.memory_module.get_process_memory_map(self.current_process_id)
        
        # Update display
        self.filter_memory_regions()
    
    def filter_memory_regions(self):
        """Filter and display memory regions based on filter criteria."""
        if not self.memory_regions:
            return
            
        filter_text = self.region_filter_input.text().lower()
        filter_type = self.region_type_combo.currentText().lower()
        
        # Clear current table
        self.regions_table.setRowCount(0)
        
        # Add regions to table
        row = 0
        for region in self.memory_regions:
            # Apply filters
        self.module = None
        self.current_process_id = None
        self.current_memory = None
        self.search_results = None
        
        if self.app:
            self.set_app(self.app)
            
        self.init_ui()
    
    def set_app(self, app):
        """Set the application instance."""
        self.app = app
        
        # Get module reference
        if self.app:
            self.module = self.app.module_manager.get_module("memory_editor")
    
    def init_ui(self):
        """Initialize the user interface."""
        main_layout = QVBoxLayout()
        
        # Toolbar
        toolbar = QToolBar()
        
        self.attach_action = QAction("Attach Process", self)
        self.attach_action.triggered.connect(self.attach_process)
        toolbar.addAction(self.attach_action)
        
        self.detach_action = QAction("Detach", self)
        self.detach_action.triggered.connect(self.detach_process)
        self.detach_action.setEnabled(False)
        toolbar.addAction(self.detach_action)
        
        toolbar.addSeparator()
        
        self.search_action = QAction("Search Memory", self)
        self.search_action.triggered.connect(self.search_memory)
        self.search_action.setEnabled(False)
        toolbar.addAction(self.search_action)
        
        self.snapshot_action = QAction("Take Snapshot", self)
        self.snapshot_action.triggered.connect(self.take_snapshot)
        self.snapshot_action.setEnabled(False)
        toolbar.addAction(self.snapshot_action)
        
        self.compare_action = QAction("Compare Snapshots", self)
        self.compare_action.triggered.connect(self.compare_snapshots)
        self.compare_action.setEnabled(False)
        toolbar.addAction(self.compare_action)
        
        main_layout.addWidget(toolbar)
        
        # Process info
        self.process_info_group = QGroupBox("Process Information")
        info_layout = QFormLayout()
        
        self.pid_label = QLabel("Not attached")
        info_layout.addRow("PID:", self.pid_label)
        
        self.name_label = QLabel("")
        info_layout.addRow("Name:", self.name_label)
        
        self.user_label = QLabel("")
        info_layout.addRow("User:", self.user_label)
        
        self.process_info_group.setLayout(info_layout)
        main_layout.addWidget(self.process_info_group)
        
        # Splitter for memory regions and editor
        splitter = QSplitter(Qt.Horizontal)
        
        # Memory regions
        self.regions_group = QGroupBox("Memory Regions")
        regions_layout = QVBoxLayout()
        
        self.regions_table = QTableWidget()
        self.regions_table.setColumnCount(5)
        self.regions_table.setHorizontalHeaderLabels(["Address", "Size", "Perms", "Type", "Path"])
        self.regions_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.regions_table.verticalHeader().setVisible(False)
        self.regions_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.regions_table.setSelectionMode(QTableWidget.SingleSelection)
        self.regions_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.regions_table.doubleClicked.connect(self.on_region_selected)
        regions_layout.addWidget(self.regions_table)
        
        self.regions_group.setLayout(regions_layout)
        splitter.addWidget(self.regions_group)
        
        # Memory editor
        self.editor_group = QGroupBox("Memory Editor")
        editor_layout = QVBoxLayout()
        
        self.address_layout = QHBoxLayout()
        
        self.address_label = QLabel("Address:")
        self.address_layout.addWidget(self.address_label)
        
        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("Enter memory address (hex)")
        self.address_layout.addWidget(self.address_input)
        
        self.size_label = QLabel("Size:")
        self.address_layout.addWidget(self.size_label)
        
        self.size_input = QSpinBox()
        self.size_input.setMinimum(1)
        self.size_input.setMaximum(65536)  # 64KB max
        self.size_input.setValue(256)
        self.address_layout.addWidget(self.size_input)
        
        self.read_button = QPushButton("Read Memory")
        self.read_button.clicked.connect(self.read_memory)
        self.read_button.setEnabled(False)
        self.address_layout.addWidget(self.read_button)
        
        editor_layout.addLayout(self.address_layout)
        
        # Memory view
        self.hex_editor = HexEditor()
        self.hex_editor.memoryChanged.connect(self.on_memory_changed)
        editor_layout.addWidget(self.hex_editor)
        
        self.editor_group.setLayout(editor_layout)
        splitter.addWidget(self.editor_group)
        
        # Set splitter sizes
        splitter.setSizes([200, 600])
        main_layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.showMessage("Ready")
        main_layout.addWidget(self.status_bar)
        
        self.setLayout(main_layout)
    
    def attach_process(self):
        """Show dialog to attach to a process."""
        if not self.module:
            QMessageBox.warning(self, "Module Not Available", 
                               "Memory Editor module is not available.")
            return
        
        dialog = ProcessAttachDialog(self.module, self)
        if dialog.exec_() == QDialog.Accepted and dialog.get_selected_pid():
            pid = dialog.get_selected_pid()
            
            # Attach to the process
            process_id = self.module.attach_process(pid)
            
            if process_id:
                self.current_process_id = process_id
                self.update_process_info()
                self.update_memory_regions()
                
                # Enable actions
                self.detach_action.setEnabled(True)
                self.search_action.setEnabled(True)
                self.snapshot_action.setEnabled(True)
                self.read_button.setEnabled(True)
                
                self.status_bar.showMessage(f"Attached to process {pid}")
            else:
                QMessageBox.warning(self, "Attachment Failed", 
                                   f"Failed to attach to process {pid}.")
    
    def detach_process(self):
        """Detach from the current process."""
        if not self.module or not self.current_process_id:
            return
            
        # Detach from the process
        if self.module.detach_process(self.current_process_id):
            self.current_process_id = None
            self.current_memory = None
            
            # Clear UI
            self.pid_label.setText("Not attached")
            self.name_label.setText("")
            self.user_label.setText("")
            self.regions_table.setRowCount(0)
            self.hex_editor.set_data(bytes())
            
            # Disable actions
            self.detach_action.setEnabled(False)
            self.search_action.setEnabled(False)
            self.snapshot_action.setEnabled(False)
            self.compare_action.setEnabled(False)
            self.read_button.setEnabled(False)
            
            self.status_bar.showMessage("Detached from process")
    
    def update_process_info(self):
        """Update the process information display."""
        if not self.module or not self.current_process_id:
            return
            
        process_info = self.module.get_process_status(self.current_process_id)
        
        if process_info and "info" in process_info:
            info = process_info["info"]
            self.pid_label.setText(str(info["pid"]))
            self.name_label.setText(info["name"])
            self.user_label.setText(info["user"])
    
    def update_memory_regions(self):
        """Update the memory regions table."""
        if not self.module or not self.current_process_id:
            return
            
        memory_map = self.module.get_process_memory_map(self.current_process_id)
        
        self.regions_table.setRowCount(0)
        
        for i, region in enumerate(memory_map):
            self.regions_table.insertRow(i)
            
            # Format address and size
            start_addr = f"0x{region['start_address']:x}"
            size = region['end_address'] - region['start_address']
            size_str = f"{size:,} bytes"
            
            # Create items
            addr_item = QTableWidgetItem(start_addr)
            addr_item.setData(Qt.UserRole, region['start_address'])
            
            self.regions_table.setItem(i, 0, addr_item)
            self.regions_table.setItem(i, 1, QTableWidgetItem(size_str))
            self.regions_table.setItem(i, 2, QTableWidgetItem(region['permissions']))
            self.regions_table.setItem(i, 3, QTableWidgetItem(region['type']))
            self.regions_table.setItem(i, 4, QTableWidgetItem(region.get('path', '')))
        
        self.regions_table.resizeColumnsToContents()
    
    def on_region_selected(self, index):
        """Handle selection of a memory region."""
        row = index.row()
        addr_item = self.regions_table.item(row, 0)
        address = addr_item.data(Qt.UserRole)
        
        # Set the address in the input field
        self.address_input.setText(f"0x{address:x}")
        
        # Read memory from this address
        self.read_memory()
    
    def read_memory(self):
        """Read memory from the specified address."""
        if not self.module or not self.current_process_id:
            return
            
        try:
            # Parse the address
            address_text = self.address_input.text().strip()
            if not address_text:
                QMessageBox.warning(self, "Invalid Address", 
                                   "Please enter a memory address.")
                return
                
            if address_text.startswith("0x"):
                address = int(address_text, 16)
            else:
                address = int(address_text)
                
            # Get the size
            size = self.size_input.value()
            
            # Read memory
            result = self.module.read_memory(self.current_process_id, address, size)
            
            if "error" in result:
                QMessageBox.warning(self, "Memory Read Error", 
                                   f"Failed to read memory: {result['error']}")
                return
                
            # Store current memory and display it
            self.current_memory = result
            
            # Convert data to bytes if it's not already
            data = result.get("data", b"")
            if not isinstance(data, (bytes, bytearray)):
                if isinstance(data, list):
                    # Convert list of integers to bytes
                    data = bytes(data)
                elif isinstance(data, str):
                    # Convert hex string to bytes
                    try:
                        data = bytes.fromhex(data)
                    except ValueError:
                        # If not a hex string, encode as UTF-8
                        data = data.encode("utf-8")
            
            self.hex_editor.set_data(data, address)
            self.status_bar.showMessage(f"Read {len(data)} bytes from address 0x{address:x}")
            
        except ValueError as e:
            QMessageBox.warning(self, "Invalid Input", 
                               f"Please enter a valid address: {str(e)}")
        except Exception as e:
            QMessageBox.warning(self, "Error", 
                               f"An error occurred: {str(e)}")
    
    def search_memory(self):
        """Search for a pattern in memory."""
        if not self.module or not self.current_process_id:
            return
            
        dialog = MemorySearchDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            try:
                search_options = dialog.get_search_options()
                
                # Show busy cursor
                QApplication.setOverrideCursor(Qt.WaitCursor)
                
                # Perform search
                results = self.module.search_memory(
                    self.current_process_id,
                    search_options["pattern"],
                    search_options["pattern_type"],
                    search_options["region_type"]
                )
                
                # Restore cursor
                QApplication.restoreOverrideCursor()
                
                if "error" in results:
                    QMessageBox.warning(self, "Search Error", 
                                       f"Failed to search memory: {results['error']}")
                    return
                    
                # Store search results
                self.search_results = results
                
                # Show results dialog
                self.show_search_results()
                
                self.status_bar.showMessage(
                    f"Found {results.get('matches', 0)} matches for pattern"
                )
                
            except Exception as e:
                # Restore cursor
                QApplication.restoreOverrideCursor()
                QMessageBox.warning(self, "Search Error", 
                                   f"An error occurred: {str(e)}")
    
    def show_search_results(self):
        """Show the search results in a dialog."""
        if not self.search_results:
            return
            
        dialog = QDialog(self)
        dialog.setWindowTitle("Memory Search Results")
        dialog.resize(700, 500)
        
        layout = QVBoxLayout()
        
        results_widget = SearchResultsWidget(self.search_results)
        results_widget.addressSelected.connect(self.on_search_result_selected)
        layout.addWidget(results_widget)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def on_search_result_selected(self, address):
        """Handle selection of a search result."""
        # Set the address and read memory around it
        self.address_input.setText(f"0x{address:x}")
        self.read_memory()
    
    def take_snapshot(self):
        """Take a snapshot of the process memory."""
        if not self.module or not self.current_process_id:
            return
            
        # Show options dialog
        region_types = ["all", "heap", "stack", "data"]
        selected_type, ok = QInputDialog.getItem(
            self, "Memory Snapshot", 
            "Select memory regions to snapshot:",
            region_types, 0, False
        )
        
        if ok and selected_type:
            # Show busy cursor
            QApplication.setOverrideCursor(Qt.WaitCursor)
            
            # Take snapshot
            result = self.module.create_memory_snapshot(self.current_process_id, selected_type)
            
            # Restore cursor
            QApplication.restoreOverrideCursor()
            
            if "error" in result:
                QMessageBox.warning(self, "Snapshot Error", 
                                   f"Failed to create snapshot: {result['error']}")
                return
                
            self.compare_action.setEnabled(True)
            
            QMessageBox.information(self, "Snapshot Created", 
                                  f"Memory snapshot created with ID: {result['snapshot_id']}\n"
                                  f"Captured {result['region_count']} memory regions.")
            
            self.status_bar.showMessage(
                f"Created memory snapshot with {result['region_count']} regions"
            )
    
    def compare_snapshots(self):
        """Compare two memory snapshots."""
        if not self.module:
            return
            
        # This would be expanded to show a dialog to select two snapshots
        # and display their differences
        QMessageBox.information(self, "Not Implemented", 
                              "Snapshot comparison feature is not fully implemented in this UI.")
    
    def on_memory_changed(self, address, data):
        """Handle memory edits from the hex editor."""
        if not self.module or not self.current_process_id or not self.current_memory:
            return
            
        # Write memory changes
        result = self.module.write_memory(
            self.current_process_id, 
            address, 
            data, 
            "byte"
        )
        
        if "error" in result:
            QMessageBox.warning(self, "Write Error", 
                               f"Failed to write memory: {result['error']}")
        else:
            self.status_bar.showMessage(
                f"Modified {len(data)} bytes at address 0x{address:x}"
            )