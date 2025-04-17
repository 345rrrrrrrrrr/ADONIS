#!/usr/bin/env python3
# ADONIS Debugger Widget

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                           QPushButton, QTextEdit, QTabWidget, QTreeView, QSplitter, 
                           QToolBar, QAction, QMenu, QComboBox, QTableWidget, 
                           QTableWidgetItem, QHeaderView, QFrame)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QSize
from PyQt5.QtGui import QIcon, QFont

class DebuggerWidget(QWidget):
    """
    Widget for the debugger module of ADONIS.
    Provides an interface for debugging applications.
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
        
        self.action_run = QAction(QIcon.fromTheme("media-playback-start"), "Run", self)
        self.action_pause = QAction(QIcon.fromTheme("media-playback-pause"), "Pause", self)
        self.action_stop = QAction(QIcon.fromTheme("media-playback-stop"), "Stop", self)
        self.action_step_over = QAction(QIcon.fromTheme("go-next"), "Step Over", self)
        self.action_step_into = QAction(QIcon.fromTheme("go-down"), "Step Into", self)
        self.action_step_out = QAction(QIcon.fromTheme("go-up"), "Step Out", self)
        self.action_restart = QAction(QIcon.fromTheme("view-refresh"), "Restart", self)
        
        self.toolbar.addAction(self.action_run)
        self.toolbar.addAction(self.action_pause)
        self.toolbar.addAction(self.action_stop)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.action_step_over)
        self.toolbar.addAction(self.action_step_into)
        self.toolbar.addAction(self.action_step_out)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.action_restart)
        
        self.main_layout.addWidget(self.toolbar)
        
        # Splitter for main content
        self.main_splitter = QSplitter(Qt.Vertical)
        
        # Source code area
        self.code_area = QTextEdit()
        self.code_area.setReadOnly(True)
        self.code_area.setFont(QFont("Monospace", 10))
        
        # Bottom panel with tabs
        self.bottom_panel = QTabWidget()
        
        # Variables tab
        self.variables_widget = QTableWidget()
        self.variables_widget.setColumnCount(3)
        self.variables_widget.setHorizontalHeaderLabels(["Name", "Type", "Value"])
        self.variables_widget.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.bottom_panel.addTab(self.variables_widget, "Variables")
        
        # Breakpoints tab
        self.breakpoints_widget = QTableWidget()
        self.breakpoints_widget.setColumnCount(3)
        self.breakpoints_widget.setHorizontalHeaderLabels(["File", "Line", "Condition"])
        self.breakpoints_widget.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.bottom_panel.addTab(self.breakpoints_widget, "Breakpoints")
        
        # Stack frames tab
        self.stack_widget = QTableWidget()
        self.stack_widget.setColumnCount(3)
        self.stack_widget.setHorizontalHeaderLabels(["Level", "Function", "Location"])
        self.stack_widget.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.bottom_panel.addTab(self.stack_widget, "Call Stack")
        
        # Console output tab
        self.console_widget = QTextEdit()
        self.console_widget.setFont(QFont("Monospace", 10))
        self.console_widget.setReadOnly(True)
        self.bottom_panel.addTab(self.console_widget, "Console")
        
        # Command input for the debugger
        self.command_layout = QHBoxLayout()
        self.command_label = QLabel("Command:")
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter debugger command...")
        self.command_button = QPushButton("Send")
        
        self.command_layout.addWidget(self.command_label)
        self.command_layout.addWidget(self.command_input, 1)  # Stretch factor
        self.command_layout.addWidget(self.command_button)
        
        # Add widgets to the main splitter
        self.main_splitter.addWidget(self.code_area)
        self.main_splitter.addWidget(self.bottom_panel)
        
        # Add splitter and command layout to main layout
        self.main_layout.addWidget(self.main_splitter, 1)  # Stretch factor
        self.main_layout.addLayout(self.command_layout)
        
        # Configure splitter
        self.main_splitter.setStretchFactor(0, 2)  # Code area gets more space
        self.main_splitter.setStretchFactor(1, 1)  # Bottom panel gets less
        
        # Connect signals
        self.action_run.triggered.connect(self.on_run)
        self.action_pause.triggered.connect(self.on_pause)
        self.action_stop.triggered.connect(self.on_stop)
        self.action_step_over.triggered.connect(self.on_step_over)
        self.action_step_into.triggered.connect(self.on_step_into)
        self.action_step_out.triggered.connect(self.on_step_out)
        self.action_restart.triggered.connect(self.on_restart)
        self.command_button.clicked.connect(self.on_send_command)
        self.command_input.returnPressed.connect(self.on_send_command)
        
        # Disable buttons initially
        self.set_buttons_enabled(False)
    
    def set_module(self, module):
        """
        Set the module instance associated with this widget.
        
        Args:
            module: Debugger module instance
        """
        self.module = module
        
        # Connect signals from the module
        if hasattr(module, "debug_output_signal"):
            module.debug_output_signal.connect(self.on_debug_output)
            
        if hasattr(module, "status_changed_signal"):
            module.status_changed_signal.connect(self.on_status_changed)
            
        if hasattr(module, "source_code_signal"):
            module.source_code_signal.connect(self.on_source_code_update)
            
        if hasattr(module, "variables_signal"):
            module.variables_signal.connect(self.on_variables_update)
            
        if hasattr(module, "breakpoints_signal"):
            module.breakpoints_signal.connect(self.on_breakpoints_update)
            
        if hasattr(module, "stack_signal"):
            module.stack_signal.connect(self.on_stack_update)
    
    def set_buttons_enabled(self, enabled, status="idle"):
        """
        Enable or disable buttons based on current debugger status.
        
        Args:
            enabled: Whether to enable buttons
            status: Current debugger status
        """
        if status == "idle":
            self.action_run.setEnabled(enabled)
            self.action_pause.setEnabled(False)
            self.action_stop.setEnabled(False)
            self.action_step_over.setEnabled(False)
            self.action_step_into.setEnabled(False)
            self.action_step_out.setEnabled(False)
            self.action_restart.setEnabled(False)
        elif status == "running":
            self.action_run.setEnabled(False)
            self.action_pause.setEnabled(enabled)
            self.action_stop.setEnabled(enabled)
            self.action_step_over.setEnabled(False)
            self.action_step_into.setEnabled(False)
            self.action_step_out.setEnabled(False)
            self.action_restart.setEnabled(enabled)
        elif status == "paused":
            self.action_run.setEnabled(enabled)
            self.action_pause.setEnabled(False)
            self.action_stop.setEnabled(enabled)
            self.action_step_over.setEnabled(enabled)
            self.action_step_into.setEnabled(enabled)
            self.action_step_out.setEnabled(enabled)
            self.action_restart.setEnabled(enabled)
    
    @pyqtSlot()
    def on_run(self):
        """Handle run button click."""
        if self.module:
            self.module.run_target()
    
    @pyqtSlot()
    def on_pause(self):
        """Handle pause button click."""
        if self.module:
            self.module.pause_target()
    
    @pyqtSlot()
    def on_stop(self):
        """Handle stop button click."""
        if self.module:
            self.module.stop_target()
    
    @pyqtSlot()
    def on_step_over(self):
        """Handle step over button click."""
        if self.module:
            self.module.step_over()
    
    @pyqtSlot()
    def on_step_into(self):
        """Handle step into button click."""
        if self.module:
            self.module.step_into()
    
    @pyqtSlot()
    def on_step_out(self):
        """Handle step out button click."""
        if self.module:
            self.module.step_out()
    
    @pyqtSlot()
    def on_restart(self):
        """Handle restart button click."""
        if self.module:
            self.module.restart_target()
    
    @pyqtSlot()
    def on_send_command(self):
        """Handle sending commands to the debugger."""
        command = self.command_input.text().strip()
        
        if command and self.module:
            self.console_widget.append(f"> {command}")
            self.module.send_command(command)
            self.command_input.clear()
    
    @pyqtSlot(str)
    def on_debug_output(self, output):
        """
        Handle debugger output.
        
        Args:
            output: Output text from the debugger
        """
        self.console_widget.append(output)
        # Auto-scroll to bottom
        cursor = self.console_widget.textCursor()
        cursor.movePosition(cursor.End)
        self.console_widget.setTextCursor(cursor)
    
    @pyqtSlot(str)
    def on_status_changed(self, status):
        """
        Handle debugger status changes.
        
        Args:
            status: New debugger status
        """
        self.set_buttons_enabled(True, status)
    
    @pyqtSlot(str, str, int)
    def on_source_code_update(self, file_path, source_code, current_line):
        """
        Update the source code display.
        
        Args:
            file_path: Path to the source file
            source_code: Source code content
            current_line: Current line number
        """
        self.code_area.setText(source_code)
        
        # Highlight the current line
        cursor = self.code_area.textCursor()
        cursor.setPosition(0)
        
        # Move to the current line
        for _ in range(current_line - 1):
            cursor.movePosition(cursor.Down)
        
        cursor.movePosition(cursor.EndOfLine, cursor.KeepAnchor)
        format = cursor.charFormat()
        format.setBackground(Qt.yellow)
        cursor.setCharFormat(format)
        
        self.code_area.setTextCursor(cursor)
        self.code_area.ensureCursorVisible()
    
    @pyqtSlot(list)
    def on_variables_update(self, variables):
        """
        Update the variables display.
        
        Args:
            variables: List of variable dictionaries
        """
        self.variables_widget.setRowCount(0)
        
        for var in variables:
            row = self.variables_widget.rowCount()
            self.variables_widget.insertRow(row)
            
            self.variables_widget.setItem(row, 0, QTableWidgetItem(var.get("name", "")))
            self.variables_widget.setItem(row, 1, QTableWidgetItem(var.get("type", "")))
            self.variables_widget.setItem(row, 2, QTableWidgetItem(var.get("value", "")))
    
    @pyqtSlot(list)
    def on_breakpoints_update(self, breakpoints):
        """
        Update the breakpoints display.
        
        Args:
            breakpoints: List of breakpoint dictionaries
        """
        self.breakpoints_widget.setRowCount(0)
        
        for bp in breakpoints:
            row = self.breakpoints_widget.rowCount()
            self.breakpoints_widget.insertRow(row)
            
            file_item = QTableWidgetItem(bp.get("file", ""))
            line_item = QTableWidgetItem(str(bp.get("line", "")))
            cond_item = QTableWidgetItem(bp.get("condition", ""))
            
            self.breakpoints_widget.setItem(row, 0, file_item)
            self.breakpoints_widget.setItem(row, 1, line_item)
            self.breakpoints_widget.setItem(row, 2, cond_item)
    
    @pyqtSlot(list)
    def on_stack_update(self, stack_frames):
        """
        Update the stack frames display.
        
        Args:
            stack_frames: List of stack frame dictionaries
        """
        self.stack_widget.setRowCount(0)
        
        for frame in stack_frames:
            row = self.stack_widget.rowCount()
            self.stack_widget.insertRow(row)
            
            level_item = QTableWidgetItem(str(frame.get("level", "")))
            func_item = QTableWidgetItem(frame.get("function", ""))
            loc_item = QTableWidgetItem(frame.get("location", ""))
            
            self.stack_widget.setItem(row, 0, level_item)
            self.stack_widget.setItem(row, 1, func_item)
            self.stack_widget.setItem(row, 2, loc_item)