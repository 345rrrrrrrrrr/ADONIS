#!/usr/bin/env python3
# ADONIS Terminal Widget

import os
import time
from typing import Dict, List, Any, Optional, Callable

from PyQt5.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot, QSize
from PyQt5.QtGui import QFont, QFontMetrics, QKeyEvent, QKeySequence, QColor, QPalette, QTextCursor
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox,
    QTextEdit, QPlainTextEdit, QTabWidget, QSplitter, QLineEdit, 
    QAction, QMenu, QFileDialog, QMessageBox, QDialog, QDialogButtonBox,
    QFormLayout, QGroupBox
)

class TerminalDisplay(QPlainTextEdit):
    """
    Custom widget for displaying terminal output and handling input.
    """
    
    # Signal emitted when user presses a key
    keyPressed = pyqtSignal(QKeyEvent)
    
    def __init__(self, parent=None):
        """Initialize the terminal display widget."""
        super().__init__(parent)
        
        # Set up appearance
        self.setReadOnly(False)
        font = QFont("Monospace", 10)
        font.setStyleHint(QFont.TypeWriter)
        self.setFont(font)
        
        # Set colors for a dark terminal look
        palette = self.palette()
        palette.setColor(QPalette.Base, QColor(0, 0, 0))  # Black background
        palette.setColor(QPalette.Text, QColor(240, 240, 240))  # Light text
        self.setPalette(palette)
        
        # Store cursor position
        self.last_cursor_pos = 0
        
        # Connect signals
        self.cursorPositionChanged.connect(self.on_cursor_changed)
    
    def keyPressEvent(self, event):
        """Handle key press events."""
        # Emit signal for parent to handle
        self.keyPressed.emit(event)
        
        # Let the parent class handle some keys
        if event.key() in [Qt.Key_Left, Qt.Key_Right, Qt.Key_Home, Qt.Key_End]:
            # Allow navigation within editable area
            cursor = self.textCursor()
            if cursor.position() >= self.last_cursor_pos:
                super().keyPressEvent(event)
        elif event.key() in [Qt.Key_Up, Qt.Key_Down]:
            # Let parent handle history navigation
            pass
        elif event.key() in [Qt.Key_Backspace]:
            # Allow backspace only in editable area
            cursor = self.textCursor()
            if cursor.position() > self.last_cursor_pos:
                super().keyPressEvent(event)
        else:
            # For other keys, allow editing
            super().keyPressEvent(event)
    
    def on_cursor_changed(self):
        """Handle cursor position changes."""
        cursor = self.textCursor()
        # Don't allow cursor to move before the last output position
        if cursor.position() < self.last_cursor_pos:
            cursor.setPosition(self.last_cursor_pos)
            self.setTextCursor(cursor)
    
    def append_output(self, text):
        """Append output text to the display."""
        # Move cursor to the end
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.setTextCursor(cursor)
        
        # Insert the text
        self.insertPlainText(text)
        
        # Update last cursor position
        self.last_cursor_pos = self.textCursor().position()
        
        # Scroll to the bottom
        self.ensureCursorVisible()
    
    def get_input(self):
        """Get the current input text."""
        cursor = self.textCursor()
        cursor.setPosition(self.last_cursor_pos)
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        return cursor.selectedText()
    
    def clear_input(self):
        """Clear the current input."""
        cursor = self.textCursor()
        cursor.setPosition(self.last_cursor_pos)
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        cursor.removeSelectedText()
        self.setTextCursor(cursor)


class TerminalTab(QWidget):
    """
    Widget for a single terminal tab.
    """
    
    # Signals
    terminalClosed = pyqtSignal(str)  # Emits terminal ID when closed
    
    def __init__(self, terminal_id, module, parent=None):
        """Initialize the terminal tab."""
        super().__init__(parent)
        self.terminal_id = terminal_id
        self.module = module
        self.history_index = -1
        self.history = []
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_terminal)
        self.timer.setInterval(100)  # Update every 100ms
        
        self.init_ui()
        self.timer.start()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Terminal display
        self.terminal_display = TerminalDisplay()
        self.terminal_display.keyPressed.connect(self.on_key_pressed)
        layout.addWidget(self.terminal_display)
        
        self.setLayout(layout)
    
    def update_terminal(self):
        """Update the terminal display with new output."""
        if not self.module or not self.terminal_id:
            return
            
        # Get terminal status
        status = self.module.get_terminal_status(self.terminal_id)
        
        # Check if terminal is still alive
        if status.get("status") != "running":
            self.timer.stop()
            # Append exit message
            exit_code = status.get("exit_code")
            if exit_code is not None:
                self.terminal_display.append_output(f"\n[Process exited with code {exit_code}]\n")
            else:
                self.terminal_display.append_output("\n[Terminal closed]\n")
            
            # Emit signal that terminal closed
            self.terminalClosed.emit(self.terminal_id)
            return
            
        # Read and display new output
        output = self.module.read_output(self.terminal_id)
        if output:
            self.terminal_display.append_output(output.decode('utf-8', errors='replace'))
    
    def on_key_pressed(self, event):
        """Handle key press events in the terminal."""
        key = event.key()
        
        # Handle Enter key
        if key == Qt.Key_Return or key == Qt.Key_Enter:
            # Get current input
            input_text = self.terminal_display.get_input()
            # Send input to terminal with newline
            if self.module.send_input(self.terminal_id, input_text + "\n"):
                # Update history
                if input_text.strip():
                    self.history.append(input_text)
                    if len(self.history) > 100:  # Limit local history
                        self.history.pop(0)
                    self.history_index = len(self.history)
                
                # Clear input line (terminal will echo it back)
                self.terminal_display.clear_input()
            
            # Prevent default handling
            event.accept()
            return
            
        # Handle Up/Down keys for history navigation
        elif key == Qt.Key_Up:
            event.accept()
            # Navigate history backwards
            if self.history and self.history_index > 0:
                self.history_index -= 1
                self.terminal_display.clear_input()
                self.terminal_display.append_output(self.history[self.history_index])
            return
            
        elif key == Qt.Key_Down:
            event.accept()
            # Navigate history forwards
            if self.history and self.history_index < len(self.history) - 1:
                self.history_index += 1
                self.terminal_display.clear_input()
                self.terminal_display.append_output(self.history[self.history_index])
            elif self.history_index == len(self.history) - 1:
                # At the end of history, clear input
                self.history_index = len(self.history)
                self.terminal_display.clear_input()
            return
            
        # Handle Ctrl+C
        elif event.key() == Qt.Key_C and event.modifiers() & Qt.ControlModifier:
            # Send SIGINT equivalent (Ctrl+C)
            self.module.send_input(self.terminal_id, "\x03")
            event.accept()
            return
            
        # Handle Ctrl+D
        elif event.key() == Qt.Key_D and event.modifiers() & Qt.ControlModifier:
            # Send EOF (Ctrl+D)
            self.module.send_input(self.terminal_id, "\x04")
            event.accept()
            return
            
        # Handle Ctrl+Z
        elif event.key() == Qt.Key_Z and event.modifiers() & Qt.ControlModifier:
            # Send SIGTSTP equivalent (Ctrl+Z)
            self.module.send_input(self.terminal_id, "\x1A")
            event.accept()
            return
    
    def resize_terminal(self, rows, cols):
        """Resize the terminal."""
        self.module.resize_terminal(self.terminal_id, rows, cols)
    
    def cleanup(self):
        """Clean up resources."""
        self.timer.stop()
        if self.module and self.terminal_id:
            # Send exit command gently first
            self.module.send_input(self.terminal_id, "exit\n")
            # Then force stop after a short delay
            QTimer.singleShot(100, lambda: self.module.stop_terminal(self.terminal_id))


class ShellSettingsDialog(QDialog):
    """
    Dialog for configuring terminal settings.
    """
    
    def __init__(self, parent=None):
        """Initialize the dialog."""
        super().__init__(parent)
        self.setWindowTitle("Terminal Settings")
        self.resize(400, 300)
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Shell selection
        shell_group = QGroupBox("Shell")
        shell_layout = QFormLayout()
        
        self.shell_combo = QComboBox()
        self.shell_combo.addItem("Default", "")
        self.shell_combo.addItem("Bash", "/bin/bash")
        self.shell_combo.addItem("Zsh", "/bin/zsh")
        self.shell_combo.addItem("Sh", "/bin/sh")
        
        shell_layout.addRow("Shell:", self.shell_combo)
        
        self.working_dir_edit = QLineEdit()
        self.working_dir_edit.setPlaceholderText("Leave empty for home directory")
        shell_layout.addRow("Working Directory:", self.working_dir_edit)
        
        dir_button = QPushButton("Browse...")
        dir_button.clicked.connect(self.browse_directory)
        shell_layout.addRow("", dir_button)
        
        shell_group.setLayout(shell_layout)
        layout.addWidget(shell_group)
        
        # Environment variables
        env_group = QGroupBox("Environment Variables")
        env_layout = QVBoxLayout()
        
        self.env_edit = QPlainTextEdit()
        self.env_edit.setPlaceholderText("VAR=value\nANOTHER_VAR=value")
        env_layout.addWidget(self.env_edit)
        
        env_group.setLayout(env_layout)
        layout.addWidget(env_group)
        
        # Dialog buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
    
    def browse_directory(self):
        """Open a directory browser dialog."""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Working Directory",
            self.working_dir_edit.text() or os.path.expanduser("~")
        )
        if directory:
            self.working_dir_edit.setText(directory)
    
    def get_shell(self):
        """Get the selected shell."""
        return self.shell_combo.currentData()
    
    def get_working_dir(self):
        """Get the working directory."""
        return self.working_dir_edit.text() or None
    
    def get_environment_vars(self):
        """Get the environment variables."""
        env_vars = {}
        for line in self.env_edit.toPlainText().splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                env_vars[key.strip()] = value.strip()
        return env_vars


class TerminalWidget(QWidget):
    """
    Widget for the Terminal module.
    Provides UI elements for terminal/shell access.
    """
    
    def __init__(self, app=None, parent=None):
        super().__init__(parent)
        self.app = app
        self.module = None
        
        if self.app:
            self.set_app(self.app)
            
        self.init_ui()
    
    def set_app(self, app):
        """Set the application instance."""
        self.app = app
        
        # Get module reference
        if self.app:
            self.module = self.app.module_manager.get_module("terminal")
    
    def init_ui(self):
        """Initialize the user interface."""
        main_layout = QVBoxLayout()
        
        # Toolbar
        toolbar_layout = QHBoxLayout()
        
        self.new_terminal_btn = QPushButton("New Terminal")
        self.new_terminal_btn.clicked.connect(self.new_terminal)
        toolbar_layout.addWidget(self.new_terminal_btn)
        
        self.close_terminal_btn = QPushButton("Close Terminal")
        self.close_terminal_btn.clicked.connect(self.close_current_terminal)
        toolbar_layout.addWidget(self.close_terminal_btn)
        
        toolbar_layout.addStretch()
        
        main_layout.addLayout(toolbar_layout)
        
        # Tab widget for terminals
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_terminal_tab)
        main_layout.addWidget(self.tab_widget)
        
        self.setLayout(main_layout)
        
        # Auto-open first terminal
        QTimer.singleShot(100, self.new_terminal)
    
    def new_terminal(self):
        """Open a new terminal tab."""
        if not self.module:
            QMessageBox.warning(self, "Module Not Available", 
                               "Terminal module is not available.")
            return
            
        # Show settings dialog
        settings_dialog = ShellSettingsDialog(self)
        if settings_dialog.exec_() != QDialog.Accepted:
            return
            
        # Get settings
        shell = settings_dialog.get_shell()
        working_dir = settings_dialog.get_working_dir()
        env_vars = settings_dialog.get_environment_vars()
        
        # Start terminal
        terminal_id = self.module.start_terminal(
            shell=shell,
            working_dir=working_dir,
            env_vars=env_vars,
            callback=self.terminal_exited
        )
        
        if terminal_id:
            # Create new tab with terminal
            tab = TerminalTab(terminal_id, self.module, self)
            tab.terminalClosed.connect(self.handle_terminal_closed)
            
            # Determine tab name (based on shell and directory)
            shell_name = os.path.basename(shell) if shell else "Terminal"
            if working_dir:
                dir_name = os.path.basename(working_dir)
                tab_name = f"{shell_name} - {dir_name}"
            else:
                tab_name = shell_name
                
            index = self.tab_widget.addTab(tab, tab_name)
            self.tab_widget.setCurrentIndex(index)
            
            # Set focus to terminal
            tab.terminal_display.setFocus()
            
            # Calculate and set terminal size
            self.update_terminal_size(tab)
        else:
            QMessageBox.warning(self, "Terminal Error", 
                               "Failed to start terminal.")
    
    def close_terminal_tab(self, index):
        """Close a terminal tab."""
        tab = self.tab_widget.widget(index)
        if isinstance(tab, TerminalTab):
            tab.cleanup()
        self.tab_widget.removeTab(index)
    
    def close_current_terminal(self):
        """Close the current terminal tab."""
        current_index = self.tab_widget.currentIndex()
        if current_index >= 0:
            self.close_terminal_tab(current_index)
    
    def terminal_exited(self, terminal_id, exit_code):
        """Handle terminal process exit."""
        # Find the tab with this terminal ID
        for i in range(self.tab_widget.count()):
            tab = self.tab_widget.widget(i)
            if isinstance(tab, TerminalTab) and tab.terminal_id == terminal_id:
                # Update tab title to indicate it's closed
                self.tab_widget.setTabText(i, f"{self.tab_widget.tabText(i)} [Exited]")
                break
    
    def handle_terminal_closed(self, terminal_id):
        """Handle terminal closed signal from tab."""
        # Terminal cleanup is already handled in the tab
        pass
    
    def update_terminal_size(self, tab):
        """
        Calculate and set terminal size based on widget size.
        
        Args:
            tab: The TerminalTab to resize
        """
        if not isinstance(tab, TerminalTab):
            return
            
        # Get font metrics
        font_metrics = QFontMetrics(tab.terminal_display.font())
        char_width = font_metrics.averageCharWidth()
        char_height = font_metrics.height()
        
        # Calculate terminal dimensions
        width = tab.terminal_display.width()
        height = tab.terminal_display.height()
        
        cols = max(80, int(width / char_width))
        rows = max(24, int(height / char_height))
        
        # Resize terminal
        tab.resize_terminal(rows, cols)
    
    def resizeEvent(self, event):
        """Handle widget resize event."""
        super().resizeEvent(event)
        
        # Update terminal sizes for all tabs
        for i in range(self.tab_widget.count()):
            tab = self.tab_widget.widget(i)
            if isinstance(tab, TerminalTab):
                self.update_terminal_size(tab)
    
    def cleanup(self):
        """Clean up resources."""
        # Close all terminal tabs
        while self.tab_widget.count() > 0:
            self.close_terminal_tab(0)