#!/usr/bin/env python3
# ADONIS Terminal Widget

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QFont, QTextCursor, QColor, QTextCharFormat

class TerminalWidget(QWidget):
    """
    Widget for the terminal module of ADONIS.
    Provides an interface for command line operations.
    """
    
    command_entered = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.module = None
        self.history = []
        self.history_position = 0
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.main_layout = QVBoxLayout(self)
        
        # Target selection
        self.target_layout = QHBoxLayout()
        self.target_label = QLabel("Terminal:")
        self.target_combo = QComboBox()
        self.target_combo.addItems(["Local Terminal", "Remote Shell"])
        
        self.target_layout.addWidget(self.target_label)
        self.target_layout.addWidget(self.target_combo, 1)  # Stretch factor
        
        # Terminal output
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setFont(QFont("Monospace", 10))
        # Set a dark background for terminal feel
        self.output_area.setStyleSheet("background-color: #2b2b2b; color: #f0f0f0;")
        
        # Command input
        self.input_layout = QHBoxLayout()
        self.prompt_label = QLabel("$")
        self.prompt_label.setFont(QFont("Monospace", 10, QFont.Bold))
        self.command_input = QLineEdit()
        self.command_input.setFont(QFont("Monospace", 10))
        self.command_input.setStyleSheet("background-color: #2b2b2b; color: #f0f0f0;")
        self.send_button = QPushButton("Send")
        
        self.input_layout.addWidget(self.prompt_label)
        self.input_layout.addWidget(self.command_input, 1)  # Stretch factor
        self.input_layout.addWidget(self.send_button)
        
        # Add widgets to the main layout
        self.main_layout.addLayout(self.target_layout)
        self.main_layout.addWidget(self.output_area, 1)  # Stretch factor
        self.main_layout.addLayout(self.input_layout)
        
        # Connect signals
        self.command_input.returnPressed.connect(self.on_send_command)
        self.send_button.clicked.connect(self.on_send_command)
        self.command_input.installEventFilter(self)  # For up/down arrow history
        
        # Welcome message
        self.append_output("ADONIS Terminal Interface\n" +
                          "Type 'help' for available commands.\n", color="#75b798")
    
    def set_module(self, module):
        """
        Set the module instance associated with this widget.
        
        Args:
            module: Terminal module instance
        """
        self.module = module
        
        # Connect signals from the module
        if hasattr(module, "output_signal"):
            module.output_signal.connect(self.on_terminal_output)
    
    def eventFilter(self, obj, event):
        """
        Event filter for command input.
        Handles up/down arrow key presses for command history.
        
        Args:
            obj: Object that triggered the event
            event: Event object
            
        Returns:
            True if event was handled, False otherwise
        """
        from PyQt5.QtCore import QEvent
        from PyQt5.QtGui import QKeyEvent
        
        if obj is self.command_input and event.type() == QEvent.KeyPress:
            key_event = QKeyEvent(event)
            
            # Handle up arrow for previous command
            if key_event.key() == Qt.Key_Up:
                self.history_previous()
                return True
                
            # Handle down arrow for next command
            elif key_event.key() == Qt.Key_Down:
                self.history_next()
                return True
                
        return super().eventFilter(obj, event)
    
    def history_previous(self):
        """Navigate to previous command in history."""
        if not self.history:
            return
            
        if self.history_position > 0:
            self.history_position -= 1
            self.command_input.setText(self.history[self.history_position])
    
    def history_next(self):
        """Navigate to next command in history."""
        if not self.history:
            return
            
        if self.history_position < len(self.history) - 1:
            self.history_position += 1
            self.command_input.setText(self.history[self.history_position])
        else:
            # Clear input if at the end of history
            self.command_input.clear()
    
    def append_output(self, text, color=None):
        """
        Append text to the terminal output.
        
        Args:
            text: Text to append
            color: Optional color for the text
        """
        cursor = self.output_area.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        if color:
            format = QTextCharFormat()
            format.setForeground(QColor(color))
            cursor.setCharFormat(format)
            
        cursor.insertText(text)
        
        # Reset format if color was applied
        if color:
            format = QTextCharFormat()
            format.setForeground(QColor("#f0f0f0"))  # Default color
            cursor.setCharFormat(format)
            
        # Auto-scroll to bottom
        cursor.movePosition(QTextCursor.End)
        self.output_area.setTextCursor(cursor)
    
    @pyqtSlot()
    def on_send_command(self):
        """Handle sending commands to the terminal."""
        command = self.command_input.text().strip()
        
        if not command:
            return
            
        # Add command to history
        if not self.history or self.history[-1] != command:
            self.history.append(command)
        self.history_position = len(self.history)
        
        # Show command in output
        self.append_output(f"\n$ {command}\n", color="#75b798")
        
        # Clear the input field
        self.command_input.clear()
        
        # Emit signal for command processing
        self.command_entered.emit(command)
        
        # Send to module if available
        if self.module:
            self.module.execute_command(command)
    
    @pyqtSlot(str, bool)
    def on_terminal_output(self, output, error=False):
        """
        Handle terminal output.
        
        Args:
            output: Output text from the terminal
            error: Whether this is an error message
        """
        # Determine color based on error status
        color = "#f07178" if error else None
        
        self.append_output(output, color=color)