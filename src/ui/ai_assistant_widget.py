#!/usr/bin/env python3
# ADONIS - AI Assistant Widget

import logging
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QLabel, QSplitter, QComboBox, QCheckBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QTextCursor


class AIAssistantWidget(QWidget):
    """
    Widget for interacting with the AI Assistant.
    Provides a chat-like interface for querying and receiving responses.
    """
    
    def __init__(self, app, parent=None):
        """Initialize the AI Assistant widget."""
        super().__init__(parent)
        self.app = app  # ADONIS application instance
        self.logger = logging.getLogger("adonis.ui.ai_assistant")
        self.ai_assistant = None
        
        if hasattr(self.app, 'ai_assistant'):
            self.ai_assistant = self.app.ai_assistant
        
        self._setup_ui()
        
        # Connect to AI assistant events if available
        if self.ai_assistant:
            self.ai_assistant.register_callback("on_response", self._on_ai_response)
            self.ai_assistant.register_callback("on_error", self._on_ai_error)
            self.ai_assistant.register_callback("on_status_change", self._on_ai_status_change)
    
    def _setup_ui(self):
        """Set up the UI components."""
        # Main layout
        layout = QVBoxLayout(self)
        
        # Status bar
        status_layout = QHBoxLayout()
        
        # Status indicator
        self.status_label = QLabel("AI Assistant: Ready")
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch(1)
        
        # Enable/disable checkbox
        self.enable_checkbox = QCheckBox("Enabled")
        self.enable_checkbox.setChecked(True)
        self.enable_checkbox.toggled.connect(self._on_enable_toggled)
        status_layout.addWidget(self.enable_checkbox)
        
        layout.addLayout(status_layout)
        
        # Conversation display
        self.conversation_display = QTextEdit()
        self.conversation_display.setReadOnly(True)
        self.conversation_display.setAcceptRichText(True)
        self.conversation_display.setFont(QFont("Arial", 10))
        layout.addWidget(self.conversation_display)
        
        # Input controls
        input_layout = QHBoxLayout()
        
        # Context selector
        self.context_selector = QComboBox()
        self.context_selector.addItem("General")
        self.context_selector.addItem("Network Scanner")
        self.context_selector.addItem("Debugger")
        self.context_selector.addItem("Terminal")
        self.context_selector.addItem("Packet Analyzer")
        self.context_selector.addItem("Memory Editor")
        input_layout.addWidget(self.context_selector, 1)
        
        # Input field
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Ask a question or request assistance...")
        self.input_field.returnPressed.connect(self._on_send_clicked)
        input_layout.addWidget(self.input_field, 3)
        
        # Send button
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self._on_send_clicked)
        input_layout.addWidget(self.send_button)
        
        layout.addLayout(input_layout)
        
        # Add additional controls
        controls_layout = QHBoxLayout()
        
        # Clear button
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self._on_clear_clicked)
        controls_layout.addWidget(self.clear_button)
        
        controls_layout.addStretch(1)
        
        # Help button
        self.help_button = QPushButton("AI Help")
        self.help_button.clicked.connect(self._on_help_clicked)
        controls_layout.addWidget(self.help_button)
        
        layout.addLayout(controls_layout)
    
    def _on_send_clicked(self):
        """Handle sending a query to the AI assistant."""
        query = self.input_field.text().strip()
        if not query:
            return
        
        # Clear the input field
        self.input_field.clear()
        
        # Display the user's query
        self._add_message("You", query, is_user=True)
        
        # If AI is not available, show a message
        if not self.ai_assistant or not self.enable_checkbox.isChecked():
            self._add_message(
                "System",
                "AI Assistant is not available or is disabled.",
                is_system=True
            )
            return
        
        # Get context from selector
        context = self.context_selector.currentText()
        
        # Update AI assistant context if needed
        if context != "General":
            self.ai_assistant.set_context({"current_module": context.lower()})
        
        # Show thinking indicator
        self._add_message("AI Assistant", "Thinking...", is_thinking=True)
        
        # Send query to AI assistant
        self.ai_assistant.ask(query, self._on_ai_response)
    
    def _on_ai_response(self, response):
        """Handle AI assistant response."""
        # Remove thinking message (last message)
        cursor = self.conversation_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.select(QTextCursor.BlockUnderCursor)
        cursor.removeSelectedText()
        cursor.deletePreviousChar()  # Remove the newline
        
        # Add the actual response
        self._add_message("AI Assistant", response)
    
    def _on_ai_error(self, error_message):
        """Handle AI assistant errors."""
        self._add_message("AI Assistant", f"Error: {error_message}", is_error=True)
    
    def _on_ai_status_change(self, enabled):
        """Handle AI assistant status change."""
        self.enable_checkbox.setChecked(enabled)
        status = "Enabled" if enabled else "Disabled"
        self.status_label.setText(f"AI Assistant: {status}")
    
    def _on_enable_toggled(self, checked):
        """Handle enable/disable toggle."""
        if self.ai_assistant:
            self.ai_assistant.set_enabled(checked)
        
        status = "Enabled" if checked else "Disabled"
        self.status_label.setText(f"AI Assistant: {status}")
    
    def _on_clear_clicked(self):
        """Handle clear button click."""
        self.conversation_display.clear()
        
        # Clear AI assistant history if available
        if self.ai_assistant:
            self.ai_assistant.clear_history()
    
    def _on_help_clicked(self):
        """Handle help button click."""
        help_text = """
        <b>AI Assistant Help</b><br>
        The AI Assistant helps you with tasks across all modules. You can:
        <ul>
            <li>Ask questions about how to use ADONIS</li>
            <li>Get help analyzing data or results</li>
            <li>Request suggestions for scan options, filters, etc.</li>
            <li>Automate complex workflows with natural language</li>
        </ul>
        Select a context from the dropdown to help the AI provide more relevant answers.
        """
        self._add_message("System", help_text, is_system=True)
    
    def _add_message(self, sender, message, is_user=False, is_system=False, is_error=False, is_thinking=False):
        """Add a message to the conversation display."""
        # Format based on message type
        if is_user:
            color = "#4a86e8"  # Blue for user
        elif is_system:
            color = "#888888"  # Gray for system
        elif is_error:
            color = "#e84a4a"  # Red for errors
        elif is_thinking:
            color = "#888888"  # Gray for thinking
            message = "<i>" + message + "</i>"  # Italicize thinking messages
        else:
            color = "#43a047"  # Green for AI
        
        # Format the message
        formatted_message = f"""
        <div style="margin-bottom: 8px;">
            <span style="font-weight: bold; color: {color};">{sender}:</span>
            <span style="margin-left: 8px;">{message}</span>
        </div>
        """
        
        # Add to display
        cursor = self.conversation_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(formatted_message)
        
        # Scroll to bottom
        scrollbar = self.conversation_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def cleanup(self):
        """Clean up resources when closing."""
        # Nothing specific to clean up for now
        pass