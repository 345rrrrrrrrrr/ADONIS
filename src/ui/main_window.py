#!/usr/bin/env python3
# ADONIS - Main Window class

import sys
import os
import logging
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (
    QMainWindow, QApplication, QTabWidget, QDockWidget, QAction,
    QToolBar, QStatusBar, QMessageBox, QFileDialog, QMenu
)
from PyQt5.QtCore import Qt, QSize, pyqtSignal, QSettings
from PyQt5.QtGui import QIcon, QKeySequence

from ui.dashboard import DashboardWidget
from ui.module_widgets.network_scanner_widget import NetworkScannerWidget
from ui.module_widgets.debugger_widget import DebuggerWidget
from ui.module_widgets.terminal_widget import TerminalWidget
from ui.module_widgets.packet_analyzer_widget import PacketAnalyzerWidget
from ui.module_widgets.memory_editor_widget import MemoryEditorWidget
from ui.settings_dialog import SettingsDialog
from ui.ai_assistant_widget import AIAssistantWidget
from ui.utils import load_stylesheet, resource_path


class MainWindow(QMainWindow):
    """Main window for the ADONIS application."""
    
    def __init__(self, app):
        """Initialize the main window."""
        super().__init__()
        self.app = app  # ADONIS application instance
        self.logger = logging.getLogger("adonis.ui.main_window")
        self.module_widgets = {}
        self.setWindowTitle("ADONIS - AI-powered Debugging and Offensive Network Suite")
        
        # Set window size based on screen
        self.resize(1200, 800)
        self.setMinimumSize(800, 600)
        
        # Set up UI components
        self._setup_ui()
        
        # Load previous window state if available
        self._load_window_state()
        
        self.logger.info("Main window initialized")
    
    def _setup_ui(self):
        """Set up UI components."""
        # Set stylesheet
        stylesheet = load_stylesheet("dark")
        if stylesheet:
            self.setStyleSheet(stylesheet)
        
        # Main tab widget
        self.tab_widget = QTabWidget(self)
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self._on_tab_close_requested)
        self.setCentralWidget(self.tab_widget)
        
        # Dashboard as first tab
        self.dashboard = DashboardWidget(self.app, self)
        self.tab_widget.addTab(self.dashboard, "Dashboard")
        self.tab_widget.setTabsClosable(True)
        
        # Make dashboard tab not closable
        self.tab_widget.tabBar().setTabButton(0, self.tab_widget.tabBar().RightSide, None)
        
        # Create dock widgets
        self._setup_dock_widgets()
        
        # Create menus
        self._setup_menus()
        
        # Create toolbars
        self._setup_toolbars()
        
        # Create status bar
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
    
    def _setup_dock_widgets(self):
        """Create dock widgets."""
        # AI Assistant dock
        self.ai_assistant_widget = AIAssistantWidget(self.app, self)
        self.ai_dock = QDockWidget("AI Assistant", self)
        self.ai_dock.setWidget(self.ai_assistant_widget)
        self.ai_dock.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea | Qt.BottomDockWidgetArea)
        self.addDockWidget(Qt.RightDockWidgetArea, self.ai_dock)
        
        # Module explorer dock
        # Will be implemented later
        
        # Resource monitor dock
        # Will be implemented later
    
    def _setup_menus(self):
        """Create application menus."""
        # Main menu bar
        self.menu_bar = self.menuBar()
        
        # File menu
        self.file_menu = self.menu_bar.addMenu("&File")
        
        new_menu = QMenu("New", self)
        self.file_menu.addMenu(new_menu)
        
        # New session actions
        self.new_network_scan_action = QAction("Network Scan", self)
        self.new_network_scan_action.setShortcut(QKeySequence("Ctrl+N, S"))
        self.new_network_scan_action.triggered.connect(self._on_new_network_scan)
        new_menu.addAction(self.new_network_scan_action)
        
        self.new_debugging_session_action = QAction("Debugging Session", self)
        self.new_debugging_session_action.setShortcut(QKeySequence("Ctrl+N, D"))
        self.new_debugging_session_action.triggered.connect(self._on_new_debugging_session)
        new_menu.addAction(self.new_debugging_session_action)
        
        self.new_terminal_action = QAction("Terminal", self)
        self.new_terminal_action.setShortcut(QKeySequence("Ctrl+N, T"))
        self.new_terminal_action.triggered.connect(self._on_new_terminal)
        new_menu.addAction(self.new_terminal_action)
        
        self.new_packet_capture_action = QAction("Packet Capture", self)
        self.new_packet_capture_action.setShortcut(QKeySequence("Ctrl+N, P"))
        self.new_packet_capture_action.triggered.connect(self._on_new_packet_capture)
        new_menu.addAction(self.new_packet_capture_action)
        
        self.new_memory_editor_action = QAction("Memory Editor", self)
        self.new_memory_editor_action.setShortcut(QKeySequence("Ctrl+N, M"))
        self.new_memory_editor_action.triggered.connect(self._on_new_memory_editor)
        new_menu.addAction(self.new_memory_editor_action)
        
        self.file_menu.addSeparator()
        
        # Open action
        self.open_action = QAction("&Open...", self)
        self.open_action.setShortcut(QKeySequence.Open)
        self.open_action.triggered.connect(self._on_open)
        self.file_menu.addAction(self.open_action)
        
        # Save action
        self.save_action = QAction("&Save", self)
        self.save_action.setShortcut(QKeySequence.Save)
        self.save_action.triggered.connect(self._on_save)
        self.file_menu.addAction(self.save_action)
        
        # Save As action
        self.save_as_action = QAction("Save &As...", self)
        self.save_as_action.setShortcut(QKeySequence.SaveAs)
        self.save_as_action.triggered.connect(self._on_save_as)
        self.file_menu.addAction(self.save_as_action)
        
        self.file_menu.addSeparator()
        
        # Exit action
        self.exit_action = QAction("E&xit", self)
        self.exit_action.setShortcut(QKeySequence.Quit)
        self.exit_action.triggered.connect(self.close)
        self.file_menu.addAction(self.exit_action)
        
        # Edit menu
        self.edit_menu = self.menu_bar.addMenu("&Edit")
        
        # Settings action
        self.settings_action = QAction("&Settings", self)
        self.settings_action.setShortcut(QKeySequence("Ctrl+,"))
        self.settings_action.triggered.connect(self._on_settings)
        self.edit_menu.addAction(self.settings_action)
        
        # View menu
        self.view_menu = self.menu_bar.addMenu("&View")
        
        # Toggle AI Assistant action
        self.toggle_ai_assistant_action = QAction("AI Assistant", self)
        self.toggle_ai_assistant_action.setCheckable(True)
        self.toggle_ai_assistant_action.setChecked(True)
        self.toggle_ai_assistant_action.triggered.connect(
            lambda checked: self.ai_dock.setVisible(checked)
        )
        self.view_menu.addAction(self.toggle_ai_assistant_action)
        
        # Module specific menus will be added when modules are loaded
        
        # Help menu
        self.help_menu = self.menu_bar.addMenu("&Help")
        
        # Documentation action
        self.docs_action = QAction("&Documentation", self)
        self.docs_action.setShortcut(QKeySequence("F1"))
        self.docs_action.triggered.connect(self._on_documentation)
        self.help_menu.addAction(self.docs_action)
        
        # About action
        self.about_action = QAction("&About", self)
        self.about_action.triggered.connect(self._on_about)
        self.help_menu.addAction(self.about_action)
    
    def _setup_toolbars(self):
        """Create application toolbars."""
        # Main toolbar
        self.main_toolbar = QToolBar("Main Tools", self)
        self.main_toolbar.setIconSize(QSize(24, 24))
        self.main_toolbar.setObjectName("main_toolbar")  # Used for saving state
        self.addToolBar(Qt.TopToolBarArea, self.main_toolbar)
        
        # Add module shortcuts
        # Network Scanner
        self.network_scan_action = QAction("Network Scanner", self)
        self.network_scan_action.triggered.connect(self._on_new_network_scan)
        self.main_toolbar.addAction(self.network_scan_action)
        
        # Debugger
        self.debugger_action = QAction("Debugger", self)
        self.debugger_action.triggered.connect(self._on_new_debugging_session)
        self.main_toolbar.addAction(self.debugger_action)
        
        # Terminal
        self.terminal_action = QAction("Terminal", self)
        self.terminal_action.triggered.connect(self._on_new_terminal)
        self.main_toolbar.addAction(self.terminal_action)
        
        # Packet Analyzer
        self.packet_analyzer_action = QAction("Packet Analyzer", self)
        self.packet_analyzer_action.triggered.connect(self._on_new_packet_capture)
        self.main_toolbar.addAction(self.packet_analyzer_action)
        
        # Memory Editor
        self.memory_editor_action = QAction("Memory Editor", self)
        self.memory_editor_action.triggered.connect(self._on_new_memory_editor)
        self.main_toolbar.addAction(self.memory_editor_action)
        
        # Module-specific toolbars will be created when the module is activated
    
    def _load_window_state(self):
        """Load window size, position and state from settings."""
        settings = QSettings("ADONIS", "MainWindow")
        if settings.contains("geometry"):
            self.restoreGeometry(settings.value("geometry"))
        if settings.contains("windowState"):
            self.restoreState(settings.value("windowState"))
    
    def _save_window_state(self):
        """Save window size, position and state to settings."""
        settings = QSettings("ADONIS", "MainWindow")
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("windowState", self.saveState())
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Ask for confirmation
        reply = QMessageBox.question(
            self, 'Exit Confirmation',
            "Are you sure you want to exit ADONIS?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Save window state
            self._save_window_state()
            
            # Let modules clean up
            for widget in self.module_widgets.values():
                if hasattr(widget, 'cleanup'):
                    try:
                        widget.cleanup()
                    except Exception as e:
                        self.logger.error(f"Error cleaning up module: {str(e)}")
            
            # Accept the event
            event.accept()
        else:
            # Ignore the event
            event.ignore()
    
    def _on_tab_close_requested(self, index):
        """Handle tab close request."""
        # Don't close the dashboard (index 0)
        if index == 0:
            return
        
        # Check if the tab has unsaved changes
        widget = self.tab_widget.widget(index)
        if hasattr(widget, 'has_unsaved_changes') and widget.has_unsaved_changes():
            reply = QMessageBox.question(
                self, 'Unsaved Changes',
                "This tab has unsaved changes. Close anyway?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        
        # Clean up the widget if needed
        if hasattr(widget, 'cleanup'):
            try:
                widget.cleanup()
            except Exception as e:
                self.logger.error(f"Error cleaning up widget: {str(e)}")
        
        # Remove the tab
        self.tab_widget.removeTab(index)
    
    def _on_new_network_scan(self):
        """Create a new network scan tab."""
        widget = NetworkScannerWidget(self.app, self)
        self.module_widgets[f"network_scan_{len(self.module_widgets)}"] = widget
        index = self.tab_widget.addTab(widget, "Network Scan")
        self.tab_widget.setCurrentIndex(index)
    
    def _on_new_debugging_session(self):
        """Create a new debugging session tab."""
        widget = DebuggerWidget(self.app, self)
        self.module_widgets[f"debugger_{len(self.module_widgets)}"] = widget
        index = self.tab_widget.addTab(widget, "Debugger")
        self.tab_widget.setCurrentIndex(index)
    
    def _on_new_terminal(self):
        """Create a new terminal tab."""
        widget = TerminalWidget(self.app, self)
        self.module_widgets[f"terminal_{len(self.module_widgets)}"] = widget
        index = self.tab_widget.addTab(widget, "Terminal")
        self.tab_widget.setCurrentIndex(index)
    
    def _on_new_packet_capture(self):
        """Create a new packet capture tab."""
        widget = PacketAnalyzerWidget(self.app, self)
        self.module_widgets[f"packet_analyzer_{len(self.module_widgets)}"] = widget
        index = self.tab_widget.addTab(widget, "Packet Analyzer")
        self.tab_widget.setCurrentIndex(index)
    
    def _on_new_memory_editor(self):
        """Create a new memory editor tab."""
        widget = MemoryEditorWidget(self.app, self)
        self.module_widgets[f"memory_editor_{len(self.module_widgets)}"] = widget
        index = self.tab_widget.addTab(widget, "Memory Editor")
        self.tab_widget.setCurrentIndex(index)
    
    def _on_open(self):
        """Handle open action."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open File",
            "",
            "ADONIS Files (*.adonis);;All Files (*)"
        )
        if file_path:
            # Determine file type and open in appropriate module
            self._open_file(file_path)
    
    def _on_save(self):
        """Handle save action."""
        current_widget = self.tab_widget.currentWidget()
        if current_widget and current_widget != self.dashboard:
            if hasattr(current_widget, 'save'):
                current_widget.save()
    
    def _on_save_as(self):
        """Handle save as action."""
        current_widget = self.tab_widget.currentWidget()
        if current_widget and current_widget != self.dashboard:
            if hasattr(current_widget, 'save_as'):
                current_widget.save_as()
    
    def _on_settings(self):
        """Open the settings dialog."""
        dialog = SettingsDialog(self.app, self)
        dialog.exec_()
    
    def _on_documentation(self):
        """Open documentation."""
        # Will be implemented later - could open local docs or website
        QMessageBox.information(
            self, 
            "Documentation",
            "Documentation will be opened in your browser."
        )
    
    def _on_about(self):
        """Show about dialog."""
        from src.version import VERSION
        QMessageBox.about(
            self,
            "About ADONIS",
            f"""<b>ADONIS</b> - AI-powered Debugging and Offensive Network Integrated Suite
            <p>Version: {VERSION}</p>
            <p>A comprehensive security, network scanning, and debugging platform.</p>
            <p>© 2025 ADONIS Team</p>"""
        )
    
    def _open_file(self, file_path):
        """Open a file in the appropriate module."""
        # This is a placeholder that would need to determine file type and open accordingly
        extension = os.path.splitext(file_path)[1].lower()
        
        try:
            if extension == '.adonis':
                # Open the ADONIS project file
                pass
            elif extension in ['.pcap', '.pcapng']:
                # Open in packet analyzer
                widget = PacketAnalyzerWidget(self.app, self)
                if hasattr(widget, 'load_file'):
                    widget.load_file(file_path)
                index = self.tab_widget.addTab(widget, os.path.basename(file_path))
                self.tab_widget.setCurrentIndex(index)
            else:
                QMessageBox.warning(
                    self,
                    "Unknown File Type",
                    f"File type {extension} is not supported."
                )
        except Exception as e:
            self.logger.error(f"Error opening file {file_path}: {str(e)}")
            QMessageBox.critical(
                self,
                "Error Opening File",
                f"An error occurred while opening the file:\n{str(e)}"
            )
    
    def show_message(self, message, timeout=5000):
        """Show a message in the status bar."""
        self.status_bar.showMessage(message, timeout)


def launch_ui(app_instance):
    """Launch the UI with the given application instance."""
    qt_app = QApplication(sys.argv)
    window = MainWindow(app_instance)
    window.show()
    return qt_app.exec_()