#!/usr/bin/env python3
# ADONIS - Dashboard Widget

import logging
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QGroupBox, QFrame,
    QSizePolicy, QSpacerItem
)
from PyQt5.QtCore import Qt, QSize, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor

from ui.utils import load_icon, resource_path


class ModuleCard(QFrame):
    """A card widget representing a module on the dashboard."""
    
    clicked = pyqtSignal(str)  # Signal emitted when the card is clicked
    
    def __init__(self, title, icon_name, description, module_id):
        super().__init__()
        self.module_id = module_id
        self.setFrameShape(QFrame.StyledPanel)
        self.setFrameShadow(QFrame.Raised)
        self.setMinimumHeight(150)
        self.setMinimumWidth(220)
        self.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Preferred)
        self.setCursor(Qt.PointingHandCursor)
        
        # Set object name for styling
        self.setObjectName("moduleCard")
        
        # Create layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Icon
        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignCenter)
        icon = load_icon(icon_name)
        if not icon.isNull():
            icon_label.setPixmap(icon.pixmap(48, 48))
        else:
            # Fallback if icon not found
            icon_label.setText("⚙️")
            icon_label.setFont(QFont("Arial", 24))
        layout.addWidget(icon_label)
        
        # Title
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(title_label)
        
        # Description
        desc_label = QLabel(description)
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        # Set layout
        self.setLayout(layout)
    
    def mousePressEvent(self, event):
        """Handle mouse press events."""
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.module_id)
        super().mousePressEvent(event)


class StatusWidget(QFrame):
    """Widget showing system status information."""
    
    def __init__(self):
        super().__init__()
        self.setFrameShape(QFrame.StyledPanel)
        self.setFrameShadow(QFrame.Raised)
        
        # Create layout
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("System Status")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(title)
        
        # Status indicators
        self.indicators = {}
        
        status_layout = QGridLayout()
        
        # CPU usage
        status_layout.addWidget(QLabel("CPU:"), 0, 0)
        self.indicators["cpu"] = QLabel("0%")
        status_layout.addWidget(self.indicators["cpu"], 0, 1)
        
        # Memory usage
        status_layout.addWidget(QLabel("Memory:"), 1, 0)
        self.indicators["memory"] = QLabel("0 MB")
        status_layout.addWidget(self.indicators["memory"], 1, 1)
        
        # Disk usage
        status_layout.addWidget(QLabel("Disk:"), 2, 0)
        self.indicators["disk"] = QLabel("0 GB")
        status_layout.addWidget(self.indicators["disk"], 2, 1)
        
        # Network
        status_layout.addWidget(QLabel("Network:"), 3, 0)
        self.indicators["network"] = QLabel("0 KB/s")
        status_layout.addWidget(self.indicators["network"], 3, 1)
        
        layout.addLayout(status_layout)
        layout.addStretch(1)
        
        # Update button
        update_button = QPushButton("Refresh")
        update_button.clicked.connect(self.refresh_status)
        layout.addWidget(update_button)
        
        self.setLayout(layout)
    
    def refresh_status(self):
        """Refresh the status information."""
        # This would be connected to the core module for real-time stats
        pass
    
    def update_indicators(self, status_data: Dict[str, Any]):
        """Update status indicators with new data."""
        if "cpu" in status_data:
            self.indicators["cpu"].setText(f"{status_data['cpu']}%")
        
        if "memory" in status_data:
            self.indicators["memory"].setText(f"{status_data['memory']} MB")
        
        if "disk" in status_data:
            self.indicators["disk"].setText(f"{status_data['disk']} GB")
        
        if "network" in status_data:
            self.indicators["network"].setText(f"{status_data['network']} KB/s")


class RecentActivityWidget(QFrame):
    """Widget showing recent activity."""
    
    def __init__(self):
        super().__init__()
        self.setFrameShape(QFrame.StyledPanel)
        self.setFrameShadow(QFrame.Raised)
        
        # Create layout
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Recent Activity")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(title)
        
        # Activity list - placeholder for now
        self.activity_list = QLabel("No recent activity")
        layout.addWidget(self.activity_list)
        
        layout.addStretch(1)
        
        # Clear button
        clear_button = QPushButton("Clear History")
        layout.addWidget(clear_button)
        
        self.setLayout(layout)
    
    def add_activity(self, activity_text):
        """Add a new activity to the list."""
        # This would append to a list widget in a real implementation
        self.activity_list.setText(activity_text)


class DashboardWidget(QWidget):
    """Main dashboard widget showing module cards and system info."""
    
    def __init__(self, app, parent=None):
        super().__init__(parent)
        self.app = app
        self.logger = logging.getLogger("adonis.ui.dashboard")
        
        # Create layout
        main_layout = QHBoxLayout(self)
        
        # Left side - Module cards
        left_layout = QVBoxLayout()
        
        # Welcome message
        welcome = QLabel("Welcome to ADONIS")
        welcome.setFont(QFont("Arial", 16, QFont.Bold))
        welcome.setAlignment(Qt.AlignCenter)
        left_layout.addWidget(welcome)
        
        # Description
        description = QLabel("AI-powered Debugging and Offensive Network Integrated Suite")
        description.setAlignment(Qt.AlignCenter)
        description.setWordWrap(True)
        left_layout.addWidget(description)
        
        left_layout.addSpacing(20)
        
        # Module cards
        modules_title = QLabel("Modules")
        modules_title.setFont(QFont("Arial", 14, QFont.Bold))
        left_layout.addWidget(modules_title)
        
        # Grid layout for module cards
        modules_grid = QGridLayout()
        
        # Create module cards
        self._setup_module_cards(modules_grid)
        
        left_layout.addLayout(modules_grid)
        left_layout.addStretch(1)
        
        main_layout.addLayout(left_layout, 3)  # Give more space to the module cards
        
        # Right side - Status and activity
        right_layout = QVBoxLayout()
        
        # Status widget
        self.status_widget = StatusWidget()
        right_layout.addWidget(self.status_widget)
        
        # Recent activity widget
        self.activity_widget = RecentActivityWidget()
        right_layout.addWidget(self.activity_widget)
        
        main_layout.addLayout(right_layout, 1)
        
        self.setLayout(main_layout)
        
        # Update status once initially
        self.update_status()
    
    def _setup_module_cards(self, grid_layout):
        """Set up module cards in the grid layout."""
        modules = [
            {
                "title": "Network Scanner",
                "icon": "network.png",
                "description": "Scan networks and discover hosts",
                "id": "network_scanner"
            },
            {
                "title": "Debugger",
                "icon": "debug.png",
                "description": "Debug applications and analyze code",
                "id": "debugger"
            },
            {
                "title": "Terminal",
                "icon": "terminal.png",
                "description": "Command-line interface and shell access",
                "id": "terminal"
            },
            {
                "title": "Packet Analyzer",
                "icon": "packet.png",
                "description": "Capture and analyze network traffic",
                "id": "packet_analyzer"
            },
            {
                "title": "Memory Editor",
                "icon": "memory.png",
                "description": "View and edit process memory",
                "id": "memory_editor"
            }
        ]
        
        # Create module cards and arrange them in a grid
        row, col = 0, 0
        for module in modules:
            card = ModuleCard(
                module["title"],
                module["icon"],
                module["description"],
                module["id"]
            )
            card.clicked.connect(self._on_module_clicked)
            grid_layout.addWidget(card, row, col)
            
            # Update grid position
            col += 1
            if col > 1:  # 2 cards per row
                col = 0
                row += 1
    
    def _on_module_clicked(self, module_id):
        """Handle module card clicks."""
        self.logger.info(f"Module clicked: {module_id}")
        
        # Get parent (main window)
        parent = self.parent()
        if parent:
            # Call the appropriate function in the main window based on module ID
            if module_id == "network_scanner":
                parent._on_new_network_scan()
            elif module_id == "debugger":
                parent._on_new_debugging_session()
            elif module_id == "terminal":
                parent._on_new_terminal()
            elif module_id == "packet_analyzer":
                parent._on_new_packet_capture()
            elif module_id == "memory_editor":
                parent._on_new_memory_editor()
    
    def update_status(self):
        """Update status information."""
        if hasattr(self.app, "core_module"):
            core_module = self.app.module_manager.get_module("core")
            if core_module:
                resource_usage = core_module.get_resource_usage()
                
                status_data = {}
                if "cpu" in resource_usage:
                    status_data["cpu"] = resource_usage["cpu"]["percent"]
                
                if "memory" in resource_usage:
                    status_data["memory"] = f"{resource_usage['memory']['used_gb']:.1f}"
                
                if "disk" in resource_usage:
                    status_data["disk"] = f"{resource_usage['disk']['used_gb']:.1f}"
                
                if "network" in resource_usage:
                    # Calculate network rate (this would need more logic in a real app)
                    status_data["network"] = "0"
                
                # Update the status widget
                self.status_widget.update_indicators(status_data)