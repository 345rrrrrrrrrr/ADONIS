#!/usr/bin/env python3
# ADONIS - UI Utilities

import os
import sys
import logging
from typing import Optional

from PyQt5.QtGui import QIcon, QFont, QColor
from PyQt5.QtCore import QFile, QTextStream, QDir

def resource_path(relative_path):
    """
    Get absolute path to resource, works for dev and for PyInstaller.
    
    Args:
        relative_path: Path relative to resources directory
        
    Returns:
        Absolute path to the resource
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = getattr(sys, '_MEIPASS', None)
        if base_path is None:
            # If not running as bundled executable, use the script location
            base_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
        
        return os.path.join(base_path, 'ui', 'resources', relative_path)
    except Exception as e:
        logging.getLogger("adonis.ui.utils").error(f"Error resolving resource path: {str(e)}")
        return os.path.join(os.path.abspath(os.path.dirname(__file__)), 'resources', relative_path)

def load_stylesheet(theme_name="dark") -> Optional[str]:
    """
    Load application stylesheet.
    
    Args:
        theme_name: Name of the theme to load (default: "dark")
        
    Returns:
        Stylesheet string or None if not found
    """
    try:
        # Try to load from resources
        file_path = resource_path(f"themes/{theme_name}.qss")
        
        if not os.path.exists(file_path):
            # If not found in resources, try from current directory
            file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources', 'themes', f"{theme_name}.qss")
        
        if not os.path.exists(file_path):
            logging.getLogger("adonis.ui.utils").warning(f"Stylesheet not found: {theme_name}")
            return None
            
        qss_file = QFile(file_path)
        if qss_file.open(QFile.ReadOnly | QFile.Text):
            stream = QTextStream(qss_file)
            stylesheet = stream.readAll()
            qss_file.close()
            return stylesheet
            
    except Exception as e:
        logging.getLogger("adonis.ui.utils").error(f"Error loading stylesheet: {str(e)}")
    
    return None

def load_icon(icon_name) -> QIcon:
    """
    Load an icon from resources.
    
    Args:
        icon_name: Name of the icon file (with extension)
        
    Returns:
        QIcon object
    """
    try:
        # Try to load from resources
        file_path = resource_path(f"icons/{icon_name}")
        
        if not os.path.exists(file_path):
            # If not found in resources, try from current directory
            file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources', 'icons', icon_name)
        
        return QIcon(file_path)
        
    except Exception as e:
        logging.getLogger("adonis.ui.utils").error(f"Error loading icon {icon_name}: {str(e)}")
        return QIcon()

def create_font(family="Consolas", size=10, weight=None, italic=False) -> QFont:
    """
    Create a font with specified properties.
    
    Args:
        family: Font family name
        size: Font size
        weight: Font weight (e.g., QFont.Bold)
        italic: Whether the font should be italic
        
    Returns:
        QFont object
    """
    font = QFont()
    font.setFamily(family)
    font.setPointSize(size)
    if weight is not None:
        font.setWeight(weight)
    font.setItalic(italic)
    return font

def get_syntax_highlighting_colors(theme="dark"):
    """
    Get color scheme for syntax highlighting.
    
    Args:
        theme: Theme name ("dark" or "light")
        
    Returns:
        Dictionary of color settings
    """
    if theme == "dark":
        return {
            "background": QColor("#282C34"),
            "text": QColor("#ABB2BF"),
            "keyword": QColor("#C678DD"),
            "operator": QColor("#56B6C2"),
            "brace": QColor("#D19A66"),
            "defclass": QColor("#61AFEF"),
            "string": QColor("#98C379"),
            "string2": QColor("#56B6C2"),
            "comment": QColor("#5C6370"),
            "self": QColor("#E06C75"),
            "numbers": QColor("#D19A66"),
        }
    else:  # light theme
        return {
            "background": QColor("#FFFFFF"),
            "text": QColor("#24292E"),
            "keyword": QColor("#D73A49"),
            "operator": QColor("#005CC5"),
            "brace": QColor("#6F42C1"),
            "defclass": QColor("#6F42C1"),
            "string": QColor("#032F62"),
            "string2": QColor("#032F62"),
            "comment": QColor("#6A737D"),
            "self": QColor("#22863A"),
            "numbers": QColor("#005CC5"),
        }

def create_action(text, parent=None, shortcut=None, icon=None, tip=None, checkable=False, triggered=None):
    from PyQt5.QtWidgets import QAction
    action = QAction(text, parent)
    if icon:
        action.setIcon(icon)
    if shortcut:
        action.setShortcut(shortcut)
    if tip:
        action.setToolTip(tip)
        action.setStatusTip(tip)
    action.setCheckable(checkable)
    if triggered:
        action.triggered.connect(triggered)
    return action