from PyQt5.QtWidgets import QDialog

class SettingsDialog(QDialog):
    def __init__(self, app, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        # Minimal stub for settings dialog
