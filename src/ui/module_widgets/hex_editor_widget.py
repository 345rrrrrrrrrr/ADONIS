from PyQt5.QtWidgets import QWidget
from PyQt5.QtCore import pyqtSignal

class HexEditor(QWidget):
    dataChanged = pyqtSignal(int, bytes)
    def __init__(self, parent=None):
        super().__init__(parent)
        # Minimal stub for HexEditor
    def set_data(self, data, address=0):
        pass
    def clear_data(self):
        pass
