from PyQt5.QtWidgets import QWidget
from PyQt5.QtCore import pyqtSignal

class SearchResultsWidget(QWidget):
    addressSelected = pyqtSignal(int)
    def __init__(self, results, parent=None):
        super().__init__(parent)
        # Minimal stub for results widget
        self.results = results
