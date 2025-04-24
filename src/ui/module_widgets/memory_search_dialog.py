from PyQt5.QtWidgets import QDialog

class MemorySearchDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        # Minimal stub for dialog
        self.setWindowTitle("Memory Search")
    def get_search_options(self):
        # Return dummy search options for now
        return {"pattern": b"", "pattern_type": "Bytes", "region_type": "All"}
