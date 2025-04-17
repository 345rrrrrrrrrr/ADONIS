#!/usr/bin/env python3
# ADONIS Memory Editor Widget

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QTextEdit, QTableWidget, QTableWidgetItem, 
                             QComboBox, QToolBar, QAction, QHeaderView, QSplitter, 
                             QGroupBox, QSpinBox, QMessageBox, QMenu)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QSize
from PyQt5.QtGui import QIcon, QFont, QColor, QBrush

class MemoryEditorWidget(QWidget):
    """
    Widget for the memory editor module of ADONIS.
    Provides an interface for viewing and modifying process memory.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.module = None
        self.current_process = None
        self.memory_regions = []
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.main_layout = QVBoxLayout(self)
        
        # Create toolbar
        self.toolbar = QToolBar()
        self.toolbar.setIconSize(QSize(24, 24))
        
        self.action_refresh = QAction(QIcon.fromTheme("view-refresh"), "Refresh", self)
        self.action_search = QAction(QIcon.fromTheme("edit-find"), "Search", self)
        self.action_dump = QAction(QIcon.fromTheme("document-save"), "Dump Region", self)
        self.action_load = QAction(QIcon.fromTheme("document-open"), "Load Dump", self)
        
        self.toolbar.addAction(self.action_refresh)
        self.toolbar.addAction(self.action_search)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.action_dump)
        self.toolbar.addAction(self.action_load)
        
        self.main_layout.addWidget(self.toolbar)
        
        # Process selection
        self.process_layout = QHBoxLayout()
        
        self.process_label = QLabel("Process:")
        self.process_combo = QComboBox()
        self.refresh_button = QPushButton("Refresh List")
        self.pid_label = QLabel("PID:")
        self.pid_input = QLineEdit()
        self.pid_input.setPlaceholderText("Or enter PID manually")
        self.attach_button = QPushButton("Attach")
        
        self.process_layout.addWidget(self.process_label)
        self.process_layout.addWidget(self.process_combo, 2)  # Stretch factor
        self.process_layout.addWidget(self.refresh_button)
        self.process_layout.addWidget(self.pid_label)
        self.process_layout.addWidget(self.pid_input, 1)  # Stretch factor
        self.process_layout.addWidget(self.attach_button)
        
        self.main_layout.addLayout(self.process_layout)
        
        # Splitter for regions and memory view
        self.main_splitter = QSplitter(Qt.Horizontal)
        
        # Memory regions panel
        self.regions_group = QGroupBox("Memory Regions")
        self.regions_layout = QVBoxLayout(self.regions_group)
        
        self.regions_table = QTableWidget()
        self.regions_table.setColumnCount(5)
        self.regions_table.setHorizontalHeaderLabels(["Address", "Size", "Permissions", "Name", "Type"])
        self.regions_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        
        self.regions_layout.addWidget(self.regions_table)
        
        # Memory view and edit panel
        self.memory_group = QGroupBox("Memory View")
        self.memory_layout = QVBoxLayout(self.memory_group)
        
        # Address and navigation controls
        self.address_layout = QHBoxLayout()
        
        self.address_label = QLabel("Address:")
        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("Enter hex address (e.g. 0x12345678)")
        self.go_button = QPushButton("Go")
        self.prev_button = QPushButton("◀")
        self.next_button = QPushButton("▶")
        
        self.address_layout.addWidget(self.address_label)
        self.address_layout.addWidget(self.address_input, 1)  # Stretch factor
        self.address_layout.addWidget(self.go_button)
        self.address_layout.addWidget(self.prev_button)
        self.address_layout.addWidget(self.next_button)
        
        self.memory_layout.addLayout(self.address_layout)
        
        # Bytes per row and data type controls
        self.view_options_layout = QHBoxLayout()
        
        self.bytes_per_row_label = QLabel("Bytes per row:")
        self.bytes_per_row_spin = QSpinBox()
        self.bytes_per_row_spin.setRange(8, 32)
        self.bytes_per_row_spin.setValue(16)
        self.bytes_per_row_spin.setSingleStep(4)
        
        self.data_type_label = QLabel("Data type:")
        self.data_type_combo = QComboBox()
        self.data_type_combo.addItems(["Hex", "Decimal", "ASCII", "Binary"])
        
        self.view_options_layout.addWidget(self.bytes_per_row_label)
        self.view_options_layout.addWidget(self.bytes_per_row_spin)
        self.view_options_layout.addWidget(self.data_type_label)
        self.view_options_layout.addWidget(self.data_type_combo, 1)  # Stretch factor
        
        self.memory_layout.addLayout(self.view_options_layout)
        
        # Memory hex editor
        self.hex_editor = QTableWidget()
        self.hex_editor.setColumnCount(17)  # Address + 16 bytes + ASCII
        self.hex_editor.verticalHeader().setVisible(False)
        self.hex_editor.setSelectionMode(QTableWidget.SingleSelection)
        self.hex_editor.setFont(QFont("Monospace", 10))
        
        # Set header for hex editor
        headers = ["Address"]
        for i in range(16):
            headers.append(f"{i:X}")
        headers.append("ASCII")
        self.hex_editor.setHorizontalHeaderLabels(headers)
        
        self.memory_layout.addWidget(self.hex_editor, 1)  # Stretch factor
        
        # Add widgets to the main splitter
        self.main_splitter.addWidget(self.regions_group)
        self.main_splitter.addWidget(self.memory_group)
        
        # Set splitter sizes
        self.main_splitter.setStretchFactor(0, 1)
        self.main_splitter.setStretchFactor(1, 2)
        
        # Status bar
        self.status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.info_label = QLabel("")
        self.status_layout.addWidget(self.status_label, 1)  # Stretch factor
        self.status_layout.addWidget(self.info_label)
        
        # Add widgets to the main layout
        self.main_layout.addWidget(self.main_splitter, 1)  # Stretch factor
        self.main_layout.addLayout(self.status_layout)
        
        # Connect signals
        self.action_refresh.triggered.connect(self.on_refresh)
        self.action_search.triggered.connect(self.on_search)
        self.action_dump.triggered.connect(self.on_dump_region)
        self.action_load.triggered.connect(self.on_load_dump)
        
        self.refresh_button.clicked.connect(self.on_refresh_process_list)
        self.attach_button.clicked.connect(self.on_attach_process)
        self.go_button.clicked.connect(self.on_go_to_address)
        self.prev_button.clicked.connect(self.on_prev_page)
        self.next_button.clicked.connect(self.on_next_page)
        
        self.regions_table.itemSelectionChanged.connect(self.on_region_selected)
        self.bytes_per_row_spin.valueChanged.connect(self.on_bytes_per_row_changed)
        self.data_type_combo.currentIndexChanged.connect(self.on_data_type_changed)
        
        # Set up context menus
        self.hex_editor.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hex_editor.customContextMenuRequested.connect(self.on_hex_context_menu)
        
        self.regions_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.regions_table.customContextMenuRequested.connect(self.on_regions_context_menu)
    
    def set_module(self, module):
        """
        Set the module instance associated with this widget.
        
        Args:
            module: Memory editor module instance
        """
        self.module = module
        
        # Fetch initial process list
        self.on_refresh_process_list()
    
    def on_refresh_process_list(self):
        """Refresh the list of processes."""
        if not self.module:
            return
            
        self.process_combo.clear()
        
        try:
            processes = self.module.get_process_list()
            
            for process in processes:
                pid = process.get("pid", 0)
                name = process.get("name", "Unknown")
                self.process_combo.addItem(f"{name} (PID: {pid})", userData=pid)
                
            self.status_label.setText(f"Found {len(processes)} processes")
            
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
    
    def on_attach_process(self):
        """Attach to the selected process."""
        if not self.module:
            return
            
        # Get PID from combo box or manual input
        pid = None
        
        manual_pid = self.pid_input.text().strip()
        if manual_pid:
            try:
                pid = int(manual_pid)
            except ValueError:
                self.status_label.setText("Error: Invalid PID")
                return
        else:
            pid = self.process_combo.currentData()
            
        if not pid:
            self.status_label.setText("Error: No process selected")
            return
            
        try:
            # Attach to process
            process_info = self.module.attach_process(pid)
            
            if process_info:
                self.current_process = process_info
                self.status_label.setText(f"Attached to process {process_info.get('name')} (PID: {process_info.get('pid')})")
                
                # Get memory regions
                self.memory_regions = self.module.get_memory_regions()
                self.update_regions_table()
                
                # Enable buttons
                self.action_dump.setEnabled(True)
                self.action_search.setEnabled(True)
                
            else:
                self.status_label.setText(f"Failed to attach to process with PID {pid}")
                
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
    
    def update_regions_table(self):
        """Update the memory regions table."""
        self.regions_table.setRowCount(0)
        
        for region in self.memory_regions:
            row = self.regions_table.rowCount()
            self.regions_table.insertRow(row)
            
            # Format address as hex
            start_addr = region.get("start_address", 0)
            size = region.get("size", 0)
            perms = region.get("permissions", "")
            name = region.get("name", "")
            region_type = region.get("type", "")
            
            self.regions_table.setItem(row, 0, QTableWidgetItem(f"0x{start_addr:X}"))
            self.regions_table.setItem(row, 1, QTableWidgetItem(f"{size:,}"))
            self.regions_table.setItem(row, 2, QTableWidgetItem(perms))
            self.regions_table.setItem(row, 3, QTableWidgetItem(name))
            self.regions_table.setItem(row, 4, QTableWidgetItem(region_type))
            
            # Color rows based on permissions
            if "w" in perms.lower():
                for col in range(5):
                    item = self.regions_table.item(row, col)
                    item.setBackground(QBrush(QColor(240, 255, 240)))  # Light green
    
    def on_region_selected(self):
        """Handle selection of a memory region."""
        selected = self.regions_table.selectedItems()
        
        if not selected:
            return
            
        row = selected[0].row()
        addr_item = self.regions_table.item(row, 0)
        
        if addr_item:
            # Strip the "0x" prefix if present
            addr_text = addr_item.text()
            addr_text = addr_text[2:] if addr_text.startswith("0x") else addr_text
            
            # Set address in the address input field
            self.address_input.setText(addr_text)
            
            # Go to the address
            self.on_go_to_address()
    
    def on_go_to_address(self):
        """Go to the specified memory address."""
        if not self.module or not self.current_process:
            return
            
        addr_text = self.address_input.text().strip()
        
        if not addr_text:
            return
            
        try:
            # Convert address to integer, supporting hex format
            if addr_text.startswith("0x"):
                address = int(addr_text, 16)
            else:
                address = int(addr_text, 16)  # Assume hex even without prefix
                
            # Read memory at this address
            bytes_per_row = self.bytes_per_row_spin.value()
            num_rows = 16  # Number of rows to display
            
            memory_data = self.module.read_memory(address, bytes_per_row * num_rows)
            
            self.display_memory(address, memory_data, bytes_per_row)
            
            # Update status
            self.status_label.setText(f"Viewing memory at address 0x{address:X}")
            
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
    
    def display_memory(self, start_address, data, bytes_per_row):
        """
        Display memory data in the hex editor.
        
        Args:
            start_address: Starting address of the memory region
            data: Bytes of memory data
            bytes_per_row: Number of bytes to display per row
        """
        self.hex_editor.setRowCount(0)
        
        # Adjust column count based on bytes per row
        self.hex_editor.setColumnCount(bytes_per_row + 2)  # Address + bytes + ASCII
        
        # Set headers
        headers = ["Address"]
        for i in range(bytes_per_row):
            headers.append(f"{i:X}")
        headers.append("ASCII")
        self.hex_editor.setHorizontalHeaderLabels(headers)
        
        # Calculate number of rows
        data_length = len(data)
        num_rows = (data_length + bytes_per_row - 1) // bytes_per_row
        
        for row in range(num_rows):
            self.hex_editor.insertRow(row)
            
            # Address column
            address = start_address + (row * bytes_per_row)
            address_item = QTableWidgetItem(f"0x{address:X}")
            address_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            address_item.setBackground(QBrush(QColor(240, 240, 255)))  # Light blue
            self.hex_editor.setItem(row, 0, address_item)
            
            # Hex values
            ascii_text = ""
            for col in range(bytes_per_row):
                byte_index = row * bytes_per_row + col
                
                if byte_index < data_length:
                    byte_value = data[byte_index]
                    
                    # Display based on selected data type
                    data_type = self.data_type_combo.currentText()
                    if data_type == "Hex":
                        display_value = f"{byte_value:02X}"
                    elif data_type == "Decimal":
                        display_value = f"{byte_value}"
                    elif data_type == "Binary":
                        display_value = f"{byte_value:08b}"
                    else:  # ASCII
                        display_value = f"{byte_value:02X}"
                    
                    item = QTableWidgetItem(display_value)
                    
                    # Add to ASCII representation
                    if 32 <= byte_value <= 126:  # Printable ASCII
                        ascii_text += chr(byte_value)
                    else:
                        ascii_text += "."
                else:
                    item = QTableWidgetItem("")
                    item.setFlags(Qt.NoItemFlags)
                    
                self.hex_editor.setItem(row, col + 1, item)
            
            # ASCII column
            ascii_item = QTableWidgetItem(ascii_text)
            ascii_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            ascii_item.setFont(QFont("Monospace", 10))
            self.hex_editor.setItem(row, bytes_per_row + 1, ascii_item)
        
        # Update current address for navigation
        self.current_address = start_address
        
        # Resize columns to contents
        self.hex_editor.resizeColumnsToContents()
    
    def on_prev_page(self):
        """Navigate to previous page of memory."""
        if not self.current_address:
            return
            
        bytes_per_row = self.bytes_per_row_spin.value()
        num_rows = 16  # Number of rows displayed
        prev_address = self.current_address - (bytes_per_row * num_rows)
        
        if prev_address < 0:
            prev_address = 0
            
        self.address_input.setText(f"0x{prev_address:X}")
        self.on_go_to_address()
    
    def on_next_page(self):
        """Navigate to next page of memory."""
        if not self.current_address:
            return
            
        bytes_per_row = self.bytes_per_row_spin.value()
        num_rows = 16  # Number of rows displayed
        next_address = self.current_address + (bytes_per_row * num_rows)
            
        self.address_input.setText(f"0x{next_address:X}")
        self.on_go_to_address()
    
    def on_bytes_per_row_changed(self, value):
        """Handle change in bytes per row setting."""
        # Refresh the display if we have data
        if hasattr(self, "current_address") and self.current_address is not None:
            self.on_go_to_address()
    
    def on_data_type_changed(self, index):
        """Handle change in data type display setting."""
        # Refresh the display if we have data
        if hasattr(self, "current_address") and self.current_address is not None:
            self.on_go_to_address()
    
    def on_refresh(self):
        """Refresh the current memory view."""
        if hasattr(self, "current_address") and self.current_address is not None:
            self.on_go_to_address()
    
    def on_search(self):
        """Open search dialog."""
        if not self.module or not self.current_process:
            return
            
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QRadioButton, QButtonGroup
            
        dialog = QDialog(self)
        dialog.setWindowTitle("Memory Search")
        dialog.resize(400, 200)
        
        layout = QVBoxLayout(dialog)
        
        # Search type selection
        type_layout = QHBoxLayout()
        type_label = QLabel("Search Type:")
        type_layout.addWidget(type_label)
        
        type_group = QButtonGroup(dialog)
        
        hex_radio = QRadioButton("Hex")
        text_radio = QRadioButton("Text")
        value_radio = QRadioButton("Value")
        
        type_group.addButton(hex_radio, 0)
        type_group.addButton(text_radio, 1)
        type_group.addButton(value_radio, 2)
        
        hex_radio.setChecked(True)
        
        type_layout.addWidget(hex_radio)
        type_layout.addWidget(text_radio)
        type_layout.addWidget(value_radio)
        
        layout.addLayout(type_layout)
        
        # Search value input
        value_layout = QHBoxLayout()
        value_label = QLabel("Search For:")
        value_input = QLineEdit()
        
        value_layout.addWidget(value_label)
        value_layout.addWidget(value_input)
        
        layout.addLayout(value_layout)
        
        # Options for value search
        value_options = QGroupBox("Value Options")
        value_options.setVisible(False)
        value_options_layout = QHBoxLayout(value_options)
        
        value_type_combo = QComboBox()
        value_type_combo.addItems(["Byte (1)", "Short (2)", "Int (4)", "Long (8)", "Float", "Double"])
        
        value_options_layout.addWidget(QLabel("Type:"))
        value_options_layout.addWidget(value_type_combo)
        
        layout.addWidget(value_options)
        
        # Connect signals to show/hide options
        def update_options():
            value_options.setVisible(value_radio.isChecked())
            
            if hex_radio.isChecked():
                value_input.setPlaceholderText("Enter hex bytes (e.g. 12 34 AB CD)")
            elif text_radio.isChecked():
                value_input.setPlaceholderText("Enter text to search for")
            else:
                value_input.setPlaceholderText("Enter numeric value")
                
        hex_radio.toggled.connect(update_options)
        text_radio.toggled.connect(update_options)
        value_radio.toggled.connect(update_options)
        
        update_options()  # Initial setup
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        
        layout.addWidget(button_box)
        
        # Execute dialog
        if dialog.exec_() == QDialog.Accepted:
            search_type = type_group.checkedId()
            search_value = value_input.text().strip()
            
            if not search_value:
                self.status_label.setText("Error: No search value entered")
                return
                
            try:
                # Convert input based on type
                if search_type == 0:  # Hex
                    # Convert space-separated hex values to bytes
                    search_bytes = bytes.fromhex(search_value.replace(" ", ""))
                elif search_type == 1:  # Text
                    search_bytes = search_value.encode("utf-8")
                else:  # Value
                    # This would need proper implementation based on selected value type
                    # For now, just convert text to bytes
                    search_bytes = search_value.encode("utf-8")
                
                # Perform search
                results = self.module.search_memory(search_bytes)
                
                if results:
                    # Show results
                    self.show_search_results(results)
                else:
                    self.status_label.setText("No matches found")
                    
            except Exception as e:
                self.status_label.setText(f"Search error: {str(e)}")
    
    def show_search_results(self, results):
        """
        Show search results in a dialog.
        
        Args:
            results: List of addresses where matches were found
        """
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QListWidget, QListWidgetItem, QDialogButtonBox
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Search Results")
        dialog.resize(300, 400)
        
        layout = QVBoxLayout(dialog)
        
        result_list = QListWidget()
        
        for address in results:
            item = QListWidgetItem(f"0x{address:X}")
            item.setData(Qt.UserRole, address)
            result_list.addItem(item)
        
        layout.addWidget(QLabel(f"Found {len(results)} matches:"))
        layout.addWidget(result_list)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(dialog.accept)
        
        layout.addWidget(button_box)
        
        # Connect double-click to go to address
        result_list.itemDoubleClicked.connect(lambda item: self.go_to_result(item.data(Qt.UserRole)))
        
        # Update status
        self.status_label.setText(f"Found {len(results)} matches")
        
        dialog.exec_()
    
    def go_to_result(self, address):
        """
        Go to a search result address.
        
        Args:
            address: Memory address to view
        """
        self.address_input.setText(f"0x{address:X}")
        self.on_go_to_address()
    
    def on_dump_region(self):
        """Dump the selected memory region to a file."""
        if not self.module or not self.current_process:
            return
            
        selected = self.regions_table.selectedItems()
        
        if not selected:
            self.status_label.setText("Error: No memory region selected")
            return
            
        row = selected[0].row()
        
        try:
            # Get region info
            addr_text = self.regions_table.item(row, 0).text()
            size_text = self.regions_table.item(row, 1).text()
            
            # Convert address to int, removing prefix if needed
            addr_text = addr_text[2:] if addr_text.startswith("0x") else addr_text
            address = int(addr_text, 16)
            
            # Convert size to int, removing commas if needed
            size = int(size_text.replace(",", ""))
            
            # Confirm before dumping large regions
            if size > 10 * 1024 * 1024:  # 10 MB
                result = QMessageBox.question(
                    self, 
                    "Confirm Dump",
                    f"The selected region is {size / (1024*1024):.2f} MB. Continue?",
                    QMessageBox.Yes | QMessageBox.No
                )
                
                if result != QMessageBox.Yes:
                    return
            
            # Get save path
            from PyQt5.QtWidgets import QFileDialog
            
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Memory Dump",
                f"memory_dump_{address:X}.bin",
                "Binary Files (*.bin);;All Files (*)"
            )
            
            if not file_path:
                return
                
            # Dump memory to file
            success = self.module.dump_memory(address, size, file_path)
            
            if success:
                self.status_label.setText(f"Memory dumped to {file_path}")
            else:
                self.status_label.setText("Error dumping memory")
                
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
    
    def on_load_dump(self):
        """Load a memory dump file."""
        if not self.module or not self.current_process:
            return
            
        # Get load file path
        from PyQt5.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Memory Dump",
            "",
            "Binary Files (*.bin);;All Files (*)"
        )
        
        if not file_path:
            return
            
        try:
            # Get address to load at
            address_text, ok = QInputDialog.getText(
                self, 
                "Load Address",
                "Enter address to load dump at (hex):",
                QLineEdit.Normal,
                "0x0"
            )
            
            if not ok or not address_text:
                return
                
            # Convert address to int
            address_text = address_text[2:] if address_text.startswith("0x") else address_text
            address = int(address_text, 16)
            
            # Load dump
            success, size = self.module.load_dump(file_path, address)
            
            if success:
                self.status_label.setText(f"Loaded {size} bytes at address 0x{address:X}")
                # View the loaded memory
                self.address_input.setText(f"0x{address:X}")
                self.on_go_to_address()
            else:
                self.status_label.setText("Error loading memory dump")
                
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
    
    def on_hex_context_menu(self, pos):
        """Show context menu for hex editor."""
        if not self.hex_editor.selectedItems():
            return
            
        item = self.hex_editor.itemAt(pos)
        if not item:
            return
            
        menu = QMenu(self)
        
        # Add menu actions
        copy_action = menu.addAction("Copy Value")
        edit_action = menu.addAction("Edit Value")
        
        # Get action result
        action = menu.exec_(self.hex_editor.mapToGlobal(pos))
        
        if action == copy_action:
            from PyQt5.QtWidgets import QApplication
            QApplication.clipboard().setText(item.text())
            
        elif action == edit_action:
            row = item.row()
            col = item.column()
            
            # Don't allow editing address or ASCII columns
            if col == 0 or col == self.hex_editor.columnCount() - 1:
                return
                
            from PyQt5.QtWidgets import QInputDialog
            
            current_value = item.text()
            new_value, ok = QInputDialog.getText(
                self,
                "Edit Value",
                "Enter new value:",
                QLineEdit.Normal,
                current_value
            )
            
            if ok and new_value != current_value:
                # Calculate address of this byte
                base_address = self.current_address
                byte_offset = (row * (self.hex_editor.columnCount() - 2)) + (col - 1)
                byte_address = base_address + byte_offset
                
                # Convert input based on current display type
                data_type = self.data_type_combo.currentText()
                try:
                    if data_type == "Hex":
                        byte_value = int(new_value, 16)
                    elif data_type == "Decimal":
                        byte_value = int(new_value)
                    elif data_type == "Binary":
                        byte_value = int(new_value, 2)
                    else:  # ASCII
                        byte_value = ord(new_value[0]) if new_value else 0
                        
                    # Ensure value is in byte range
                    byte_value = byte_value & 0xFF
                    
                    # Write to memory
                    if self.module:
                        success = self.module.write_memory(byte_address, bytes([byte_value]))
                        
                        if success:
                            # Update the display
                            item.setText(f"{byte_value:02X}" if data_type == "Hex" else new_value)
                            
                            # Update ASCII column
                            ascii_item = self.hex_editor.item(row, self.hex_editor.columnCount() - 1)
                            if ascii_item:
                                ascii_text = ascii_item.text()
                                new_char = chr(byte_value) if 32 <= byte_value <= 126 else "."
                                position = col - 1
                                if position < len(ascii_text):
                                    ascii_text = ascii_text[:position] + new_char + ascii_text[position+1:]
                                    ascii_item.setText(ascii_text)
                        else:
                            self.status_label.setText(f"Failed to write to address 0x{byte_address:X}")
                            
                except Exception as e:
                    self.status_label.setText(f"Error: {str(e)}")
    
    def on_regions_context_menu(self, pos):
        """Show context menu for regions table."""
        if not self.regions_table.selectedItems():
            return
            
        item = self.regions_table.itemAt(pos)
        if not item:
            return
            
        menu = QMenu(self)
        
        # Add menu actions
        view_action = menu.addAction("View in Hex Editor")
        dump_action = menu.addAction("Dump to File")
        
        # Get action result
        action = menu.exec_(self.regions_table.mapToGlobal(pos))
        
        if action == view_action:
            self.on_region_selected()
            
        elif action == dump_action:
            self.on_dump_region()