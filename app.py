import sys
import os
import importlib
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication, QWidget, QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QTextEdit, QLabel, QGroupBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QSpinBox, QAbstractItemView,
    QMessageBox, QRadioButton, QLineEdit, QFormLayout, QComboBox
)
from PySide6.QtCore import Qt, QEvent

# Import your existing processing scripts (must be in same directory)
# pcap_to_csv.py must define process_pcap(pcap_file, output_dir='output') and module-level flags we will set
import pcap_to_csv
import normalize_windows
import glob

# Helper for pretty logging to console
def log_to_console(log_widget, msg):
    log_widget.append(msg)
    # keep GUI responsive
    QApplication.processEvents()

class PcapRow:
    def __init__(self, name, path, add_time=False, hrs=0, mins=0, secs=0):
        self.name = name
        self.path = path
        self.add_time = add_time
        self.hrs = hrs
        self.mins = mins
        self.secs = secs

class CsvRow:
    def __init__(self, name, path, first_window=0, last_window=0):
        self.name = name
        self.path = path
        self.first_window = first_window
        self.last_window = last_window

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PCAP Processing and Normalization Tool")
        self.resize(900, 700)

        # Central widget and main layout
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # Tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Tab 1: PCAP -> CSV
        self.tab_pcap = QWidget()
        self._build_pcap_tab()
        self.tabs.addTab(self.tab_pcap, "PCAP → CSV")

        # Tab 2: Normalize Windows
        self.tab_norm = QWidget()
        self._build_normalize_tab()
        self.tabs.addTab(self.tab_norm, "Normalize Windows")

        # Bottom: Run/Process buttons area
        bottom_box = QGroupBox("Run")
        bottom_layout = QHBoxLayout()
        bottom_box.setLayout(bottom_layout)

        self.process_button = QPushButton("Process PCAPs")
        self.process_button.clicked.connect(self.on_process)
        bottom_layout.addWidget(self.process_button)

        self.normalize_button = QPushButton("Normalize CSVs")
        self.normalize_button.clicked.connect(self.on_normalize)
        bottom_layout.addWidget(self.normalize_button)

        self.run_button = QPushButton("Run All")
        self.run_button.clicked.connect(self.on_process)
        bottom_layout.addWidget(self.run_button)

        # Spacer
        bottom_layout.addStretch()

        # Log console
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFixedHeight(180)

        main_layout.addWidget(bottom_box)
        main_layout.addWidget(QLabel("Log:"))
        main_layout.addWidget(self.log)

        # Internal file model
        self.file_rows = []  # list of PcapRow objects
        self.selected_pcap_rows = set()  # set of selected rows

        self.csv_file_rows = []  # list of CsvRow objects
        self.selected_csv_rows = set()  # set of selected rows

    def eventFilter(self, obj, event):
        if obj == self.csv_table.viewport() and event.type() == QEvent.Resize:
            self._update_csv_placeholder()
        return super().eventFilter(obj, event)

    # ----------------------------
    # Build PCAP tab UI
    # ----------------------------
    def _build_pcap_tab(self):
        layout = QVBoxLayout()
        self.tab_pcap.setLayout(layout)

        group = QGroupBox("PCAP Input Files")
        group_layout = QVBoxLayout()
        group.setLayout(group_layout)

        # File table
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["Select", "Name", "File Path", "Add Time?", "Hours", "Minutes", "Seconds", "Remove"])
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        # self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        group_layout.addWidget(self.table)

        # Buttons to add/remove files
        btn_layout = QHBoxLayout()
        self.add_files_btn = QPushButton("Add PCAP/PCAPNG File(s)")
        self.add_files_btn.clicked.connect(self.add_files_pcap)
        self.add_from_folder_btn = QPushButton("Add from Folder")
        self.add_from_folder_btn.clicked.connect(self.add_files_from_folder)
        self.remove_selected_btn = QPushButton("Remove Selected")
        self.remove_selected_btn.clicked.connect(self.remove_selected_files)
        btn_layout.addWidget(self.add_files_btn)
        btn_layout.addWidget(self.add_from_folder_btn)
        btn_layout.addWidget(self.remove_selected_btn)
        btn_layout.addStretch()

        group_layout.addLayout(btn_layout)

        # Output folder selection
        out_group = QGroupBox("Output Directory")
        out_layout = QHBoxLayout()
        out_group.setLayout(out_layout)
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setPlaceholderText("Select output directory for CSV files")
        self.output_dir_btn = QPushButton("Browse")
        self.output_dir_btn.clicked.connect(self.choose_output_dir)
        out_layout.addWidget(self.output_dir_edit)
        out_layout.addWidget(self.output_dir_btn)

        layout.addWidget(group)
        layout.addWidget(out_group)

    def add_files_from_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder containing PCAP/PCAPNG files", os.getcwd())
        if folder:
            for entry in os.scandir(folder):
                if entry.is_file() and entry.name.lower().endswith(('.pcap', '.pcapng')):
                    f = entry.path
                    if not any(r.path == f for r in self.file_rows):
                        # Default no add-time
                        name = os.path.basename(f)
                        row = PcapRow(name=name, path=f, add_time=False, hrs=0, mins=0, secs=0)
                        self.file_rows.append(row)
                        self._append_row_to_table(row)

    def add_files_pcap(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select PCAP/PCAPNG files",
                                                os.getcwd(),
                                                "PCAP Files (*.pcap *.pcapng);;All Files (*)")
        for f in files:
            if not any(r.path == f for r in self.file_rows):
                # Default no add-time
                name = os.path.basename(f)
                row = PcapRow(name=name, path=f, add_time=False, hrs=0, mins=0, secs=0)
                self.file_rows.append(row)
                self._append_row_to_table(row)

    def _append_row_to_table(self, pcap_row):
        row_idx = self.table.rowCount()
        self.table.insertRow(row_idx)

        # Add Selection checkbox
        sel = QCheckBox()
        sel.setChecked(False)
        sel.stateChanged.connect(self._on_select_toggled)
        self.table.setCellWidget(row_idx, 0, sel)

        # File name
        item = QTableWidgetItem(pcap_row.name)
        self.table.setItem(row_idx, 1, item)

        # File path
        item2 = QTableWidgetItem(pcap_row.path)
        self.table.setItem(row_idx, 2, item2)

        # Add Time checkbox
        chk = QCheckBox()
        chk.setChecked(pcap_row.add_time)
        chk.stateChanged.connect(self._on_add_time_toggled)
        self.table.setCellWidget(row_idx, 3, chk)

        # Hours spinbox
        hrs = QSpinBox()
        hrs.setRange(0, 23)
        hrs.setValue(pcap_row.hrs)
        hrs.setEnabled(False)
        self.table.setCellWidget(row_idx, 4, hrs)

        # Minutes spinbox
        mins = QSpinBox()
        mins.setRange(0, 59)
        mins.setValue(pcap_row.mins)
        mins.setEnabled(False)
        self.table.setCellWidget(row_idx, 5, mins)

        # Seconds spinbox
        secs = QSpinBox()
        secs.setRange(0, 59)
        secs.setValue(pcap_row.secs)
        secs.setEnabled(False)
        self.table.setCellWidget(row_idx, 6, secs)

        # Remove button
        rem = QPushButton("Remove")
        rem.clicked.connect(self._remove_row)
        self.table.setCellWidget(row_idx, 7, rem)

    def _on_add_time_toggled(self):
        # Safely fetch widgets because rows may shift when removing
        chk = self.sender()
        if not chk:
            log_to_console(self.log, "ERROR: Could not identify Add Time checkbox toggled.")
            return

        # Find which row contains this checkbox
        for row in range(self.table.rowCount()):
            if self.table.cellWidget(row, 3) is chk:
                hrs  = self.table.cellWidget(row, 4)
                mins = self.table.cellWidget(row, 5)
                secs = self.table.cellWidget(row, 6)

                enabled = chk.isChecked()
                if hrs:  hrs.setEnabled(enabled)
                if mins: mins.setEnabled(enabled)
                if secs: secs.setEnabled(enabled)
                break

    def remove_selected_files(self):
        # collect rows to remove
        rows_to_remove = self.selected_pcap_rows.copy()
        self.selected_pcap_rows.clear()
        if not rows_to_remove:
            log_to_console(self.log, "Could not remove rows. No rows selected to be removed.")
            return
        for row in sorted(rows_to_remove, reverse=True):
            self.table.removeRow(row)
            # remove from file_rows as well
            if row < len(self.file_rows):
                self.file_rows.pop(row)

    def _remove_row(self):
        # remove single row and model
        button = self.sender()
        if not button:
            log_to_console(self.log, "ERROR: Could not identify Remove button clicked.")
            return
        
        # Find which row contains this button
        for row in range(self.table.rowCount()):
            if self.table.cellWidget(row, 7) == button:
                self.table.removeRow(row)
                if row < len(self.file_rows):
                    self.file_rows.pop(row)
                break

    def _on_select_toggled(self):
         # Safely fetch widgets because rows may shift when removing
        sel = self.sender()
        if not sel:
            log_to_console(self.log, "ERROR: Could not identify Select checkbox toggled.")
            return

        # Find which row contains this checkbox
        for row in range(self.table.rowCount()):
            if self.table.cellWidget(row, 0) is sel:
                selected = sel.isChecked()
                if selected:
                    self.selected_pcap_rows.add(row)
                else:
                    self.selected_pcap_rows.discard(row)
                break

    def choose_output_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select output folder", os.getcwd())
        if d:
            self.output_dir_edit.setText(d)

    # ----------------------------
    # Build Normalize tab UI
    # ----------------------------
    def _build_normalize_tab(self):
        layout = QVBoxLayout()
        self.tab_norm.setLayout(layout)

        # Top input selection
        norm_input_group = QGroupBox("Normalization Input Files")
        norm_input_layout = QVBoxLayout()
        norm_input_group.setLayout(norm_input_layout)

        # CSV File table
        self.csv_table = QTableWidget(0, 6)
        self.csv_table.setHorizontalHeaderLabels(["Select", "Name", "File Path", "Start Window", "End Window", "Remove"])
        self.csv_table.horizontalHeader().setStretchLastSection(False)
        self.csv_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.csv_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.csv_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.csv_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        norm_input_layout.addWidget(self.csv_table)

        # Placeholder label
        self.csv_placeholder = QLabel(
            "Leave blank to use PCAP output if running both steps",
            self.csv_table.viewport()
        )
        self.csv_placeholder.setAlignment(Qt.AlignCenter)
        self.csv_placeholder.setStyleSheet("""
            QLabel {
                color: #888;
                font-style: italic;
                font-size: 12px;
            }
        """)
        self.csv_placeholder.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.csv_placeholder.show()

        def update_csv_placeholder():
            self.csv_placeholder.setVisible(self.csv_table.rowCount() == 0)
            self.csv_placeholder.resize(self.csv_table.viewport().size())

        self._update_csv_placeholder = update_csv_placeholder
        self.csv_table.viewport().installEventFilter(self)
        self._update_csv_placeholder()

        # Buttons to add/remove files
        csv_btn_layout = QHBoxLayout()
        self.add_files_btn_csv = QPushButton("Add CSV File(s)")
        self.add_files_btn_csv.clicked.connect(self.add_files_csv)
        self.add_from_folder_btn_csv = QPushButton("Add from Folder")
        self.add_from_folder_btn_csv.clicked.connect(self.add_files_from_folder_csv)
        self.remove_selected_btn_csv = QPushButton("Remove Selected")
        self.remove_selected_btn_csv.clicked.connect(self.remove_selected_files_csv)
        csv_btn_layout.addWidget(self.add_files_btn_csv)
        csv_btn_layout.addWidget(self.add_from_folder_btn_csv)
        csv_btn_layout.addWidget(self.remove_selected_btn_csv)
        csv_btn_layout.addStretch()

        norm_input_layout.addLayout(csv_btn_layout)

        # Options Tab: Normalization options
        top_group = QGroupBox("Normalization Options")
        top_layout = QVBoxLayout()
        top_group.setLayout(top_layout)

        # Trim & Align option
        trim_align_group = QGroupBox("Trim + Align Options")
        trim_align_layout = QHBoxLayout()
        trim_align_group.setLayout(trim_align_layout)

        self.trim_align_chk = QCheckBox("Enable Trim + Align")
        self.trim_align_chk.setChecked(True)
        trim_align_layout.addWidget(self.trim_align_chk)
        trim_align_layout.addStretch()

        top_layout.addWidget(trim_align_group)

        # Starting window choice
        start_choice_group = QGroupBox("Starting Window Adjustment")
        sc_layout = QHBoxLayout()
        start_choice_group.setLayout(sc_layout)

        self.keep_current_radio = QRadioButton("Keep current window numbers")
        self.keep_current_radio.setChecked(True)
        self.set_new_radio = QRadioButton("Set new starting window number")
        self.start_window_spin = QSpinBox()
        self.start_window_spin.setRange(0, 10_000_000)
        self.start_window_spin.setEnabled(False)

        self.set_new_radio.toggled.connect(lambda val: self.start_window_spin.setEnabled(val))

        sc_layout.addWidget(self.keep_current_radio)
        sc_layout.addWidget(self.set_new_radio)
        sc_layout.addWidget(QLabel("Start Window:"))
        sc_layout.addWidget(self.start_window_spin)
        sc_layout.addStretch()

        top_layout.addWidget(start_choice_group)

        # Output folder override
        out_group = QGroupBox("Normalization Output Directory")
        out_layout = QHBoxLayout()
        out_group.setLayout(out_layout)
        self.norm_output_edit = QLineEdit()
        self.norm_output_edit.setPlaceholderText("Leave blank to use PCAP output directory if running both steps (WILL OVERWRITE PRE-NORMALIZED FILES)")
        self.norm_output_btn = QPushButton("Browse")
        self.norm_output_btn.clicked.connect(self.choose_norm_output_dir)
        out_layout.addWidget(self.norm_output_edit)
        out_layout.addWidget(self.norm_output_btn)

        layout.addWidget(norm_input_group)
        layout.addWidget(top_group)
        layout.addWidget(out_group)

    def add_files_from_folder_csv(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder containing CSV files", os.getcwd())
        if folder:
            for entry in os.scandir(folder):
                if entry.is_file() and entry.name.lower().endswith(('.csv')):
                    f = entry.path
                    if not any(r.path == f for r in self.csv_file_rows):
                        self._update_csv_placeholder()
                        # Default no add-time
                        name = os.path.basename(f)
                        ext = normalize_windows.get_window_extremes(f)
                        first_win = ext['min'] if ext['min'] is not None else 0
                        last_win = ext['max'] if ext['max'] is not None else 0

                        row = CsvRow(name=name, path=f, first_window=first_win, last_window=last_win)
                        self.csv_file_rows.append(row)
                        self._append_row_to_table_csv(row)

    def add_files_csv(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select CSV files",
                                                os.getcwd(),
                                                "CSV Files (*.csv);;All Files (*)")
        for f in files:
            if not any(r.path == f for r in self.csv_file_rows):
                self._update_csv_placeholder()
                # Default no add-time
                name = os.path.basename(f)
                ext = normalize_windows.get_window_extremes(f)
                first_win = ext['min'] if ext['min'] is not None else 0
                last_win = ext['max'] if ext['max'] is not None else 0

                row = CsvRow(name=name, path=f, first_window=first_win, last_window=last_win)
                self.csv_file_rows.append(row)
                self._append_row_to_table_csv(row)

    def _append_row_to_table_csv(self, csv_row):
        row_idx = self.csv_table.rowCount()
        self.csv_table.insertRow(row_idx)

        # Add Selection checkbox
        sel = QCheckBox()
        sel.setChecked(False)
        sel.stateChanged.connect(self._on_select_toggled_csv)
        self.csv_table.setCellWidget(row_idx, 0, sel)

        # File name
        item = QTableWidgetItem(csv_row.name)
        self.csv_table.setItem(row_idx, 1, item)

        # File path
        item2 = QTableWidgetItem(csv_row.path)
        self.csv_table.setItem(row_idx, 2, item2)

        # Start Window
        item3 = QTableWidgetItem(str(csv_row.first_window))
        self.csv_table.setItem(row_idx, 3, item3)

        # End Window
        item4 = QTableWidgetItem(str(csv_row.last_window))
        self.csv_table.setItem(row_idx, 4, item4)

        # Remove button
        rem = QPushButton("Remove")
        rem.clicked.connect(self._remove_row_csv)
        self.csv_table.setCellWidget(row_idx, 5, rem)

    def remove_selected_files_csv(self):
        # collect rows to remove
        rows_to_remove = self.selected_csv_rows.copy()
        self.selected_csv_rows.clear()
        if not rows_to_remove:
            log_to_console(self.log, "Could not remove rows. No rows selected to be removed.")
            return
        self._update_csv_placeholder()
        for row in sorted(rows_to_remove, reverse=True):
            self.csv_table.removeRow(row)
            # remove from file_rows as well
            if row < len(self.csv_file_rows):
                self.csv_file_rows.pop(row)

    def _remove_row_csv(self):
        # remove single row and model
        button = self.sender()
        if not button:
            log_to_console(self.log, "ERROR: Could not identify Remove button clicked.")
            return
        self._update_csv_placeholder()
        # Find which row contains this button
        for row in range(self.csv_table.rowCount()):
            if self.csv_table.cellWidget(row, 5) == button:
                self.csv_table.removeRow(row)
                if row < len(self.csv_file_rows):
                    self.csv_file_rows.pop(row)
                break

    def _on_select_toggled_csv(self):
         # Safely fetch widgets because rows may shift when removing
        sel = self.sender()
        if not sel:
            log_to_console(self.log, "ERROR: Could not identify Select checkbox toggled.")
            return

        # Find which row contains this checkbox
        for row in range(self.csv_table.rowCount()):
            if self.csv_table.cellWidget(row, 0) is sel:
                selected = sel.isChecked()
                if selected:
                    self.selected_csv_rows.add(row)
                else:
                    self.selected_csv_rows.discard(row)
                break

    def choose_norm_output_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select normalization output folder", os.getcwd())
        if d:
            self.norm_output_edit.setText(d)

    # ----------------------------
    # Process workflow (PCAP processing -> normalization)
    # ----------------------------    
    def on_process(self):
        # Clear log and start
        self.log.clear()
        log_to_console(self.log, "Starting process pcap files...")

        # Validate
        if self.table.rowCount() == 0:
            QMessageBox.warning(self, "No files", "Please add at least one pcap file to process.")
            return

        output_dir = self.output_dir_edit.text().strip()
        if not output_dir:
            QMessageBox.warning(self, "No output folder", "Please select an output folder for CSV files.")
            return

        # Ensure output dir exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Read table rows into a local model to avoid synchronization issues when modifying the table
        files_to_process = []
        for r in range(self.table.rowCount()):
            file_path = self.table.item(r, 2).text() if self.table.item(r, 2) else ""
            add_time_widget = self.table.cellWidget(r, 3)
            hrs_widget = self.table.cellWidget(r, 4)
            mins_widget = self.table.cellWidget(r, 5)
            secs_widget = self.table.cellWidget(r, 6)
            add_time = bool(add_time_widget.isChecked()) if add_time_widget else False
            hrs = int(hrs_widget.value()) if hrs_widget else 0
            mins = int(mins_widget.value()) if mins_widget else 0
            secs = int(secs_widget.value()) if secs_widget else 0
            files_to_process.append(PcapRow(name="", path=file_path, add_time=add_time, hrs=hrs, mins=mins, secs=secs))

        # --- Run PCAP -> CSV for each file, adjusting pcap_to_csv module globals as needed ---
        for idx, fr in enumerate(files_to_process):
            log_to_console(self.log, f"[{idx+1}/{len(files_to_process)}] Processing: {fr.path}")
            try:
                # Set module-level flags on pcap_to_csv
                pcap_to_csv.bAddTime = bool(fr.add_time)
                pcap_to_csv.AddHours = int(fr.hrs)
                pcap_to_csv.AddMinutes = int(fr.mins)
                pcap_to_csv.AddSeconds = int(fr.secs)
                # Call the existing processing function
                pcap_to_csv.process_pcap(fr.path, output_dir)
                log_to_console(self.log, f"Finished processing: {fr.path}")
            except Exception as e:
                log_to_console(self.log, f"Error processing {fr.path}: {e}")

        # Finished
        log_to_console(self.log, "All requested processing steps completed.")
        QMessageBox.information(self, "Complete", "Processing complete. See log for details.")

    def on_normalize(self):
        """
        Along with below functionality to include file inputs, also allow for no input files and use output dir from PCAP tab IF running both steps.
        Could also instead just add a part of on_run_all to add csv files from output dir of PCAP step and leave this one as-is.
        """

        # Clear log and start
        self.log.clear()
        log_to_console(self.log, "Starting normalize csv...")

        # Validate
        if self.csv_table.rowCount() == 0:
            QMessageBox.warning(self, "No files", "Please add at least one csv file to process.")
            return

        norm_output_dir = self.norm_output_edit.text().strip()
        if not norm_output_dir:
            QMessageBox.warning(self, "No output folder", "Please select an output folder for normalized CSV files.")
            return

        # Ensure output dir exists
        Path(norm_output_dir).mkdir(parents=True, exist_ok=True)

        # Read table rows into a local model to avoid synchronization issues when modifying the table
        files_to_process = []
        for r in range(self.csv_table.rowCount()):
            try:
                file_path = self.csv_table.item(r, 2).text() if self.csv_table.item(r, 2) else ""
                if not file_path:
                    continue
                min_win = int(self.csv_table.item(r, 3).text()) if self.csv_table.item(r, 3) else None
                max_win = int(self.csv_table.item(r, 4).text()) if self.csv_table.item(r, 4) else None
                files_to_process.append(CsvRow(name="", path=file_path, first_window=min_win, last_window=max_win))
            except Exception as e:
                log_to_console(self.log, f"Error reading CSV row {r}: {e}")
                QMessageBox.warning(self, "Normalize Error", f"Error normalizing window numbers: {e}")
                return

        csv_files = [fr.path for fr in files_to_process]
        mins = [fr.first_window for fr in files_to_process]
        maxs = [fr.last_window for fr in files_to_process]

        # If Trim+Align is enabled, compute extremes and proposed trim range
        if self.trim_align_chk.isChecked():
            log_to_console(self.log, "Trim+Align enabled; computing window extremes...")
            if not mins or not maxs:
                log_to_console(self.log, "No valid CSV files found for trim+align.")
                QMessageBox.warning(self, "No valid CSVs", "No CSVs with Window_Num found for trimming/alignment.")
                return
            else:
                global_largest_start = max(mins)
                global_smallest_end = min(maxs)
                # per your spec: trim_start = largest_start + 1 ; trim_end = smallest_end - 1
                trim_start = int(global_largest_start) + 1
                trim_end = int(global_smallest_end) - 1

                if trim_start > trim_end:   
                    log_to_console(self.log, f"Computed trim range invalid: start {trim_start} > end {trim_end}")
                    QMessageBox.warning(self, "Invalid Trim Range", "Computed trim range is invalid (start > end). Cannot proceed.")
                    return

                log_to_console(self.log, f"Proposed trim range: {trim_start} to {trim_end}")

                # Compute how many windows each file would lose
                files_will_lose = []
                for fr in files_to_process:
                    cur_min = fr.first_window
                    cur_max = fr.last_window
                    if cur_min is None or cur_max is None:
                        # file has no window_num values
                        lost = 0
                    else:
                        # rows removed = count of rows with Window_Num < trim_start or > trim_end
                        # For preview we estimate by numeric ranges
                        left_lost = max(0, trim_start - cur_min)
                        right_lost = max(0, cur_max - trim_end)
                        lost = left_lost + right_lost
                    files_will_lose.append((os.path.basename(fr.path), lost))

                # If any file would lose more than threshold, show a warning dialog allowing continue/cancel
                threshold = 25
                heavy = [(fn, lost) for fn, lost in files_will_lose if lost > threshold]
                if heavy:
                    text = "Warning: The following files would lose more than 25 windows after Trim+Align:\n\n"
                    for fn, lost in heavy:
                        text += f"  {fn}: {lost} windows would be removed\n"
                    text += "\nContinue with Trim+Align or cancel normalization?"
                    reply = QMessageBox.question(self, "Trim+Align Warning", text,
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                                 QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.No:
                        log_to_console(self.log, "User cancelled normalization due to Trim+Align warning.")
                        QMessageBox.information(self, "Cancelled", "Normalization was cancelled by the user.")
                        return

                # Execute trim_and_align
                try:
                    log_to_console(self.log, f"Running trim_and_align...")
                    normalize_windows.trim_and_align_files(csv_files, norm_output_dir, trim_start, trim_end)
                    log_to_console(self.log, "Trim+Align completed.")
                except Exception as e:
                    log_to_console(self.log, f"Error during trim_and_align: {e}")
                    QMessageBox.warning(self, "Trim Error", f"Error during Trim+Align: {e}")
                    return
        else:
            log_to_console(self.log, "Trim+Align disabled; skipping.")

        # Next: If user requested a new starting window number, call normalize_window_numbers
        if self.set_new_radio.isChecked():
            new_start = int(self.start_window_spin.value())
            try:
                log_to_console(self.log, f"Normalizing window numbers to start from {new_start} ...")
                normalize_windows.normalize_window_numbers_files(csv_files, new_start, norm_output_dir)
                log_to_console(self.log, "Window number normalization completed.")
            except Exception as e:
                log_to_console(self.log, f"Error normalizing window numbers: {e}")
                QMessageBox.warning(self, "Normalize Error", f"Error normalizing window numbers: {e}")
                return
        else:
            log_to_console(self.log, "Keeping current window numbering.")

        # Finished
        log_to_console(self.log, "All requested normalization steps completed.")
        QMessageBox.information(self, "Complete", "Normalization complete. See log for details.")
        return

    def on_run_all(self):
        # Process PCAPs
        self.on_process()

        # Check if Normalize inputs and outputs were set to use PCAP output
        if self.csv_table.rowCount() == 0:
            log_to_console(self.log, "No CSV files specified for normalization; using PCAP output directory.")
            pcap_output_dir = self.output_dir_edit.text().strip()
            if not pcap_output_dir:
                log_to_console(self.log, "No PCAP output directory found; cannot proceed with normalization.")
                QMessageBox.warning(self, "No Normalize Input", "No PCAP output directory found; cannot proceed with normalization.")
                return
            # Populate CSV table with all CSVs from pcap_output_dir
            csv_files = glob.glob(os.path.join(pcap_output_dir, "*.csv"))
            if not csv_files:
                log_to_console(self.log, "No CSV files found in PCAP output directory; cannot proceed with normalization.")
                QMessageBox.warning(self, "No CSVs", "No CSV files found in PCAP output directory; cannot proceed with normalization.")
                return
            self.add_files_from_folder_csv(pcap_output_dir)
        if not self.norm_output_edit.text().strip():
            log_to_console(self.log, "No normalization output directory specified; using PCAP output directory.")
            pcap_output_dir = self.output_dir_edit.text().strip()
            if not pcap_output_dir:
                log_to_console(self.log, "No PCAP output directory found; cannot proceed with normalization.")
                QMessageBox.warning(self, "No Normalize Output", "No PCAP output directory found; cannot proceed with normalization.")
                return
            self.norm_output_edit.setText(pcap_output_dir)

        # Normalize CSVs
        self.on_normalize()

        # Finished
        log_to_console(self.log, "All requested processing and normalization steps completed.")
        QMessageBox.information(self, "Complete", "Processing and normalization complete. See log for details.")

        return

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
