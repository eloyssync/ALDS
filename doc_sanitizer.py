import sys
import os
import re
import io
import time
import zipfile
import secrets
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, pyqtSlot, QUrl, QSize
)
from PyQt6.QtGui import (
    QIcon, QFont, QColor, QDragEnterEvent, QDropEvent,
    QDesktopServices, QTextCursor
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QCheckBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QTextEdit, QProgressBar, QFileDialog, QFrame,
    QSplitter, QGroupBox, QMessageBox, QAbstractItemView
)

try:
    import pypdf
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import NameObject, ArrayObject, DictionaryObject, NullObject
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

SUPPORTED_EXTENSIONS = {'.pdf', '.docx', '.xlsx', '.pptx'}

DARK_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0f1117;
    color: #e2e8f0;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}

QGroupBox {
    border: 1px solid #2d3748;
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 14px;
    font-weight: bold;
    color: #94a3b8;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 4px;
}

QTableWidget {
    background-color: #161922;
    border: 1px solid #2d3748;
    border-radius: 8px;
    gridline-color: #1f2430;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

QHeaderView::section {
    background-color: #1a1e29;
    color: #94a3b8;
    padding: 6px;
    border: none;
    border-bottom: 1px solid #2d3748;
    font-weight: 600;
}

QTextEdit {
    background-color: #0b0d13;
    border: 1px solid #232936;
    border-radius: 8px;
    color: #cbd5e1;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    padding: 6px;
}

QPushButton {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    color: #f8fafc;
    padding: 8px 16px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #334155;
    border-color: #475569;
}

QPushButton:pressed {
    background-color: #0f172a;
}

QPushButton#PrimaryButton {
    background-color: #2563eb;
    border: 1px solid #1d4ed8;
    color: #ffffff;
}

QPushButton#PrimaryButton:hover {
    background-color: #1d4ed8;
}

QPushButton#PrimaryButton:disabled {
    background-color: #1e293b;
    border-color: #334155;
    color: #64748b;
}

QCheckBox {
    spacing: 8px;
    color: #cbd5e1;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid #475569;
    background-color: #1e293b;
}

QCheckBox::indicator:checked {
    background-color: #2563eb;
    border-color: #3b82f6;
}

QProgressBar {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    text-align: center;
    color: #f8fafc;
    font-weight: bold;
    height: 18px;
}

QProgressBar::chunk {
    background-color: #2563eb;
    border-radius: 5px;
}
"""

@dataclass
class SanitizeOptions:
    strip_metadata: bool = True
    remove_comments: bool = True
    randomize_hash: bool = True
    pdf_deep_flatten: bool = False

class DocumentSanitizerEngine:

    @staticmethod
    def calculate_hashes(file_path: str) -> Tuple[str, str]:

        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()

    @classmethod
    def sanitize(cls, input_path: str, output_path: str, options: SanitizeOptions) -> List[str]:

        ext = Path(input_path).suffix.lower()
        logs = []

        if ext == '.pdf':
            logs = cls._sanitize_pdf(input_path, output_path, options)
        elif ext in {'.docx', '.xlsx', '.pptx'}:
            logs = cls._sanitize_ooxml(input_path, output_path, options)
        else:
            raise ValueError(f"Unsupported format: {ext}")

        if options.randomize_hash:
            cls._randomize_file_hash(output_path, ext)
            logs.append("Applied cryptographic hash randomization.")

        return logs

    @classmethod
    def _sanitize_pdf(cls, in_path: str, out_path: str, options: SanitizeOptions) -> List[str]:
        if not PYPDF_AVAILABLE:
            raise RuntimeError("pypdf is not installed. Please run: pip install pypdf")

        logs = []
        reader = PdfReader(in_path)
        writer = PdfWriter()

        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                raise PermissionError("Encrypted / Password-protected PDF cannot be sanitized.")

        for i, page in enumerate(reader.pages):
            if options.pdf_deep_flatten:

                if "/Annots" in page:
                    page.pop("/Annots")
                if "/AA" in page:
                    page.pop("/AA")
            writer.add_page(page)

        if options.strip_metadata:
            writer.add_metadata({})

            if "/Metadata" in writer.root_object:
                writer.root_object.pop("/Metadata")
            logs.append("Purged /Info dictionary & XML XMP metadata stream.")

        if options.pdf_deep_flatten:
            if "/AcroForm" in writer.root_object:
                writer.root_object.pop("/AcroForm")
            if "/Names" in writer.root_object:
                writer.root_object.pop("/Names")
            if "/OpenAction" in writer.root_object:
                writer.root_object.pop("/OpenAction")
            if "/AA" in writer.root_object:
                writer.root_object.pop("/AA")
            logs.append("Removed AcroForms, embedded JavaScript, and trigger actions.")

        with open(out_path, "wb") as f_out:
            writer.write(f_out)

        return logs

    @classmethod
    def _sanitize_ooxml(cls, in_path: str, out_path: str, options: SanitizeOptions) -> List[str]:

        logs = []
        ext = Path(in_path).suffix.lower()

        unwanted_patterns = [
            r"docProps/custom\.xml$",
        ]
        if options.remove_comments:
            unwanted_patterns.extend([
                r"word/comments.*\.xml$",
                r"word/people\.xml$",
                r"word/revisions\.xml$",
                r"xl/comments.*\.xml$",
                r"xl/threadedComments/.*\.xml$",
                r"xl/drawings/vmlDrawing.*\.vml$",
                r"ppt/comments/.*\.xml$",
                r"ppt/authors\.xml$",
                r"ppt/commentAuthors\.xml$",
            ])

        unwanted_regex = re.compile("|".join(f"({p})" for p in unwanted_patterns), re.IGNORECASE)

        clean_core_xml = (
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/coreProperties" '
            b'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            b'xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>'
        )

        with zipfile.ZipFile(in_path, 'r') as zin, zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                filename = item.filename

                if unwanted_regex.search(filename):
                    logs.append(f"Stripped internal trace: {filename}")
                    continue

                content = zin.read(filename)

                if options.strip_metadata and filename == "docProps/core.xml":
                    content = clean_core_xml
                    logs.append("Reset docProps/core.xml (Author, Company, Revision dates).")

                elif options.strip_metadata and filename == "docProps/app.xml":
                    content = cls._clean_app_xml(content)
                    logs.append("Sanitized docProps/app.xml (System & Template paths).")

                elif filename == "[Content_Types].xml" and options.remove_comments:
                    content = cls._clean_content_types(content)

                elif filename.endswith(".rels") and options.remove_comments:
                    content = cls._clean_relationships(content)

                zout.writestr(item, content)

        return logs

    @staticmethod
    def _clean_app_xml(xml_bytes: bytes) -> bytes:

        try:
            root = ET.fromstring(xml_bytes)

            tags_to_clear = {'Template', 'Company', 'Manager', 'HyperlinkBase', 'Application', 'AppVersion'}
            for elem in root.iter():
                tag_name = elem.tag.split('}')[-1]
                if tag_name in tags_to_clear:
                    elem.text = ""
            return ET.tostring(root, encoding='utf-8', xml_declaration=True)
        except Exception:
            return xml_bytes

    @staticmethod
    def _clean_content_types(xml_bytes: bytes) -> bytes:

        try:
            root = ET.fromstring(xml_bytes)
            for child in list(root):
                part_name = child.attrib.get('PartName', '')
                if any(x in part_name.lower() for x in ['comment', 'custom.xml', 'people.xml', 'revisions']):
                    root.remove(child)
            return ET.tostring(root, encoding='utf-8', xml_declaration=True)
        except Exception:
            return xml_bytes

    @staticmethod
    def _clean_relationships(xml_bytes: bytes) -> bytes:

        try:
            root = ET.fromstring(xml_bytes)
            for child in list(root):
                target = child.attrib.get('Target', '')
                rel_type = child.attrib.get('Type', '')
                if any(x in target.lower() or x in rel_type.lower() for x in ['comment', 'custom', 'people', 'revision']):
                    root.remove(child)
            return ET.tostring(root, encoding='utf-8', xml_declaration=True)
        except Exception:
            return xml_bytes

    @staticmethod
    def _randomize_file_hash(file_path: str, ext: str) -> None:

        salt = secrets.token_bytes(32)
        if ext == '.pdf':

            with open(file_path, 'ab') as f:
                f.write(b'\n%DS_SALT_' + salt.hex().encode('ascii') + b'\n')
        elif ext in {'.docx', '.xlsx', '.pptx'}:

            with zipfile.ZipFile(file_path, 'a') as zf:
                zf.comment = b"SALT:" + salt.hex().encode('ascii')

class SanitizerWorker(QThread):
    progress_changed = pyqtSignal(int, int)
    file_status_updated = pyqtSignal(int, str, str)
    log_message = pyqtSignal(str, str)
    finished = pyqtSignal(int, int, str)

    def __init__(self, file_items: List[Tuple[int, str]], output_dir: str, options: SanitizeOptions):
        super().__init__()
        self.file_items = file_items
        self.output_dir = output_dir
        self.options = options
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        total = len(self.file_items)
        success_count = 0
        fail_count = 0

        os.makedirs(self.output_dir, exist_ok=True)
        self.log_message.emit("INFO", f"Starting batch processing of {total} document(s)...")

        for idx, (row, input_path) in enumerate(self.file_items):
            if self._is_cancelled:
                self.log_message.emit("WARN", "Sanitization aborted by user.")
                break

            filename = os.path.basename(input_path)
            self.file_status_updated.emit(row, "Processing...", "#3b82f6")
            self.log_message.emit("INFO", f"[{idx+1}/{total}] Processing: {filename}")

            stem = Path(input_path).stem
            suffix = Path(input_path).suffix
            out_filename = f"{stem}_clean{suffix}"
            output_path = os.path.join(self.output_dir, out_filename)

            try:

                orig_md5, orig_sha = DocumentSanitizerEngine.calculate_hashes(input_path)

                step_logs = DocumentSanitizerEngine.sanitize(input_path, output_path, self.options)
                for log in step_logs:
                    self.log_message.emit("DETAIL", f"  ↳ {log}")

                new_md5, new_sha = DocumentSanitizerEngine.calculate_hashes(output_path)
                self.log_message.emit("SUCCESS", f"  ↳ MD5: {orig_md5[:8]}... ➔ {new_md5[:8]}...")

                self.file_status_updated.emit(row, "Cleaned", "#10b981")
                success_count += 1
            except Exception as e:
                fail_count += 1
                self.file_status_updated.emit(row, "Failed", "#ef4444")
                self.log_message.emit("ERROR", f"Failed to sanitize {filename}: {str(e)}")

            self.progress_changed.emit(idx + 1, total)

        self.finished.emit(success_count, fail_count, self.output_dir)

class DropArea(QFrame):

    files_dropped = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setObjectName("DropArea")
        self.setStyleSheet("""
            QFrame#DropArea {
                border: 2px dashed #334155;
                border-radius: 10px;
                background-color: #12151e;
                min-height: 100px;
            }
            QFrame#DropArea:hover {
                border-color: #3b82f6;
                background-color: #161b26;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.icon_label = QLabel("📥")
        self.icon_label.setStyleSheet("font-size: 28px; background: transparent;")
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.text_label = QLabel("Drag & Drop PDF, DOCX, XLSX, PPTX files or folders here")
        self.text_label.setStyleSheet("color: #94a3b8; font-weight: 600; font-size: 13px; background: transparent;")
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(self.icon_label)
        layout.addWidget(self.text_label)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        paths = []
        for url in event.mimeData().urls():
            local_path = url.toLocalFile()
            if os.path.exists(local_path):
                paths.append(local_path)
        if paths:
            self.files_dropped.emit(paths)
        event.acceptProposedAction()

class DocSanitizerApp(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DocSanitizer - Anti-Leak Document Sanitizer")
        self.resize(1050, 720)
        self.setMinimumSize(850, 550)
        self.setStyleSheet(DARK_STYLESHEET)

        self.files_data: List[str] = []
        self.output_directory = os.path.abspath("sanitized_output")
        self.worker: Optional[SanitizerWorker] = None

        self._init_ui()

    def _init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        header_layout = QHBoxLayout()
        title_label = QLabel("ALDS DocSanitizer")
        title_label.setStyleSheet("font-size: 20px; font-weight: 800; color: #60a5fa;")
        subtitle_label = QLabel("Deep Metadata Stripping & Anti-Forensics Cleaner")
        subtitle_label.setStyleSheet("color: #64748b; font-size: 13px; margin-left: 8px;")
        header_layout.addWidget(title_label)
        header_layout.addWidget(subtitle_label)
        header_layout.addStretch()
        main_layout.addLayout(header_layout)

        self.drop_area = DropArea()
        self.drop_area.files_dropped.connect(self.add_paths)
        main_layout.addWidget(self.drop_area)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Filename", "Type", "Original Size", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        splitter.addWidget(self.table)

        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        splitter.addWidget(self.log_console)
        splitter.setSizes([260, 140])
        main_layout.addWidget(splitter)

        options_group = QGroupBox("Sanitization Configuration")
        options_layout = QHBoxLayout(options_group)
        options_layout.setContentsMargins(12, 8, 12, 8)

        self.cb_metadata = QCheckBox("Strip All Core & Custom Metadata")
        self.cb_metadata.setChecked(True)

        self.cb_comments = QCheckBox("Remove Comments & Revision History")
        self.cb_comments.setChecked(True)

        self.cb_hash = QCheckBox("Randomize Cryptographic Hash (MD5/SHA256)")
        self.cb_hash.setChecked(True)

        self.cb_pdf_flatten = QCheckBox("Deep PDF Flatten (Purge Scripts/Forms/Annots)")
        self.cb_pdf_flatten.setChecked(False)

        options_layout.addWidget(self.cb_metadata)
        options_layout.addWidget(self.cb_comments)
        options_layout.addWidget(self.cb_hash)
        options_layout.addWidget(self.cb_pdf_flatten)
        main_layout.addWidget(options_group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        actions_layout = QHBoxLayout()

        self.btn_add_files = QPushButton("Add Files...")
        self.btn_add_files.clicked.connect(self.browse_files)

        self.btn_add_folder = QPushButton("Add Folder...")
        self.btn_add_folder.clicked.connect(self.browse_folder)

        self.btn_clear = QPushButton("Clear List")
        self.btn_clear.clicked.connect(self.clear_file_list)

        self.btn_open_out = QPushButton("Open Output Folder")
        self.btn_open_out.clicked.connect(self.open_output_folder)

        self.btn_start = QPushButton("Start Sanitizing")
        self.btn_start.setObjectName("PrimaryButton")
        self.btn_start.clicked.connect(self.start_sanitization)

        actions_layout.addWidget(self.btn_add_files)
        actions_layout.addWidget(self.btn_add_folder)
        actions_layout.addWidget(self.btn_clear)
        actions_layout.addStretch()
        actions_layout.addWidget(self.btn_open_out)
        actions_layout.addWidget(self.btn_start)

        main_layout.addLayout(actions_layout)

        self.log("INFO", "DocSanitizer ready. Drag files or folders to begin.")
        if not PYPDF_AVAILABLE:
            self.log("WARN", "'pypdf' not found. PDF sanitization will be disabled until installed.")

    def log(self, level: str, message: str):
        colors = {
            "INFO": "#94a3b8",
            "SUCCESS": "#10b981",
            "WARN": "#f59e0b",
            "ERROR": "#ef4444",
            "DETAIL": "#64748b"
        }
        color = colors.get(level, "#cbd5e1")
        timestamp = time.strftime("%H:%M:%S")
        formatted = f'<span style="color: #475569;">[{timestamp}]</span> <span style="color: {color}; font-weight: bold;">[{level}]</span> <span style="color: #e2e8f0;">{message}</span>'
        self.log_console.append(formatted)
        self.log_console.moveCursor(QTextCursor.MoveOperation.End)

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def browse_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select Documents to Sanitize", "",
            "Supported Documents (*.pdf *.docx *.xlsx *.pptx);;All Files (*)"
        )
        if files:
            self.add_paths(files)

    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder Containing Documents")
        if folder:
            self.add_paths([folder])

    def add_paths(self, paths: List[str]):

        added_count = 0
        for path in paths:
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        if Path(full_path).suffix.lower() in SUPPORTED_EXTENSIONS:
                            if self._insert_file_to_table(full_path):
                                added_count += 1
            elif os.path.isfile(path):
                if Path(path).suffix.lower() in SUPPORTED_EXTENSIONS:
                    if self._insert_file_to_table(path):
                        added_count += 1

        if added_count > 0:
            self.log("INFO", f"Added {added_count} file(s) to the queue.")

    def _insert_file_to_table(self, file_path: str) -> bool:
        if file_path in self.files_data:
            return False

        self.files_data.append(file_path)
        row = self.table.rowCount()
        self.table.insertRow(row)

        file_stat = os.stat(file_path)
        ext = Path(file_path).suffix.upper().replace('.', '')

        item_name = QTableWidgetItem(os.path.basename(file_path))
        item_type = QTableWidgetItem(ext)
        item_size = QTableWidgetItem(self._format_size(file_stat.st_size))
        item_status = QTableWidgetItem("Queued")
        item_status.setForeground(QColor("#94a3b8"))

        item_type.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        item_size.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        item_status.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        self.table.setItem(row, 0, item_name)
        self.table.setItem(row, 1, item_type)
        self.table.setItem(row, 2, item_size)
        self.table.setItem(row, 3, item_status)
        return True

    def clear_file_list(self):
        self.files_data.clear()
        self.table.setRowCount(0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setValue(0)
        self.log("INFO", "Queue cleared.")

    def open_output_folder(self):
        os.makedirs(self.output_directory, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.output_directory))

    def start_sanitization(self):
        if not self.files_data:
            QMessageBox.warning(self, "No Files", "Please add at least one document to sanitize.")
            return

        options = SanitizeOptions(
            strip_metadata=self.cb_metadata.isChecked(),
            remove_comments=self.cb_comments.isChecked(),
            randomize_hash=self.cb_hash.isChecked(),
            pdf_deep_flatten=self.cb_pdf_flatten.isChecked()
        )

        file_items = [(i, path) for i, path in enumerate(self.files_data)]

        self._toggle_ui_state(processing=True)

        self.progress_bar.setMaximum(len(file_items))
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)

        self.worker = SanitizerWorker(file_items, self.output_directory, options)
        self.worker.progress_changed.connect(self.on_progress)
        self.worker.file_status_updated.connect(self.on_file_status_updated)
        self.worker.log_message.connect(self.log)
        self.worker.finished.connect(self.on_processing_finished)
        self.worker.start()

    def _toggle_ui_state(self, processing: bool):
        self.btn_start.setEnabled(not processing)
        self.btn_add_files.setEnabled(not processing)
        self.btn_add_folder.setEnabled(not processing)
        self.btn_clear.setEnabled(not processing)
        self.drop_area.setEnabled(not processing)

    @pyqtSlot(int, str, str)
    def on_file_status_updated(self, row: int, status: str, color_hex: str):
        item = self.table.item(row, 3)
        if item:
            item.setText(status)
            item.setForeground(QColor(color_hex))

    @pyqtSlot(int, int)
    def on_progress(self, current: int, total: int):
        self.progress_bar.setValue(current)

    @pyqtSlot(int, int, str)
    def on_processing_finished(self, success_count: int, fail_count: int, output_dir: str):
        self._toggle_ui_state(processing=False)
        self.log("SUCCESS", f"Completed: {success_count} sanitized, {fail_count} failed.")

        self.open_output_folder()

        QMessageBox.information(
            self,
            "Sanitization Complete",
            f"Successfully cleaned: {success_count}\nFailed: {fail_count}\n\nSaved to:\n{output_dir}"
        )

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    window = DocSanitizerApp()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
