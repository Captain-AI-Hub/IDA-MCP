"""Hex viewer/editor widget for binary file inspection."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


from app.ui.theme import mono_font


def _hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """Format binary data as a classic hex dump string."""
    lines: list[str] = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset : offset + bytes_per_line]
        hex_offset = f"{offset:08X}"
        hex_parts: list[str] = []
        for i in range(bytes_per_line):
            if i < len(chunk):
                hex_parts.append(f"{chunk[i]:02X}")
            else:
                hex_parts.append("  ")
            if i == 7:
                hex_parts.append(" ")
        hex_str = " ".join(hex_parts)
        ascii_chars: list[str] = []
        for b in chunk:
            if 0x20 <= b < 0x7F:
                ascii_chars.append(chr(b))
            else:
                ascii_chars.append(".")
        ascii_str = "".join(ascii_chars)
        lines.append(f"{hex_offset}  {hex_str}  {ascii_str}")
    return "\n".join(lines)


def _parse_hex_dump(text: str) -> bytes | None:
    """Parse a hex dump back to bytes. Returns None on parse error."""
    result = bytearray()
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("  ", 2)
        if len(parts) < 2:
            return None
        hex_section = parts[1].strip()
        for token in hex_section.split():
            if len(token) != 2:
                continue
            try:
                result.append(int(token, 16))
            except ValueError:
                return None
    return bytes(result)


class HexViewWidget(QWidget):
    """Hex viewer/editor for binary files."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._file_path: str | None = None
        self._original_data: bytes = b""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar
        toolbar = QWidget()
        toolbar.setObjectName("hexToolbar")
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(10, 8, 10, 8)
        toolbar_layout.setSpacing(8)

        self._path_label = QLabel("No file opened")
        self._path_label.setObjectName("hexPathLabel")

        self._size_label = QLabel("")
        self._size_label.setObjectName("hexSizeLabel")

        self._readonly_label = QLabel("READONLY")
        self._readonly_label.setObjectName("hexReadonlyLabel")

        self._edit_btn = QPushButton("Edit")
        self._edit_btn.setCheckable(True)
        self._edit_btn.setObjectName("hexEditToggle")
        self._edit_btn.clicked.connect(self._on_toggle_edit)

        self._save_btn = QPushButton("Save")
        self._save_btn.setObjectName("hexSaveButton")
        self._save_btn.setVisible(False)
        self._save_btn.clicked.connect(self._on_save)

        toolbar_layout.addWidget(self._path_label, 1)
        toolbar_layout.addWidget(self._size_label)
        toolbar_layout.addWidget(self._readonly_label)
        toolbar_layout.addWidget(self._edit_btn)
        toolbar_layout.addWidget(self._save_btn)

        # Hex content
        self._content = QTextEdit()
        self._content.setObjectName("hexContent")
        self._content.setReadOnly(True)
        self._content.setFont(mono_font())
        self._content.setLineWrapMode(QTextEdit.NoWrap)
        self._content.setPlaceholderText(
            "Open a binary file from the directory tree to view its hex content."
        )

        layout.addWidget(toolbar)
        layout.addWidget(self._content, 1)

    def load_file(self, path: str) -> None:
        """Load a file and display its hex content."""
        self._file_path = str(Path(path).resolve())
        self._original_data = Path(path).read_bytes()
        name = Path(path).name
        self._path_label.setText(name)
        self._path_label.setToolTip(self._file_path)
        size = len(self._original_data)
        self._size_label.setText(f"{size:,} bytes ({size:#x})")
        self._content.setPlainText(_hex_dump(self._original_data))
        cursor = self._content.textCursor()
        cursor.movePosition(QTextCursor.Start)
        self._content.setTextCursor(cursor)
        self.set_readonly(True)

    def set_readonly(self, ro: bool) -> None:
        self._readonly = ro
        self._content.setReadOnly(ro)
        self._readonly_label.setText("READONLY" if ro else "EDITABLE")
        self._edit_btn.setChecked(not ro)
        self._save_btn.setVisible(not ro)

    def _on_toggle_edit(self, checked: bool) -> None:
        self.set_readonly(not checked)

    def _on_save(self) -> None:
        if not self._file_path:
            return
        new_bytes = _parse_hex_dump(self._content.toPlainText())
        if new_bytes is not None:
            Path(self._file_path).write_bytes(new_bytes)
            self._original_data = new_bytes
            self._size_label.setText(f"{len(new_bytes):,} bytes ({len(new_bytes):#x})")

    def file_path(self) -> str | None:
        return self._file_path
