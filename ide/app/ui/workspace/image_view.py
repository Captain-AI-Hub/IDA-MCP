"""Image viewer widget for common image formats."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)


class ImageViewWidget(QWidget):
    """Display images with fit-to-window scaling and scroll for large images."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._file_path: str | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar
        toolbar = QWidget()
        toolbar.setObjectName("imageToolbar")
        tb = QHBoxLayout(toolbar)
        tb.setContentsMargins(10, 8, 10, 8)
        tb.setSpacing(8)

        self._path_label = QLabel("No image opened")
        self._path_label.setObjectName("imagePathLabel")

        self._size_label = QLabel("")
        self._size_label.setObjectName("imageSizeLabel")

        tb.addWidget(self._path_label, 1)
        tb.addWidget(self._size_label)

        # Scroll area for large images
        self._scroll = QScrollArea()
        self._scroll.setObjectName("imageScroll")
        self._scroll.setWidgetResizable(True)
        self._scroll.setAlignment(Qt.AlignCenter)

        self._image_label = QLabel("Open an image file to preview it.")
        self._image_label.setObjectName("imageLabel")
        self._image_label.setAlignment(Qt.AlignCenter)
        self._image_label.setScaledContents(False)

        self._scroll.setWidget(self._image_label)

        layout.addWidget(toolbar)
        layout.addWidget(self._scroll, 1)

        self._pixmap: QPixmap | None = None

    def load_file(self, path: str) -> None:
        """Load and display an image file."""
        self._file_path = str(Path(path).resolve())
        name = Path(path).name
        self._path_label.setText(name)
        self._path_label.setToolTip(self._file_path)

        pixmap = QPixmap(self._file_path)
        if pixmap.isNull():
            self._image_label.setText(f"Failed to load image: {name}")
            self._size_label.setText("")
            self._pixmap = None
            return

        self._pixmap = pixmap
        w, h = pixmap.width(), pixmap.height()
        self._size_label.setText(f"{w} × {h}")
        self._fit_to_view()

    def _fit_to_view(self) -> None:
        if self._pixmap is None or self._pixmap.isNull():
            return
        # Scale to fit the scroll area viewport, preserving aspect ratio
        vw = max(self._scroll.viewport().width() - 4, 1)
        vh = max(self._scroll.viewport().height() - 4, 1)
        scaled = self._pixmap.scaled(
            vw, vh, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        self._image_label.setPixmap(scaled)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._fit_to_view()

    def file_path(self) -> str | None:
        return self._file_path
