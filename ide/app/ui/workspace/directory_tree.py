"""VS Code-style directory tree widget."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFileIconProvider,
    QFileSystemModel,
    QHBoxLayout,
    QPushButton,
    QTreeView,
    QVBoxLayout,
    QWidget,
)


class DirectoryTreeWidget(QWidget):
    """Directory tree with open-folder button and file double-click signal."""

    file_selected = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._root_path: str | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar with centered open button
        toolbar = QWidget()
        toolbar.setObjectName("dirTreeToolbar")
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(10, 8, 10, 8)

        self._open_btn = QPushButton("Open Folder")
        self._open_btn.setObjectName("openFolderButton")
        self._open_btn.clicked.connect(self._on_open_folder)

        toolbar_layout.addStretch()
        toolbar_layout.addWidget(self._open_btn)
        toolbar_layout.addStretch()

        # Tree view
        self._model = QFileSystemModel(self)
        self._model.setIconProvider(QFileIconProvider())
        self._model.setFilter(self._model.filter())

        self._tree = QTreeView(self)
        self._tree.setObjectName("dirTreeView")
        self._tree.setModel(self._model)
        self._tree.setHeaderHidden(True)
        self._tree.setAnimated(True)
        self._tree.setIndentation(16)
        self._tree.setUniformRowHeights(True)
        self._tree.setSortingEnabled(True)
        self._tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self._tree.doubleClicked.connect(self._on_double_click)

        # Hide all columns except Name (column 0)
        for col in range(1, 4):
            self._tree.hideColumn(col)

        # Initially hide the tree until a directory is opened
        self._tree.setVisible(False)

        layout.addWidget(toolbar)
        layout.addWidget(self._tree, 1)

    def open_directory(self, path: str) -> None:
        """Set the directory tree root."""
        path = str(Path(path).resolve())
        self._root_path = path
        idx = self._model.setRootPath(path)
        self._tree.setRootIndex(idx)
        self._tree.setVisible(True)
        self._open_btn.setText(Path(path).name or path)
        self._open_btn.setToolTip(path)

    def _on_open_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Open Folder")
        if path:
            self.open_directory(path)

    def _on_double_click(self, index) -> None:
        path = self._model.filePath(index)
        if path and not self._model.isDir(index):
            self.file_selected.emit(path)
