"""Workspace selector dialog — pick a recent folder or browse for a new one."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
)

from shared.database import DatabaseStore


class WorkspaceSelectorDialog(QDialog):
    """Modal dialog shown on startup when no workspace is configured.

    Displays recent workspaces from ``workspace_history`` and lets the user
    browse for a new folder.
    """

    def __init__(self, db: DatabaseStore, parent=None) -> None:
        super().__init__(parent)
        self._db = db
        self._selected_path: str | None = None
        self._setup_ui()
        self._load_history()

    def _setup_ui(self) -> None:
        self.setWindowTitle("选择工作区")
        self.setObjectName("workspaceSelectorDialog")
        self.setMinimumWidth(520)
        self.setMinimumHeight(360)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 24, 24, 24)

        # Header
        header = QLabel("<b>打开工作区</b>")
        header.setObjectName("workspaceSelectorHeader")
        layout.addWidget(header)

        sub = QLabel("选择一个最近使用的工作区，或浏览新文件夹。")
        sub.setObjectName("workspaceSelectorSub")
        layout.addWidget(sub)

        # Recent list
        self._list = QListWidget()
        self._list.setObjectName("workspaceSelectorList")
        self._list.itemClicked.connect(self._on_item_clicked)
        self._list.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self._list, 1)

        # Buttons
        btn_box = QDialogButtonBox()
        self._browse_btn = QPushButton("浏览...")
        self._browse_btn.setObjectName("workspaceSelectorBrowse")
        self._browse_btn.clicked.connect(self._on_browse)
        btn_box.addButton(self._browse_btn, QDialogButtonBox.ButtonRole.ActionRole)

        self._open_btn = QPushButton("打开")
        self._open_btn.setObjectName("workspaceSelectorOpen")
        self._open_btn.setEnabled(False)
        self._open_btn.clicked.connect(self.accept)
        btn_box.addButton(self._open_btn, QDialogButtonBox.ButtonRole.AcceptRole)

        skip_btn = QPushButton("跳过")
        skip_btn.setObjectName("workspaceSelectorSkip")
        skip_btn.setToolTip("暂不设置工作区，可在侧边栏手动打开文件夹")
        skip_btn.clicked.connect(self._on_skip)
        btn_box.addButton(skip_btn, QDialogButtonBox.ButtonRole.RejectRole)

        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_box.addButton(cancel_btn, QDialogButtonBox.ButtonRole.RejectRole)

        layout.addWidget(btn_box)

    def _load_history(self) -> None:
        """Populate the list from ``workspace_history`` ordered by recency."""
        rows = self._db.load_rows("workspace_history")
        # Sort by last_opened_at descending
        rows.sort(key=lambda r: r.get("last_opened_at", ""), reverse=True)

        if not rows:
            item = QListWidgetItem("无最近工作区 — 请点击“浏览”选择文件夹")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self._list.addItem(item)
            return

        for row in rows:
            path = row.get("path", "")
            name = row.get("name", "") or Path(path).name or path
            display = f"{name}\n{path}"
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, path)
            item.setToolTip(path)
            self._list.addItem(item)

    def _on_item_clicked(self, item: QListWidgetItem) -> None:
        path = item.data(Qt.ItemDataRole.UserRole)
        if path:
            self._selected_path = path
            self._open_btn.setEnabled(True)

    def _on_item_double_clicked(self, item: QListWidgetItem) -> None:
        self._on_item_clicked(item)
        if self._selected_path:
            self.accept()

    def _on_browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择工作区文件夹")
        if path:
            self._selected_path = str(Path(path).resolve())
            self.accept()

    def _on_skip(self) -> None:
        self._selected_path = ""
        self.accept()

    def selected_path(self) -> str | None:
        """Return the chosen workspace path, or ``None`` if cancelled."""
        return self._selected_path

    @staticmethod
    def record_workspace(db: DatabaseStore, path: str) -> None:
        """Upsert a workspace into the history table."""
        from datetime import datetime, timezone

        path = str(Path(path).resolve())
        name = Path(path).name or path
        now = datetime.now(timezone.utc).isoformat()

        # Upsert via delete + insert
        with db._connect() as conn:
            conn.execute("DELETE FROM workspace_history WHERE path = ?", (path,))
            conn.execute(
                "INSERT INTO workspace_history (path, name, last_opened_at) VALUES (?, ?, ?)",
                (path, name, now),
            )
            conn.commit()

        # Prune old entries — keep last 10
        rows = db.load_rows("workspace_history")
        rows.sort(key=lambda r: r.get("last_opened_at", ""), reverse=True)
        for old in rows[10:]:
            old_id = old.get("id")
            if old_id is not None:
                db.delete_row("workspace_history", int(old_id))
