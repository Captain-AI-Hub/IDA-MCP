"""First-run dialog prompting the user to install the IDA-MCP plugin."""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)


class FirstRunInstallDialog(QDialog):
    """Shown on startup when IDA-MCP is not detected in the global plugins dir.

    Offers a one-click path to the Settings page (where install can be triggered)
    or a Skip button that suppresses future prompts.
    """

    def __init__(self, ida_dir: str, plugin_dir: str, parent=None) -> None:
        super().__init__(parent)
        self._initial_ida_dir = ida_dir
        self._initial_plugin_dir = plugin_dir
        self._setup_ui(ida_dir, plugin_dir)

    def _setup_ui(self, ida_dir: str, plugin_dir: str) -> None:
        self.setWindowTitle("IDA-MCP 未安装")
        self.setObjectName("firstRunInstallDialog")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 24, 24, 24)

        header = QLabel("<b>IDA-MCP 插件未检测到</b>")
        header.setObjectName("firstRunInstallHeader")
        layout.addWidget(header)

        body = QLabel(
            "全局插件目录中未发现 IDA-MCP。<br><br>"
            "安装后 IDE 可通过 MCP 协议与 IDA Pro 通信，"
            "实现反汇编、函数分析等自动化操作。"
        )
        body.setWordWrap(True)
        body.setTextFormat(Qt.TextFormat.RichText)
        body.setObjectName("firstRunInstallBody")
        layout.addWidget(body)

        # IDA directory selector
        ida_label = QLabel("IDA 安装目录：")
        ida_label.setObjectName("firstRunInstallIdaLabel")
        layout.addWidget(ida_label)

        ida_row = QHBoxLayout()
        ida_row.setSpacing(8)
        self._ida_dir_edit = QLineEdit(ida_dir)
        self._ida_dir_edit.setObjectName("firstRunInstallIdaEdit")
        self._ida_dir_edit.setPlaceholderText("选择 IDA 安装目录...")
        ida_row.addWidget(self._ida_dir_edit, 1)

        browse_btn = QPushButton("浏览...")
        browse_btn.setObjectName("firstRunInstallBrowseBtn")
        browse_btn.clicked.connect(self._on_browse)
        ida_row.addWidget(browse_btn)
        layout.addLayout(ida_row)

        # Derived plugin directory (read-only)
        plugin_label = QLabel("推导插件目录：")
        plugin_label.setObjectName("firstRunInstallPluginLabel")
        layout.addWidget(plugin_label)

        self._plugin_dir_edit = QLineEdit(plugin_dir)
        self._plugin_dir_edit.setObjectName("firstRunInstallPluginEdit")
        self._plugin_dir_edit.setReadOnly(True)
        layout.addWidget(self._plugin_dir_edit)

        hint = QLabel(
            "<small>选择 IDA 安装目录后，插件目录会自动推导为 "
            "<code>&lt;ida_dir&gt;/plugins</code>。"
            "若该目录不存在，将回退到全局默认插件目录。</small>"
        )
        hint.setWordWrap(True)
        hint.setTextFormat(Qt.TextFormat.RichText)
        hint.setObjectName("firstRunInstallHint")
        layout.addWidget(hint)

        layout.addSpacing(8)

        btn_box = QDialogButtonBox()

        self._install_btn = QPushButton("前往安装")
        self._install_btn.setObjectName("firstRunInstallBtn")
        self._install_btn.clicked.connect(self.accept)
        btn_box.addButton(self._install_btn, QDialogButtonBox.ButtonRole.AcceptRole)

        skip_btn = QPushButton("跳过（不再提示）")
        skip_btn.setObjectName("firstRunSkipBtn")
        skip_btn.clicked.connect(self.reject)
        btn_box.addButton(skip_btn, QDialogButtonBox.ButtonRole.RejectRole)

        layout.addWidget(btn_box)

    def _on_browse(self) -> None:
        start = self._ida_dir_edit.text().strip() or self._initial_ida_dir or ""
        selected = QFileDialog.getExistingDirectory(
            self,
            "选择 IDA 安装目录",
            start,
        )
        if selected:
            self._ida_dir_edit.setText(os.path.normpath(selected))
            # Update derived plugin dir
            from supervisor.models import derive_plugin_dir
            self._plugin_dir_edit.setText(derive_plugin_dir(selected))

    def selected_ida_dir(self) -> str:
        """Return the IDA directory chosen by the user."""
        return self._ida_dir_edit.text().strip()
