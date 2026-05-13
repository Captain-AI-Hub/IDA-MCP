"""Dialogs used by the settings page."""

from __future__ import annotations

import json

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.ui.settings.widgets import (
    ContextTokenEdit,
    NoWheelComboBox,
    NoWheelDoubleSpinBox,
)


class ModelProviderDialog(QDialog):
    """Dialog for adding or editing a model provider entry."""

    def __init__(
        self,
        i18n,
        *,
        provider=None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._i18n = i18n
        self._provider = provider  # None = add new, else edit existing
        self._setup_ui()

    def _t(self, key: str, **kwargs: object) -> str:
        return self._i18n.t(key, **kwargs)

    def _setup_ui(self) -> None:
        self.setWindowTitle(
            self._t("settings.model.dialog.add")
            if self._provider is None
            else self._t("settings.model.dialog.edit")
        )
        self.setObjectName("modelProviderDialog")
        self.setMinimumWidth(480)

        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(24, 24, 24, 24)

        # --- Section: Identity ---
        layout.addWidget(self._section_label(self._t("settings.field.model_name")))
        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("My GPT-4o")
        layout.addWidget(self._name_edit)

        layout.addSpacing(2)
        layout.addWidget(self._field_label(self._t("settings.field.model_id")))
        self._model_id_edit = QLineEdit()
        self._model_id_edit.setPlaceholderText("gpt-4o")
        layout.addWidget(self._model_id_edit)

        layout.addWidget(self._separator())
        layout.addSpacing(4)

        # --- Section: Connection ---
        layout.addWidget(self._section_label(self._t("settings.field.model_base_url")))
        self._base_url_edit = QLineEdit()
        self._base_url_edit.setPlaceholderText("https://api.openai.com/v1")
        layout.addWidget(self._base_url_edit)

        layout.addSpacing(2)
        layout.addWidget(self._field_label(self._t("settings.field.model_api_key")))
        self._api_key_edit = QLineEdit()
        self._api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key_edit.setPlaceholderText("sk-...")
        layout.addWidget(self._api_key_edit)

        layout.addSpacing(2)
        layout.addWidget(self._field_label(self._t("settings.field.model_api_mode")))
        self._api_mode_combo = NoWheelComboBox()
        self._api_mode_items = [
            ("openai_responses", self._t("settings.model.api_mode.openai_responses")),
            ("openai_compatible", self._t("settings.model.api_mode.openai_compatible")),
            ("anthropic", self._t("settings.model.api_mode.anthropic")),
        ]
        for value, label in self._api_mode_items:
            self._api_mode_combo.addItem(label, value)
        self._api_mode_combo.setCurrentIndex(1)  # default: openai_compatible
        layout.addWidget(self._api_mode_combo)

        layout.addWidget(self._separator())
        layout.addSpacing(4)

        # --- Section: Parameters ---
        layout.addWidget(self._section_label(self._t("settings.field.model_top_p")))
        self._top_p_spin = NoWheelDoubleSpinBox()
        self._top_p_spin.setRange(0.0, 1.0)
        self._top_p_spin.setSingleStep(0.05)
        self._top_p_spin.setDecimals(2)
        self._top_p_spin.setValue(1.0)
        layout.addWidget(self._top_p_spin)

        layout.addSpacing(2)
        layout.addWidget(self._field_label(self._t("settings.field.model_temperature")))
        self._temp_spin = NoWheelDoubleSpinBox()
        self._temp_spin.setRange(0.0, 2.0)
        self._temp_spin.setSingleStep(0.1)
        self._temp_spin.setDecimals(1)
        self._temp_spin.setValue(0.7)
        layout.addWidget(self._temp_spin)

        layout.addSpacing(2)
        layout.addWidget(self._field_label(self._t("settings.field.model_context")))
        self._context_edit = ContextTokenEdit()
        self._context_edit.setPlaceholderText(self._t("settings.field.model_context.placeholder"))
        self._context_edit.setValue(0)
        layout.addWidget(self._context_edit)

        layout.addWidget(self._separator())
        layout.addSpacing(4)

        # Validation error label (hidden until needed)
        self._error_label = QLabel("")
        self._error_label.setObjectName("settingsErrorLabel")
        self._error_label.setWordWrap(True)
        self._error_label.hide()
        layout.addWidget(self._error_label)

        layout.addSpacing(8)

        # Buttons
        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.accepted.connect(self._validate_and_accept)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

        # Pre-fill if editing
        if self._provider is not None:
            self._name_edit.setText(self._provider.name or "")
            self._base_url_edit.setText(self._provider.base_url or "")
            self._api_key_edit.setText(self._provider.api_key or "")
            self._model_id_edit.setText(self._provider.model_name or "")
            self._context_edit.setValue(self._provider.max_context_tokens)
            self._top_p_spin.setValue(self._provider.top_p)
            self._temp_spin.setValue(self._provider.temperature)
            # Set api_mode combo
            for i, (value, _) in enumerate(self._api_mode_items):
                if value == self._provider.api_mode:
                    self._api_mode_combo.setCurrentIndex(i)
                    break

    def get_values(self) -> dict:
        """Return a dict of all field values."""
        return {
            "name": self._name_edit.text().strip(),
            "base_url": self._base_url_edit.text().strip(),
            "api_key": self._api_key_edit.text().strip(),
            "api_mode": self._api_mode_combo.currentData() or "openai_compatible",
            "model_name": self._model_id_edit.text().strip(),
            "max_context_tokens": self._context_edit.value(),
            "top_p": self._top_p_spin.value(),
            "temperature": self._temp_spin.value(),
            # enabled is controlled from the card toggle, not the dialog.
            # Preserve existing state when editing; default True for new.
            "enabled": self._provider.enabled if self._provider else True,
        }

    def _section_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("dialogSectionTitle")
        return label

    def _field_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("settingsFieldLabel")
        return label

    def _separator(self) -> QFrame:
        line = QFrame()
        line.setObjectName("dialogSeparator")
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFixedHeight(1)
        return line

    def _validate_and_accept(self) -> None:
        """Validate required fields before accepting the dialog."""
        errors: list[str] = []
        name = self._name_edit.text().strip()
        model_id = self._model_id_edit.text().strip()

        if not name:
            errors.append(self._t("settings.model.validation.name_required"))
        if not model_id:
            errors.append(self._t("settings.model.validation.model_id_required"))

        if errors:
            self._error_label.setText("\n".join(errors))
            self._error_label.show()
            return

        self._error_label.hide()
        self.accept()


class McpServerDialog(QDialog):
    """Dialog for adding or editing an MCP server entry."""

    def __init__(self, i18n, *, server=None, parent=None) -> None:
        super().__init__(parent)
        self._i18n = i18n
        self._server = server
        self._setup_ui()

    def _t(self, key: str, **kwargs: object) -> str:
        return self._i18n.t(key, **kwargs)

    def _setup_ui(self) -> None:
        self.setWindowTitle(
            self._t("settings.mcp.dialog.add")
            if self._server is None
            else self._t("settings.mcp.dialog.edit")
        )
        self.setObjectName("mcpServerDialog")
        self.setMinimumWidth(480)

        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(24, 24, 24, 24)

        # --- Name ---
        layout.addWidget(self._section_label(self._t("settings.field.mcp_server_name")))
        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("my-server")
        layout.addWidget(self._name_edit)

        # --- Transport ---
        layout.addWidget(self._section_label(self._t("settings.field.mcp_transport")))
        self._transport_combo = NoWheelComboBox()
        self._transport_items = [
            ("stdio", self._t("settings.mcp.transport.stdio")),
            ("http", self._t("settings.mcp.transport.http")),
            ("sse", self._t("settings.mcp.transport.sse")),
        ]
        for value, label in self._transport_items:
            self._transport_combo.addItem(label, value)
        self._transport_combo.currentIndexChanged.connect(self._on_transport_changed)
        layout.addWidget(self._transport_combo)

        layout.addWidget(self._separator())
        layout.addSpacing(4)

        # --- Stdio fields ---
        self._stdio_widget = QWidget()
        stdio_layout = QVBoxLayout(self._stdio_widget)
        stdio_layout.setContentsMargins(0, 0, 0, 0)
        stdio_layout.setSpacing(6)

        stdio_layout.addWidget(self._field_label(self._t("settings.field.mcp_command")))
        self._command_edit = QLineEdit()
        self._command_edit.setPlaceholderText("python")
        stdio_layout.addWidget(self._command_edit)

        stdio_layout.addWidget(self._field_label(self._t("settings.field.mcp_args")))
        self._args_edit = QTextEdit()
        self._args_edit.setMaximumHeight(72)
        self._args_edit.setPlaceholderText("/path/to/server.py\n--verbose")
        stdio_layout.addWidget(self._args_edit)

        stdio_layout.addWidget(self._field_label(self._t("settings.field.mcp_env")))
        self._env_edit = QTextEdit()
        self._env_edit.setMaximumHeight(72)
        self._env_edit.setPlaceholderText("API_KEY=xxx\nANOTHER_VAR=value")
        stdio_layout.addWidget(self._env_edit)

        stdio_layout.addWidget(self._field_label(self._t("settings.field.mcp_cwd")))
        self._cwd_edit = QLineEdit()
        self._cwd_edit.setPlaceholderText("/working/directory")
        stdio_layout.addWidget(self._cwd_edit)

        layout.addWidget(self._stdio_widget)

        # --- HTTP/SSE fields ---
        self._http_widget = QWidget()
        http_layout = QVBoxLayout(self._http_widget)
        http_layout.setContentsMargins(0, 0, 0, 0)
        http_layout.setSpacing(6)

        http_layout.addWidget(self._field_label(self._t("settings.field.mcp_url")))
        self._url_edit = QLineEdit()
        self._url_edit.setPlaceholderText("http://localhost:8000/mcp")
        http_layout.addWidget(self._url_edit)

        http_layout.addWidget(self._field_label(self._t("settings.field.mcp_headers")))
        self._headers_edit = QTextEdit()
        self._headers_edit.setMaximumHeight(72)
        self._headers_edit.setPlaceholderText("Authorization: Bearer token\nX-Custom-Header: value")
        http_layout.addWidget(self._headers_edit)

        http_layout.addWidget(self._field_label(self._t("settings.field.mcp_timeout")))
        self._timeout_spin = NoWheelDoubleSpinBox()
        self._timeout_spin.setRange(1.0, 600.0)
        self._timeout_spin.setSingleStep(5.0)
        self._timeout_spin.setDecimals(1)
        self._timeout_spin.setValue(30.0)
        self._timeout_spin.setSuffix(" s")
        http_layout.addWidget(self._timeout_spin)

        layout.addWidget(self._http_widget)

        # --- Enabled ---
        self._enabled_check = QCheckBox(self._t("settings.skills.enabled"))
        self._enabled_check.setChecked(True)
        layout.addWidget(self._enabled_check)

        layout.addSpacing(8)

        # --- Buttons ---
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        # --- Pre-fill ---
        if self._server is not None:
            self._name_edit.setText(self._server.name or "")
            self._command_edit.setText(self._server.command or "")
            self._cwd_edit.setText(self._server.cwd or "")
            self._url_edit.setText(self._server.url or "")
            self._timeout_spin.setValue(self._server.timeout)
            self._enabled_check.setChecked(self._server.enabled)

            # Decode JSON args → plain text lines
            try:
                args_list = json.loads(self._server.args) if self._server.args else []
                self._args_edit.setPlainText("\n".join(args_list))
            except (json.JSONDecodeError, TypeError):
                self._args_edit.setPlainText(self._server.args or "")

            # Decode JSON env → "KEY=VALUE" lines
            try:
                env_dict = json.loads(self._server.env) if self._server.env else {}
                self._env_edit.setPlainText(
                    "\n".join(f"{k}={v}" for k, v in env_dict.items())
                )
            except (json.JSONDecodeError, TypeError):
                self._env_edit.setPlainText(self._server.env or "")

            # Decode JSON headers → "Key: Value" lines
            try:
                hdr_dict = json.loads(self._server.headers) if self._server.headers else {}
                self._headers_edit.setPlainText(
                    "\n".join(f"{k}: {v}" for k, v in hdr_dict.items())
                )
            except (json.JSONDecodeError, TypeError):
                self._headers_edit.setPlainText(self._server.headers or "")

            for i, (value, _) in enumerate(self._transport_items):
                if value == self._server.transport:
                    self._transport_combo.setCurrentIndex(i)
                    break
        else:
            self._transport_combo.setCurrentIndex(0)

        self._on_transport_changed()

    def _section_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("dialogSectionTitle")
        return label

    def _field_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("settingsFieldLabel")
        return label

    def _separator(self) -> QFrame:
        line = QFrame()
        line.setObjectName("dialogSeparator")
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFixedHeight(1)
        return line

    def _on_transport_changed(self) -> None:
        transport = self._transport_combo.currentData() or "stdio"
        is_stdio = transport == "stdio"
        self._stdio_widget.setVisible(is_stdio)
        self._http_widget.setVisible(not is_stdio)

    def _validate_and_accept(self) -> None:
        errors: list[str] = []
        if not self._name_edit.text().strip():
            errors.append(self._t("settings.mcp.validation.name_required"))
        transport = self._transport_combo.currentData() or "stdio"
        if transport == "stdio":
            if not self._command_edit.text().strip():
                errors.append(self._t("settings.mcp.validation.command_required"))
        else:
            if not self._url_edit.text().strip():
                errors.append(self._t("settings.mcp.validation.url_required"))
        if errors:
            QMessageBox.warning(self, self._t("settings.dialog.settings"), "\n".join(errors))
            return
        self.accept()

    def get_values(self) -> dict:
        transport = self._transport_combo.currentData() or "stdio"

        # args: plain text lines → JSON array string
        args_raw = self._args_edit.toPlainText().strip()
        args_list = [line.strip() for line in args_raw.splitlines() if line.strip()]
        args_json = json.dumps(args_list)

        # env: "KEY=VALUE" lines → JSON object string
        env_raw = self._env_edit.toPlainText().strip()
        env_dict: dict[str, str] = {}
        for line in env_raw.splitlines():
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                env_dict[k.strip()] = v.strip()
        env_json = json.dumps(env_dict) if env_dict else ""

        # headers: "Key: Value" lines → JSON object string
        headers_raw = self._headers_edit.toPlainText().strip()
        headers_dict: dict[str, str] = {}
        for line in headers_raw.splitlines():
            line = line.strip()
            if ":" in line:
                k, v = line.split(":", 1)
                headers_dict[k.strip()] = v.strip()
        headers_json = json.dumps(headers_dict) if headers_dict else ""

        return {
            "name": self._name_edit.text().strip(),
            "transport": transport,
            "command": self._command_edit.text().strip(),
            "args": args_json,
            "env": env_json,
            "cwd": self._cwd_edit.text().strip(),
            "url": self._url_edit.text().strip(),
            "headers": headers_json,
            "timeout": self._timeout_spin.value(),
            "enabled": self._enabled_check.isChecked(),
        }


class McpServerDetailDialog(QDialog):
    """Dialog showing MCP server details including available tools.

    Displays server connection info and a table of tools fetched
    from the MCP server via a background worker.
    """

    def __init__(
        self,
        i18n,
        *,
        server=None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._i18n = i18n
        self._server = server
        self._setup_ui()

    def _t(self, key: str, **kwargs: object) -> str:
        return self._i18n.t(key, **kwargs)

    def _setup_ui(self) -> None:
        server = self._server
        self.setWindowTitle(
            self._t("settings.mcp.detail.title", name=server.name if server else "")
        )
        self.setObjectName("mcpServerDetailDialog")
        self.setMinimumSize(560, 420)
        self.resize(640, 520)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 24, 24, 24)

        if server is None:
            layout.addWidget(QLabel("No server data."))
            return

        # --- Server info section ---
        info_label = QLabel(self._t("settings.mcp.detail.server_info"))
        info_label.setObjectName("dialogSectionTitle")
        layout.addWidget(info_label)

        info_grid = QWidget()
        info_layout = QVBoxLayout(info_grid)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(4)

        transport_labels = {
            "stdio": self._t("settings.mcp.transport.stdio"),
            "http": self._t("settings.mcp.transport.http"),
            "sse": self._t("settings.mcp.transport.sse"),
        }

        # Row helper
        def _info_row(key: str, value: str) -> QWidget:
            row = QWidget()
            rl = QVBoxLayout(row)
            rl.setContentsMargins(0, 0, 0, 0)
            rl.setSpacing(1)
            kl = QLabel(key)
            kl.setObjectName("settingsFieldDescription")
            vl = QLabel(value)
            vl.setObjectName("settingsFieldLabel")
            vl.setWordWrap(True)
            rl.addWidget(kl)
            rl.addWidget(vl)
            return row

        enabled_text = self._t("settings.bool.yes") if server.enabled else self._t("settings.bool.no")
        info_layout.addWidget(_info_row(
            self._t("settings.field.mcp_server_name"), server.name or "—"
        ))
        info_layout.addWidget(_info_row(
            self._t("settings.field.mcp_transport"),
            transport_labels.get(server.transport, server.transport)
        ))
        info_layout.addWidget(_info_row(
            self._t("settings.skills.enabled"), enabled_text
        ))

        if server.transport == "stdio":
            info_layout.addWidget(_info_row(
                self._t("settings.field.mcp_command"), server.command or "—"
            ))
            try:
                args_list = json.loads(server.args) if server.args else []
            except (json.JSONDecodeError, TypeError):
                args_list = []
            args_display = " ".join(args_list) if args_list else "—"
            info_layout.addWidget(_info_row(
                self._t("settings.field.mcp_args"), args_display
            ))
            if server.cwd:
                info_layout.addWidget(_info_row(
                    self._t("settings.field.mcp_cwd"), server.cwd
                ))
        else:
            info_layout.addWidget(_info_row(
                self._t("settings.field.mcp_url"), server.url or "—"
            ))

        layout.addWidget(info_grid)

        # --- Separator ---
        sep = QFrame()
        sep.setObjectName("dialogSeparator")
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        layout.addWidget(sep)

        # --- Tools section ---
        tools_header = QWidget()
        tools_header_layout = QVBoxLayout(tools_header)
        tools_header_layout.setContentsMargins(0, 0, 0, 0)
        tools_header_layout.setSpacing(4)

        tools_title = QLabel(self._t("settings.mcp.detail.tools"))
        tools_title.setObjectName("dialogSectionTitle")
        tools_header_layout.addWidget(tools_title)

        self._tool_count_label = QLabel(
            self._t("settings.mcp.detail.tools_loading")
        )
        self._tool_count_label.setObjectName("settingsFieldDescription")
        tools_header_layout.addWidget(self._tool_count_label)

        layout.addWidget(tools_header)

        # Tools table
        self._tools_table = QTableWidget(0, 2)
        self._tools_table.setObjectName("mcpToolsTable")
        self._tools_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._tools_table.setSelectionMode(QTableWidget.NoSelection)
        self._tools_table.verticalHeader().setVisible(False)
        self._tools_table.setHorizontalHeaderLabels([
            self._t("settings.mcp.detail.tool_name"),
            self._t("settings.mcp.detail.tool_description"),
        ])
        self._tools_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self._tools_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch
        )
        layout.addWidget(self._tools_table, 1)

        # Close button
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        # Start fetching tools
        self._start_tool_fetch(server)

    def _start_tool_fetch(self, server) -> None:
        from app.ui.settings.workers import McpToolFetchWorker

        config = server.to_langchain_config()
        self._fetch_worker = McpToolFetchWorker(
            server_name=server.name,
            server_config=config,
            parent=self,
        )
        self._fetch_worker.tools_fetched.connect(self._on_tools_fetched)
        self._fetch_worker.fetch_failed.connect(self._on_fetch_failed)
        self._fetch_worker.start()

    def _on_tools_fetched(self, tools: list) -> None:
        self._tool_count_label.setText(
            self._t("settings.mcp.detail.tools_count", count=len(tools))
        )
        self._tools_table.setRowCount(len(tools))
        for row_index, tool_info in enumerate(tools):
            name_item = QTableWidgetItem(tool_info.get("name", ""))
            desc_item = QTableWidgetItem(tool_info.get("description", ""))
            desc_item.setToolTip(tool_info.get("description", ""))
            self._tools_table.setItem(row_index, 0, name_item)
            self._tools_table.setItem(row_index, 1, desc_item)

    def _on_fetch_failed(self, error: str) -> None:
        self._tool_count_label.setText(
            self._t("settings.mcp.detail.tools_error", error=error)
        )
        self._tools_table.setRowCount(0)

    def reject(self) -> None:
        # Clean up worker
        worker = getattr(self, "_fetch_worker", None)
        if worker is not None and worker.isRunning():
            worker.requestInterruption()
            worker.wait(3000)
        super().reject()
