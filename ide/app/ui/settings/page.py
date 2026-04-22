"""Settings page for the PySide6 IDE MVP."""

from __future__ import annotations

import json
import os

from PySide6.QtCore import Qt, Signal

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTableWidget,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.i18n import I18n, normalize_language
from app.presenters.settings_presenter import (
    build_check_message,
    build_reinstall_message,
    effective_install_python_path,
    form_state_to_updates,
    snapshot_to_form_state,
)
from app.services.settings_service import SettingsService
from app.ui.settings.dialogs import McpServerDialog, ModelProviderDialog
from app.ui.settings.widgets import (
    NoWheelComboBox,
    NoWheelSpinBox,
)
from app.ui.settings.workers import (
    _ConfigFormBinder,
    _InstallController,
    _InstallationDisplay,
)


# ===================================================================
# SettingsPage — thin orchestrator
# ===================================================================

class SettingsPage(QWidget):
    language_changed = Signal(str)

    def __init__(
        self,
        settings_service: SettingsService | None = None,
    ) -> None:
        super().__init__()
        self._settings_service = settings_service or SettingsService()

        initial_snapshot = self._settings_service.load()
        self._language = normalize_language(initial_snapshot.ide_config.language)
        self._i18n = I18n(self._language)

        self._category_list = QListWidget()
        self._stack = QStackedWidget()
        self._category_row_connected = False
        self._language_combo_connected = False
        self._retained_widgets: list[QWidget] = []

        self._install_notes = QTextEdit()
        self._install_notes.setReadOnly(True)
        self._requirements_path = QLineEdit()
        self._requirements_path.setReadOnly(True)
        self._requirements_table = QTableWidget(0, 3)
        self._requirements_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._requirements_table.setSelectionMode(QTableWidget.NoSelection)
        self._requirements_table.verticalHeader().setVisible(False)
        self._requirements_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self._requirements_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch
        )
        self._requirements_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )
        self._upgrade_notes = QTextEdit()
        self._upgrade_notes.setReadOnly(True)
        self._save_hint_labels: list[QLabel] = []

        self._install_python_path = QLineEdit()
        self._install_python_path.setReadOnly(True)
        self._install_plugin_dir = QLineEdit()
        self._install_plugin_dir.setReadOnly(True)

        self._plugin_dir = QLineEdit()
        self._language_combo = NoWheelComboBox()
        self._ide_request_timeout = NoWheelSpinBox()
        self._ide_request_timeout.setRange(1, 3600)
        self._ide_request_timeout.setSuffix(" s")

        self._enable_http = QCheckBox()
        self._enable_stdio = QCheckBox()
        self._enable_unsafe = QCheckBox()
        self._wsl_path_bridge = QCheckBox()
        self._http_host = QLineEdit()
        self._http_port = NoWheelSpinBox()
        self._http_port.setRange(1, 65535)
        self._http_path = QLineEdit()
        self._ida_default_port = NoWheelSpinBox()
        self._ida_default_port.setRange(1, 65535)
        self._ida_host = QLineEdit()
        self._ida_path = QLineEdit()
        self._ida_python = QLineEdit()
        self._open_in_ida_bundle_dir = QLineEdit()
        self._open_in_ida_bundle_dir_field = self._path_field(
            self._open_in_ida_bundle_dir,
            self._browse_directory,
        )
        self._open_in_ida_autonomous = QCheckBox()
        self._auto_start = QCheckBox()
        self._server_name = QLineEdit()
        self._ida_request_timeout = NoWheelSpinBox()
        self._ida_request_timeout.setRange(1, 3600)
        self._ida_request_timeout.setSuffix(" s")
        self._debug = QCheckBox()

        # --- Model providers widgets ---
        self._model_providers_container = QWidget()
        self._model_providers_layout = QVBoxLayout(self._model_providers_container)
        self._model_providers_layout.setContentsMargins(0, 0, 0, 0)
        self._model_providers_layout.setSpacing(10)
        self._model_providers_layout.addStretch(1)

        # --- MCP settings widgets ---
        self._mcp_servers_container = QWidget()
        self._mcp_servers_layout = QVBoxLayout(self._mcp_servers_container)
        self._mcp_servers_layout.setContentsMargins(0, 0, 0, 0)
        self._mcp_servers_layout.setSpacing(10)
        self._mcp_servers_layout.addStretch(1)

        # --- Skills widgets ---
        self._skills_container = QWidget()
        self._skills_layout = QVBoxLayout(self._skills_container)
        self._skills_layout.setContentsMargins(0, 0, 0, 0)
        self._skills_layout.setSpacing(10)
        self._skills_layout.addStretch(1)

        self._wsl_toggle = QToolButton()
        self._wsl_toggle.setCheckable(True)
        self._wsl_toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self._wsl_toggle.clicked.connect(self._toggle_wsl_section)
        self._wsl_container = QWidget()
        self._wsl_layout = QVBoxLayout(self._wsl_container)
        self._wsl_layout.setContentsMargins(0, 0, 0, 0)
        self._wsl_layout.setSpacing(12)
        self._wsl_path_bridge.toggled.connect(self._sync_wsl_bridge_fields)
        self._wsl_group: QWidget | None = None

        # --- Delegated helpers ---
        self._form_binder = _ConfigFormBinder(self)
        self._install_display = _InstallationDisplay(self)
        self._install_ctrl = _InstallController(
            self,
            self._settings_service,
            on_check_result=self._install_display.apply_installation_check,
            on_install_result=self._handle_install_result,
            on_progress=self._on_install_progress,
            on_busy_changed=self._set_install_buttons_enabled,
        )

        self._build_ui()
        self._apply_snapshot(initial_snapshot)

    def _t(self, key: str, **kwargs: object) -> str:
        return self._i18n.t(key, **kwargs)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        current_row = self._category_list.currentRow()
        self._save_hint_labels.clear()
        self._flush_retained_widgets()
        old_layout = self.layout()
        if old_layout is None:
            root_layout = QVBoxLayout(self)
            root_layout.setContentsMargins(0, 0, 0, 0)
            root_layout.setSpacing(10)

            body = QWidget()
            body_layout = QHBoxLayout(body)
            body_layout.setContentsMargins(0, 0, 0, 0)
            body_layout.setSpacing(0)
            body_layout.addWidget(self._category_list)
            body_layout.addWidget(self._stack, 1)

            root_layout.addWidget(body, 1)

        self._category_list.clear()
        self._category_list.setObjectName("settingsCategoryList")
        self._category_list.setFixedWidth(180)
        for name in (
            self._t("settings.category.config"),
            self._t("settings.category.install"),
            self._t("settings.category.upgrade"),
            self._t("settings.category.model"),
            self._t("settings.category.mcp_settings"),
            self._t("settings.category.skills"),
        ):
            item = QListWidgetItem(name)
            font = item.font()
            if font.pointSize() <= 0:
                ps = self.font().pointSize()
                font.setPointSize(ps if ps > 0 else 10)
            font.setBold(False)
            item.setFont(font)
            self._category_list.addItem(item)
        if not self._category_row_connected:
            self._category_list.currentRowChanged.connect(self._stack.setCurrentIndex)
            self._category_row_connected = True

        while self._stack.count():
            page = self._stack.widget(0)
            self._stack.removeWidget(page)
            page.setParent(None)
            self._retained_widgets.append(page)

        self._stack.addWidget(self._build_config_page())
        self._stack.addWidget(self._build_install_page())
        self._stack.addWidget(self._build_upgrade_page())
        self._stack.addWidget(self._build_model_page())
        self._stack.addWidget(self._build_mcp_settings_page())
        self._stack.addWidget(self._build_skills_page())

        if current_row < 0:
            current_row = 0
        self._category_list.setCurrentRow(current_row)

    def _build_config_page(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        layout.addWidget(
            self._build_config_group(
                self._t("settings.group.global_paths"),
                self._t("settings.group.global_paths.desc"),
                [
                    self._build_field_row(
                        self._t("settings.field.plugin_dir"),
                        self._t("settings.field.plugin_dir.desc"),
                        self._path_field(self._plugin_dir, self._browse_directory),
                    ),
                ],
            )
        )
        layout.addWidget(
            self._build_config_group(
                self._t("settings.group.runtime"),
                self._t("settings.group.runtime.desc"),
                [
                    self._build_field_row(
                        self._t("settings.field.language"),
                        self._t("settings.field.language.desc"),
                        self._build_language_field(),
                    ),
                    self._build_field_row(
                        self._t("settings.field.ide_request_timeout"),
                        self._t("settings.field.ide_request_timeout.desc"),
                        self._ide_request_timeout,
                    ),
                ],
            )
        )
        layout.addWidget(
            self._build_config_group(
                self._t("settings.group.transport"),
                self._t("settings.group.transport.desc"),
                [
                    self._build_checkbox_row(
                        self._enable_http,
                        self._t("settings.field.enable_http"),
                        self._t("settings.field.enable_http.desc"),
                    ),
                    self._build_checkbox_row(
                        self._enable_stdio,
                        self._t("settings.field.enable_stdio"),
                        self._t("settings.field.enable_stdio.desc"),
                    ),
                    self._build_checkbox_row(
                        self._enable_unsafe,
                        self._t("settings.field.enable_unsafe"),
                        self._t("settings.field.enable_unsafe.desc"),
                    ),
                    self._build_field_row(
                        self._t("settings.field.http_host"),
                        self._t("settings.field.http_host.desc"),
                        self._http_host,
                    ),
                    self._build_field_row(
                        self._t("settings.field.http_port"),
                        self._t("settings.field.http_port.desc"),
                        self._http_port,
                    ),
                    self._build_field_row(
                        self._t("settings.field.http_path"),
                        self._t("settings.field.http_path.desc"),
                        self._http_path,
                    ),
                    self._build_checkbox_row(
                        self._debug,
                        self._t("settings.field.debug"),
                        self._t("settings.field.debug.desc"),
                    ),
                ],
            )
        )
        layout.addWidget(
            self._build_config_group(
                self._t("settings.group.execution"),
                self._t("settings.group.execution.desc"),
                [
                    self._build_field_row(
                        self._t("settings.field.ida_executable"),
                        self._t("settings.field.ida_executable.desc"),
                        self._path_field(self._ida_path, self._browse_file),
                    ),
                    self._build_field_row(
                        self._t("settings.field.ida_python"),
                        self._t("settings.field.ida_python_effective.desc"),
                        self._path_field(self._ida_python, self._browse_file),
                    ),
                    self._build_field_row(
                        self._t("settings.field.ida_default_port"),
                        self._t("settings.field.ida_default_port.desc"),
                        self._ida_default_port,
                    ),
                    self._build_field_row(
                        self._t("settings.field.ida_host"),
                        self._t("settings.field.ida_host.desc"),
                        self._ida_host,
                    ),
                    self._build_field_row(
                        self._t("settings.field.ida_request_timeout"),
                        self._t("settings.field.ida_request_timeout.desc"),
                        self._ida_request_timeout,
                    ),
                    self._build_checkbox_row(
                        self._open_in_ida_autonomous,
                        self._t("settings.field.open_in_ida_autonomous"),
                        self._t("settings.field.open_in_ida_autonomous.desc"),
                    ),
                    self._build_checkbox_row(
                        self._auto_start,
                        self._t("settings.field.auto_start"),
                        self._t("settings.field.auto_start.desc"),
                    ),
                    self._build_field_row(
                        self._t("settings.field.server_name"),
                        self._t("settings.field.server_name.desc"),
                        self._server_name,
                    ),
                ],
            )
        )

        self._refresh_wsl_section()
        layout.addWidget(self._wsl_toggle)
        layout.addWidget(self._wsl_container)

        layout.addStretch(1)

        layout.addWidget(self._build_save_bar(show_hint=True))

        return self._wrap_scroll(widget)

    def _build_install_page(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        layout.addWidget(
            self._build_config_group(
                self._t("settings.install.inputs"),
                self._t("settings.install.inputs.desc"),
                [
                    self._build_field_row(
                        self._t("settings.field.ida_python"),
                        self._t("settings.field.ida_python_effective.desc"),
                        self._install_python_path,
                    ),
                    self._build_field_row(
                        self._t("settings.field.plugin_dir"),
                        self._t("settings.field.plugin_dir.desc"),
                        self._install_plugin_dir,
                    ),
                ],
            )
        )
        layout.addWidget(
            self._build_config_group(
                self._t("settings.install.requirements"),
                self._t("settings.install.requirements.desc"),
                [
                    self._build_field_row(
                        self._t("settings.install.requirements_path"),
                        self._t("settings.install.requirements_path.desc"),
                        self._requirements_path,
                    ),
                    self._requirements_table,
                ],
            )
        )
        layout.addWidget(
            self._build_config_group(
                self._t("settings.category.install"),
                self._t("settings.install.placeholder"),
                [self._install_notes],
            )
        )

        action_bar = QWidget()
        action_bar_layout = QHBoxLayout(action_bar)
        action_bar_layout.setContentsMargins(0, 0, 0, 0)
        action_bar_layout.setSpacing(8)
        check_button = QPushButton(self._t("settings.install.check"))
        check_button.clicked.connect(self.check)
        install_button = QPushButton(self._t("settings.install.install"))
        install_button.setObjectName("primaryButton")
        install_button.clicked.connect(self.reinstall)
        action_bar_layout.addStretch(1)
        action_bar_layout.addWidget(check_button)
        action_bar_layout.addWidget(install_button)
        layout.addWidget(action_bar)

        layout.addStretch(1)
        return self._wrap_scroll(widget)

    def _build_upgrade_page(self) -> QWidget:
        self._upgrade_notes.setPlainText(self._t("settings.upgrade.placeholder"))
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        layout.addWidget(
            self._build_config_group(
                self._t("settings.category.upgrade"),
                self._t("settings.upgrade.placeholder"),
                [self._upgrade_notes],
            )
        )
        layout.addStretch(1)
        return widget

    # ------------------------------------------------------------------
    # Model providers page
    # ------------------------------------------------------------------

    def _build_model_page(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        layout.addWidget(
            self._build_config_group(
                self._t("settings.group.model_providers"),
                self._t("settings.group.model_providers.desc"),
                [self._model_providers_container],
            )
        )

        action_bar = QWidget()
        action_bar_layout = QHBoxLayout(action_bar)
        action_bar_layout.setContentsMargins(0, 0, 0, 0)
        action_bar_layout.setSpacing(8)
        add_button = QPushButton(self._t("settings.model.add"))
        add_button.setObjectName("primaryButton")
        add_button.clicked.connect(self._add_model_provider)
        action_bar_layout.addWidget(add_button)
        action_bar_layout.addStretch(1)
        layout.addWidget(action_bar)

        layout.addStretch(1)
        layout.addWidget(self._build_save_bar(show_hint=True))
        return self._wrap_scroll(widget)

    def _add_model_provider(self) -> None:
        dialog = ModelProviderDialog(self._i18n, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        values = dialog.get_values()
        self._settings_service.add_model_provider(**values)
        self._refresh_model_cards()

    def _edit_model_provider(self, provider_id: int) -> None:
        providers = self._settings_service.get_model_providers()
        provider = next((p for p in providers if p.id == provider_id), None)
        if provider is None:
            return
        dialog = ModelProviderDialog(self._i18n, provider=provider, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        values = dialog.get_values()
        self._settings_service.update_model_provider(provider_id, **values)
        self._refresh_model_cards()

    def _delete_model_provider(self, provider_id: int) -> None:
        self._settings_service.remove_model_provider(provider_id)
        self._refresh_model_cards()

    def _toggle_provider_enabled(
        self, provider_id: int, state: int, card: QFrame
    ) -> None:
        """Toggle provider enabled state and persist immediately."""
        from PySide6.QtCore import Qt as QtCoreQt

        enabled = state == QtCoreQt.CheckState.Checked.value
        self._settings_service.update_model_provider(
            provider_id, enabled=enabled
        )
        # Update card style without rebuilding the whole list
        card.setProperty("provider_enabled", "true" if enabled else "false")
        card.style().unpolish(card)
        card.style().polish(card)

    def _refresh_model_cards(self) -> None:
        # Remove existing cards (keep the trailing stretch)
        while self._model_providers_layout.count():
            item = self._model_providers_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()

        providers = self._settings_service.get_model_providers()
        if not providers:
            empty = QLabel(self._t("settings.model.empty"))
            empty.setObjectName("settingsFieldDescription")
            empty.setWordWrap(True)
            self._model_providers_layout.addWidget(empty)
            self._model_providers_layout.addStretch(1)
            return

        for provider in providers:
            self._model_providers_layout.addWidget(
                self._build_provider_card(provider)
            )
        self._model_providers_layout.addStretch(1)

    def _build_provider_card(self, provider) -> QFrame:
        """Build a single model provider card widget."""
        card = QFrame()
        card.setObjectName("modelProviderCard")
        card.setProperty("provider_enabled", "true" if provider.enabled else "false")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(6)

        api_mode_labels = {
            "openai_responses": self._t("settings.model.api_mode.openai_responses"),
            "openai_compatible": self._t("settings.model.api_mode.openai_compatible"),
            "anthropic": self._t("settings.model.api_mode.anthropic"),
        }

        # --- Header row: name + enabled toggle + buttons ---
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(8)

        name_label = QLabel(provider.name or "—")
        name_label.setObjectName("settingsFieldLabel")
        name_font = name_label.font()
        name_font.setPointSize(name_font.pointSize() + 1)
        name_font.setBold(True)
        name_label.setFont(name_font)
        header_layout.addWidget(name_label)

        enabled_check = QCheckBox(self._t("settings.skills.enabled"))
        enabled_check.setChecked(provider.enabled)
        enabled_check.setCursor(Qt.CursorShape.PointingHandCursor)
        enabled_check.stateChanged.connect(
            lambda state, pid=provider.id, c=card: self._toggle_provider_enabled(pid, state, c)
        )
        header_layout.addWidget(enabled_check)

        header_layout.addStretch(1)

        edit_btn = QPushButton(self._t("settings.model.dialog.edit"))
        edit_btn.setObjectName("modelCardEditButton")
        edit_btn.setFixedHeight(28)
        edit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        edit_btn.clicked.connect(
            lambda checked, pid=provider.id: self._edit_model_provider(pid)
        )
        header_layout.addWidget(edit_btn)

        del_btn = QPushButton(self._t("settings.model.remove"))
        del_btn.setObjectName("dangerButton")
        del_btn.setFixedHeight(28)
        del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        del_btn.clicked.connect(
            lambda checked, pid=provider.id: self._delete_model_provider(pid)
        )
        header_layout.addWidget(del_btn)

        card_layout.addWidget(header)

        separator = QFrame()
        separator.setObjectName("cardSeparator")
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFixedHeight(1)
        card_layout.addWidget(separator)

        # --- Details row ---
        details = QWidget()
        details_layout = QHBoxLayout(details)
        details_layout.setContentsMargins(0, 4, 0, 0)
        details_layout.setSpacing(24)

        # Model ID + API Mode
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(2)
        left_layout.addWidget(self._detail_label(
            self._t("settings.field.model_id"), provider.model_name or "—"
        ))
        left_layout.addWidget(self._detail_label(
            self._t("settings.field.model_api_mode"),
            api_mode_labels.get(provider.api_mode, provider.api_mode),
        ))
        details_layout.addWidget(left, 1)

        # Base URL + Top-P / Temperature
        mid = QWidget()
        mid_layout = QVBoxLayout(mid)
        mid_layout.setContentsMargins(0, 0, 0, 0)
        mid_layout.setSpacing(2)
        base_url_display = provider.base_url or "—"
        if len(base_url_display) > 40:
            base_url_display = base_url_display[:37] + "..."
        mid_layout.addWidget(self._detail_label(
            self._t("settings.field.model_base_url"), base_url_display
        ))
        mid_layout.addWidget(self._detail_label(
            f"{self._t('settings.field.model_top_p')} / {self._t('settings.field.model_temperature')}",
            f"{provider.top_p:.2f} / {provider.temperature:.1f}",
        ))
        details_layout.addWidget(mid, 1)

        card_layout.addWidget(details)

        return card

    def _detail_label(self, key: str, value: str) -> QWidget:
        """Build a key:value detail row for a card."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(1)
        key_label = QLabel(key)
        key_label.setObjectName("settingsFieldDescription")
        val_label = QLabel(value)
        val_label.setObjectName("settingsFieldLabel")
        layout.addWidget(key_label)
        layout.addWidget(val_label)
        return w

    # ------------------------------------------------------------------
    # MCP settings page
    # ------------------------------------------------------------------

    def _build_mcp_settings_page(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        layout.addWidget(
            self._build_config_group(
                self._t("settings.group.mcp_servers"),
                self._t("settings.group.mcp_servers.desc"),
                [self._mcp_servers_container],
            )
        )

        action_bar = QWidget()
        action_bar_layout = QHBoxLayout(action_bar)
        action_bar_layout.setContentsMargins(0, 0, 0, 0)
        action_bar_layout.setSpacing(8)
        add_button = QPushButton(self._t("settings.mcp.add"))
        add_button.setObjectName("primaryButton")
        add_button.clicked.connect(self._add_mcp_server)
        action_bar_layout.addWidget(add_button)
        action_bar_layout.addStretch(1)
        layout.addWidget(action_bar)

        layout.addStretch(1)
        layout.addWidget(self._build_save_bar(show_hint=True))
        return self._wrap_scroll(widget)

    # --- MCP server CRUD handlers ---

    def _refresh_mcp_servers(self) -> None:
        """Populate the MCP server cards from the service."""
        while self._mcp_servers_layout.count():
            item = self._mcp_servers_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()

        servers = self._settings_service.get_mcp_servers()
        if not servers:
            empty = QLabel(self._t("settings.mcp.empty"))
            empty.setObjectName("settingsFieldDescription")
            self._mcp_servers_layout.addWidget(empty)
            self._mcp_servers_layout.addStretch(1)
            return

        for server in servers:
            self._mcp_servers_layout.addWidget(
                self._build_mcp_server_card(server)
            )
        self._mcp_servers_layout.addStretch(1)

    def _add_mcp_server(self) -> None:
        dialog = McpServerDialog(self._i18n, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            values = dialog.get_values()
            self._settings_service.add_mcp_server(**values)
            self._refresh_mcp_servers()

    def _delete_mcp_server(self, server_id: int) -> None:
        self._settings_service.remove_mcp_server(server_id)
        self._refresh_mcp_servers()

    def _toggle_mcp_server_enabled(self, server_id: int, enabled: bool) -> None:
        self._settings_service.update_mcp_server(server_id, enabled=enabled)
        self._refresh_mcp_servers()

    def _edit_mcp_server(self, server_id: int) -> None:
        servers = self._settings_service.get_mcp_servers()
        server = next((s for s in servers if s.id == server_id), None)
        if server is None:
            return
        dialog = McpServerDialog(self._i18n, server=server, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            values = dialog.get_values()
            self._settings_service.update_mcp_server(server_id, **values)
            self._refresh_mcp_servers()

    def _build_mcp_server_card(self, server) -> QFrame:
        """Build a single MCP server card widget."""
        card = QFrame()
        card.setObjectName("modelProviderCard")
        card.setProperty("server_enabled", "true" if server.enabled else "false")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(6)

        transport_labels = {
            "stdio": self._t("settings.mcp.transport.stdio"),
            "http": self._t("settings.mcp.transport.http"),
            "sse": self._t("settings.mcp.transport.sse"),
        }

        # --- Header row: name + transport badge + enabled + buttons ---
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(8)

        name_label = QLabel(server.name or "—")
        name_label.setObjectName("settingsFieldLabel")
        name_font = name_label.font()
        name_font.setPointSize(name_font.pointSize() + 1)
        name_font.setBold(True)
        name_label.setFont(name_font)
        header_layout.addWidget(name_label)

        transport_label = QLabel(transport_labels.get(server.transport, server.transport))
        transport_label.setObjectName("cardBadgeTransport")
        header_layout.addWidget(transport_label)

        enabled_label = QLabel(
            "● " + (self._t("settings.bool.yes") if server.enabled else self._t("settings.bool.no"))
        )
        enabled_label.setObjectName("cardBadgeEnabled" if server.enabled else "cardBadgeDisabled")
        header_layout.addWidget(enabled_label)

        header_layout.addStretch(1)

        toggle_btn = QPushButton(
            self._t("settings.bool.no") if server.enabled else self._t("settings.bool.yes")
        )
        toggle_btn.setObjectName("cardToggleButton")
        toggle_btn.setProperty("active", "true" if server.enabled else "false")
        toggle_btn.setFixedHeight(28)
        toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        toggle_btn.clicked.connect(
            lambda checked, sid=server.id, en=not server.enabled: self._toggle_mcp_server_enabled(sid, en)
        )
        header_layout.addWidget(toggle_btn)

        edit_btn = QPushButton(self._t("settings.model.dialog.edit"))
        edit_btn.setObjectName("modelCardEditButton")
        edit_btn.setFixedHeight(28)
        edit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        edit_btn.clicked.connect(
            lambda checked, sid=server.id: self._edit_mcp_server(sid)
        )
        header_layout.addWidget(edit_btn)

        del_btn = QPushButton(self._t("settings.mcp.remove"))
        del_btn.setObjectName("dangerButton")
        del_btn.setFixedHeight(28)
        del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        del_btn.clicked.connect(
            lambda checked, sid=server.id: self._delete_mcp_server(sid)
        )
        header_layout.addWidget(del_btn)

        card_layout.addWidget(header)

        separator = QFrame()
        separator.setObjectName("cardSeparator")
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFixedHeight(1)
        card_layout.addWidget(separator)

        # --- Details row ---
        details = QWidget()
        details_layout = QHBoxLayout(details)
        details_layout.setContentsMargins(0, 4, 0, 0)
        details_layout.setSpacing(24)

        if server.transport == "stdio":
            left = QWidget()
            left_layout = QVBoxLayout(left)
            left_layout.setContentsMargins(0, 0, 0, 0)
            left_layout.setSpacing(2)
            left_layout.addWidget(self._detail_label(
                self._t("settings.field.mcp_command"), server.command or "—"
            ))
            details_layout.addWidget(left, 1)

            mid = QWidget()
            mid_layout = QVBoxLayout(mid)
            mid_layout.setContentsMargins(0, 0, 0, 0)
            mid_layout.setSpacing(2)
            try:
                args_list = json.loads(server.args) if server.args else []
            except (json.JSONDecodeError, TypeError):
                args_list = []
            args_display = " ".join(args_list) if args_list else "—"
            if len(args_display) > 50:
                args_display = args_display[:47] + "..."
            mid_layout.addWidget(self._detail_label(
                self._t("settings.field.mcp_args"), args_display
            ))
            details_layout.addWidget(mid, 1)

            right = QWidget()
            right_layout = QVBoxLayout(right)
            right_layout.setContentsMargins(0, 0, 0, 0)
            right_layout.setSpacing(2)
            cwd_display = server.cwd or "—"
            if len(cwd_display) > 40:
                cwd_display = cwd_display[:37] + "..."
            right_layout.addWidget(self._detail_label(
                self._t("settings.field.mcp_cwd"), cwd_display
            ))
            details_layout.addWidget(right, 1)
        else:
            left = QWidget()
            left_layout = QVBoxLayout(left)
            left_layout.setContentsMargins(0, 0, 0, 0)
            left_layout.setSpacing(2)
            url_display = server.url or "—"
            if len(url_display) > 60:
                url_display = url_display[:57] + "..."
            left_layout.addWidget(self._detail_label(
                self._t("settings.field.mcp_url"), url_display
            ))
            details_layout.addWidget(left, 2)

            right = QWidget()
            right_layout = QVBoxLayout(right)
            right_layout.setContentsMargins(0, 0, 0, 0)
            right_layout.setSpacing(2)
            right_layout.addWidget(self._detail_label(
                self._t("settings.field.mcp_timeout"),
                f"{server.timeout:.1f} s",
            ))
            details_layout.addWidget(right, 1)

        card_layout.addWidget(details)

        return card

    # ------------------------------------------------------------------
    # Skills settings page
    # ------------------------------------------------------------------

    def _build_skills_page(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        layout.addWidget(
            self._build_config_group(
                self._t("settings.group.skills_registry"),
                self._t("settings.group.skills_registry.desc"),
                [self._skills_container],
            )
        )

        action_bar = QWidget()
        action_bar_layout = QHBoxLayout(action_bar)
        action_bar_layout.setContentsMargins(0, 0, 0, 0)
        action_bar_layout.setSpacing(8)
        import_button = QPushButton(self._t("settings.skills.import"))
        import_button.setObjectName("primaryButton")
        import_button.clicked.connect(self._import_skill_zip)
        action_bar_layout.addWidget(import_button)
        action_bar_layout.addStretch(1)
        layout.addWidget(action_bar)

        layout.addStretch(1)
        layout.addWidget(self._build_save_bar(show_hint=True))
        return self._wrap_scroll(widget)

    # --- Skills CRUD handlers ---

    def _refresh_skills(self) -> None:
        """Populate the skill cards from the service."""
        while self._skills_layout.count():
            item = self._skills_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()

        skills = self._settings_service.get_skills()
        if not skills:
            empty = QLabel(self._t("settings.skills.empty"))
            empty.setObjectName("settingsFieldDescription")
            empty.setWordWrap(True)
            self._skills_layout.addWidget(empty)
            self._skills_layout.addStretch(1)
            return

        for skill in skills:
            self._skills_layout.addWidget(self._build_skill_card(skill))
        self._skills_layout.addStretch(1)

    def _import_skill_zip(self) -> None:
        """Open a file dialog to select and import a skill zip package."""
        start = ""
        selected, _ = QFileDialog.getOpenFileName(
            self,
            self._t("settings.skills.dialog.import"),
            start,
            "Zip Packages (*.zip);;All Files (*)",
        )
        if not selected:
            return

        import shutil
        import tempfile
        import zipfile
        from datetime import datetime, timezone
        from pathlib import Path

        zip_path = Path(selected)
        file_name = zip_path.name

        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp = Path(tmp_dir)
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(tmp)

                manifest = None
                skill_root = tmp
                for candidate in (tmp / "skill.json", tmp / "package.json"):
                    if candidate.exists():
                        manifest = json.loads(candidate.read_text(encoding="utf-8"))
                        break

                if manifest is None:
                    for subdir in tmp.iterdir():
                        if subdir.is_dir():
                            for candidate in (subdir / "skill.json", subdir / "package.json"):
                                if candidate.exists():
                                    manifest = json.loads(candidate.read_text(encoding="utf-8"))
                                    skill_root = subdir
                                    break
                            if manifest:
                                break

                skill_name = manifest.get("name", "") if manifest else zip_path.stem
                if not skill_name:
                    skill_name = zip_path.stem
                skill_description = manifest.get("description", "") if manifest else ""
                skill_version = manifest.get("version", "") if manifest else ""

                safe_name = "".join(
                    c if c.isalnum() or c in ("-", "_") else "_" for c in skill_name
                )
                install_dir_name = safe_name

                skills_dir = self._settings_service.get_skills_dir()
                dest = skills_dir / install_dir_name
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(skill_root, dest)

            now = datetime.now(timezone.utc).isoformat()
            self._settings_service.add_skill(
                name=skill_name,
                description=skill_description,
                version=skill_version,
                file_path=file_name,
                install_dir=install_dir_name,
                installed_at=now,
            )
            self._refresh_skills()
            QMessageBox.information(
                self,
                self._t("settings.dialog.settings"),
                self._t("settings.skills.import_success", name=skill_name),
            )
        except Exception as exc:
            QMessageBox.warning(
                self,
                self._t("settings.dialog.settings"),
                self._t("settings.skills.import_failed", error=str(exc)),
            )

    def _delete_skill(self, skill_id: int) -> None:
        """Remove a skill and delete its installed files."""
        import shutil

        skills = self._settings_service.get_skills()
        skill = next((s for s in skills if s.id == skill_id), None)
        if skill is None:
            return

        reply = QMessageBox.question(
            self,
            self._t("settings.dialog.settings"),
            self._t("settings.skills.remove_confirm", name=skill.name),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        if skill.install_dir:
            try:
                skills_dir = self._settings_service.get_skills_dir()
                dest = skills_dir / skill.install_dir
                if dest.exists():
                    shutil.rmtree(dest)
            except Exception:
                pass

        self._settings_service.remove_skill(skill_id)
        self._refresh_skills()

    def _toggle_skill_enabled(self, skill_id: int, enabled: bool) -> None:
        self._settings_service.update_skill(skill_id, enabled=enabled)
        self._refresh_skills()

    def _build_skill_card(self, skill) -> QFrame:
        """Build a single skill card widget."""
        card = QFrame()
        card.setObjectName("modelProviderCard")
        card.setProperty("skill_enabled", "true" if skill.enabled else "false")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(6)

        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(8)

        name_label = QLabel(skill.name or "—")
        name_label.setObjectName("settingsFieldLabel")
        name_font = name_label.font()
        name_font.setPointSize(name_font.pointSize() + 1)
        name_font.setBold(True)
        name_label.setFont(name_font)
        header_layout.addWidget(name_label)

        if skill.version:
            version_label = QLabel(f"v{skill.version}")
            version_label.setObjectName("cardBadgeVersion")
            header_layout.addWidget(version_label)

        enabled_label = QLabel(
            "● " + (self._t("settings.bool.yes") if skill.enabled else self._t("settings.bool.no"))
        )
        enabled_label.setObjectName("cardBadgeEnabled" if skill.enabled else "cardBadgeDisabled")
        header_layout.addWidget(enabled_label)

        header_layout.addStretch(1)

        toggle_btn = QPushButton(
            self._t("settings.bool.no") if skill.enabled else self._t("settings.bool.yes")
        )
        toggle_btn.setObjectName("cardToggleButton")
        toggle_btn.setProperty("active", "true" if skill.enabled else "false")
        toggle_btn.setFixedHeight(28)
        toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        toggle_btn.clicked.connect(
            lambda checked, sid=skill.id, en=not skill.enabled: self._toggle_skill_enabled(sid, en)
        )
        header_layout.addWidget(toggle_btn)

        del_btn = QPushButton(self._t("settings.skills.remove"))
        del_btn.setObjectName("dangerButton")
        del_btn.setFixedHeight(28)
        del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        del_btn.clicked.connect(lambda checked, sid=skill.id: self._delete_skill(sid))
        header_layout.addWidget(del_btn)

        card_layout.addWidget(header)

        separator = QFrame()
        separator.setObjectName("cardSeparator")
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFixedHeight(1)
        card_layout.addWidget(separator)

        details = QWidget()
        details_layout = QHBoxLayout(details)
        details_layout.setContentsMargins(0, 4, 0, 0)
        details_layout.setSpacing(24)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(2)
        desc_display = skill.description or "—"
        if len(desc_display) > 80:
            desc_display = desc_display[:77] + "..."
        left_layout.addWidget(
            self._detail_label(self._t("settings.skills.description"), desc_display)
        )
        details_layout.addWidget(left, 2)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(2)
        right_layout.addWidget(
            self._detail_label(self._t("settings.skills.version"), skill.version or "—")
        )
        installed_display = skill.installed_at[:10] if skill.installed_at else "—"
        right_layout.addWidget(
            self._detail_label(
                self._t("settings.skills.installed_at"), installed_display
            )
        )
        details_layout.addWidget(right, 1)

        card_layout.addWidget(details)

        return card

    # ------------------------------------------------------------------
    # Snapshot / state application
    # ------------------------------------------------------------------

    def reload(self) -> None:
        self._apply_snapshot(self._settings_service.load())

    def _apply_snapshot(self, snapshot) -> None:
        previous_language = self._language
        self._language = normalize_language(snapshot.ide_config.language)
        self._i18n.set_language(self._language)
        self._refresh_language_combo()

        form_state = snapshot_to_form_state(snapshot)
        self._plugin_dir.setText(form_state.plugin_dir)
        self._ide_request_timeout.setValue(form_state.ide_request_timeout)
        self._install_python_path.setText(effective_install_python_path(snapshot))
        self._install_plugin_dir.setText(form_state.plugin_dir)
        self._set_all_save_hints(self._t("settings.save_hint"))
        self._install_notes.setPlaceholderText(self._t("settings.install.placeholder"))

        # Defer installation check to a background worker — never block UI.
        self._install_ctrl.run_check()

        self._form_binder.apply_form_state(form_state)

        self._refresh_model_cards()
        self._refresh_mcp_servers()
        self._refresh_skills()

        self._sync_wsl_bridge_fields()
        if self._language != previous_language:
            self.language_changed.emit(self._language)

    # ------------------------------------------------------------------
    # Save / check / install
    # ------------------------------------------------------------------

    def cleanup(self) -> None:
        """Stop background workers. Call before the page is destroyed."""
        self._install_ctrl.cleanup()
        self._flush_retained_widgets()

    def _flush_retained_widgets(self) -> None:
        """Schedule deferred deletion for all retained widgets."""
        for w in self._retained_widgets:
            w.deleteLater()
        self._retained_widgets.clear()

    def save(self) -> None:
        self._save_settings(show_message=True)

    def _save_settings(self, *, show_message: bool) -> None:
        form_state = self._form_binder.collect_form_state(self)
        ide_updates, ida_mcp_updates = form_state_to_updates(form_state)
        snapshot = self._settings_service.save(
            ide_updates=ide_updates,
            ida_mcp_updates=ida_mcp_updates,
        )
        self._apply_snapshot(snapshot)
        self._set_all_save_hints(self._t("settings.saved"))
        if show_message:
            QMessageBox.information(
                self,
                self._t("settings.dialog.settings"),
                self._t("settings.saved.message"),
            )

    def check(self) -> None:
        self._save_settings(show_message=False)
        # The save above triggers _apply_snapshot which fires a background
        # check.  We also run a synchronous check here for the dialog message,
        # matching the original behaviour for the "Check" button.
        installation = self._settings_service.check_installation()
        self._install_display.apply_installation_check(installation)
        report = self._settings_service.check()
        message = build_check_message(report, installation, self._t, self._bool_text)
        self._install_notes.setPlainText(message.details)
        QMessageBox.information(
            self,
            self._t("settings.dialog.check"),
            message.details,
        )

    def reinstall(self) -> None:
        self._save_settings(show_message=False)
        self._set_install_buttons_enabled(False)
        self._install_notes.setPlainText("")
        self._install_notes.append(self._t("settings.install.starting"))
        self._install_ctrl.run_install()

    def _on_install_progress(self, message: str) -> None:
        self._install_notes.append(message)

    def _handle_install_result(self, result) -> None:
        self._install_display.apply_installation_check(result.check)
        message = build_reinstall_message(result, self._t, self._bool_text)
        QMessageBox.information(
            self,
            self._t("settings.dialog.install"),
            message.details,
        )

    def _set_install_buttons_enabled(self, enabled: bool) -> None:
        page = self._stack.widget(1)  # install page
        if page is None:
            return
        for button in page.findChildren(QPushButton):
            button.setEnabled(enabled)

    # ------------------------------------------------------------------
    # Reusable widget builders
    # ------------------------------------------------------------------

    def _build_config_group(
        self,
        title: str,
        description: str,
        rows: list[QWidget],
    ) -> QWidget:
        container = QFrame()
        container.setObjectName("settingsGroup")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        title_label = QLabel(title)
        title_label.setObjectName("settingsGroupTitle")
        description_label = QLabel(description)
        description_label.setObjectName("settingsGroupDescription")
        description_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(description_label)
        layout.addSpacing(4)
        for row in rows:
            layout.addWidget(row)
        return container

    def _set_all_save_hints(self, text: str) -> None:
        for label in self._save_hint_labels:
            label.setText(text)

    def _build_save_bar(self, *, show_hint: bool) -> QWidget:
        save_bar = QWidget()
        save_bar_layout = QHBoxLayout(save_bar)
        save_bar_layout.setContentsMargins(0, 8, 0, 0)
        save_bar_layout.setSpacing(8)
        if show_hint:
            hint = QLabel(self._t("settings.save_hint"))
            hint.setObjectName("settingsHint")
            save_bar_layout.addWidget(hint, 1)
            self._save_hint_labels.append(hint)
        else:
            save_bar_layout.addStretch(1)
        save_button = QPushButton(self._t("settings.save"))
        save_button.setObjectName("primaryButton")
        save_button.clicked.connect(self.save)
        reload_button = QPushButton(self._t("settings.reload"))
        reload_button.clicked.connect(self.reload)
        save_bar_layout.addWidget(reload_button)
        save_bar_layout.addWidget(save_button)
        return save_bar

    def _build_field_row(self, label: str, description: str, field: QWidget) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        label_widget = QLabel(label)
        label_widget.setObjectName("settingsFieldLabel")
        description_widget = QLabel(description)
        description_widget.setWordWrap(True)
        description_widget.setObjectName("settingsFieldDescription")

        layout.addWidget(label_widget)
        layout.addWidget(description_widget)
        layout.addWidget(field)
        return container

    def _build_checkbox_row(
        self,
        checkbox: QCheckBox,
        label: str,
        description: str,
    ) -> QWidget:
        checkbox.setText(label)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(2)

        description_widget = QLabel(description)
        description_widget.setWordWrap(True)
        description_widget.setObjectName("settingsFieldDescription")

        layout.addWidget(checkbox)
        layout.addWidget(description_widget)
        return container

    def _build_language_field(self) -> QWidget:
        self._refresh_language_combo()
        return self._language_combo

    def _refresh_language_combo(self) -> None:
        self._language_combo.blockSignals(True)
        self._language_combo.clear()
        self._language_combo.addItem(self._t("settings.language.english"), "en")
        self._language_combo.addItem(self._t("settings.language.chinese"), "zh")
        self._language_combo.setCurrentIndex(0 if self._language == "en" else 1)
        if not self._language_combo_connected:
            self._language_combo.currentIndexChanged.connect(self._on_language_changed)
            self._language_combo_connected = True
        self._language_combo.blockSignals(False)

    def _on_language_changed(self) -> None:
        language = normalize_language(self._language_combo.currentData())
        if language == self._language:
            return
        self._language = language
        self._i18n.set_language(language)
        self._build_ui()
        self._set_all_save_hints(self._t("settings.save_hint"))
        self._install_notes.setPlaceholderText(self._t("settings.install.placeholder"))
        self.language_changed.emit(language)

    def _wrap_scroll(self, widget: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(widget)
        return scroll

    def _path_field(self, widget: QLineEdit, picker) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        button = QPushButton(self._t("settings.button.browse"))
        button.clicked.connect(lambda: picker(widget))
        layout.addWidget(widget, 1)
        layout.addWidget(button)
        return container

    def _browse_file(self, widget: QLineEdit) -> None:
        start = widget.text().strip() or ""
        selected, _ = QFileDialog.getOpenFileName(
            self,
            self._t("settings.dialog.select_file"),
            start,
        )
        if selected:
            widget.setText(os.path.normpath(selected))

    def _browse_directory(self, widget: QLineEdit) -> None:
        start = widget.text().strip() or ""
        selected = QFileDialog.getExistingDirectory(
            self,
            self._t("settings.dialog.select_directory"),
            start,
        )
        if selected:
            widget.setText(os.path.normpath(selected))

    def _bool_text(self, value: bool) -> str:
        return self._t("settings.bool.yes") if value else self._t("settings.bool.no")

    # ------------------------------------------------------------------
    # WSL section toggles
    # ------------------------------------------------------------------

    def _toggle_wsl_section(self) -> None:
        self._refresh_wsl_section()

    def _sync_wsl_bridge_fields(self) -> None:
        enabled = self._wsl_path_bridge.isChecked()
        if not enabled:
            self._open_in_ida_bundle_dir.clear()
        self._open_in_ida_bundle_dir_field.setEnabled(enabled)

    def _refresh_wsl_section(self) -> None:
        show_wsl = self._wsl_toggle.isChecked()
        self._wsl_toggle.setText(self._t("settings.group.wsl"))
        self._wsl_toggle.setArrowType(Qt.DownArrow if show_wsl else Qt.RightArrow)
        self._wsl_toggle.blockSignals(True)
        self._wsl_toggle.setChecked(show_wsl)
        self._wsl_toggle.blockSignals(False)
        self._wsl_container.setVisible(show_wsl)

        if self._wsl_group is not None:
            self._wsl_layout.removeWidget(self._wsl_group)
            self._wsl_group.setParent(None)
            self._retained_widgets.append(self._wsl_group)
            self._wsl_group = None

        if not show_wsl:
            return

        self._wsl_group = self._build_config_group(
            self._t("settings.group.wsl"),
            self._t("settings.group.wsl.desc"),
            [
                self._build_checkbox_row(
                    self._wsl_path_bridge,
                    self._t("settings.field.wsl_path_bridge"),
                    self._t("settings.field.wsl_path_bridge.desc"),
                ),
                self._build_field_row(
                    self._t("settings.field.open_in_ida_bundle_dir"),
                    self._t("settings.field.open_in_ida_bundle_dir.desc"),
                    self._open_in_ida_bundle_dir_field,
                ),
            ],
        )
        self._wsl_layout.addWidget(self._wsl_group)
