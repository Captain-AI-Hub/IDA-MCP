"""Worker and binding helpers for the settings page."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import QTableWidgetItem

from shared.platform import display_path as _display_path
from app.presenters.settings_presenter import SettingsFormState
from app.services.settings_service import SettingsService

if TYPE_CHECKING:
    from app.ui.settings.page import SettingsPage


class _InstallWorker(QThread):
    """Runs reinstall in a background thread."""

    progress = Signal(str)
    finished = Signal(object)  # InstallationActionResult

    def __init__(
        self,
        settings_service: SettingsService,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._settings_service = settings_service

    def run(self) -> None:
        try:
            result = self._settings_service.reinstall(on_progress=self.progress.emit)
            self.finished.emit(result)
        except Exception as exc:
            self.progress.emit(f"Error: {exc}")
            self.finished.emit(None)


class _CheckWorker(QThread):
    """Runs installation check in a background thread."""

    finished = Signal(object)  # InstallationCheck

    def __init__(
        self,
        settings_service: SettingsService,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._settings_service = settings_service

    def run(self) -> None:
        try:
            result = self._settings_service.check_installation()
            self.finished.emit(result)
        except Exception:
            self.finished.emit(None)


class _ConfigFormBinder:
    """Owns the field binding table and handles reading/writing form state."""

    _IDA_FIELD_BINDINGS: list[tuple[str, str, str]] = [
        ("enable_http", "_enable_http", "checkbox"),
        ("enable_stdio", "_enable_stdio", "checkbox"),
        ("enable_unsafe", "_enable_unsafe", "checkbox"),
        ("wsl_path_bridge", "_wsl_path_bridge", "checkbox"),
        ("http_host", "_http_host", "lineedit"),
        ("http_port", "_http_port", "spinbox"),
        ("http_path", "_http_path", "lineedit"),
        ("ida_default_port", "_ida_default_port", "spinbox"),
        ("ida_host", "_ida_host", "lineedit"),
        ("ida_path", "_ida_path", "lineedit"),
        ("ida_python", "_ida_python", "lineedit"),
        ("open_in_ida_bundle_dir", "_open_in_ida_bundle_dir", "lineedit"),
        ("open_in_ida_autonomous", "_open_in_ida_autonomous", "checkbox"),
        ("auto_start", "_auto_start", "checkbox"),
        ("server_name", "_server_name", "lineedit"),
        ("ida_request_timeout", "_ida_request_timeout", "spinbox"),
        ("debug", "_debug", "checkbox"),
    ]

    def __init__(self, page: SettingsPage) -> None:
        self._page = page

    def apply_form_state(self, form_state: SettingsFormState) -> None:
        """Populate widgets from a SettingsFormState."""
        for field_name, widget_attr, widget_type in self._IDA_FIELD_BINDINGS:
            widget = getattr(self._page, widget_attr)
            value = getattr(form_state, field_name)
            if widget_type == "checkbox":
                widget.setChecked(value)
            elif widget_type == "spinbox":
                widget.setValue(value)
            else:
                widget.setText(str(value))

    def collect_form_state(self, page: SettingsPage) -> SettingsFormState:
        """Read current widget values into a SettingsFormState."""
        data: dict[str, object] = {
            "ida_dir": page._ida_dir.text(),
            "plugin_dir": page._plugin_dir.text(),
            "language": str(page._language_combo.currentData() or page._language),
            "theme_mode": str(page._theme_combo.currentData() or "light"),
            "ide_request_timeout": page._ide_request_timeout.value(),
        }
        for field_name, widget_attr, widget_type in self._IDA_FIELD_BINDINGS:
            widget = getattr(page, widget_attr)
            if widget_type == "checkbox":
                data[field_name] = widget.isChecked()
            elif widget_type == "spinbox":
                data[field_name] = widget.value()
            else:
                data[field_name] = widget.text()
        return SettingsFormState.from_flat_dict(data)


class _InstallationDisplay:
    """Renders installation check results into the requirements table."""

    def __init__(self, page: SettingsPage) -> None:
        self._page = page

    def _t(self, key: str, **kwargs: object) -> str:
        return self._page._t(key, **kwargs)

    def apply_installation_check(self, installation) -> None:
        """Render an InstallationCheck into the requirements widgets."""
        raw_path = installation.requirements_path or ""
        display = _display_path(raw_path) if raw_path else ""
        self._page._requirements_path.setText(
            display or self._t("settings.install.requirements.missing")
        )
        self._page._requirements_table.setHorizontalHeaderLabels(
            [
                self._t("settings.install.table.package"),
                self._t("settings.install.table.required"),
                self._t("settings.install.table.installed"),
            ]
        )
        rows = self._build_requirement_rows(installation)
        self._page._requirements_table.setRowCount(len(rows))
        for row_index, row_values in enumerate(rows):
            for column_index, value in enumerate(row_values):
                self._page._requirements_table.setItem(
                    row_index,
                    column_index,
                    QTableWidgetItem(value),
                )

    def _build_requirement_rows(self, installation) -> list[tuple[str, str, str]]:
        rows: list[tuple[str, str, str]] = []
        installed = installation.installed_requirements
        missing = set(installation.missing_requirements)
        unresolved = set(installation.unresolved_requirements)
        for requirement in installation.requirements:
            if requirement in installed:
                status = (
                    f"{self._t('settings.install.table.status.installed')} "
                    f"({installed[requirement]})"
                )
            elif requirement in missing:
                status = self._t("settings.install.table.status.missing")
            elif requirement in unresolved:
                status = self._t("settings.install.table.status.unresolved")
            else:
                status = self._t("settings.install.table.status.unresolved")
            rows.append(
                (self._requirement_package_name(requirement), requirement, status)
            )
        return rows

    @staticmethod
    def _requirement_package_name(requirement: str) -> str:
        for index, char in enumerate(requirement):
            if not (char.isalnum() or char in "._-"):
                return requirement[:index]
        return requirement


class _InstallController:
    """Manages background worker threads for installation and checking.

    All worker creation/teardown is encapsulated here.  The host page
    receives results through callback callables.
    """

    def __init__(
        self,
        page: SettingsPage,
        settings_service: SettingsService,
        *,
        on_check_result,
        on_install_result,
        on_progress,
        on_busy_changed,
    ) -> None:
        self._page = page
        self._settings_service = settings_service
        self._on_check_result = on_check_result
        self._on_install_result = on_install_result
        self._on_progress = on_progress
        self._on_busy_changed = on_busy_changed
        self._install_worker: _InstallWorker | None = None
        self._check_worker: _CheckWorker | None = None

    @property
    def is_install_busy(self) -> bool:
        return self._install_worker is not None and self._install_worker.isRunning()

    def cleanup(self) -> None:
        """Stop and clean up all background workers."""
        self._cleanup_check_worker()
        self._cleanup_install_worker()

    def run_check(self) -> None:
        """Start a background installation check."""
        self._cleanup_check_worker()
        worker = _CheckWorker(self._settings_service, parent=self._page)
        self._check_worker = worker
        worker.finished.connect(
            lambda result, w=worker: self._on_check_finished(result, w)
        )
        worker.start()

    def run_install(self) -> None:
        """Start a background reinstall."""
        if self.is_install_busy:
            return
        self._cleanup_install_worker()
        self._on_busy_changed(False)
        worker = _InstallWorker(self._settings_service, parent=self._page)
        self._install_worker = worker
        worker.progress.connect(self._on_progress)
        worker.finished.connect(
            lambda result, w=worker: self._on_install_finished(result, w)
        )
        worker.start()

    def _on_check_finished(self, result: object, worker: _CheckWorker) -> None:
        if self._check_worker is not worker:
            worker.deleteLater()
            return
        worker.deleteLater()
        self._check_worker = None
        if result is not None:
            self._on_check_result(result)

    def _on_install_finished(self, result: object, worker: _InstallWorker) -> None:
        if self._install_worker is worker:
            worker.deleteLater()
            self._install_worker = None
            self._on_busy_changed(True)
        from supervisor.models import InstallationActionResult

        if not isinstance(result, InstallationActionResult):
            self._on_progress("Error: Unexpected result type")
            return
        self._on_install_result(result)

    def _cleanup_install_worker(self) -> None:
        worker = self._install_worker
        if worker is None:
            return
        if worker.isRunning():
            worker.requestInterruption()
            worker.wait(3000)
        worker.deleteLater()
        self._install_worker = None

    def _cleanup_check_worker(self) -> None:
        worker = self._check_worker
        if worker is None:
            return
        if worker.isRunning():
            worker.requestInterruption()
            worker.wait(3000)
        worker.deleteLater()
        self._check_worker = None


class McpToolFetchWorker(QThread):
    """Fetches available tools from an MCP server in a background thread.

    Creates a temporary ``MultiServerMCPClient``, calls ``get_tools()``,
    and returns a list of ``(name, description)`` tuples via the
    ``tools_fetched`` signal.  On error, ``fetch_failed`` is emitted with
    the error message string.
    """

    tools_fetched = Signal(list)  # list[dict] with keys: name, description
    fetch_failed = Signal(str)   # error message

    def __init__(
        self,
        server_name: str,
        server_config: dict,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._server_name = server_name
        self._server_config = server_config

    def run(self) -> None:
        try:
            from langchain_mcp_adapters.client import MultiServerMCPClient

            loop = asyncio.new_event_loop()
            client = None
            try:
                client = MultiServerMCPClient(
                    {self._server_name: self._server_config},
                    tool_name_prefix=True,
                )
                tools = loop.run_until_complete(client.get_tools())
            finally:
                # Clean up the client before closing the loop
                if client is not None and hasattr(client, "close"):
                    try:
                        loop.run_until_complete(client.close())
                    except Exception:
                        pass
                loop.close()

            result: list[dict] = []
            for tool in tools:
                result.append({
                    "name": getattr(tool, "name", str(tool)),
                    "description": getattr(tool, "description", "") or "",
                })
            self.tools_fetched.emit(result)
        except Exception as exc:
            self.fetch_failed.emit(str(exc))
