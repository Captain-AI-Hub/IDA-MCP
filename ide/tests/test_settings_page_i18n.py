import os
from dataclasses import dataclass

from PySide6.QtWidgets import QApplication, QTableWidget

from app.services.settings_service import SettingsSnapshot
from app.ui.settings.page import SettingsPage
from supervisor.models import IdaMcpConfig, IdeConfig, InstallationCheck


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@dataclass
class _StubSettingsService:
    snapshot: SettingsSnapshot

    def __post_init__(self) -> None:
        self.saved = False

    def load(self) -> SettingsSnapshot:
        return self.snapshot

    def save(self, *, ide_updates, ida_mcp_updates) -> SettingsSnapshot:
        self.saved = True
        for key, value in ide_updates.items():
            setattr(self.snapshot.ide_config, key, value)
        for key, value in ida_mcp_updates.items():
            setattr(self.snapshot.ida_mcp_config, key, value)
        return self.snapshot

    def check_installation(self) -> InstallationCheck:
        return InstallationCheck(
            plugin_dir="E:/plugins",
            plugin_dir_exists=True,
            config_path="E:/plugins/ida_mcp/config.conf",
            config_exists=True,
            python_executable="E:/IDA/python.exe",
            python_exists=True,
            ida_mcp_py_exists=True,
            ida_mcp_package_exists=True,
            summary="ok",
            requirements_path="E:/DM/IDA-MCP/requirements.txt",
            requirements=["fastmcp", "pytest"],
            installed_requirements={"fastmcp": "1.0.0"},
            missing_requirements=["pytest"],
        )

    def get_model_providers(self) -> list:
        return []

    def add_model_provider(self, **kwargs):
        pass

    def update_model_provider(self, provider_id, **updates):
        pass

    def remove_model_provider(self, provider_id):
        pass

    def get_mcp_servers(self) -> list:
        return []

    def add_mcp_server(self, **kwargs):
        pass

    def update_mcp_server(self, server_id, **updates):
        pass

    def remove_mcp_server(self, server_id):
        pass

    def get_skills(self) -> list:
        return []

    def get_skills_dir(self):
        return Path("D:/tools/ida-mcp-ide/data/skills")

    def update_skill(self, skill_id, **updates):
        pass

    def add_skill(self, **kwargs):
        pass

    def remove_skill(self, skill_id):
        pass


def test_settings_page_language_switch_rebuilds_without_deleting_core_widgets() -> None:
    _app()
    service = _StubSettingsService(
        SettingsSnapshot(
            ide_config=IdeConfig(language="zh", request_timeout=30),
            ida_mcp_config=IdaMcpConfig(
                wsl_path_bridge=True,
                ida_default_port=10010,
                ida_host="127.0.0.2",
                open_in_ida_bundle_dir="E:/bundle",
                open_in_ida_autonomous=False,
                auto_start=True,
                server_name="IDA-MCP-Test",
                request_timeout=90,
            ),
        )
    )
    page = SettingsPage(service)

    category_list = page._category_list
    stack = page._stack

    assert category_list.item(0).text() == "配置"
    assert page._language_combo.currentData() == "zh"

    page._language_combo.setCurrentIndex(0)
    QApplication.processEvents()

    assert page._category_list is category_list
    assert page._stack is stack
    assert category_list.item(0).text() == "Config"
    assert category_list.item(1).text() == "Install"
    assert category_list.item(2).text() == "Upgrade"
    assert category_list.item(3).text() == "Model"
    assert category_list.item(4).text() == "MCP"
    assert category_list.item(5).text() == "Skills"
    assert stack.count() == 6
    assert page._save_hint_labels[-1].text().startswith("Save writes IDE config")

    # Wait for the background check worker to finish and populate fields.
    # The install check runs in a QThread; process events until it completes.
    ctrl = page._install_ctrl
    if ctrl._check_worker is not None:
        ctrl._check_worker.wait(3000)
    QApplication.processEvents()

    assert page._requirements_path.text().endswith("requirements.txt")
    assert isinstance(page._requirements_table, QTableWidget)
    assert page._requirements_table.rowCount() == 2
    assert page._requirements_table.item(0, 0).text() == "fastmcp"
    assert page._requirements_table.item(0, 1).text() == "fastmcp"
    assert page._requirements_table.item(1, 2).text() in {"Missing", "未安装"}
    assert page._open_in_ida_autonomous.isChecked() is False
    assert page._auto_start.isChecked() is True
    assert page._server_name.text() == "IDA-MCP-Test"
    assert page._ida_host.text() == "127.0.0.2"
    assert page._wsl_container.isHidden() is True
    assert page._open_in_ida_bundle_dir_field.isEnabled() is True
    assert "Only used when WSL path bridge is enabled" in page._t(
        "settings.field.open_in_ida_bundle_dir.desc"
    )

    page._wsl_path_bridge.setChecked(False)
    QApplication.processEvents()
    assert page._open_in_ida_bundle_dir_field.isEnabled() is False
    assert page._open_in_ida_bundle_dir.text() == ""

    page._wsl_path_bridge.setChecked(True)
    QApplication.processEvents()
    assert page._open_in_ida_bundle_dir_field.isEnabled() is True

    page._wsl_toggle.click()
    QApplication.processEvents()
    assert page._wsl_container.isHidden() is False

    page._save_settings(show_message=False)
    QApplication.processEvents()

    assert service.saved is True
    assert page._install_plugin_dir.text()  # default IDA plugins path

    page.close()
