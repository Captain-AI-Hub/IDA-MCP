"""Settings service for IDE MVP."""

from __future__ import annotations

from dataclasses import dataclass

from app.i18n import normalize_language
from app.services.supervisor_client import SupervisorClient
from supervisor.models import (
    HealthReport,
    IdaMcpConfig,
    InstallationActionResult,
    InstallationCheck,
    IdeConfig,
    McpServerEntry,
    ModelProvider,
    SkillEntry,
)


@dataclass(slots=True)
class SettingsSnapshot:
    ide_config: IdeConfig
    ida_mcp_config: IdaMcpConfig


class SettingsService:
    def __init__(self, supervisor_client: SupervisorClient | None = None) -> None:
        self._supervisor_client = supervisor_client or SupervisorClient()

    def load(self) -> SettingsSnapshot:
        ide_config = self._supervisor_client.get_ide_config()
        ida_mcp_config = self._supervisor_client.get_ida_mcp_config()
        ide_config.language = normalize_language(ide_config.language)
        return SettingsSnapshot(
            ide_config=ide_config,
            ida_mcp_config=ida_mcp_config,
        )

    def save(
        self,
        *,
        ide_updates: dict[str, object],
        ida_mcp_updates: dict[str, object],
    ) -> SettingsSnapshot:
        normalized_ide_updates = dict(ide_updates)
        normalized_ide_updates["language"] = normalize_language(
            normalized_ide_updates.get("language")
        )
        self._supervisor_client.update_ide_config(**normalized_ide_updates)
        self._supervisor_client.update_ida_mcp_config(**ida_mcp_updates)
        return self.load()

    def check(self) -> HealthReport:
        return self._supervisor_client.get_health_report()

    def check_installation(self) -> InstallationCheck:
        return self._supervisor_client.check_installation()

    def reinstall(self, *, on_progress=None) -> InstallationActionResult:
        return self._supervisor_client.reinstall(on_progress=on_progress)

    # --- Model providers ---

    def get_model_providers(self) -> list[ModelProvider]:
        return self._supervisor_client.get_model_providers()

    def add_model_provider(self, **kwargs) -> int:
        return self._supervisor_client.add_model_provider(**kwargs)

    def update_model_provider(self, provider_id: int, **updates: object) -> bool:
        return self._supervisor_client.update_model_provider(provider_id, **updates)

    def remove_model_provider(self, provider_id: int) -> bool:
        return self._supervisor_client.remove_model_provider(provider_id)

    # --- MCP servers ---

    def get_mcp_servers(self) -> list[McpServerEntry]:
        return self._supervisor_client.get_mcp_servers()

    def add_mcp_server(self, **kwargs) -> int:
        return self._supervisor_client.add_mcp_server(**kwargs)

    def update_mcp_server(self, server_id: int, **updates: object) -> bool:
        return self._supervisor_client.update_mcp_server(server_id, **updates)

    def remove_mcp_server(self, server_id: int) -> bool:
        return self._supervisor_client.remove_mcp_server(server_id)

    # --- Skills ---

    def get_skills(self) -> list[SkillEntry]:
        return self._supervisor_client.get_skills()

    def add_skill(self, **kwargs) -> int:
        return self._supervisor_client.add_skill(**kwargs)

    def update_skill(self, skill_id: int, **updates: object) -> bool:
        return self._supervisor_client.update_skill(skill_id, **updates)

    def remove_skill(self, skill_id: int) -> bool:
        return self._supervisor_client.remove_skill(skill_id)

    def get_skills_dir(self) -> "Path":
        return self._supervisor_client.get_skills_dir()

    def detect_ida_executable(self, ida_dir: str) -> str | None:
        return self._supervisor_client.detect_ida_executable(ida_dir)

    def detect_ida_python(self, ida_dir: str) -> str | None:
        return self._supervisor_client.detect_ida_python(ida_dir)
