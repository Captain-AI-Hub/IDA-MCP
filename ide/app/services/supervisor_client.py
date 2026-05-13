"""Simple in-process client for the local supervisor MVP."""

from __future__ import annotations

from typing import Callable

from supervisor.api import create_manager
from supervisor.models import (
    HealthReport,
    IdaMcpConfig,
    InstallationActionResult,
    InstallationCheck,
    IdeConfig,
    McpServerEntry,
    ModelProvider,
    SkillEntry,
    SupervisorSnapshot,
)


class SupervisorClient:
    def __init__(self) -> None:
        self._manager = create_manager()

    def get_snapshot(
        self, log: Callable[[str], None] | None = None
    ) -> SupervisorSnapshot:
        return self._manager.get_snapshot(log=log)

    def get_health_report(
        self, log: Callable[[str], None] | None = None
    ) -> HealthReport:
        return self._manager.get_health_report(log=log)

    def get_ide_config(self) -> IdeConfig:
        return self._manager.get_ide_config()

    def get_config(self) -> IdeConfig:
        return self.get_ide_config()

    def get_ida_mcp_config(self) -> IdaMcpConfig:
        return self._manager.get_ida_mcp_config()

    def get_ide_config_store_info(self):
        return self._manager.get_ide_config_store_info()

    def get_ida_mcp_config_store_info(self):
        return self._manager.get_ida_mcp_config_store_info()

    def start_gateway(
        self, log: Callable[[str], None] | None = None
    ) -> SupervisorSnapshot:
        self._manager.start_gateway(log=log)
        return self.get_snapshot(log=log)

    def stop_gateway(
        self, *, log: Callable[[str], None] | None = None
    ) -> SupervisorSnapshot:
        self._manager.stop_gateway(log=log)
        return self.get_snapshot(log=log)

    def update_ide_config(self, **updates: object) -> IdeConfig:
        return self._manager.update_ide_config(**updates)

    def update_config(self, **updates: object) -> IdeConfig:
        return self.update_ide_config(**updates)

    def update_ida_mcp_config(self, **updates: object) -> IdaMcpConfig:
        return self._manager.update_ida_mcp_config(**updates)

    def check_installation(self) -> InstallationCheck:
        return self._manager.check_installation()

    def repair_installation(self) -> InstallationActionResult:
        return self._manager.repair_installation()

    def reinstall(self, *, on_progress=None) -> InstallationActionResult:
        return self._manager.reinstall(on_progress=on_progress)

    def detect_ida_executable(self, ida_dir: str) -> str | None:
        return self._manager.installer.detect_ida_executable(ida_dir)

    def detect_ida_python(self, ida_dir: str) -> str | None:
        return self._manager.installer.detect_ida_python(ida_dir)

    # --- Model providers ---

    def get_model_providers(self) -> list[ModelProvider]:
        return self._manager.get_model_providers()

    def add_model_provider(
        self,
        name: str = "",
        base_url: str = "",
        api_key: str = "",
        api_mode: str = "openai_compatible",
        model_name: str = "",
        max_context_tokens: int = 0,
        top_p: float = 1.0,
        temperature: float = 0.7,
        *,
        enabled: bool = True,
    ) -> int:
        return self._manager.add_model_provider(
            name=name,
            base_url=base_url,
            api_key=api_key,
            api_mode=api_mode,
            model_name=model_name,
            max_context_tokens=max_context_tokens,
            top_p=top_p,
            temperature=temperature,
            enabled=enabled,
        )

    def update_model_provider(self, provider_id: int, **updates: object) -> bool:
        return self._manager.update_model_provider(provider_id, **updates)

    def remove_model_provider(self, provider_id: int) -> bool:
        return self._manager.remove_model_provider(provider_id)

    # --- MCP servers ---

    def get_mcp_servers(self) -> list[McpServerEntry]:
        return self._manager.get_mcp_servers()

    def add_mcp_server(
        self,
        name: str = "",
        transport: str = "stdio",
        *,
        enabled: bool = True,
        command: str = "",
        args: str = "",
        env: str = "",
        cwd: str = "",
        encoding: str = "utf-8",
        url: str = "",
        headers: str = "",
        timeout: float = 30.0,
        sse_read_timeout: float = 300.0,
    ) -> int:
        return self._manager.add_mcp_server(
            name=name,
            transport=transport,
            enabled=enabled,
            command=command,
            args=args,
            env=env,
            cwd=cwd,
            encoding=encoding,
            url=url,
            headers=headers,
            timeout=timeout,
            sse_read_timeout=sse_read_timeout,
        )

    def update_mcp_server(self, server_id: int, **updates: object) -> bool:
        return self._manager.update_mcp_server(server_id, **updates)

    def remove_mcp_server(self, server_id: int) -> bool:
        return self._manager.remove_mcp_server(server_id)

    # --- Skills ---

    def get_skills(self) -> list[SkillEntry]:
        return self._manager.get_skills()

    def add_skill(
        self,
        name: str,
        description: str = "",
        *,
        enabled: bool = True,
        version: str = "",
        file_path: str = "",
        install_dir: str = "",
        installed_at: str = "",
    ) -> int:
        return self._manager.add_skill(
            name,
            description,
            enabled=enabled,
            version=version,
            file_path=file_path,
            install_dir=install_dir,
            installed_at=installed_at,
        )

    def update_skill(self, skill_id: int, **updates: object) -> bool:
        return self._manager.update_skill(skill_id, **updates)

    def remove_skill(self, skill_id: int) -> bool:
        return self._manager.remove_skill(skill_id)

    def get_skills_dir(self) -> "Path":
        return self._manager.get_skills_dir()
