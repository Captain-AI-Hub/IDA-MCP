"""Presentation helpers for the settings page."""

from __future__ import annotations

from dataclasses import dataclass, fields as dc_fields
from typing import Any, Callable

from app.services.settings_service import SettingsSnapshot
from shared.platform import display_path as _display_path
from supervisor.models import (
    DEFAULT_HTTP_HOST,
    DEFAULT_IDA_HOST,
    DEFAULT_GATEWAY_PATH,
    DEFAULT_SERVER_NAME,
    HealthReport,
    IdaMcpConfig,
    InstallationActionResult,
    InstallationCheck,
)

# Fields in IdaMcpConfig that need a different name in the form to avoid
# collisions with IdeConfig fields of the same semantic origin.
_IDA_MCP_FIELD_ALIASES: dict[str, str] = {
    "request_timeout": "ida_request_timeout",
}


@dataclass(slots=True)
class SettingsFormState:
    """Flat form state for the settings UI.

    IDE-owned fields (ida_dir, plugin_dir, language, theme_mode, ide_request_timeout)
    are mapped manually.  All IdaMcpConfig fields are included automatically
    via ``from_flat_dict``.
    """

    ida_dir: str
    plugin_dir: str
    language: str
    theme_mode: str
    ide_request_timeout: int
    enable_http: bool
    enable_stdio: bool
    enable_unsafe: bool
    wsl_path_bridge: bool
    http_host: str
    http_port: int
    http_path: str
    ida_default_port: int
    ida_host: str
    ida_path: str
    ida_python: str
    open_in_ida_bundle_dir: str
    open_in_ida_autonomous: bool
    auto_start: bool
    server_name: str
    ida_request_timeout: int
    debug: bool

    @classmethod
    def from_flat_dict(cls, data: dict[str, Any]) -> SettingsFormState:
        """Construct from a flat dict, ignoring unknown keys."""
        allowed = {f.name for f in dc_fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass(slots=True)
class SettingsMessage:
    summary: str
    details: str


def snapshot_to_form_state(snapshot: SettingsSnapshot) -> SettingsFormState:
    ide_config = snapshot.ide_config
    ida_mcp_dict = snapshot.ida_mcp_config.to_dict()

    # Apply field aliases so ida_mcp request_timeout → ida_request_timeout
    for src, dst in _IDA_MCP_FIELD_ALIASES.items():
        if src in ida_mcp_dict:
            ida_mcp_dict[dst] = ida_mcp_dict.pop(src)

    # Coerce None strings to "" for UI display.
    # NOTE: Do *not* apply display_path() here.  These values are
    # round-tripped back to config on save (form_state_to_updates).
    # Normalizing separators would silently corrupt WSL/POSIX paths
    # (e.g. /mnt/e/… → \mnt\e\…) on Windows.
    for key in ("ida_path", "ida_python", "open_in_ida_bundle_dir"):
        if ida_mcp_dict.get(key) is None:
            ida_mcp_dict[key] = ""

    flat: dict[str, Any] = {
        "ida_dir": getattr(ide_config, "ida_dir", "") or "",
        "plugin_dir": ide_config.plugin_dir or "",
        "language": ide_config.language,
        "theme_mode": getattr(ide_config, "theme_mode", "light") or "light",
        "ide_request_timeout": ide_config.request_timeout,
        **ida_mcp_dict,
    }
    return SettingsFormState.from_flat_dict(flat)


def effective_install_python_path(snapshot: SettingsSnapshot) -> str:
    return snapshot.ida_mcp_config.ida_python or ""


# Fields that need strip-then-fallback-to-default treatment on save.
_STRIP_OR_DEFAULT: dict[str, tuple[str, str]] = {
    "http_host": ("", DEFAULT_HTTP_HOST),
    "http_path": ("", DEFAULT_GATEWAY_PATH),
    "ida_host": ("", DEFAULT_IDA_HOST),
    "server_name": ("", DEFAULT_SERVER_NAME),
}

# Fields that should be cleaned to None when empty on save.
_OPTIONAL_STR_FIELDS = {"ida_path", "ida_python", "open_in_ida_bundle_dir"}


def form_state_to_updates(
    state: SettingsFormState,
) -> tuple[dict[str, object], dict[str, object]]:
    ide_updates: dict[str, object] = {
        "ida_dir": state.ida_dir.strip(),
        "plugin_dir": _clean_plugin_dir(state.ida_dir, state.plugin_dir),
        "request_timeout": state.ide_request_timeout,
        "language": state.language,
        "theme_mode": state.theme_mode,
    }

    # Build ida_mcp updates from the form state automatically.
    ida_mcp_updates: dict[str, object] = {}
    for name in IdaMcpConfig.field_names():
        form_name = _IDA_MCP_FIELD_ALIASES.get(name, name)
        if not hasattr(state, form_name):
            continue
        value = getattr(state, form_name)

        if name in _OPTIONAL_STR_FIELDS:
            value = _clean_optional(str(value))
        elif name in _STRIP_OR_DEFAULT:
            stripped = str(value).strip()
            fallback = _STRIP_OR_DEFAULT[name][1]
            value = stripped or fallback
        ida_mcp_updates[name] = value

    return ide_updates, ida_mcp_updates


def build_check_message(
    report: HealthReport,
    installation: InstallationCheck,
    translate: Callable[[str], str],
    bool_text: Callable[[bool], str],
) -> SettingsMessage:
    lines = [
        f"Supervisor: {report.supervisor.state.value} - {report.supervisor.summary}",
        f"Gateway: {report.gateway.state.value} - {report.gateway.summary}",
        f"Environment: {report.environment.state.value} - {report.environment.summary}",
        "",
        f"{translate('settings.install.status')}:",
        f"- {translate('settings.install.plugin_dir')}: {_display_path(installation.plugin_dir) or '(not found)'}",
        f"- {translate('settings.install.config')}: {_display_path(installation.config_path) or '(not resolved)'} [{bool_text(installation.config_exists)}]",
        f"- {translate('settings.install.python')}: {_display_path(installation.python_executable) or '(not found)'} [{bool_text(installation.python_exists)}]",
        f"- {translate('settings.install.ida_mcp_py')}: {bool_text(installation.ida_mcp_py_exists)}",
        f"- {translate('settings.install.ida_mcp_pkg')}: {bool_text(installation.ida_mcp_package_exists)}",
        "",
        f"{translate('settings.install.requirements')}:",
        f"- {translate('settings.install.requirements_path')}: {_display_path(installation.requirements_path) or '(not found)'}",
        f"- {translate('settings.install.requirements_status')}: {_format_requirement_summary(installation)}",
    ]
    if installation.warnings:
        lines.extend(
            ["", translate("settings.install.warning")]
            + [f"- {item}" for item in installation.warnings]
        )
    return SettingsMessage(summary=installation.summary, details="\n".join(lines))


def build_reinstall_message(
    result: InstallationActionResult,
    translate: Callable[[str], str],
    bool_text: Callable[[bool], str],
) -> SettingsMessage:
    lines = [
        result.summary,
        "",
        f"{translate('settings.install.plugin_dir')}: {_display_path(result.check.plugin_dir) or '(not found)'}",
        f"{translate('settings.install.config')}: {_display_path(result.config_path or result.check.config_path) or '(not resolved)'}",
        f"{translate('settings.install.created')}: {bool_text(result.created)}",
        f"{translate('settings.install.already_exists')}: {bool_text(result.already_exists)}",
        f"{translate('settings.install.python_exists')}: {bool_text(result.check.python_exists)}",
        f"{translate('settings.install.requirements_status')}: {_format_requirement_summary(result.check)}",
    ]
    if result.warnings:
        lines.extend(
            ["", translate("settings.install.warning")]
            + [f"- {item}" for item in result.warnings]
        )
    return SettingsMessage(summary=result.summary, details="\n".join(lines))


def _clean_optional(value: str) -> str | None:
    cleaned = value.strip()
    return cleaned or None


def _clean_plugin_dir(ida_dir: str, plugin_dir: str) -> str:
    """Return stripped plugin_dir, deriving from ida_dir or falling back to default."""
    from supervisor.models import derive_plugin_dir

    ida = ida_dir.strip()
    if ida:
        return derive_plugin_dir(ida)
    cleaned = plugin_dir.strip()
    if cleaned:
        return cleaned
    from supervisor.models import default_ida_plugin_dir

    return default_ida_plugin_dir()


def _format_requirement_summary(installation: InstallationCheck) -> str:
    total = len(installation.requirements)
    installed = len(installation.installed_requirements)
    missing = len(installation.missing_requirements)
    unresolved = len(installation.unresolved_requirements)
    parts = [f"{installed}/{total} installed"]
    if missing:
        parts.append(f"{missing} missing")
    if unresolved:
        parts.append(f"{unresolved} unresolved")
    return ", ".join(parts)
