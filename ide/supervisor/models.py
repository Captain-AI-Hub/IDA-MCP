"""Data models for the local supervisor MVP."""

from __future__ import annotations

import locale
import os
from dataclasses import asdict, dataclass, field, fields
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar


class HealthState(str, Enum):
    OK = "ok"
    WARNING = "warning"
    ERROR = "error"
    UNKNOWN = "unknown"


class GatewayState(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    STARTING = "starting"
    ERROR = "error"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Canonical default values — single source of truth
# ---------------------------------------------------------------------------
DEFAULT_GATEWAY_HOST = "127.0.0.1"
DEFAULT_GATEWAY_PORT = 11338
DEFAULT_GATEWAY_PATH = "/mcp"
DEFAULT_HTTP_HOST = "0.0.0.0"
DEFAULT_IDA_HOST = "127.0.0.1"
DEFAULT_IDA_PORT = 10000
DEFAULT_SERVER_NAME = "IDA-MCP"


def _default_language() -> str:
    preferred = locale.getlocale()[0] or ""
    if preferred.lower().startswith("zh"):
        return "zh"
    return "en"


def default_ida_plugin_dir() -> str:
    """Return the default IDA global plugins directory.

    Windows: %APPDATA%\\Hex-Rays\\IDA Pro\\plugins
    Linux/macOS: ~/.idapro/plugins
    """
    if os.name == "nt":
        appdata = os.environ.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming"
        )
        return str(Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins")
    return str(Path.home() / ".idapro" / "plugins")


# Backward-compatible alias; prefer ``default_ida_plugin_dir()``.
_default_ida_plugin_dir = default_ida_plugin_dir


@dataclass(slots=True)
class IdeConfig:
    gateway_host: str = DEFAULT_GATEWAY_HOST
    gateway_port: int = DEFAULT_GATEWAY_PORT
    gateway_path: str = DEFAULT_GATEWAY_PATH
    request_timeout: int = 30
    auto_start_gateway: bool = False
    plugin_dir: str = field(default_factory=_default_ida_plugin_dir)
    language: str = field(default_factory=_default_language)
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "IdeConfig":
        if not data:
            return cls()
        allowed = {field.name for field in cls.__dataclass_fields__.values()}
        return cls(
            **{
                key: value
                for key, value in data.items()
                if key in allowed and value is not None
            }
        )


@dataclass(slots=True)
class IdaMcpConfig:
    enable_stdio: bool = False
    enable_http: bool = True
    enable_unsafe: bool = True
    wsl_path_bridge: bool = False
    http_host: str = DEFAULT_HTTP_HOST
    http_port: int = DEFAULT_GATEWAY_PORT
    http_path: str = DEFAULT_GATEWAY_PATH
    ida_default_port: int = DEFAULT_IDA_PORT
    ida_host: str = DEFAULT_IDA_HOST
    ida_path: str | None = None
    ida_python: str | None = None
    open_in_ida_bundle_dir: str | None = None
    open_in_ida_autonomous: bool = True
    auto_start: bool = False
    server_name: str = DEFAULT_SERVER_NAME
    request_timeout: int = 30
    debug: bool = False
    skills_enabled: bool = True
    config_path: str | None = None

    # Field groups for config rendering order and comments.
    FIELD_GROUPS: ClassVar[list[tuple[str, list[str]]]] = [
        (
            "Transport switches",
            [
                "enable_stdio",
                "enable_http",
                "enable_unsafe",
                "wsl_path_bridge",
            ],
        ),
        (
            "HTTP gateway settings",
            [
                "http_host",
                "http_port",
                "http_path",
            ],
        ),
        (
            "IDA instance settings",
            [
                "ida_default_port",
                "ida_host",
                "ida_path",
                "ida_python",
                "open_in_ida_bundle_dir",
                "open_in_ida_autonomous",
                "auto_start",
                "server_name",
            ],
        ),
        (
            "General settings",
            [
                "request_timeout",
                "debug",
            ],
        ),
    ]

    @classmethod
    def field_names(cls) -> set[str]:
        """Return the set of config field names (excludes config_path)."""
        return {f.name for f in fields(cls) if f.name != "config_path"}

    @classmethod
    def defaults(cls) -> dict[str, Any]:
        """Return a dict of default values for all config fields (excludes config_path)."""
        result: dict[str, Any] = {}
        for f in fields(cls):
            if f.name == "config_path":
                continue
            result[f.name] = f.default
        return result

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("config_path", None)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "IdaMcpConfig":
        if not data:
            return cls()
        allowed = cls.field_names() | {"config_path"}
        return cls(**{key: value for key, value in data.items() if key in allowed})


@dataclass(slots=True)
class ConfigStoreInfo:
    path: str
    exists: bool


@dataclass(slots=True)
class GatewayStatus:
    state: GatewayState
    alive: bool
    proxy_alive: bool
    enabled: bool
    host: str
    port: int
    path: str
    instance_count: int = 0
    instances: list[dict[str, Any]] = field(default_factory=list)
    last_error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EnvironmentProbe:
    python_executable: str | None
    python_version: str
    ida_mcp_importable: bool
    ida_mcp_location: str | None
    ida_path_candidates: list[str] = field(default_factory=list)
    ida_python_candidates: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class InstallationCheck:
    plugin_dir: str | None
    plugin_dir_exists: bool
    config_path: str | None
    config_exists: bool
    python_executable: str | None
    python_exists: bool
    ida_mcp_py_exists: bool
    ida_mcp_package_exists: bool
    summary: str
    requirements_path: str | None = None
    requirements: list[str] = field(default_factory=list)
    installed_requirements: dict[str, str] = field(default_factory=dict)
    missing_requirements: list[str] = field(default_factory=list)
    unresolved_requirements: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class InstallationActionResult:
    action: str
    ok: bool
    summary: str
    check: InstallationCheck
    config_path: str | None = None
    created: bool = False
    already_exists: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ComponentHealth:
    name: str
    state: HealthState
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class HealthReport:
    supervisor: ComponentHealth
    gateway: ComponentHealth
    environment: ComponentHealth
    config: IdeConfig
    gateway_status: GatewayStatus
    environment_probe: EnvironmentProbe


@dataclass(slots=True)
class SupervisorSnapshot:
    config: IdeConfig
    config_store: ConfigStoreInfo
    gateway: GatewayStatus
    environment: EnvironmentProbe
    health: HealthReport


# ---------------------------------------------------------------------------
# Chat agent config models (stored in SQLite)
# ---------------------------------------------------------------------------

# API mode constants
API_MODE_OPENAI_RESPONSES = "openai_responses"
API_MODE_OPENAI_COMPATIBLE = "openai_compatible"
API_MODE_ANTHROPIC = "anthropic"
ALL_API_MODES = (
    API_MODE_OPENAI_RESPONSES,
    API_MODE_OPENAI_COMPATIBLE,
    API_MODE_ANTHROPIC,
)


@dataclass(slots=True)
class ModelProvider:
    """A single LLM model provider entry."""
    id: int | None = None
    name: str = ""
    base_url: str = ""
    api_key: str = ""
    api_mode: str = API_MODE_OPENAI_COMPATIBLE
    model_name: str = ""
    top_p: float = 1.0
    temperature: float = 0.7
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ModelProvider":
        if not data:
            return cls()
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass(slots=True)
class McpServerEntry:
    """A single MCP server connection following langchain-mcp-adapters config.

    Fields map to the MultiServerMCPClient dict format:
      - ``stdio`` transport uses: command, args, env, cwd, encoding
      - ``http`` / ``sse`` transport uses: url, headers, timeout, sse_read_timeout

    JSON-encoded fields (args, env, headers) are stored as strings in SQLite
    and decoded when building the LangChain config dict.
    """

    id: int | None = None
    name: str = ""          # server key (e.g. "math", "weather")
    transport: str = "stdio"  # "http" | "sse" | "stdio"
    enabled: bool = True
    # stdio fields
    command: str = ""        # executable, e.g. "python"
    args: str = ""           # JSON array, e.g. '["/path/to/server.py"]'
    env: str = ""            # JSON object, e.g. '{"API_KEY": "xxx"}'
    cwd: str = ""            # working directory for stdio
    encoding: str = "utf-8"  # encoding for stdio transport
    # http / sse fields
    url: str = ""            # e.g. "http://localhost:8000/mcp"
    headers: str = ""        # JSON object, e.g. '{"Authorization": "Bearer t"}'
    timeout: float = 30.0    # HTTP timeout in seconds
    sse_read_timeout: float = 300.0  # SSE read timeout in seconds

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["id"] = d["id"]  # keep id in dict for upsert
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "McpServerEntry":
        if not data:
            return cls()
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in allowed})

    def to_langchain_config(self) -> dict[str, Any]:
        """Convert to MultiServerMCPClient-compatible dict.

        The returned dict is suitable as a value in the MultiServerMCPClient
        constructor's config dict, keyed by server name.
        """
        import json

        config: dict[str, Any] = {"transport": self.transport}

        if self.transport == "stdio":
            config["command"] = self.command
            if self.args:
                try:
                    config["args"] = json.loads(self.args)
                except (json.JSONDecodeError, TypeError):
                    config["args"] = []
            if self.env:
                try:
                    config["env"] = json.loads(self.env)
                except (json.JSONDecodeError, TypeError):
                    pass
            if self.cwd:
                config["cwd"] = self.cwd
            if self.encoding and self.encoding != "utf-8":
                config["encoding"] = self.encoding
        else:
            # http, sse — all use url
            config["url"] = self.url
            if self.headers:
                try:
                    config["headers"] = json.loads(self.headers)
                except (json.JSONDecodeError, TypeError):
                    pass
            if self.timeout and self.transport in ("http", "sse"):
                config["timeout"] = self.timeout
            if self.sse_read_timeout and self.transport == "sse":
                config["sse_read_timeout"] = self.sse_read_timeout

        return config


@dataclass(slots=True)
class SkillEntry:
    """A skill registered for the chat agent.

    Skills can be installed from zip packages that are extracted into
    ``{ide_data_dir}/skills/{name}/`` (typically ``{exe_dir}/data/skills/``).
    """

    id: int | None = None
    name: str = ""
    description: str = ""
    enabled: bool = True
    version: str = ""          # skill version string, e.g. "1.0.0"
    file_path: str = ""        # original zip file name
    install_dir: str = ""      # relative path under the skills directory
    installed_at: str = ""     # ISO timestamp of installation

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "SkillEntry":
        if not data:
            return cls()
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in allowed})
