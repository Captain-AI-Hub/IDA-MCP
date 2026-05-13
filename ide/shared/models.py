"""Shared data models for IDE layers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any, ClassVar


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
