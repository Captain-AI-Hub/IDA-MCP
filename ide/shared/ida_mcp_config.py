"""Simple ida_mcp config.conf reader/writer for the IDE.

Now backed by SQLite (via DatabaseStore) while maintaining sync with the
file-based config.conf that the IDA plugin reads at runtime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.database import DatabaseStore
from shared.paths import ensure_directory, get_ida_mcp_resources_dir

from shared.models import ConfigStoreInfo, IdaMcpConfig


_ASSIGNMENT_RE = re.compile(
    r"^(?P<indent>\s*)(?P<comment>#\s*)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*)$"
)

# Derive known keys from the single source of truth in IdaMcpConfig.
_KNOWN_KEYS = IdaMcpConfig.field_names()


@dataclass(slots=True)
class _ParsedLine:
    raw: str
    key: str | None = None
    value: Any = None
    is_assignment: bool = False
    is_active: bool = False
    indent: str = ""
    inline_comment: str = ""


def _default_config_candidates(plugin_dir: Path | None = None) -> list[Path]:
    resources_dir = get_ida_mcp_resources_dir()
    candidates: list[Path] = []
    if plugin_dir:
        candidates.append(plugin_dir / "ida_mcp" / "config.conf")
    candidates.extend(
        [
            resources_dir / "ida_mcp" / "config.conf",
        ]
    )
    return candidates


def resolve_config_path(
    config_path: str | Path | None = None,
    *,
    plugin_dir: str | Path | None = None,
) -> Path:
    if config_path:
        return Path(config_path).expanduser()

    plugin_path = Path(plugin_dir).expanduser() if plugin_dir else None
    candidates = _default_config_candidates(plugin_path)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _split_value_and_comment(text: str) -> tuple[str, str]:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
            continue
        if char == "#":
            return text[:index].rstrip(), text[index:].rstrip()
    return text.rstrip(), ""


def _parse_scalar(text: str) -> Any:
    value = text.strip()
    if not value:
        return ""
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        inner = value[1:-1]
        return inner.replace(f"\\{value[0]}", value[0]).replace("\\\\", "\\")
    return value


def _format_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = "" if value is None else str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _parse_line(raw_line: str) -> _ParsedLine:
    line = raw_line.rstrip("\n")
    match = _ASSIGNMENT_RE.match(line)
    if not match:
        return _ParsedLine(raw=line)
    value_text, inline_comment = _split_value_and_comment(match.group("value"))
    return _ParsedLine(
        raw=line,
        key=match.group("key"),
        value=_parse_scalar(value_text),
        is_assignment=True,
        is_active=match.group("comment") is None,
        indent=match.group("indent") or "",
        inline_comment=inline_comment,
    )


class IdaMcpConfigStore:
    """SQLite-backed store for IdaMcpConfig with config.conf sync.

    Primary storage is the ``ida_mcp_config`` KV table in SQLite.
    Every write also syncs to the config.conf file so the IDA plugin
    can read it at runtime.
    """

    def __init__(
        self,
        config_path: Path | str | None = None,
        *,
        plugin_dir: Path | str | None = None,
        db: DatabaseStore | None = None,
    ) -> None:
        self._config_path = resolve_config_path(config_path, plugin_dir=plugin_dir)
        if db is not None:
            self._db = db
        else:
            self._db = DatabaseStore()

    @property
    def config_path(self) -> Path:
        return self._config_path

    def info(self) -> ConfigStoreInfo:
        return ConfigStoreInfo(
            path=str(self._config_path),
            exists=self._config_path.exists(),
        )

    def load(self) -> IdaMcpConfig:
        raw = self._db.load_kv_typed("ida_mcp_config", IdaMcpConfig)
        if raw:
            return IdaMcpConfig(**raw, config_path=str(self._config_path))

        # First-time: try to load from config.conf and seed SQLite.
        config = self._load_from_conf()
        self._db.save_kv("ida_mcp_config", config.to_dict())
        return config

    def save(self, config: IdaMcpConfig) -> IdaMcpConfig:
        return self.update(**config.to_dict())

    def update(self, **updates: object) -> IdaMcpConfig:
        pending = {key: value for key, value in updates.items() if key in _KNOWN_KEYS}
        self._db.save_kv("ida_mcp_config", pending)

        # Sync to config.conf for the IDA plugin.
        self._sync_to_conf(pending)

        return self.load()

    # ------------------------------------------------------------------
    # config.conf sync
    # ------------------------------------------------------------------

    def _load_from_conf(self) -> IdaMcpConfig:
        """Load from config.conf file (legacy fallback)."""
        values = IdaMcpConfig().to_dict()
        if not self._config_path.exists():
            return IdaMcpConfig(**values, config_path=str(self._config_path))

        active_values: dict[str, Any] = {}
        fallback_values: dict[str, Any] = {}
        for line in self._read_parsed_lines():
            if not line.is_assignment or not line.key or line.key not in _KNOWN_KEYS:
                continue
            target = active_values if line.is_active else fallback_values
            target[line.key] = line.value

        values.update(fallback_values)
        values.update(active_values)
        return IdaMcpConfig(**values, config_path=str(self._config_path))

    def _sync_to_conf(self, updates: dict[str, Any]) -> None:
        """Write updates to the config.conf file, preserving comments."""
        parsed_lines = self._read_parsed_lines() if self._config_path.exists() else []
        applied: set[str] = set()
        output: list[str] = []

        for line in parsed_lines:
            if line.is_assignment and line.key in updates and line.key not in applied:
                output.append(
                    self._render_assignment(line.key, updates[line.key], line)
                )
                applied.add(line.key)
                continue
            output.append(line.raw)

        for key, value in updates.items():
            if key in applied:
                continue
            output.append(self._render_assignment(key, value))

        ensure_directory(self._config_path.parent)
        self._config_path.write_text(
            "\n".join(output).rstrip() + "\n", encoding="utf-8"
        )

    def _read_parsed_lines(self) -> list[_ParsedLine]:
        text = self._config_path.read_text(encoding="utf-8")
        return [_parse_line(line) for line in text.splitlines()]

    def _render_assignment(
        self,
        key: str,
        value: object,
        existing: _ParsedLine | None = None,
    ) -> str:
        indent = existing.indent if existing else ""
        inline_comment = (
            f" {existing.inline_comment}"
            if existing and existing.inline_comment
            else ""
        )
        return f"{indent}{key} = {_format_scalar(value)}{inline_comment}".rstrip()
