"""IDA-MCP configuration management module.

Reads config.conf files and provides access to all configurable options.

Configuration sources, later wins:
    1. built-in defaults
    2. packaged ``ida_mcp/config.conf`` (plugin install directory)
    3. user config ``<IDA_MCP_STATE_DIR|IDAUSR|~/.idapro>/ida-mcp/config.conf``
    4. environment overrides ``IDA_MCP_CONFIG_<KEY>``
    5. HCLI ida-settings overrides (only while running inside IDA)

Configuration Options
====================
MCP server (standalone process):
    - stdio is the only transport; no HTTP settings remain

IDA / headless launch:
    - ida_python: interpreter that can ``import idapro``; drives headless
      idalib workers (normally IDA's own bundled runtime)

General:
    - request_timeout: request timeout in seconds (default 30)
    - debug: whether to enable debug logging (default false)
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, Mapping

# config file path
_CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
_CONFIG_FILE = os.path.join(_CONFIG_DIR, "config.conf")

_TRANSPORTS = ("stdio", "http")

# default configuration
_DEFAULT_CONFIG = {
    # IDA / headless launch
    "ida_python": None,  # Python executable that runs idalib workers
    # general
    "request_timeout": 30,
    "debug": False,
}

# HCLI-managed settings. HCLI stores these in ida-config.json and the
# ida-settings package exposes them while the plugin is running inside IDA.
_HCLI_SETTING_KEYS = (
    "ida_python",
    "request_timeout",
    "debug",
)
_ENV_PREFIX = "IDA_MCP_CONFIG_"
_AUTO_PYTHON_SENTINELS = {"auto", "detect", "auto-detect"}

# cached configuration
_cached_config: Dict[str, Any] | None = None


def _coerce_bool(value: Any, default: bool) -> bool:
    """Coerce a config value to boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        parsed = _parse_value(value)
        if isinstance(parsed, bool):
            return parsed
        if isinstance(parsed, (int, float)):
            return bool(parsed)
    return default


def _coerce_int_range(value: Any, default: int, minimum: int, maximum: int) -> int:
    """Coerce an integer config value and clamp invalid values to default."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if minimum <= parsed <= maximum:
        return parsed
    return default


def _parse_value(value: str) -> Any:
    """Parse a config value, supporting strings, integers, and booleans."""
    value = value.strip()

    # strip quotes
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]

    # booleans
    if value.lower() in ("true", "yes", "on", "1"):
        return True
    if value.lower() in ("false", "no", "off", "0"):
        return False

    # integers
    try:
        return int(value)
    except ValueError:
        pass

    # floats
    try:
        return float(value)
    except ValueError:
        pass

    return value


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


def parse_config_file(path: str) -> Dict[str, Any]:
    """Parse any config.conf-style file."""
    config: Dict[str, Any] = {}

    if not os.path.exists(path):
        return config

    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                value, _comment = _split_value_and_comment(value)
                config[key.strip()] = _parse_value(value)
    except Exception:
        return {}

    return config


def _user_config_file() -> str:
    """User-scope config path (also used by uvx-launched standalone servers)."""
    try:
        from . import instances

        state_dir = instances.get_state_dir()
    except Exception:  # noqa: BLE001 - state dir must never break config
        state_dir = None
    if not state_dir:
        return os.path.join(os.path.expanduser("~"), ".idapro", "ida-mcp", "config.conf")
    return os.path.join(str(state_dir), "config.conf")


def _environment_overrides() -> Dict[str, Any]:
    """Read settings forwarded to child processes or set explicitly."""
    overrides: Dict[str, Any] = {}
    for key in _HCLI_SETTING_KEYS:
        value = os.environ.get(f"{_ENV_PREFIX}{key.upper()}")
        if value is not None:
            overrides[key] = _parse_value(value)
    return overrides


def _hcli_setting_overrides() -> Dict[str, Any]:
    """Read HCLI settings when called from an installed IDA plugin."""
    try:
        import ida_settings  # type: ignore
    except (ImportError, ModuleNotFoundError):
        return {}

    overrides: Dict[str, Any] = {}
    for key in _HCLI_SETTING_KEYS:
        try:
            value = ida_settings.get_current_plugin_setting(key)
        except Exception:
            # Configuration must remain usable if ida-settings changes or is
            # unavailable in a child process.
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
        overrides[key] = value
    return overrides


def _write_config_string(path: str, key: str, value: str) -> bool:
    """Best-effort persistence for non-HCLI plugin installations."""
    try:
        with open(path, "r", encoding="utf-8", newline="") as handle:
            lines = handle.readlines()
    except OSError:
        return False

    import json

    encoded = json.dumps(value, ensure_ascii=False)
    replaced = False
    output: list[str] = []
    for line in lines:
        ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        body = line[: -len(ending)] if ending else line
        stripped = body.lstrip()
        if not replaced and re.match(rf"^{re.escape(key)}\s*=", stripped):
            indent = body[: len(body) - len(stripped)]
            _value, comment = _split_value_and_comment(stripped.split("=", 1)[1])
            suffix = f" {comment}" if comment else ""
            output.append(f"{indent}{key} = {encoded}{suffix}{ending}")
            replaced = True
        else:
            output.append(line)

    if not replaced:
        output.append(f"{key} = {encoded}\n")
    try:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.writelines(output)
        return True
    except OSError:
        return False


def _detect_running_ida_python() -> str | None:
    """Resolve the Python executable backing the current IDAPython runtime."""
    # Exact running version first (e.g. bin/python3.12); generic names and
    # the odd prefix-root "python" come last.
    versioned = f"python{sys.version_info.major}.{sys.version_info.minor}"

    executable = getattr(sys, "executable", "")
    candidates: list[str] = []
    if executable and os.path.basename(executable).lower().startswith("python"):
        candidates.append(executable)

    for prefix in (
        getattr(sys, "exec_prefix", None),
        getattr(sys, "base_prefix", None),
        getattr(sys, "prefix", None),
    ):
        if not prefix:
            continue
        if os.name == "nt":
            candidates.append(os.path.join(prefix, "python.exe"))
        else:
            candidates.extend(
                [
                    os.path.join(prefix, "bin", versioned),
                    os.path.join(prefix, "bin", "python3"),
                    os.path.join(prefix, "bin", "python"),
                    os.path.join(prefix, versioned),
                    os.path.join(prefix, "python3"),
                    os.path.join(prefix, "python"),
                ]
            )

    seen: set[str] = set()
    for candidate in candidates:
        normalized = os.path.normcase(os.path.abspath(candidate))
        if normalized in seen:
            continue
        seen.add(normalized)
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return None


def initialize_runtime_settings() -> Dict[str, Any]:
    """Resolve machine-specific settings on first plugin load."""
    global _cached_config

    config = load_config(reload=True)
    result: Dict[str, Any] = {
        "ida_python": None,
        "ida_python_detected": False,
    }

    raw_python = config.get("ida_python")
    python_value = raw_python.strip() if isinstance(raw_python, str) else ""
    if not python_value or python_value.lower() in _AUTO_PYTHON_SENTINELS:
        detected = _detect_running_ida_python()
        if detected:
            python_value = detected
            # Cache into the USER config; the packaged config.conf stays
            # pristine (wheel installs are read-only).
            if persist_user_setting("ida_python", detected):
                result["ida_python_detected"] = True
    result["ida_python"] = python_value or None

    _cached_config = None
    effective = load_config(reload=True)
    if python_value and (
        not raw_python
        or str(raw_python).strip().lower() in _AUTO_PYTHON_SENTINELS
    ):
        effective["ida_python"] = python_value
    _cached_config = effective
    return result


def load_config(reload: bool = False) -> Dict[str, Any]:
    """Load defaults, config files, environment, and HCLI settings."""
    global _cached_config

    if _cached_config is not None and not reload:
        return _cached_config

    config = dict(_DEFAULT_CONFIG)
    config.update(parse_config_file(_CONFIG_FILE))
    config.update(parse_config_file(_user_config_file()))
    config.update(_environment_overrides())
    config.update(_hcli_setting_overrides())
    _cached_config = config
    return config


def build_subprocess_environment(
    base: Mapping[str, str] | None = None,
) -> Dict[str, str]:
    """Forward effective settings to spawned child processes."""
    environment = dict(os.environ if base is None else base)
    config = load_config()
    for key in _HCLI_SETTING_KEYS:
        value = config.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        if isinstance(value, bool):
            serialized = "true" if value else "false"
        else:
            serialized = str(value)
        environment[f"{_ENV_PREFIX}{key.upper()}"] = serialized
    return environment


# ============================================================================
# User-scope config persistence (used by standalone/uvx runs)
# ============================================================================


def persist_user_setting(key: str, value: str) -> bool:
    """Persist one setting into <state_dir>/config.conf, creating it if needed.

    Used to cache machine-specific detections (e.g. the idalib Python) so
    later uvx/stdio launches skip probing.
    """
    path = _user_config_file()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "# IDA-MCP user configuration (managed by IDA-MCP; edit freely)\n"
                )
        _write_config_string(path, key, value)
        global _cached_config
        _cached_config = None
        return True
    except OSError:
        return False


# ============================================================================
# IDA / headless launch config accessors
# ============================================================================


def get_ida_python() -> str | None:
    """Get the IDA Python executable path."""
    config = load_config()
    path = config.get("ida_python")

    if isinstance(path, str):
        path = path.strip()
        if path and path.lower() not in _AUTO_PYTHON_SENTINELS:
            return path
    return None


# ============================================================================
# General config accessors
# ============================================================================


def get_request_timeout() -> int:
    """Get the request timeout in seconds."""
    config = load_config()
    return _coerce_int_range(config.get("request_timeout", 30), 30, 1, 3600)


def is_debug_enabled() -> bool:
    """Whether debug logging is enabled."""
    config = load_config()
    return bool(config.get("debug", False))


