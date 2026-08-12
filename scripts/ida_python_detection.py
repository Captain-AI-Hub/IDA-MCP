"""Best-effort discovery of the Python interpreter loaded by IDA Pro.

The important distinction here is between the Python that launches HCLI and the
Python selected by IDA's ``idapyswitch``/``idat`` runtime.  Dependency installs
must always target the latter.
"""

from __future__ import annotations

import json
import ntpath
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


_IDA_PROBE = """
import io
import json
import os
import sys
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
print("__ida_mcp_python__:" + json.dumps({
    "prefix": sys.prefix,
    "base_prefix": getattr(sys, "base_prefix", sys.prefix),
    "executable": sys.executable,
    "virtual_env": os.environ.get("VIRTUAL_ENV"),
    "idapython_venv_executable": os.environ.get("IDAPYTHON_VENV_EXECUTABLE"),
    "version_major": sys.version_info.major,
    "version_minor": sys.version_info.minor,
}))
sys.exit()
"""


def _existing_python_candidates(prefix: str | None, *, windows: bool, version: str | None = None) -> list[Path]:
    if not prefix:
        return []
    root = Path(prefix)
    if windows:
        return [root / "Scripts" / "python.exe", root / "python.exe"]

    bindir = root / "bin"
    candidates: list[Path] = []
    if version:
        candidates.append(bindir / f"python{version}")
    candidates.extend((bindir / "python3", bindir / "python", root / "python3", root / "python"))
    return candidates


def _is_python_executable(path: str | None) -> bool:
    return bool(path and "python" in Path(path).name.lower())


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        normalized = os.path.normcase(os.path.abspath(str(path)))
        if normalized in seen:
            continue
        seen.add(normalized)
        if path.is_file():
            result.append(path.resolve())
    return result


def _derive_from_probe(info: dict[str, Any], *, windows: bool) -> Path | None:
    version = None
    if info.get("version_major") is not None and info.get("version_minor") is not None:
        version = f"{info['version_major']}.{info['version_minor']}"

    requested = info.get("idapython_venv_executable")
    if requested and Path(requested).is_file():
        return Path(requested).resolve()

    candidates = _existing_python_candidates(info.get("prefix"), windows=windows, version=version)
    candidates += _existing_python_candidates(info.get("base_prefix"), windows=windows, version=version)

    # On macOS and some Linux configurations sys.executable is idat itself, so
    # only accept it when it really looks like a Python executable.
    executable = info.get("executable")
    if executable and _is_python_executable(executable):
        candidates.append(Path(executable))

    existing = _dedupe_paths(candidates)
    return existing[0] if existing else None


def _idat_candidates(ida_executable: Path) -> list[Path]:
    ida_dir = ida_executable.parent
    names = ["idat64", "idat", "idat64.exe", "idat.exe"]
    if ida_executable.stem.lower().endswith("64"):
        names = ["idat64", "idat64.exe", "idat", "idat.exe"]
    return _dedupe_paths([ida_dir / name for name in names])


def _prepare_isolated_idausr(source: Path, destination: Path) -> None:
    """Copy IDAPython selection state without loading third-party plugins."""
    destination.mkdir(parents=True, exist_ok=True)
    for relative in (Path("ida.reg"), Path("idapythonrc.py"), Path("cfg/idapython.cfg")):
        source_file = source / relative
        if not source_file.is_file():
            continue
        destination_file = destination / relative
        destination_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, destination_file)
    for license_file in source.glob("*.hexlic"):
        if license_file.is_file():
            shutil.copy2(license_file, destination / license_file.name)


def _probe_idat(idat_path: Path, *, ida_user_dir: Path | None = None) -> dict[str, Any] | None:
    with tempfile.TemporaryDirectory(prefix="ida-mcp-python-") as temp_dir:
        temp = Path(temp_dir)
        script = temp / "probe.py"
        log = temp / "ida.log"
        script.write_text(_IDA_PROBE, encoding="utf-8")

        env = os.environ.copy()
        # Never let the HCLI/system interpreter leak into IDA's embedded Python.
        for key in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"):
            env.pop(key, None)
        if ida_user_dir is not None:
            env["IDAUSR"] = str(ida_user_dir)
            env["IDA_IS_INTERACTIVE"] = "1"

        command = [
            str(idat_path),
            "-a",
            "-A",
            "-c",
            "-t",
            f"-L{log}",
            f"-S{script}",
        ]
        try:
            process = subprocess.run(
                command,
                cwd=str(idat_path.parent),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=45,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None

        output = ""
        if log.is_file():
            output += log.read_text(encoding="utf-8", errors="replace")
        output += "\n" + process.stdout + "\n" + process.stderr
        for line in output.splitlines():
            if line.startswith("__ida_mcp_python__:"):
                try:
                    return json.loads(line.split(":", 1)[1])
                except json.JSONDecodeError:
                    return None
    return None


def parse_idapyswitch_output(output: str, *, windows: bool) -> list[dict[str, str]]:
    """Parse idapyswitch output on Windows, Linux, and macOS.

    Linux output commonly reports a ``libpython*.so`` path rather than a
    directory, and Python installations may expose ``python3`` directly under
    the reported directory.  The old parser assumed ``bin/python3`` only.
    """
    results: list[dict[str, str]] = []
    pattern = re.compile(r"#(\d+):\s+([\d.]+)\s+\([^)]+\)\s+\(([^)]+)\)")
    for match in pattern.finditer(output):
        index, version, raw_path = match.groups()
        raw_path = raw_path.strip().rstrip("\\/")
        path_module = ntpath if windows else os.path
        filename = path_module.basename(raw_path)
        if re.match(r"(?:lib)?python[\d.]*\.(?:dll|so(?:\.[\d.]+)?|dylib)$", filename, re.IGNORECASE):
            root_text = path_module.dirname(raw_path)
            if path_module.basename(root_text).lower() in {"lib", "lib64"}:
                root_text = path_module.dirname(root_text)
        else:
            root_text = raw_path
        root = Path(root_text)

        candidates = _existing_python_candidates(root, windows=windows, version=version)
        # Some idapyswitch builds report the parent of the Python prefix.
        candidates.extend(_existing_python_candidates(root / "python" / version, windows=windows, version=version))
        executable = next(iter(_dedupe_paths(candidates)), None)
        if executable is None:
            continue
        results.append(
            {
                "index": index,
                "version": version,
                "dir": str(root),
                "exe": str(executable),
            }
        )

    preferred = re.search(r"IDA previously used:\s+.+?\(([^)]+)\)", output)
    if preferred and results:
        preferred_path = preferred.group(1).strip().rstrip("\\/")
        path_module = ntpath if windows else os.path
        preferred_name = path_module.basename(preferred_path)
        if re.match(r"(?:lib)?python[\d.]*\.(?:dll|so(?:\.[\d.]+)?|dylib)$", preferred_name, re.IGNORECASE):
            preferred_path = path_module.dirname(preferred_path)
            if path_module.basename(preferred_path).lower() in {"lib", "lib64"}:
                preferred_path = path_module.dirname(preferred_path)
        preferred_norm = os.path.normcase(os.path.abspath(preferred_path))
        for position, result in enumerate(results):
            result_norm = os.path.normcase(os.path.abspath(result["dir"]))
            if result_norm == preferred_norm or result_norm.startswith(preferred_norm + os.sep):
                results.insert(0, results.pop(position))
                break
    return results


def detect_ida_python(ida_executable: Path) -> Path | None:
    """Detect IDA's actual Python, preferring an ``idat`` runtime probe."""
    configured_idausr = os.environ.get("IDAUSR")
    ida_user_dir = Path(configured_idausr.split(os.pathsep)[0]) if configured_idausr else Path.home() / ".idapro"
    if not ida_user_dir.is_dir():
        ida_user_dir = None

    # idat executes the same idapythonrc.py and loads the same embedded Python
    # as the GUI. This is authoritative and works even when idapyswitch output
    # is localized or has a platform-specific layout.
    for idat_path in _idat_candidates(ida_executable):
        info = _probe_idat(idat_path, ida_user_dir=ida_user_dir)
        if info is None and ida_user_dir is not None:
            # A broken installed plugin can abort the real IDAUSR probe. Retry
            # with only Python selection, startup, and license state copied.
            with tempfile.TemporaryDirectory(prefix="ida-mcp-idausr-") as temp_dir:
                isolated_idausr = Path(temp_dir) / "idausr"
                _prepare_isolated_idausr(ida_user_dir, isolated_idausr)
                info = _probe_idat(idat_path, ida_user_dir=isolated_idausr)
        if info:
            detected = _derive_from_probe(info, windows=os.name == "nt")
            if detected:
                return detected

    override = os.environ.get("HCLI_CURRENT_IDA_PYTHON_EXE")
    if override and Path(override).is_file():
        return Path(override).resolve()

    switch_name = "idapyswitch.exe" if os.name == "nt" else "idapyswitch"
    switch_path = ida_executable.parent / switch_name
    if switch_path.is_file():
        try:
            process = subprocess.run(
                [str(switch_path)],
                cwd=str(switch_path.parent),
                input="\n",
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            installations = parse_idapyswitch_output(process.stdout + process.stderr, windows=os.name == "nt")
            if installations:
                return Path(installations[0]["exe"]).resolve()
        except (OSError, subprocess.SubprocessError):
            pass

    fallback_roots = [ida_executable.parent / "ida-python", ida_executable.parent / "python"]
    for root in fallback_roots:
        for candidate in _existing_python_candidates(str(root), windows=os.name == "nt"):
            if candidate.is_file():
                return candidate.resolve()
    return None
