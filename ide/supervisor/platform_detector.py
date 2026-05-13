"""Platform-specific discovery of IDA installations, Python paths, and plugin directories."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


def _dedupe_paths(paths: list[Path], *, must_exist: bool = False) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for p in paths:
        s = str(p)
        if s not in seen and (not must_exist or p.exists()):
            seen.add(s)
            result.append(s)
    return result


_IDA_PYSWITCH_RE = re.compile(r'IDA previously used:\s+"([^"]+)"')


def _probe_ida_python_via_idapyswitch(ida_dir: Path) -> list[str]:
    """Run idapyswitch to discover the Python associated with an IDA install.

    Parses the ``IDA previously used: "<dll_path>"`` line from the output.
    The DLL directory (or its parent) contains the Python executable.
    """
    if os.name == "nt":
        switch_exe = ida_dir / "idapyswitch.exe"
    else:
        switch_exe = ida_dir / "idapyswitch"

    if not switch_exe.exists():
        return []

    try:
        completed = subprocess.run(
            [str(switch_exe), "--dry-run"],
            capture_output=True,
            text=True,
            timeout=15,
            input="\n",
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    output = completed.stdout + completed.stderr
    candidates: list[Path] = []

    for line in output.splitlines():
        m = _IDA_PYSWITCH_RE.search(line)
        if not m:
            continue
        dll_path = Path(m.group(1))
        python_dir = dll_path.parent
        if os.name == "nt":
            exe = python_dir / "python.exe"
            if exe.exists():
                candidates.append(exe)
        else:
            for name in ("python3", "python"):
                exe = python_dir / "bin" / name
                if exe.exists():
                    candidates.append(exe)
                exe = python_dir / name
                if exe.exists():
                    candidates.append(exe)

    # Also collect all "Found:" lines as secondary candidates
    for line in output.splitlines():
        if line.strip().startswith("Found:"):
            m_dir = re.search(r'Found:\s+"([^"]+)"', line)
            if m_dir:
                d = Path(m_dir.group(1))
                if os.name == "nt":
                    exe = d / "python.exe"
                    if exe.exists():
                        candidates.append(exe)
                else:
                    for name in ("python3", "python"):
                        exe = d / "bin" / name
                        if exe.exists():
                            candidates.append(exe)

    return _dedupe_paths(candidates)


class PlatformDetector:
    """Discovers IDA executables, IDA Python interpreters, and plugin directories."""

    def find_ida_install_dirs(self) -> list[Path]:
        """Return directories that likely contain an IDA installation."""
        dirs: list[Path] = []
        if os.name == "nt":
            for base in filter(
                None,
                [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")],
            ):
                for name in ("IDA Pro", "IDA Professional"):
                    d = Path(base) / name
                    if d.is_dir():
                        dirs.append(d)
        else:
            for p in (Path("/opt/idapro"), Path("/opt/ida")):
                if p.is_dir():
                    dirs.append(p)
            for p in Path("/Applications").glob("IDA*.app"):
                mac_dir = p / "Contents" / "MacOS"
                if mac_dir.is_dir():
                    dirs.append(mac_dir)
        return dirs

    def find_ida_paths(self) -> list[str]:
        """Detect IDA executables via filesystem scan.

        IDA 9.x ships a single ``ida.exe``; older versions used
        ``ida64.exe`` / ``idat64.exe`` etc.
        """
        candidates: list[Path] = []

        if os.name == "nt":
            for base in filter(
                None,
                [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")],
            ):
                for name in ("IDA Pro", "IDA Professional"):
                    root = Path(base) / name
                    candidates.extend(
                        [root / "ida.exe", root / "ida64.exe", root / "idat64.exe"]
                    )
        else:
            candidates.extend(
                [
                    Path("/opt/idapro/ida64"),
                    Path("/usr/local/bin/ida64"),
                ]
            )
            # macOS: discover all IDA app bundles regardless of version
            for app in Path("/Applications").glob("IDA*.app"):
                mac_exe = app / "Contents" / "MacOS" / "ida64"
                if mac_exe.parent.is_dir():
                    candidates.append(mac_exe)

        return _dedupe_paths(candidates, must_exist=True)

    def find_ida_python_paths(self) -> list[str]:
        """Detect IDA Python via ``idapyswitch --dry-run``.

        Falls back to filesystem scan if ``idapyswitch`` is unavailable.
        """
        ida_dirs = self.find_ida_install_dirs()
        for ida_dir in ida_dirs:
            paths = _probe_ida_python_via_idapyswitch(ida_dir)
            if paths:
                return paths

        return self._fallback_ida_python_scan(ida_dirs)

    def _fallback_ida_python_scan(self, ida_dirs: list[Path]) -> list[str]:
        """Last-resort scan for python executables near IDA installs."""
        candidates: list[Path] = []
        for ida_dir in ida_dirs:
            if os.name == "nt":
                candidates.extend(
                    [
                        ida_dir / "ida-python" / "python.exe",
                        ida_dir / "python" / "python.exe",
                    ]
                )
            else:
                candidates.extend(
                    [
                        ida_dir / "ida-python" / "bin" / "python3",
                        ida_dir / "python" / "bin" / "python3",
                        ida_dir / "ida-python" / "python3",
                    ]
                )
        return _dedupe_paths(candidates, must_exist=True)

    def find_plugin_dirs(self) -> list[str]:
        """Detect installed ida_mcp plugin directories.

        Only scans real IDA plugin locations, never the bundled resources
        directory (ide/resources/ida_mcp).
        """
        from .models import _default_ida_plugin_dir

        candidates: list[Path] = [Path(_default_ida_plugin_dir())]

        if os.name == "nt":
            for base in filter(
                None,
                [
                    os.environ.get("ProgramFiles"),
                    os.environ.get("ProgramFiles(x86)"),
                ],
            ):
                for name in ("IDA Pro", "IDA Professional"):
                    candidates.append(Path(base) / name / "plugins")

        valid: list[Path] = []
        for candidate in candidates:
            if not candidate.exists():
                continue
            if (candidate / "ida_mcp.py").exists() and (candidate / "ida_mcp").exists():
                valid.append(candidate)
        return _dedupe_paths(valid)
