"""Minimal environment detection for the supervisor MVP."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from shared.paths import get_ida_mcp_resources_dir

from .models import EnvironmentProbe, InstallationActionResult, InstallationCheck
from .platform_detector import PlatformDetector, _probe_ida_python_via_idapyswitch


def _read_requirements_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    requirements: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        requirements.append(line)
    return requirements


def _requirement_name(requirement: str) -> str | None:
    match = re.match(r"^([A-Za-z0-9_.-]+)", requirement)
    if not match:
        return None
    return match.group(1)


def _check_installed_requirements(
    python_executable: Path | None,
    requirements: list[str],
) -> tuple[dict[str, str], list[str], list[str], str | None]:
    package_names: list[str] = []
    requirement_by_package: dict[str, str] = {}
    unresolved_requirements: list[str] = []
    for requirement in requirements:
        package_name = _requirement_name(requirement)
        if not package_name:
            unresolved_requirements.append(requirement)
            continue
        package_names.append(package_name)
        requirement_by_package[package_name] = requirement

    if not package_names:
        return {}, [], unresolved_requirements, None
    if not python_executable or not python_executable.exists():
        missing = [requirement_by_package[name] for name in package_names]
        return (
            {},
            missing,
            unresolved_requirements,
            "python executable is unavailable for dependency checks",
        )

    script = """
import importlib.metadata
import json
import sys

result = {}
for name in json.loads(sys.argv[1]):
    try:
        result[name] = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        result[name] = None

print(json.dumps(result))
"""
    try:
        completed = subprocess.run(
            [str(python_executable), "-c", script, json.dumps(package_names)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        missing = [requirement_by_package[name] for name in package_names]
        return {}, missing, unresolved_requirements, str(exc)

    if completed.returncode != 0:
        missing = [requirement_by_package[name] for name in package_names]
        error = (
            completed.stderr.strip()
            or completed.stdout.strip()
            or "dependency check failed"
        )
        return {}, missing, unresolved_requirements, error

    try:
        versions = json.loads(completed.stdout)
    except json.JSONDecodeError:
        missing = [requirement_by_package[name] for name in package_names]
        return (
            {},
            missing,
            unresolved_requirements,
            "dependency check returned invalid JSON",
        )

    installed: dict[str, str] = {}
    missing: list[str] = []
    for package_name in package_names:
        version = versions.get(package_name)
        requirement = requirement_by_package[package_name]
        if version:
            installed[requirement] = str(version)
        else:
            missing.append(requirement)
    return installed, missing, unresolved_requirements, None


def _requirements_file_candidates(repo_root: Path) -> list[Path]:
    return [
        repo_root / "requirements.txt",
    ]


def _resolve_requirements_path(repo_root: Path) -> Path:
    for candidate in _requirements_file_candidates(repo_root):
        if candidate.exists():
            return candidate
    return _requirements_file_candidates(repo_root)[0]


class EnvironmentInstaller:
    def __init__(self, repo_root: Path | None = None) -> None:
        self._repo_root = repo_root or get_ida_mcp_resources_dir()
        self._detector = PlatformDetector()

    def probe(self, plugin_dir: str | None = None) -> EnvironmentProbe:
        warnings: list[str] = []

        python_executable = sys.executable or shutil.which("python")
        if not python_executable:
            warnings.append("python executable not detected")

        # Check ida_mcp availability:
        # 1. If an explicit plugin_dir is given, check that directly.
        # 2. Otherwise, fall back to scanning standard IDA plugin locations.
        ida_mcp_importable = False
        ida_mcp_location: str | None = None

        if plugin_dir:
            p = Path(plugin_dir)
            if (p / "ida_mcp.py").exists() and (p / "ida_mcp").exists():
                ida_mcp_importable = True
                ida_mcp_location = str(p)
        if not ida_mcp_importable:
            plugin_candidates = self._detector.find_plugin_dirs()
            if plugin_candidates:
                ida_mcp_importable = True
                ida_mcp_location = plugin_candidates[0]

        if not ida_mcp_importable:
            warnings.append("ida_mcp plugin directory not detected")

        return EnvironmentProbe(
            python_executable=python_executable,
            python_version=sys.version.split()[0],
            ida_mcp_importable=ida_mcp_importable,
            ida_mcp_location=ida_mcp_location,
            ida_path_candidates=self._detector.find_ida_paths(),
            ida_python_candidates=self._detector.find_ida_python_paths(),
            warnings=warnings,
        )

    def find_plugin_dirs(self) -> list[str]:
        return self._detector.find_plugin_dirs()

    def find_ida_paths(self) -> list[str]:
        return self._detector.find_ida_paths()

    def find_ida_python_paths(self) -> list[str]:
        return self._detector.find_ida_python_paths()

    def detect_ida_executable(self, ida_dir: str | Path) -> str | None:
        """Detect the IDA executable inside an IDA installation directory."""
        d = Path(ida_dir)
        if not d.is_dir():
            return None
        names = ("ida.exe", "ida64.exe", "idat64.exe", "ida", "ida64")
        for name in names:
            exe = d / name
            if exe.exists():
                return str(exe)
        return None

    def detect_ida_python(self, ida_dir: str | Path) -> str | None:
        """Detect the IDA Python interpreter via idapyswitch."""
        d = Path(ida_dir)
        if not d.is_dir():
            return None
        candidates = _probe_ida_python_via_idapyswitch(d)
        return candidates[0] if candidates else None

    def check_installation(
        self,
        plugin_dir: str | Path | None = None,
        python_executable: str | Path | None = None,
        config_path: str | Path | None = None,
        ida_dir: str | Path | None = None,
    ) -> InstallationCheck:
        resolved_plugin_dir = self._resolve_plugin_dir(plugin_dir, ida_dir)
        resolved_python = self._resolve_python_executable(python_executable)
        resolved_config_path = self._resolve_config_path(
            config_path, resolved_plugin_dir
        )

        warnings: list[str] = []
        plugin_dir_exists = bool(resolved_plugin_dir and resolved_plugin_dir.exists())
        config_exists = bool(resolved_config_path and resolved_config_path.exists())
        ida_mcp_py_exists = bool(
            resolved_plugin_dir and (resolved_plugin_dir / "ida_mcp.py").exists()
        )
        ida_mcp_package_exists = bool(
            resolved_plugin_dir and (resolved_plugin_dir / "ida_mcp").exists()
        )
        python_exists = bool(resolved_python and resolved_python.exists())
        requirements_path = _resolve_requirements_path(self._repo_root)
        requirements = _read_requirements_file(requirements_path)
        (
            installed_requirements,
            missing_requirements,
            unresolved_requirements,
            dependency_check_error,
        ) = _check_installed_requirements(
            resolved_python,
            requirements,
        )

        if not resolved_plugin_dir:
            warnings.append("plugin directory not found")
        elif not plugin_dir_exists:
            warnings.append("plugin directory does not exist")
        if resolved_plugin_dir and not ida_mcp_py_exists:
            warnings.append("ida_mcp.py is missing")
        if resolved_plugin_dir and not ida_mcp_package_exists:
            warnings.append("ida_mcp package directory is missing")
        if not resolved_python:
            warnings.append("python executable not configured")
        elif not python_exists:
            warnings.append("python executable does not exist")
        if resolved_plugin_dir and not config_exists:
            warnings.append("config.conf is missing")
        if dependency_check_error:
            warnings.append(f"requirements check failed: {dependency_check_error}")
        if unresolved_requirements:
            warnings.append(
                "some requirements could not be parsed for installation checks"
            )

        summary = "installation looks usable"
        if warnings:
            summary = "; ".join(warnings)

        return InstallationCheck(
            plugin_dir=str(resolved_plugin_dir) if resolved_plugin_dir else None,
            plugin_dir_exists=plugin_dir_exists,
            config_path=str(resolved_config_path) if resolved_config_path else None,
            config_exists=config_exists,
            python_executable=str(resolved_python) if resolved_python else None,
            python_exists=python_exists,
            ida_mcp_py_exists=ida_mcp_py_exists,
            ida_mcp_package_exists=ida_mcp_package_exists,
            requirements_path=str(requirements_path),
            requirements=requirements,
            installed_requirements=installed_requirements,
            missing_requirements=missing_requirements,
            unresolved_requirements=unresolved_requirements,
            summary=summary,
            warnings=warnings,
        )

    def repair_config(
        self,
        plugin_dir: str | Path | None = None,
        python_executable: str | Path | None = None,
        config_path: str | Path | None = None,
    ) -> InstallationActionResult:
        check = self.check_installation(
            plugin_dir=plugin_dir,
            python_executable=python_executable,
            config_path=config_path,
        )
        target_config_path = Path(check.config_path) if check.config_path else None
        if not target_config_path:
            return InstallationActionResult(
                action="repair_config",
                ok=False,
                summary="cannot repair config without a target path",
                check=check,
                warnings=check.warnings.copy(),
            )

        if target_config_path.exists():
            return InstallationActionResult(
                action="repair_config",
                ok=True,
                summary="config.conf already exists",
                check=check,
                config_path=str(target_config_path),
                already_exists=True,
                warnings=check.warnings.copy(),
            )

        template_path = self._repo_root / "ida_mcp" / "config.conf"
        if not template_path.exists():
            return InstallationActionResult(
                action="repair_config",
                ok=False,
                summary="default config template is missing",
                check=check,
                config_path=str(target_config_path),
                warnings=check.warnings.copy(),
            )

        target_config_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(template_path, target_config_path)
        repaired_check = self.check_installation(
            plugin_dir=check.plugin_dir,
            python_executable=check.python_executable,
            config_path=str(target_config_path),
        )
        return InstallationActionResult(
            action="repair_config",
            ok=True,
            summary="created config.conf from the default template",
            check=repaired_check,
            config_path=str(target_config_path),
            created=True,
            warnings=repaired_check.warnings.copy(),
        )

    def reinstall(
        self,
        plugin_dir: str | Path | None = None,
        python_executable: str | Path | None = None,
        config_path: str | Path | None = None,
    ) -> InstallationActionResult:
        check = self.check_installation(
            plugin_dir=plugin_dir,
            python_executable=python_executable,
            config_path=config_path,
        )
        repair = self.repair_config(
            plugin_dir=check.plugin_dir,
            python_executable=check.python_executable,
            config_path=check.config_path,
        )

        if repair.ok:
            if repair.created:
                summary = (
                    "reinstall completed: checked installation and restored config.conf"
                )
            elif repair.already_exists:
                summary = "reinstall completed: checked installation and config.conf was already present"
            else:
                summary = "reinstall completed with basic checks"
        else:
            summary = f"reinstall incomplete: {repair.summary}"

        return InstallationActionResult(
            action="reinstall",
            ok=repair.ok,
            summary=summary,
            check=repair.check,
            config_path=repair.config_path,
            created=repair.created,
            already_exists=repair.already_exists,
            warnings=repair.warnings.copy(),
        )

    def _resolve_plugin_dir(
        self,
        plugin_dir: str | Path | None,
        ida_dir: str | Path | None = None,
    ) -> Path | None:
        if plugin_dir:
            return Path(plugin_dir)
        if ida_dir:
            candidate = Path(ida_dir) / "plugins"
            if candidate.exists():
                return candidate
        candidates = self.find_plugin_dirs()
        if candidates:
            return Path(candidates[0])
        return None

    def _resolve_python_executable(
        self,
        python_executable: str | Path | None,
    ) -> Path | None:
        if python_executable:
            return Path(python_executable)
        if sys.executable:
            return Path(sys.executable)
        discovered = shutil.which("python")
        return Path(discovered) if discovered else None

    def _resolve_config_path(
        self,
        config_path: str | Path | None,
        plugin_dir: Path | None,
    ) -> Path | None:
        if config_path:
            return Path(config_path)
        if plugin_dir:
            return plugin_dir / "ida_mcp" / "config.conf"
        return None
