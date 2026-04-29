"""Nuitka build script for the Sarma IDE.

Usage:
    python build_helpers/build_nuitka.py                        # standalone (default)
    python build_helpers/build_nuitka.py --mode onefile         # single-file exe
    python build_helpers/build_nuitka.py --print-only           # preview command only
    python build_helpers/build_nuitka.py --no-debug             # strip all debug info
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

_IS_WINDOWS = platform.system() == "Windows"
_IS_LINUX = platform.system() == "Linux"
_IS_MACOS = platform.system() == "Darwin"


# ---------------------------------------------------------------------------
# Bootstrap: put project root on sys.path so we can import shared.* at parse
# time (before Nuitka compiles anything).
# ---------------------------------------------------------------------------

def _bootstrap_project_root() -> None:
    project_root = Path(__file__).resolve().parents[1]
    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)


_bootstrap_project_root()

from shared.paths import (  # noqa: E402
    ensure_directory,
    get_nuitka_output_root,
    get_project_root,
    get_resources_root,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Packages that make up the IDE application.
_INCLUDE_PACKAGES = [
    "app",
    "shared",
    "supervisor",
    "bootstrap",
]

# PySide6 sub-modules that are commonly needed at runtime.
_PYSIDE6_EXTRAS = [
    "PySide6.QtWidgets",
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtNetwork",
]


def _resolve_icon(project_root: Path) -> Path | None:
    """Resolve the application icon, preferring .ico on Windows."""
    resources = project_root / "resources"
    for name in ("logo", "Sarma"):
        ico = resources / f"{name}.ico"
        png = resources / f"{name}.png"
        if ico.exists():
            return ico
        if png.exists():
            return png
    return None


def build_command(
    *,
    onefile: bool = False,
    no_debug: bool = False,
    jobs: int | None = None,
) -> list[str]:
    """Assemble the Nuitka command line for building the IDE.

    Parameters
    ----------
    onefile:
        Build a single-file executable instead of a standalone directory.
    no_debug:
        Strip all debug information for a smaller binary.
    jobs:
        Number of parallel C compilation jobs. Defaults to Nuitka's own
        heuristic when *None*.
    """
    project_root = get_project_root()
    launcher = project_root / "launcher.py"
    output_dir = ensure_directory(get_nuitka_output_root())

    # --- core flags (platform-agnostic) ------------------------------------
    command: list[str] = [
        sys.executable,
        "-m",
        "nuitka",
        "--onefile" if onefile else "--standalone",
        "--assume-yes-for-downloads",
        "--enable-plugin=pyside6",
        f"--output-filename={launcher.stem}",
        f"--output-dir={output_dir}",
    ]

    # --- platform-specific compiler flags ----------------------------------
    if _IS_WINDOWS:
        command.append("--clang")
        command.append("--windows-console-mode=disable")
    elif _IS_MACOS:
        command.append("--macos-disable-console")

    # --- package includes --------------------------------------------------
    for pkg in _INCLUDE_PACKAGES:
        command.append(f"--include-package={pkg}")

    # Ensure PySide6 sub-modules are fully included (the plugin handles most
    # of this, but explicit is better than implicit for QtNetwork etc.)
    for mod in _PYSIDE6_EXTRAS:
        command.append(f"--include-module={mod}")

    # --- anti-bloat: exclude test/dev dependencies that leak via transitive imports
    _NOFOLLOW_MODULES = [
        "pytest",
    ]
    for mod in _NOFOLLOW_MODULES:
        command.append(f"--nofollow-import-to={mod}")

    # --- auto-track all imports (langchain, langgraph, deepagents, etc.) ---
    command.append("--follow-imports")

    # --- bundled resources -------------------------------------------------
    resources_root = get_resources_root()
    if resources_root.exists() and any(resources_root.iterdir()):
        command.append(f"--include-data-dir={resources_root}=resources")

    # --- platform-specific application icon --------------------------------
    app_icon = _resolve_icon(project_root)
    if app_icon is not None:
        if _IS_WINDOWS:
            if app_icon.suffix == ".ico":
                command.append(f"--windows-icon-from-ico={app_icon}")
            elif app_icon.suffix == ".png":
                command.append(f"--windows-icon-from-ico={app_icon}")
        elif _IS_LINUX:
            if app_icon.suffix == ".png":
                command.append(f"--linux-icon={app_icon}")
        elif _IS_MACOS:
            if app_icon.suffix == ".png":
                command.append(f"--macos-app-icon={app_icon}")

    # --- optional flags ----------------------------------------------------
    if no_debug:
        command.append("--python-flag=no_site")
        command.append("--python-flag=no_warnings")
        command.append("--no-debug")

    if jobs is not None:
        command.append(f"--jobs={jobs}")

    # --- entry point -------------------------------------------------------
    command.append(str(launcher))
    return command


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the Sarma IDE with Nuitka",
    )
    parser.add_argument(
        "--mode",
        choices=("standalone", "onefile"),
        default="standalone",
        help="Packaging mode. Use 'standalone' first to verify, then 'onefile'.",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Print the resolved command without executing.",
    )
    parser.add_argument(
        "--no-debug",
        action="store_true",
        help="Strip debug info for a smaller binary.",
    )
    parser.add_argument(
        "-j", "--jobs",
        type=int,
        default=None,
        help="Number of parallel C compilation jobs.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    command = build_command(
        onefile=args.mode == "onefile",
        no_debug=args.no_debug,
        jobs=args.jobs,
    )

    # Pretty-print the command for review
    print("Resolved Nuitka command:\n")
    for i, token in enumerate(command):
        # Align flag tokens for readability
        if token.startswith("--"):
            print(f"  {token}")
        else:
            print(f"  {token}")
    print()

    if args.print_only:
        print("[print-only] Exiting without running.")
        return 0

    print("Starting build...\n")
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
