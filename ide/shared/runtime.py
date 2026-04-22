"""Runtime helpers for development and Nuitka packaged modes."""

from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False) or getattr(sys, "__compiled__", False))


def get_runtime_root() -> Path:
    if is_frozen():
        return Path(getattr(sys, "executable", sys.argv[0])).resolve().parent
    return Path(__file__).resolve().parents[1]


def get_packaging_root() -> Path:
    return get_runtime_root() / "build_helpers"


def get_logs_root() -> Path:
    return get_runtime_root() / "logs"


def get_workspaces_root() -> Path:
    return get_runtime_root() / "workspaces"
