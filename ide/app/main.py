"""PySide6 application entrypoint for the IDE MVP."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication


def _bootstrap_project_root() -> None:
    project_root = Path(__file__).resolve().parents[1]
    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)


_bootstrap_project_root()

from shared.paths import get_project_root


def _ensure_project_root_on_path() -> None:
    project_root = get_project_root()
    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)


_ensure_project_root_on_path()

from app.ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Sarma")
    app.setApplicationDisplayName("Sarma")

    # Set app-wide icon so taskbar and all windows inherit it
    from app.ui.icons import load_app_icon

    _icon = load_app_icon()
    if _icon is not None:
        app.setWindowIcon(_icon)

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
