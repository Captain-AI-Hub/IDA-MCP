"""Provider selector — dedicated widget for model provider selection.

Shows a dropdown with provider name + model ID. Emits provider_id when
the user selects a different provider.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtWidgets import QMenu, QPushButton, QWidget

if TYPE_CHECKING:
    from app.i18n import I18n


class ProviderSelector(QWidget):
    """Compact provider/model selector dropdown."""

    provider_changed = Signal(int)  # provider_id

    def __init__(
        self,
        i18n: I18n,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._i18n = i18n
        self._models: list[tuple[int, str, str]] = []  # (id, name, api_mode)
        self._active_id: int | None = None

        self._menu = QMenu(self)
        self._menu.setObjectName("chatProviderMenu")

        self._button = QPushButton()
        self._button.setObjectName("chatModelButton")
        self._button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._button.setFixedHeight(28)
        self._button.clicked.connect(self._show_menu)

        from PySide6.QtWidgets import QHBoxLayout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._button)

        self._update_text()

    def _t(self, key: str, **kwargs: object) -> str:
        return self._i18n.t(key, **kwargs)

    def update_providers(
        self,
        providers: list[tuple[int, str, str]],
        active_id: int | None = None,
    ) -> None:
        """Update the provider list.

        Args:
            providers: List of (id, display_name, api_mode) tuples.
            active_id: Currently active provider id.
        """
        self._models = list(providers)
        self._active_id = active_id
        self._rebuild_menu()
        self._update_text()

    def _rebuild_menu(self) -> None:
        self._menu.clear()
        for pid, name, _mode in self._models:
            action = self._menu.addAction(name)
            action.setCheckable(True)
            action.setChecked(pid == self._active_id)
            action.triggered.connect(
                lambda checked, p=pid: self._on_selected(p)
            )
        if not self._models:
            action = self._menu.addAction(self._t("chat.no_models"))
            action.setEnabled(False)

    def _on_selected(self, provider_id: int) -> None:
        if provider_id == self._active_id:
            return
        self._active_id = provider_id
        self._rebuild_menu()
        self._update_text()
        self.provider_changed.emit(provider_id)

    def _update_text(self) -> None:
        if self._active_id is not None:
            for pid, name, _mode in self._models:
                if pid == self._active_id:
                    self._button.setText(f"  \u25CF {name}  \u25BE")
                    return

        self._button.setText(
            f"  \u25CF {self._t('chat.no_model')}  \u25BE"
        )

    def _show_menu(self) -> None:
        menu_size = self._menu.sizeHint()
        btn = self._button
        bottom_left = btn.mapToGlobal(btn.rect().bottomLeft())
        pos = bottom_left - QPoint(0, btn.height() + menu_size.height() + 4)
        screen = self.screen()
        if screen:
            geo = screen.availableGeometry()
            if pos.y() < geo.top():
                pos.setY(bottom_left.y() + 4)
        self._menu.popup(pos)
