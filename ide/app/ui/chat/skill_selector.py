"""Skill selector — dropdown for choosing an active agent skill.

Displays "No Skill" (default) plus all enabled skills from the database.
Emits skill_id when the user picks a skill (None for "No Skill").

NOTE: This widget is defined for future use.  The current ChatPage does
not add it to the composer — skill selection is managed via Settings.
When multi-skill support is needed, instantiate and call
``composer.add_selector(skill_selector)`` in ChatPage.__init__.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtWidgets import QMenu, QPushButton, QWidget

if TYPE_CHECKING:
    from app.i18n import I18n


class SkillSelector(QWidget):
    """Compact skill dropdown button."""

    skill_selected = Signal(object)  # int | None (skill_id or None)

    def __init__(
        self,
        i18n: I18n,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._i18n = i18n
        self._current_id: int | None = None
        self._skills: list[dict] = []

        self._menu = QMenu(self)
        self._menu.setObjectName("chatSkillMenu")

        self._button = QPushButton()
        self._button.setObjectName("chatSkillButton")
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

    def set_active(self, skill_id: int | None) -> None:
        """Set the active skill without emitting a signal."""
        self._current_id = skill_id
        self._update_text()
        self._rebuild_menu()

    def _rebuild_menu(self) -> None:
        self._menu.clear()

        # "No Skill" option
        no_skill = self._menu.addAction(self._t("chat.skill.none"))
        no_skill.setCheckable(True)
        no_skill.setChecked(self._current_id is None)
        no_skill.triggered.connect(lambda: self._select(None))
        self._menu.addSeparator()

        for skill in self._skills:
            name = skill.get("name", "")
            desc = skill.get("description", "")
            label = f"{name}" if not desc else f"{name} \u2014 {desc[:40]}"
            action = self._menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(self._current_id == skill["id"])
            action.triggered.connect(
                lambda checked, sid=skill["id"]: self._select(sid)
            )

        if not self._skills:
            empty = self._menu.addAction(self._t("chat.skill.empty"))
            empty.setEnabled(False)

    def _select(self, skill_id: int | None) -> None:
        self._current_id = skill_id
        self._update_text()
        self._rebuild_menu()
        self.skill_selected.emit(skill_id)

    def _update_text(self) -> None:
        if self._current_id is None:
            self._button.setText(f"  \u2726 {self._t('chat.skill.none')}  \u25BE")
            return

        for skill in self._skills:
            if skill["id"] == self._current_id:
                name = skill.get("name", "")
                self._button.setText(f"  \u2726 {name}  \u25BE")
                return

        self._button.setText(f"  \u2726 {self._t('chat.skill.none')}  \u25BE")

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
