"""Chat composer widget — rounded input area with model selector and send button."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, QPoint, Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QMenu,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from app.i18n import I18n


class Composer(QWidget):
    """Message input area with inline model selector and circular send button."""

    message_submitted = Signal(str)
    model_changed = Signal(int)  # provider_id

    def __init__(
        self,
        i18n: I18n,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self._i18n = i18n
        self._model_name = ""
        self._model_menu = QMenu(self)
        self._model_menu.setObjectName("chatModelMenu")

        # --- Outer container (rounded) ---
        self._container = QFrame()
        self._container.setObjectName("chatComposerContainer")

        container_layout = QVBoxLayout(self._container)
        container_layout.setContentsMargins(12, 8, 12, 8)
        container_layout.setSpacing(0)

        # --- Text input ---
        self._input = QTextEdit()
        self._input.setPlaceholderText(self._t("chat.placeholder"))
        self._input.setAcceptRichText(False)
        self._input.setObjectName("chatInput")
        self._input.installEventFilter(self)
        container_layout.addWidget(self._input, 3)

        # --- Bottom bar: model selector + send button ---
        bottom_bar = QWidget()
        bottom_layout = QHBoxLayout(bottom_bar)
        bottom_layout.setContentsMargins(0, 6, 0, 0)
        bottom_layout.setSpacing(8)

        self._model_button = QPushButton()
        self._model_button.setObjectName("chatModelButton")
        self._model_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._model_button.setFixedHeight(28)
        self._model_button.clicked.connect(self._show_model_menu)
        bottom_layout.addWidget(self._model_button)
        bottom_layout.addStretch(1)

        self._send_button = QPushButton("↑")
        self._send_button.setObjectName("chatSendRoundButton")
        self._send_button.setFixedSize(32, 32)
        self._send_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._send_button.clicked.connect(self._on_send)
        bottom_layout.addWidget(self._send_button)

        container_layout.addWidget(bottom_bar, 1)

        # --- Wrap in outer layout ---
        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 0, 12, 12)
        outer.setSpacing(0)
        outer.addWidget(self._container)

        self._update_model_text()

    def _t(self, key: str, **kwargs: object) -> str:
        return self._i18n.t(key, **kwargs)

    # ------------------------------------------------------------------
    # Event filter
    # ------------------------------------------------------------------

    def eventFilter(self, obj, event) -> bool:  # type: ignore[override]
        if obj is self._input and event.type() == QEvent.Type.KeyPress:
            key_event = event  # type: ignore[assignment]
            if key_event.key() in (Qt.Key_Return, Qt.Key_Enter):
                if key_event.modifiers() & Qt.ShiftModifier:
                    return False
                else:
                    self._on_send()
                    return True
        return super().eventFilter(obj, event)

    # ------------------------------------------------------------------
    # Model menu
    # ------------------------------------------------------------------

    def update_model_list(
        self, models: list[tuple[int, str]], active_id: int | None = None
    ) -> None:
        self._model_menu.clear()
        for pid, name in models:
            action = self._model_menu.addAction(name)
            action.setCheckable(True)
            action.setChecked(pid == active_id)
            action.triggered.connect(
                lambda checked, p=pid: self.model_changed.emit(p)
            )
        if not models:
            action = self._model_menu.addAction(self._t("chat.no_models"))
            action.setEnabled(False)

    def _show_model_menu(self) -> None:
        btn = self._model_button
        menu_size = self._model_menu.sizeHint()
        bottom_left = btn.mapToGlobal(btn.rect().bottomLeft())
        pos = bottom_left - QPoint(
            0, btn.height() + menu_size.height() + 4
        )
        screen = self.screen()
        if screen:
            geo = screen.availableGeometry()
            if pos.y() < geo.top():
                pos.setY(bottom_left.y() + 4)
        self._model_menu.popup(pos)

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    def _on_send(self) -> None:
        text = self._input.toPlainText().strip()
        if text:
            self.message_submitted.emit(text)
            self._input.clear()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_enabled(self, enabled: bool) -> None:
        self._input.setEnabled(enabled)
        self._send_button.setEnabled(enabled)

    def clear_input(self) -> None:
        self._input.clear()

    def set_placeholder(self, text: str) -> None:
        self._input.setPlaceholderText(text)

    def set_model_name(self, name: str) -> None:
        self._model_name = name or self._t("chat.no_model")
        self._update_model_text()

    def _update_model_text(self) -> None:
        self._model_button.setText(f"  ● {self._model_name}  ▲")
