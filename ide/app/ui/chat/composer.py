"""Chat composer widget — rounded input area with send button.

Phase 2: Provider and skill selectors are injected from the page layer
via `add_selector()`. The composer no longer owns a model menu.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, Qt, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from app.i18n import I18n


class Composer(QWidget):
    """Message input area with selector slots and send/stop button."""

    message_submitted = Signal(str)
    stop_requested = Signal()
    clear_requested = Signal()

    def __init__(
        self,
        i18n: I18n,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("composerArea")

        self._i18n = i18n
        self._is_running = False

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

        # --- Bottom bar: selectors + clear icon + send/stop ---
        bottom_bar = QWidget()
        self._bottom_layout = QHBoxLayout(bottom_bar)
        self._bottom_layout.setContentsMargins(0, 6, 0, 0)
        self._bottom_layout.setSpacing(8)

        # Selectors are added by ChatPage via add_selector()
        self._selector_widgets: list[QWidget] = []

        # Clear button (icon-only round button, aligned with model selectors)
        self._clear_button = QPushButton()
        self._clear_button.setObjectName("chatClearButton")
        self._clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._clear_button.setToolTip(self._t("chat.clear"))
        _clear_svg = (
            Path(__file__).resolve().parents[3] / "resources" / "icons" / "clear.svg"
        )
        if _clear_svg.exists():
            from app.ui.theme import current_palette
            from app.ui.icons import tint_svg

            palette = current_palette()
            self._clear_button.setIcon(
                tint_svg(str(_clear_svg), palette.text_secondary, size=16)
            )
        self._clear_button.clicked.connect(self.clear_requested.emit)
        self._bottom_layout.addWidget(self._clear_button)

        self._bottom_layout.addStretch(1)

        self._send_button = QPushButton()
        self._send_button.setObjectName("chatSendRoundButton")
        self._send_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._send_button.clicked.connect(self._on_send)

        # Load send icon; draw stop icon as a filled circle with white X
        _send_svg = (
            Path(__file__).resolve().parents[3]
            / "resources" / "icons" / "send.svg"
        )
        if _send_svg.exists():
            from app.ui.theme import current_palette
            from app.ui.icons import tint_svg

            _palette = current_palette()
            self._icon_send = tint_svg(
                str(_send_svg), _palette.accent_text, size=16
            )
            self._icon_stop = self._create_stop_icon(16, QColor(_palette.status_error))
            self._send_button.setIcon(self._icon_send)

        self._bottom_layout.addWidget(self._send_button)

        container_layout.addWidget(bottom_bar, 1)

        # --- Wrap in outer layout ---
        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 0, 12, 12)
        outer.setSpacing(0)
        outer.addWidget(self._container)

    def _t(self, key: str, **kwargs: object) -> str:
        return self._i18n.t(key, **kwargs)

    @staticmethod
    def _create_stop_icon(size: int, bg_color: QColor) -> QIcon:
        """Draw a circular icon with a white X in the centre."""
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)

        # Filled circle
        painter.setBrush(bg_color)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(0, 0, size, size)

        # White X
        pen = QPen(QColor("white"))
        pen.setWidth(max(1, size // 5))
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)

        padding = size // 4
        painter.drawLine(padding, padding, size - padding, size - padding)
        painter.drawLine(size - padding, padding, padding, size - padding)

        painter.end()
        return QIcon(pixmap)

    # ------------------------------------------------------------------
    # Selector management
    # ------------------------------------------------------------------

    def add_selector(self, widget: QWidget) -> None:
        """Add a selector widget to the bottom bar, before the clear icon."""
        self._selector_widgets.append(widget)
        # Layout order: [selector(s)...] [clear] [stretch] [send]
        # Insert before the clear button (index = count - 3)
        clear_index = self._bottom_layout.count() - 3
        self._bottom_layout.insertWidget(max(0, clear_index), widget)

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
    # Send
    # ------------------------------------------------------------------

    def _on_send(self) -> None:
        if self._is_running:
            self.stop_requested.emit()
            return
        text = self._input.toPlainText().strip()
        if text:
            self.message_submitted.emit(text)
            self._input.clear()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def retranslate(self) -> None:
        """Refresh all translatable text after a language change."""
        self._input.setPlaceholderText(self._t("chat.placeholder"))
        self._clear_button.setToolTip(self._t("chat.clear"))

    def set_running(self, running: bool) -> None:
        """Toggle between send mode and stop mode."""
        self._is_running = running
        if running:
            if hasattr(self, "_icon_stop"):
                self._send_button.setIcon(self._icon_stop)
            self._send_button.setObjectName("chatStopRoundButton")
            self._input.setEnabled(False)
        else:
            if hasattr(self, "_icon_send"):
                self._send_button.setIcon(self._icon_send)
            self._send_button.setObjectName("chatSendRoundButton")
            self._input.setEnabled(True)
        # Force QSS re-polish
        self._send_button.style().unpolish(self._send_button)
        self._send_button.style().polish(self._send_button)

    def clear_input(self) -> None:
        self._input.clear()
