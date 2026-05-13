"""Reusable utility widgets for the settings page."""

from __future__ import annotations

import re
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QMouseEvent, QPainter, QColor, QPalette
from PySide6.QtWidgets import QApplication, QComboBox, QDoubleSpinBox, QLineEdit, QSpinBox, QWidget


class NoWheelSpinBox(QSpinBox):
    def wheelEvent(self, event) -> None:  # type: ignore[override]
        event.ignore()


class NoWheelComboBox(QComboBox):
    def wheelEvent(self, event) -> None:  # type: ignore[override]
        event.ignore()


class NoWheelDoubleSpinBox(QDoubleSpinBox):
    def wheelEvent(self, event) -> None:  # type: ignore[override]
        event.ignore()


# -- Token-count input with K/M suffix support --

_SUFFIX_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kKmM]?)\s*$")
_SUFFIX_MULT = {"": 1, "k": 1_000, "K": 1_000, "m": 1_000_000, "M": 1_000_000}


def parse_token_text(text: str) -> int | None:
    """Parse a token-count string like ``"200K"`` or ``"1M"`` into an int.

    Returns ``None`` if *text* cannot be parsed.
    """
    m = _SUFFIX_RE.match(text)
    if not m:
        return None
    number = float(m.group(1))
    mult = _SUFFIX_MULT.get(m.group(2), 1)
    return int(number * mult)


def format_token_text(value: int) -> str:
    """Format a token count for display, using K/M suffixes when clean."""
    if value <= 0:
        return "0"
    if value % 1_000_000 == 0:
        return f"{value // 1_000_000}M"
    if value % 1_000 == 0:
        return f"{value // 1_000}K"
    return str(value)


class ContextTokenEdit(QLineEdit):
    """Single-line input that accepts token counts with optional K/M suffix.

    Internal value is always an ``int``.  Typing ``200K`` or ``1M`` is
    equivalent to ``200000`` or ``1000000`` respectively.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._value: int = 0
        self.setPlaceholderText("e.g. 200K, 1M, or 131072")
        self.setText("0")
        self.textChanged.connect(self._on_text_changed)

    # -- public API --

    def value(self) -> int:
        """Return the current token count as an integer."""
        return self._value

    def setValue(self, val: int) -> None:
        """Set the token count and update the displayed text."""
        self._value = max(0, val)
        # Block signals so we don't re-parse our own formatted text.
        self.blockSignals(True)
        self.setText(format_token_text(self._value))
        self.blockSignals(False)

    # -- internals --

    def _on_text_changed(self, text: str) -> None:
        parsed = parse_token_text(text)
        if parsed is not None:
            self._value = parsed

    def focusOutEvent(self, event):  # type: ignore[override]
        # Re-format on blur so the user sees the canonical form.
        self.blockSignals(True)
        self.setText(format_token_text(self._value))
        self.blockSignals(False)
        super().focusOutEvent(event)

    def keyPressEvent(self, event):  # type: ignore[override]
        # Allow free typing; validation happens silently.
        super().keyPressEvent(event)


# -- Circular slide toggle switch --

class ToggleSwitch(QWidget):
    """A compact circular slide toggle (iOS-style switch).

    Emits ``toggled(bool)`` when clicked.  Visuals adapt to the
    application palette so light/dark themes are handled automatically.
    """

    toggled = Signal(bool)

    _WIDTH = 36
    _HEIGHT = 20
    _HANDLE_SIZE = 16
    _PADDING = 2

    def __init__(self, parent: QWidget | None = None, checked: bool = False) -> None:
        super().__init__(parent)
        self._checked = checked
        self.setFixedSize(self._WIDTH, self._HEIGHT)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def isChecked(self) -> bool:
        return self._checked

    def setChecked(self, checked: bool) -> None:
        if self._checked == checked:
            return
        self._checked = checked
        self.update()
        self.toggled.emit(checked)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # type: ignore[override]
        if event.button() == Qt.MouseButton.LeftButton:
            self.setChecked(not self._checked)
            event.accept()
        else:
            super().mousePressEvent(event)

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        palette = QApplication.instance().palette() if QApplication.instance() else self.palette()

        # Background colour
        if self._checked:
            bg_color = palette.color(QPalette.ColorRole.Highlight)
        else:
            bg_color = QColor("#9ca3af") if self.isEnabled() else QColor("#d1d5db")

        painter.setBrush(bg_color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(self.rect(), self._HEIGHT // 2, self._HEIGHT // 2)

        # Handle (white circle)
        if self._checked:
            x = self._WIDTH - self._HANDLE_SIZE - self._PADDING
        else:
            x = self._PADDING
        y = (self._HEIGHT - self._HANDLE_SIZE) // 2
        painter.setBrush(QColor("#ffffff"))
        painter.drawEllipse(x, y, self._HANDLE_SIZE, self._HANDLE_SIZE)

        painter.end()
