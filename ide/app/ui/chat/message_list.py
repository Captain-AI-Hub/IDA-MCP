"""Chat message list widget — renders conversation messages as scrollable bubbles."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)


class MessageBubble(QFrame):
    """A single message bubble in the chat."""

    def __init__(
        self, role: str, content: str, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._role = role
        self._content_label = QLabel(content)
        self._content_label.setWordWrap(True)
        self._content_label.setTextInteractionFlags(
            Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard
        )
        self._content_label.setObjectName("chatBubbleText")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)
        layout.addWidget(self._content_label)

        self.setObjectName(
            "chatBubbleUser" if role == "user" else "chatBubbleAssistant"
        )

    def append_text(self, text: str) -> None:
        """Append streaming text to the existing content."""
        current = self._content_label.text()
        self._content_label.setText(current + text)

    def set_text(self, text: str) -> None:
        """Replace the bubble content."""
        self._content_label.setText(text)

    @property
    def content_text(self) -> str:
        return self._content_label.text()


class ToolTraceCard(QFrame):
    """Inline card showing a tool invocation trace."""

    def __init__(
        self,
        tool_name: str,
        status: str,
        summary: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("toolTraceCard")

        self._tool_label = QLabel(f"\u2699 {tool_name}")
        self._tool_label.setObjectName("toolTraceTool")

        status_text = status
        if summary:
            status_text += f" \u2014 {summary}"
        self._status_label = QLabel(status_text)
        self._status_label.setObjectName("toolTraceStatus")
        self._status_label.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(2)
        layout.addWidget(self._tool_label)
        layout.addWidget(self._status_label)

    def update_status(self, status: str, summary: str = "") -> None:
        status_text = status
        if summary:
            status_text += f" \u2014 {summary}"
        self._status_label.setText(status_text)


class MessageList(QWidget):
    """Scrollable list of chat message bubbles and tool traces."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._messages_layout = QVBoxLayout()
        self._messages_layout.setContentsMargins(8, 8, 8, 8)
        self._messages_layout.setSpacing(8)
        self._messages_layout.addStretch(1)

        container = QWidget()
        container.setLayout(self._messages_layout)

        self._scroll = QScrollArea()
        self._scroll.setWidget(container)
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarAlwaysOff
        )
        self._scroll.setFrameShape(QFrame.NoFrame)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self._scroll)

        self._last_assistant_bubble: MessageBubble | None = None

    def append_message(self, role: str, content: str) -> None:
        """Add a new message bubble."""
        bubble = MessageBubble(role, content)

        # Insert before the trailing stretch
        count = self._messages_layout.count()
        self._messages_layout.insertWidget(count - 1, bubble)

        if role == "assistant":
            self._last_assistant_bubble = bubble
        elif role == "user":
            self._last_assistant_bubble = None

        self.scroll_to_bottom()

    def append_chunk(self, content: str) -> None:
        """Append streaming text to the last assistant bubble.

        If no assistant bubble exists, creates one.
        """
        if self._last_assistant_bubble is None:
            self.append_message("assistant", content)
        else:
            self._last_assistant_bubble.append_text(content)
        self.scroll_to_bottom()

    def add_tool_trace(
        self, tool_name: str, status: str, summary: str = ""
    ) -> None:
        """Add an inline tool trace card."""
        card = ToolTraceCard(tool_name, status, summary)
        count = self._messages_layout.count()
        self._messages_layout.insertWidget(count - 1, card)
        self.scroll_to_bottom()

    def clear_messages(self) -> None:
        """Remove all messages and traces."""
        while self._messages_layout.count() > 1:
            item = self._messages_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._last_assistant_bubble = None

    def scroll_to_bottom(self) -> None:
        """Auto-scroll to the latest content."""
        scrollbar = self._scroll.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
