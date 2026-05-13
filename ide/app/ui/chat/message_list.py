"""Chat message list — flat conversation layout with markdown rendering.

Style inspired by opencode: messages are laid out linearly (no bubbles),
with role labels ("You", "Assistant"), dividers between Q&A turns, and
a pulsing dot animation while the model is thinking.

Phase 2: Markdown rendering via QTextBrowser.setMarkdown(), code block
styling, and copy-to-clipboard for code blocks.
"""

from __future__ import annotations

import re

from PySide6.QtCore import QParallelAnimationGroup, QPropertyAnimation, Qt, QSize
from PySide6.QtGui import (
    QColor,
    QFont,
    QSyntaxHighlighter,
    QTextCharFormat,
)
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QToolButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Terminal statuses — a tool card in one of these states should not be
# updated by a subsequent result for the same tool name.
_TOOL_TERMINAL_STATUSES = frozenset({
    "completed", "done", "succeeded", "failed", "error",
})


def _tool_status_icon(status: str) -> str:
    """Return an emoji icon for a tool call status string.

    Shared by ToolCallCard and TraceEntry (tool_trace_panel.py).
    """
    if status in ("running", "...", "running..."):
        return "\u23F3"
    if status in ("completed", "done", "succeeded"):
        return "\u2713"
    if status in ("failed", "error"):
        return "\u2717"
    return "\u2699"


# ---------------------------------------------------------------------------
# Code block highlighter (simple)
# ---------------------------------------------------------------------------

class _CodeBlockHighlighter(QSyntaxHighlighter):
    """Minimal syntax highlighter for code blocks inside QTextBrowser.

    Reads colours from theme.SYNTAX_TOKENS so it adapts to light/dark mode.
    """

    KEYWORDS = {
        "auto", "break", "case", "char", "const", "continue", "default",
        "do", "double", "else", "enum", "extern", "float", "for", "goto",
        "if", "int", "long", "register", "return", "short", "signed",
        "sizeof", "static", "struct", "switch", "typedef", "union",
        "unsigned", "void", "volatile", "while",
        "def", "class", "import", "from", "return", "if", "else", "elif",
        "for", "while", "try", "except", "finally", "with", "as", "lambda",
        "True", "False", "None", "and", "or", "not", "in", "is", "pass",
        "raise", "yield", "async", "await",
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._apply_theme()

    def _apply_theme(self) -> None:
        """Load colours from the current theme tokens (dark-aware)."""
        from app.ui.theme import syntax_tokens, current_theme_mode_enum

        tokens = syntax_tokens(current_theme_mode_enum())
        self._keyword_color, self._keyword_bold = tokens.get(
            "Token.Keyword", ("#7C3AED", True)
        )
        self._comment_color, _ = tokens.get("Token.Comment", ("#6A9955", False))
        self._string_color, _ = tokens.get("Token.Literal.String", ("#A31515", False))
        self._number_color, _ = tokens.get("Token.Literal.Number", ("#098658", False))

    def highlightBlock(self, text: str) -> None:
        keyword_fmt = QTextCharFormat()
        keyword_fmt.setForeground(QColor(self._keyword_color))
        if self._keyword_bold:
            keyword_fmt.setFontWeight(QFont.Weight.Bold)

        comment_fmt = QTextCharFormat()
        comment_fmt.setForeground(QColor(self._comment_color))

        string_fmt = QTextCharFormat()
        string_fmt.setForeground(QColor(self._string_color))

        number_fmt = QTextCharFormat()
        number_fmt.setForeground(QColor(self._number_color))

        # Comments: // and #
        for m in re.finditer(r"(?://|#).*", text):
            self.setFormat(m.start(), m.end() - m.start(), comment_fmt)

        # Strings: "..." and '...'
        for m in re.finditer(r"""(?:"[^"]*"|'[^']*')""", text):
            self.setFormat(m.start(), m.end() - m.start(), string_fmt)

        # Numbers
        for m in re.finditer(r"\b\d+\.?\d*\b", text):
            self.setFormat(m.start(), m.end() - m.start(), number_fmt)

        # Keywords
        for m in re.finditer(r"\b\w+\b", text):
            if m.group() in self.KEYWORDS:
                self.setFormat(m.start(), m.end() - m.start(), keyword_fmt)


# ---------------------------------------------------------------------------
# Markdown content widget
# ---------------------------------------------------------------------------


def _get_markdown_css() -> str:
    """Build markdown CSS from the current theme palette."""
    from app.ui.theme import markdown_css as _md_css, current_palette

    return _md_css(current_palette())


class MarkdownContent(QTextBrowser):
    """Read-only QTextBrowser that renders markdown content."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setOpenExternalLinks(True)
        self.setReadOnly(True)
        self.setObjectName("chatMarkdownContent")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setViewportMargins(0, 0, 0, 0)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        # QSS handles background/border/font — no inline setStyleSheet needed
        self._highlighter = _CodeBlockHighlighter(self.document())
        self._raw_markdown: str = ""

        # Re-adjust height whenever the document layout finishes or the
        # widget is resized (text reflows).  This fixes the "one line on
        # reload" bug where setFixedHeight was called before the document
        # had been laid out at its final width.
        self.document().documentLayout().documentSizeChanged.connect(
            self._adjust_height
        )

    def set_markdown(self, text: str) -> None:
        """Set content as markdown and adjust height."""
        self._raw_markdown = text
        html = self._to_html(text)
        self.setHtml(html)
        self._adjust_height()

    def append_markdown(self, text: str) -> None:
        """Append text to existing markdown content."""
        self._raw_markdown += text
        html = self._to_html(self._raw_markdown)
        self.setHtml(html)
        self._adjust_height()

    @property
    def raw_markdown(self) -> str:
        return self._raw_markdown

    def _to_html(self, markdown_text: str) -> str:
        """Convert markdown to styled HTML."""
        try:
            import markdown as md_lib
            body = md_lib.markdown(
                markdown_text,
                extensions=["fenced_code", "tables", "codehilite"],
                extension_configs={"codehilite": {"css_class": "highlight"}},
            )
        except ImportError:
            # Fallback to Qt's built-in markdown
            # We use setMarkdown and extract HTML
            doc = self.document()
            doc.setMarkdown(markdown_text)
            return doc.toHtml()

        return f"<html><head><style>{_get_markdown_css()}</style></head><body>{body}</body></html>"

    def _adjust_height(self) -> None:
        """Adjust widget height to fit content."""
        doc_height = self.document().size().height()
        self.setFixedHeight(max(30, int(doc_height) + 4))

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        """Re-layout text when the widget width changes."""
        super().resizeEvent(event)
        # Width change causes text reflow → documentSizeChanged will fire
        # and call _adjust_height, but we also do it here for immediate
        # feedback when the widget first becomes visible.
        self._adjust_height()

    def sizeHint(self) -> QSize:
        return QSize(super().sizeHint().width(), self.minimumHeight())


# ---------------------------------------------------------------------------
# Turn divider
# ---------------------------------------------------------------------------

class TurnDivider(QFrame):
    """Thin horizontal line separating conversation turns."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("chatTurnDivider")
        self.setFixedHeight(1)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)


# ---------------------------------------------------------------------------
# Role label
# ---------------------------------------------------------------------------

class RoleLabel(QLabel):
    """Small label showing "You" or "Assistant" above a message block."""

    def __init__(self, role: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName(
            "chatRoleUser" if role == "user" else "chatRoleAssistant"
        )
        self.setText(role.capitalize())


# ---------------------------------------------------------------------------
# Message block (flat, with markdown rendering)
# ---------------------------------------------------------------------------

class MessageBlock(QFrame):
    """A single flat message with role label and markdown content."""

    def __init__(
        self, role: str, content: str, show_role: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._role = role
        self.setObjectName("chatMessageBlock")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 8, 24, 8)
        layout.setSpacing(4)

        # Role label (hidden for continuation segments)
        if show_role:
            role_label = RoleLabel(role)
            layout.addWidget(role_label)

        if role == "user":
            # User messages: plain text (keep it simple)
            self._content_label = QLabel(content)
            self._content_label.setWordWrap(True)
            self._content_label.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
                | Qt.TextInteractionFlag.TextSelectableByKeyboard
            )
            self._content_label.setObjectName("chatMessageText")
            layout.addWidget(self._content_label)
            self._markdown_content: MarkdownContent | None = None
        else:
            # Assistant messages: markdown rendering
            self._content_label = None
            self._markdown_content = MarkdownContent()
            self._markdown_content.set_markdown(content)
            layout.addWidget(self._markdown_content)

    def append_text(self, text: str) -> None:
        if self._markdown_content is not None:
            self._markdown_content.append_markdown(text)
        elif self._content_label is not None:
            self._content_label.setText(self._content_label.text() + text)

    def set_text(self, text: str) -> None:
        if self._markdown_content is not None:
            self._markdown_content.set_markdown(text)
        elif self._content_label is not None:
            self._content_label.setText(text)

    @property
    def content_text(self) -> str:
        if self._markdown_content is not None:
            return self._markdown_content.raw_markdown
        if self._content_label is not None:
            return self._content_label.text()
        return ""


# ---------------------------------------------------------------------------
# Tool call card (collapsible: summary by default, expand for details)
# ---------------------------------------------------------------------------

class ToolCallCard(QFrame):
    """Collapsible card for a single MCP tool invocation.

    Default (collapsed): shows tool name + status + one-line summary.
    Expanded: shows request arguments and full response.
    """

    def __init__(
        self,
        tool_name: str,
        status: str,
        summary: str = "",
        args_text: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("toolCallCard")
        self._tool_name = tool_name
        self._status = status
        self._args_text = args_text
        self._result_text = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 8, 4, 8)
        layout.setSpacing(4)

        # --- Header row: toggle arrow + icon + name + status ---
        header = QHBoxLayout()
        header.setSpacing(6)

        self._toggle_btn = QToolButton()
        self._toggle_btn.setObjectName("toolCallToggle")
        self._toggle_btn.setArrowType(Qt.ArrowType.RightArrow)
        self._toggle_btn.setFixedSize(20, 20)
        self._toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._toggle_btn.clicked.connect(self._toggle_expand)
        header.addWidget(self._toggle_btn)

        self._icon_label = QLabel(_tool_status_icon(status))
        self._icon_label.setObjectName("toolCallIcon")
        self._icon_label.setFixedWidth(16)
        header.addWidget(self._icon_label)

        self._name_label = QLabel(tool_name)
        self._name_label.setObjectName("toolCallName")
        header.addWidget(self._name_label)

        header.addStretch(1)

        self._status_label = QLabel(status)
        self._status_label.setObjectName("toolCallStatus")
        header.addWidget(self._status_label)

        layout.addLayout(header)

        # Make the whole card clickable to toggle expand
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        # --- Summary line (visible when collapsed) ---
        summary_display = summary or ""
        if len(summary_display) > 120:
            summary_display = summary_display[:117] + "..."
        self._summary_label = QLabel(summary_display)
        self._summary_label.setObjectName("toolCallSummary")
        self._summary_label.setWordWrap(True)
        if not summary_display:
            self._summary_label.hide()
        layout.addWidget(self._summary_label)

        # --- Detail panel (hidden by default) ---
        self._detail_panel = QWidget()
        self._detail_panel.setObjectName("toolCallDetailPanel")
        detail_layout = QVBoxLayout(self._detail_panel)
        detail_layout.setContentsMargins(0, 4, 0, 0)
        detail_layout.setSpacing(6)

        # Request section
        if args_text:
            req_label = QLabel("Request")
            req_label.setObjectName("toolCallSectionLabel")
            detail_layout.addWidget(req_label)
            self._req_content = QTextBrowser()
            self._req_content.setObjectName("toolCallContent")
            self._req_content.setOpenExternalLinks(False)
            self._req_content.setReadOnly(True)
            self._req_content.setFrameShape(QFrame.Shape.NoFrame)
            self._req_content.setFixedHeight(80)
            self._req_content.setPlainText(self._format_text(args_text))
            detail_layout.addWidget(self._req_content)

        # Response section (added later when result arrives)
        self._resp_label: QLabel | None = None
        self._resp_content: QTextBrowser | None = None

        self._detail_panel.setVisible(False)
        layout.addWidget(self._detail_panel)

    # ---- helpers ----

    @staticmethod
    def _format_text(text: str) -> str:
        """Pretty-format JSON or return as-is."""
        try:
            import json
            parsed = json.loads(text)
            return json.dumps(parsed, indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            return text

    def _toggle_expand(self) -> None:
        expanded = self._detail_panel.isVisible()
        self._detail_panel.setVisible(not expanded)
        self._toggle_btn.setArrowType(
            Qt.ArrowType.DownArrow if not expanded else Qt.ArrowType.RightArrow
        )

    def mousePressEvent(self, event) -> None:  # type: ignore[override]
        """Click anywhere on the card to toggle expand."""
        if event.button() == Qt.MouseButton.LeftButton:
            self._toggle_expand()
        super().mousePressEvent(event)

    # ---- public API ----

    def update_status(self, status: str, summary: str = "", result: str = "") -> None:
        """Update status, summary, and optionally set the response content."""
        self._status = status
        self._icon_label.setText(_tool_status_icon(status))
        self._status_label.setText(status)

        if summary:
            display = summary
            if len(display) > 120:
                display = display[:117] + "..."
            self._summary_label.setText(display)
            self._summary_label.show()

        if result:
            self._result_text = result
            self._ensure_response_section()
            self._resp_content.setPlainText(self._format_text(result))
            # Adjust height based on content length
            lines = result.count("\n") + 1
            height = min(max(60, lines * 16), 300)
            self._resp_content.setFixedHeight(height)

    def _ensure_response_section(self) -> None:
        """Lazily create the response section in the detail panel."""
        if self._resp_label is not None:
            return
        detail_layout = self._detail_panel.layout()
        self._resp_label = QLabel("Response")
        self._resp_label.setObjectName("toolCallSectionLabel")
        detail_layout.addWidget(self._resp_label)
        self._resp_content = QTextBrowser()
        self._resp_content.setObjectName("toolCallContent")
        self._resp_content.setOpenExternalLinks(False)
        self._resp_content.setReadOnly(True)
        self._resp_content.setFrameShape(QFrame.Shape.NoFrame)
        self._resp_content.setFixedHeight(80)
        detail_layout.addWidget(self._resp_content)


# Backward-compatible alias
ToolTraceCard = ToolCallCard


# ---------------------------------------------------------------------------
# Thinking indicator (pulsing dots)
# ---------------------------------------------------------------------------

class ThinkingIndicator(QWidget):
    """Pulsing dot animation shown while the model is thinking."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("chatThinkingIndicator")
        self.setFixedHeight(36)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(4)

        # Role label
        role = QLabel("Assistant")
        role.setObjectName("chatRoleAssistant")
        layout.addWidget(role)

        # Three pulsing dots
        self._dots: list[QLabel] = []
        for i in range(3):
            dot = QLabel("\u2022")
            dot.setObjectName("chatThinkingDot")
            dot.setFixedWidth(12)
            dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(dot)
            self._dots.append(dot)

        layout.addStretch(1)

        # Opacity animation
        self._opacity_effects: list[QGraphicsOpacityEffect] = []
        self._animations: list[QPropertyAnimation] = []
        self._group = QParallelAnimationGroup(self)

        for i, dot in enumerate(self._dots):
            effect = QGraphicsOpacityEffect(dot)
            effect.setOpacity(0.3)
            dot.setGraphicsEffect(effect)
            self._opacity_effects.append(effect)

            anim = QPropertyAnimation(effect, b"opacity")
            anim.setDuration(800)
            anim.setStartValue(0.3)
            anim.setEndValue(1.0)
            anim.setLoopCount(-1)  # infinite
            # Stagger the start for each dot
            anim.setCurrentTime(i * 267)
            self._animations.append(anim)
            self._group.addAnimation(anim)

    def start_animation(self) -> None:
        self._group.start()

    def stop_animation(self) -> None:
        self._group.stop()


# ---------------------------------------------------------------------------
# Message list (scrollable conversation)
# ---------------------------------------------------------------------------

class MessageList(QWidget):
    """Scrollable conversation list with flat messages and turn dividers."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("messageListArea")

        self._messages_layout = QVBoxLayout()
        self._messages_layout.setContentsMargins(0, 12, 0, 12)
        self._messages_layout.setSpacing(0)
        self._messages_layout.addStretch(1)

        container = QWidget()
        container.setObjectName("messageListContainer")
        container.setLayout(self._messages_layout)

        self._scroll = QScrollArea()
        self._scroll.setWidget(container)
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setObjectName("chatScrollArea")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self._scroll)

        self._last_assistant_block: MessageBlock | None = None
        self._thinking: ThinkingIndicator | None = None
        self._thinking_divider: QFrame | None = None
        self._turn_count = 0
        self._trace_cards: list[ToolTraceCard] = []
        self._assistant_segments_in_turn: int = 0  # tracks continuation blocks

    def _insert_before_stretch(self, widget: QWidget) -> None:
        """Insert a widget immediately before the trailing stretch."""
        count = self._messages_layout.count()
        self._messages_layout.insertWidget(count - 1, widget)

    def append_message(self, role: str, content: str, show_role: bool = True) -> None:
        """Add a new message with optional turn divider."""
        # Insert divider before user messages (except the very first message)
        if role == "user" and self._turn_count > 0:
            divider = TurnDivider()
            self._insert_before_stretch(divider)

        block = MessageBlock(role, content, show_role=show_role)
        self._insert_before_stretch(block)

        if role == "assistant":
            self._last_assistant_block = block
            self._assistant_segments_in_turn += 1
            self._turn_count += 1
        elif role == "user":
            self._last_assistant_block = None

        self.scroll_to_bottom()

    def append_chunk(self, content: str) -> None:
        """Append streaming text to the last assistant block.

        If no assistant block is active (e.g. after a tool card was
        inserted), creates a new continuation block without the
        "Assistant" role label.
        """
        if self._last_assistant_block is None:
            show_role = self._assistant_segments_in_turn == 0
            self.append_message("assistant", content, show_role=show_role)
        else:
            self._last_assistant_block.append_text(content)
        self.scroll_to_bottom()

    def show_thinking(self) -> None:
        """Show the thinking indicator at the bottom of the conversation."""
        self.hide_thinking()
        self._thinking = ThinkingIndicator()
        # Add divider before thinking if there are previous messages
        if self._turn_count > 0:
            self._thinking_divider = TurnDivider()
            self._insert_before_stretch(self._thinking_divider)
        self._insert_before_stretch(self._thinking)
        self._thinking.start_animation()
        # Reset segment counter for the new turn
        self._assistant_segments_in_turn = 0
        self.scroll_to_bottom()

    def hide_thinking(self) -> None:
        """Remove the thinking indicator and its divider."""
        if self._thinking is not None:
            self._thinking.stop_animation()
            self._messages_layout.removeWidget(self._thinking)
            self._thinking.deleteLater()
            self._thinking = None
        if self._thinking_divider is not None:
            self._messages_layout.removeWidget(self._thinking_divider)
            self._thinking_divider.deleteLater()
            self._thinking_divider = None

    def add_tool_trace(
        self, tool_name: str, status: str, summary: str = "",
        args_text: str = "",
    ) -> None:
        """Add a new tool trace card.

        Inserts the card at the current position in the conversation
        flow and clears the active assistant block so that subsequent
        tokens create a fresh continuation block (without the role
        label).  This produces an interleaved layout:

            [Assistant text]
            [Tool Card]
            [Assistant continuation text]
        """
        # Finalize the current assistant block — next append_chunk
        # will create a new one (continuation, no role label).
        self._last_assistant_block = None

        card = ToolCallCard(tool_name, status, summary, args_text)
        self._insert_before_stretch(card)
        self._trace_cards.append(card)
        self.scroll_to_bottom()

    def update_last_tool_trace(
        self, tool_name: str, status: str, summary: str = "",
        result: str = "",
    ) -> None:
        """Update the most recent trace card matching tool_name.

        Searches backwards through ``_trace_cards`` and picks the first
        card that matches *and* hasn't received a terminal status yet
        (completed / failed).  This avoids misrouting results when the
        same tool is called multiple times in one turn.
        """
        terminal = _TOOL_TERMINAL_STATUSES
        for card in reversed(self._trace_cards):
            if (
                card._tool_name == tool_name
                and card._status not in terminal
            ):
                card.update_status(status, summary, result)
                return

    def clear_messages(self) -> None:
        while self._messages_layout.count() > 1:
            item = self._messages_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._last_assistant_block = None
        self._thinking = None
        self._thinking_divider = None
        self._trace_cards.clear()
        self._turn_count = 0
        self._assistant_segments_in_turn = 0

    def scroll_to_bottom(self) -> None:
        scrollbar = self._scroll.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
