"""Tool trace panel — timeline of tool call executions.

Shows a vertical timeline of tool invocations for the current turn,
with status icons, tool names, arguments preview, and result summaries.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.ui.chat.message_list import _tool_status_icon

if TYPE_CHECKING:
    from app.i18n import I18n


# ---------------------------------------------------------------------------
# Trace entry
# ---------------------------------------------------------------------------

class TraceEntry(QFrame):
    """A single tool call entry in the timeline."""

    def __init__(
        self,
        tool_name: str,
        status: str,
        summary: str = "",
        args_preview: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("traceEntry")
        self._status = status

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(3)

        # Top row: icon + tool name
        top = QHBoxLayout()
        top.setSpacing(6)

        self._icon = QLabel(_tool_status_icon(status))
        self._icon.setObjectName("traceIcon")
        self._icon.setFixedWidth(16)
        top.addWidget(self._icon)

        self._name_label = QLabel(tool_name)
        self._name_label.setObjectName("traceToolName")
        top.addWidget(self._name_label, 1)

        self._status_label = QLabel(status)
        self._status_label.setObjectName("traceStatus")
        top.addWidget(self._status_label)

        layout.addLayout(top)

        # Args preview (collapsible)
        if args_preview:
            args_text = args_preview
            if len(args_text) > 120:
                args_text = args_text[:117] + "..."
            self._args_label = QLabel(args_text)
            self._args_label.setObjectName("traceArgs")
            self._args_label.setWordWrap(True)
            layout.addWidget(self._args_label)

        # Summary / result
        if summary:
            self._summary_label = QLabel(summary)
            self._summary_label.setObjectName("traceSummary")
            self._summary_label.setWordWrap(True)
            layout.addWidget(self._summary_label)

    def update_status(self, status: str, summary: str = "") -> None:
        self._status = status
        self._icon.setText(_tool_status_icon(status))
        self._status_label.setText(status)
        if summary and hasattr(self, "_summary_label"):
            self._summary_label.setText(summary)


# ---------------------------------------------------------------------------
# Tool trace panel
# ---------------------------------------------------------------------------

class ToolTracePanel(QWidget):
    """Right-side panel showing tool call timeline for the current turn."""

    def __init__(
        self,
        i18n: I18n,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._i18n = i18n
        self._entries: list[TraceEntry] = []

        self._build_ui()

    def _t(self, key: str, **kwargs: object) -> str:
        return self._i18n.t(key, **kwargs)

    def _build_ui(self) -> None:
        self.setObjectName("toolTracePanel")
        self.setMinimumWidth(200)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Header
        header = QFrame()
        header.setObjectName("tracePanelHeader")
        header.setFixedHeight(36)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 0, 12, 0)

        self._title_label = QLabel(self._t("chat.trace.title"))
        self._title_label.setObjectName("tracePanelTitle")
        header_layout.addWidget(self._title_label)
        header_layout.addStretch(1)

        self._count_label = QLabel("")
        self._count_label.setObjectName("tracePanelCount")
        header_layout.addWidget(self._count_label)

        outer.addWidget(header)

        # Scrollable trace list
        self._list_container = QWidget()
        self._list_container.setObjectName("traceListContainer")
        self._list_layout = QVBoxLayout(self._list_container)
        self._list_layout.setContentsMargins(4, 4, 4, 4)
        self._list_layout.setSpacing(2)
        self._list_layout.addStretch(1)
        self._list_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        scroll = QScrollArea()
        scroll.setWidget(self._list_container)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setObjectName("traceScrollArea")

        outer.addWidget(scroll, 1)

    def add_trace(
        self,
        tool_name: str,
        status: str,
        summary: str = "",
        args_preview: str = "",
    ) -> None:
        """Add a new tool trace entry."""
        entry = TraceEntry(tool_name, status, summary, args_preview)
        count = self._list_layout.count()
        self._list_layout.insertWidget(count - 1, entry)
        self._entries.append(entry)
        self._update_count()

    def _update_count(self) -> None:
        count = len(self._entries)
        self._count_label.setText(str(count) if count > 0 else "")
