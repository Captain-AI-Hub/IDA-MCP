"""Chat page — main widget composing MessageList and Composer."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QSplitter, QVBoxLayout, QWidget

from app.chat.chat_service import ChatService
from app.chat.models import ChatMessage, Conversation
from app.chat.persistence import ChatPersistence
from app.ui.chat.composer import Composer
from app.ui.chat.message_list import MessageList

if TYPE_CHECKING:
    from app.i18n import I18n

logger = logging.getLogger(__name__)


class ChatPage(QWidget):
    """Main Chat page widget."""

    conversation_created = Signal(str)  # conversation_id

    def __init__(
        self,
        i18n: I18n,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self._i18n = i18n
        self._chat_service: ChatService | None = None
        self._persistence: ChatPersistence | None = None
        self._current_conversation_id: str | None = None
        self._current_provider_id: int | None = None
        self._is_running: bool = False
        self._current_assistant_content: str = ""
        self._manager = None

        self._build_ui()

    def _t(self, key: str, **kwargs: object) -> str:
        return self._i18n.t(key, **kwargs)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._message_list = MessageList()

        self._composer = Composer(self._i18n)
        self._composer.message_submitted.connect(self._on_message_submitted)
        self._composer.model_changed.connect(self._on_model_changed)

        self._splitter = QSplitter(Qt.Vertical)
        self._splitter.addWidget(self._message_list)
        self._splitter.addWidget(self._composer)
        self._splitter.setChildrenCollapsible(False)
        self._splitter.setHandleWidth(0)
        self._splitter.setSizes([800, 200])
        self._splitter.setStretchFactor(0, 4)
        self._splitter.setStretchFactor(1, 1)

        layout.addWidget(self._splitter, 1)

        self._refresh_models()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_chat_service(self, service: ChatService) -> None:
        self._chat_service = service
        self._persistence = service.get_persistence()
        self._chat_service.event_received.connect(self._on_stream_event)

    def load_conversation(self, conversation_id: str) -> None:
        if self._persistence is None:
            return

        self._current_conversation_id = conversation_id
        self._message_list.clear_messages()

        messages = self._persistence.load_messages(conversation_id)
        for msg in messages:
            if msg.role in ("user", "assistant"):
                self._message_list.append_message(msg.role, msg.content)
            elif msg.role == "tool":
                self._message_list.add_tool_trace(
                    msg.tool_name or self._t("chat.tool.unknown"),
                    self._t("chat.tool.completed"),
                    msg.content[:200],
                )

    def on_stream_event(self, event_dict: dict) -> None:
        event_type = event_dict.get("type", "")
        payload = event_dict.get("payload", {})

        if event_type == "run_started":
            self._on_run_started()
        elif event_type == "token":
            self._on_token(payload)
        elif event_type == "tool_start":
            self._on_tool_start(payload)
        elif event_type == "tool_result":
            self._on_tool_result(payload)
        elif event_type == "tool_error":
            self._on_tool_error(payload)
        elif event_type == "run_completed":
            self._on_run_completed(payload)
        elif event_type == "run_failed":
            self._on_run_failed(payload)

    # ------------------------------------------------------------------
    # Manager access
    # ------------------------------------------------------------------

    def _get_manager(self):
        if self._manager is None:
            from supervisor.api import create_manager
            self._manager = create_manager()
        return self._manager

    # ------------------------------------------------------------------
    # Message submission
    # ------------------------------------------------------------------

    def _on_message_submitted(self, text: str) -> None:
        if self._is_running:
            return

        if self._chat_service is None:
            logger.warning("ChatService not set, ignoring message")
            return

        provider_dict, servers_list, skill_dict = self._get_current_config()
        if not provider_dict:
            logger.warning("No enabled model provider, ignoring message")
            self._message_list.append_message(
                "assistant", self._t("chat.error.no_provider")
            )
            return

        if self._current_conversation_id is None:
            conv = self._chat_service.create_conversation()
            self._current_conversation_id = conv.id
            self.conversation_created.emit(conv.id)

        self._message_list.append_message("user", text)

        history_dicts: list[dict[str, Any]] = []
        if self._persistence:
            history = self._persistence.load_messages(
                self._current_conversation_id, limit=50
            )
            history_dicts = [
                m.to_dict()
                for m in history
                if m.role in ("user", "assistant")
            ]

        self._chat_service.send_message(
            conversation_id=self._current_conversation_id,
            user_message=text,
            provider=provider_dict,
            skill=skill_dict,
            mcp_servers=servers_list,
            message_history=history_dicts,
        )

    def _get_current_config(
        self,
    ) -> tuple[dict, list[dict], dict | None]:
        manager = self._get_manager()

        providers = manager.get_model_providers()
        provider_dict: dict = {}

        if self._current_provider_id is not None:
            for p in providers:
                if p.id == self._current_provider_id and p.enabled:
                    provider_dict = p.to_dict()
                    break

        if not provider_dict:
            for p in providers:
                if p.enabled:
                    provider_dict = p.to_dict()
                    self._current_provider_id = p.id
                    break

        servers = manager.get_mcp_servers()
        servers_list = [s.to_dict() for s in servers if s.enabled]

        skill_dict = None

        return provider_dict, servers_list, skill_dict

    # ------------------------------------------------------------------
    # Model selector
    # ------------------------------------------------------------------

    def _on_model_changed(self, provider_id: int) -> None:
        self._current_provider_id = provider_id
        self._refresh_models()

    def _refresh_models(self) -> None:
        try:
            manager = self._get_manager()
            providers = [
                p for p in manager.get_model_providers() if p.enabled
            ]

            models = [
                (p.id, p.name or p.model_name or self._t("chat.unknown"))
                for p in providers
            ]

            active_id = self._current_provider_id
            valid_ids = {p.id for p in providers}
            if active_id not in valid_ids:
                if providers:
                    active_id = providers[0].id
                    self._current_provider_id = active_id
                else:
                    active_id = None
                    self._current_provider_id = None

            self._composer.update_model_list(models, active_id)

            if active_id is not None:
                for p in providers:
                    if p.id == active_id:
                        self._composer.set_model_name(
                            p.name or p.model_name or self._t("chat.unknown")
                        )
                        return

            self._composer.set_model_name(self._t("chat.no_model"))
        except Exception:
            self._composer.update_model_list([], None)
            self._composer.set_model_name(self._t("chat.no_model"))

    # ------------------------------------------------------------------
    # Stream event handlers
    # ------------------------------------------------------------------

    def _on_run_started(self) -> None:
        self._is_running = True
        self._composer.set_enabled(False)
        self._current_assistant_content = ""

    def _on_token(self, payload: dict) -> None:
        chunk = payload.get("content", "")
        self._current_assistant_content += chunk
        self._message_list.append_chunk(chunk)

    def _on_tool_start(self, payload: dict) -> None:
        tool_name = payload.get("tool_name", self._t("chat.tool.unknown"))
        self._message_list.add_tool_trace(tool_name, self._t("chat.tool.running"))

    def _on_tool_result(self, payload: dict) -> None:
        tool_name = payload.get("tool_name", "")
        result = payload.get("result", "")
        summary = result[:100] if result else self._t("chat.tool.done")
        self._message_list.add_tool_trace(
            tool_name, self._t("chat.tool.completed"), summary
        )

    def _on_tool_error(self, payload: dict) -> None:
        tool_name = payload.get("tool_name", "")
        error = payload.get("error", self._t("chat.tool.unknown_error"))
        self._message_list.add_tool_trace(
            tool_name, self._t("chat.tool.failed"), error[:100]
        )

    def _on_run_completed(self, payload: dict) -> None:
        self._is_running = False
        self._composer.set_enabled(True)
        self._composer.clear_input()

    def _on_run_failed(self, payload: dict) -> None:
        self._is_running = False
        self._composer.set_enabled(True)
        error = payload.get("error", self._t("chat.tool.unknown_error"))
        self._message_list.append_message(
            "assistant", self._t("chat.error.prefix", error=error)
        )

    # ------------------------------------------------------------------
    # Slot wrapper
    # ------------------------------------------------------------------

    def _on_stream_event(self, event_dict: dict) -> None:
        self.on_stream_event(event_dict)
