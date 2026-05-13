"""Chat page — sidebar + message list + composer.

Layout:
```
QSplitter (Horizontal)
├── SessionSidebar  (left, 200px)
└── QSplitter (Vertical)
    ├── MessageList  (top, 4/5)
    └── Composer     (bottom, 1/5, with ProviderSelector)
```
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QSplitter, QVBoxLayout, QWidget

from app.chat.chat_service import ChatService
from app.chat.persistence import ChatPersistence
from app.chat.skill_resolver import SkillResolver
from app.ui.chat.composer import Composer
from app.ui.chat.message_list import MessageList
from app.ui.chat.provider_selector import ProviderSelector
from app.services.supervisor_client import SupervisorClient
from app.ui.chat.session_sidebar import SessionSidebar

if TYPE_CHECKING:
    from app.i18n import I18n

logger = logging.getLogger(__name__)


class ChatPage(QWidget):
    """Main Chat page widget."""

    conversation_created = Signal(str)  # conversation_id

    def __init__(
        self,
        i18n: I18n,
        supervisor_client: SupervisorClient | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("chatPage")

        self._i18n = i18n
        self._supervisor_client: SupervisorClient | None = supervisor_client
        self._chat_service: ChatService | None = None
        self._persistence: ChatPersistence | None = None
        self._skill_resolver: SkillResolver | None = None
        self._current_conversation_id: str | None = None
        self._current_provider_id: int | None = None
        self._current_skill_id: int | None = None
        self._is_running: bool = False
        self._current_assistant_content: str = ""

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

        # Horizontal splitter: sidebar | center
        self._h_splitter = QSplitter(Qt.Horizontal)
        self._h_splitter.setChildrenCollapsible(True)
        self._h_splitter.setHandleWidth(1)

        # --- Session sidebar (left) ---
        self._sidebar = SessionSidebar(self._i18n)
        self._sidebar.conversation_selected.connect(self._on_conversation_selected)
        self._sidebar.new_conversation_requested.connect(self._on_new_conversation)
        self._sidebar.conversation_deleted.connect(self._on_conversation_deleted)
        self._h_splitter.addWidget(self._sidebar)

        # --- Center: vertical splitter (messages 4/5 | composer 1/5) ---
        self._v_splitter = QSplitter(Qt.Vertical)
        self._v_splitter.setChildrenCollapsible(False)
        self._v_splitter.setHandleWidth(1)

        # Message list (top, 80%)
        self._message_list = MessageList()
        self._v_splitter.addWidget(self._message_list)

        # Composer (bottom, 20%)
        self._composer = Composer(self._i18n)
        self._composer.message_submitted.connect(self._on_message_submitted)
        self._composer.stop_requested.connect(self._on_stop_requested)
        self._composer.clear_requested.connect(self._on_clear_requested)

        # Provider selector only (skill selector removed — managed in Settings)
        self._provider_selector = ProviderSelector(self._i18n)
        self._provider_selector.provider_changed.connect(self._on_provider_changed)
        self._composer.add_selector(self._provider_selector)

        self._v_splitter.addWidget(self._composer)
        # 4 : 1 ratio → message list 4/5, composer 1/5
        self._v_splitter.setSizes([768, 192])
        self._v_splitter.setStretchFactor(0, 4)
        self._v_splitter.setStretchFactor(1, 1)

        self._h_splitter.addWidget(self._v_splitter)
        self._h_splitter.setSizes([200, 1020])
        self._h_splitter.setStretchFactor(0, 0)
        self._h_splitter.setStretchFactor(1, 1)

        layout.addWidget(self._h_splitter, 1)

        self._refresh_models()
        self._refresh_skills()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def refresh_providers(self) -> None:
        """Refresh the provider selector after model providers change."""
        self._refresh_models()

    def retranslate(self) -> None:
        """Refresh all translatable text after a language change."""
        self._sidebar.retranslate()
        self._composer.retranslate()
        self._provider_selector.update_providers(
            self._provider_selector._models,
            self._provider_selector._active_id,
        )

    def set_chat_service(self, service: ChatService) -> None:
        self._chat_service = service
        self._persistence = service.get_persistence()
        self._sidebar.set_persistence(self._persistence)

        # Initialize skill resolver
        self._skill_resolver = SkillResolver(self._persistence.db)
        self._refresh_skills()

        # Connect streaming
        self._chat_service.event_received.connect(self._on_stream_event)

        # Load existing conversations
        self._sidebar.refresh()

    def load_conversation(self, conversation_id: str) -> None:
        if self._persistence is None:
            return

        self._current_conversation_id = conversation_id
        self._message_list.clear_messages()

        messages = self._persistence.load_messages(conversation_id)
        # Track whether this is the first assistant segment in the turn
        # (shows role label) or a continuation (no role label).
        first_assistant_in_turn = True
        for msg in messages:
            content = msg.content or ""
            if msg.role == "user":
                self._message_list.append_message("user", content)
                first_assistant_in_turn = True
            elif msg.role == "assistant":
                show_role = first_assistant_in_turn
                self._message_list.append_message(
                    "assistant", content, show_role=show_role
                )
                first_assistant_in_turn = False
            elif msg.role == "tool":
                tool_name = msg.tool_name or self._t("chat.tool.unknown")
                args_text = ""
                result_text = ""
                # Content may be {"args": {...}, "result": "..."} JSON
                try:
                    import json
                    data = json.loads(content)
                    if isinstance(data, dict):
                        args_data = data.get("args", {})
                        if args_data:
                            args_text = json.dumps(args_data, ensure_ascii=False)
                        result_text = data.get("result", "") or ""
                    elif isinstance(data, (list, str)):
                        args_text = str(data)
                except (json.JSONDecodeError, TypeError):
                    args_text = content
                summary = result_text[:100] if result_text else self._t("chat.tool.done")
                self._message_list.add_tool_trace(
                    tool_name,
                    self._t("chat.tool.completed"),
                    summary=summary,
                    args_text=args_text,
                )
                # Restore full result into the card for expand view
                if result_text:
                    self._message_list.update_last_tool_trace(
                        tool_name,
                        self._t("chat.tool.completed"),
                        summary=summary,
                        result=result_text,
                    )
                # Next assistant block is a continuation (no role label)
                first_assistant_in_turn = False

        self._sidebar.set_active(conversation_id)

        # Restore provider selector from conversation metadata
        conv = self._persistence.get_conversation(conversation_id)
        if conv and conv.provider_id is not None:
            self._current_provider_id = conv.provider_id
            self._provider_selector.update_providers(
                self._provider_selector._models,
                self._current_provider_id,
            )

        # Restore running state if the conversation is still active
        if conv and conv.status == "running":
            self._is_running = True
            self._composer.set_running(True)
            self._message_list.show_thinking()
        else:
            self._is_running = False
            self._composer.set_running(False)
            self._message_list.hide_thinking()

    def on_stream_event(self, event_dict: dict) -> None:
        # Ignore events for other conversations to keep sessions isolated.
        if event_dict.get("conversation_id") != self._current_conversation_id:
            return

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

    def _get_current_model_name(self) -> str:
        """Return the display name of the currently selected provider."""
        try:
            if self._supervisor_client is None:
                return ""
            for p in self._supervisor_client.get_model_providers():
                if p.id == self._current_provider_id and p.enabled:
                    return p.name or p.model_name or ""
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------------
    # Session sidebar handlers
    # ------------------------------------------------------------------

    def _on_conversation_selected(self, conversation_id: str) -> None:
        self.load_conversation(conversation_id)

    def _on_new_conversation(self) -> None:
        if self._chat_service is None:
            return

        conv = self._chat_service.create_conversation(
            provider_id=self._current_provider_id,
            model_name=self._get_current_model_name(),
        )
        self._sidebar.add_conversation(conv)
        self.load_conversation(conv.id)
        self.conversation_created.emit(conv.id)

    def _on_conversation_deleted(self, conversation_id: str) -> None:
        if self._persistence is None:
            return

        self._persistence.delete_conversation(conversation_id)
        self._sidebar.remove_conversation(conversation_id)

        if self._current_conversation_id == conversation_id:
            self._current_conversation_id = None
            self._message_list.clear_messages()

    # ------------------------------------------------------------------
    # Message submission
    # ------------------------------------------------------------------

    def _on_stop_requested(self) -> None:
        """Cancel the active agent turn."""
        if self._is_running and self._chat_service:
            self._chat_service.cancel_turn()

    def _on_clear_requested(self) -> None:
        """Clear all messages in the current conversation."""
        self._message_list.clear_messages()
        if self._current_conversation_id and self._persistence:
            self._persistence.delete_conversation(self._current_conversation_id)
            self._sidebar.remove_conversation(self._current_conversation_id)
            self._current_conversation_id = None

    def _on_message_submitted(self, text: str) -> None:
        if self._is_running:
            return

        if self._chat_service is None:
            logger.warning("ChatService not set, ignoring message")
            return

        # Lock early to prevent double-submit race
        self._is_running = True
        self._composer.set_running(True)

        provider_dict, servers_list, skill_dict = self._get_current_config()
        if not provider_dict:
            logger.warning("No enabled model provider, ignoring message")
            self._is_running = False
            self._composer.set_running(False)
            self._message_list.append_message(
                "assistant", self._t("chat.error.no_provider")
            )
            return

        # Create conversation if needed
        if self._current_conversation_id is None:
            conv = self._chat_service.create_conversation(
                provider_id=self._current_provider_id,
                model_name=self._get_current_model_name(),
            )
            self._current_conversation_id = conv.id
            self._sidebar.add_conversation(conv)
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
                if m.role in ("user", "assistant", "tool")
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
        if self._supervisor_client is None:
            return {}, [], None
        try:
            providers = self._supervisor_client.get_model_providers()
            provider_dict: dict = {}

            # Use the user's explicit selection only — never auto-pick.
            if self._current_provider_id is not None:
                for p in providers:
                    if p.id == self._current_provider_id and p.enabled:
                        provider_dict = p.to_dict()
                        break

            servers = self._supervisor_client.get_mcp_servers()
            servers_list = [s.to_dict() for s in servers if s.enabled]
        except Exception:
            logger.exception("Failed to access supervisor client")
            return {}, [], None

        # Resolve skill (auto: applies all enabled skills from DB)
        skill_dict = None
        # Skill selection is managed in Settings; the agent factory
        # handles tool filtering based on skill config at build time.
        # Here we only pass skill_dict if a specific skill is resolved.
        if self._current_skill_id is not None and self._skill_resolver:
            resolved = self._skill_resolver.resolve(self._current_skill_id)
            if resolved:
                skill_dict = {
                    "id": resolved.id,
                    "name": resolved.name,
                    "system_prompt_template": resolved.system_prompt_suffix,
                    "tool_allowlist_json": (
                        json.dumps(sorted(resolved.tool_allowlist))
                        if resolved.tool_allowlist is not None else None
                    ),
                    "tool_denylist_json": (
                        json.dumps(sorted(resolved.tool_denylist))
                        if resolved.tool_denylist is not None else None
                    ),
                    "model_override": resolved.preferred_model_name or "",
                    "temperature_override": resolved.temperature_override,
                }

        return provider_dict, servers_list, skill_dict

    # ------------------------------------------------------------------
    # Provider selector
    # ------------------------------------------------------------------

    def _on_provider_changed(self, provider_id: int) -> None:
        self._current_provider_id = provider_id

    def _refresh_models(self) -> None:
        if self._supervisor_client is None:
            self._provider_selector.update_providers([], None)
            return
        try:
            providers = [
                p for p in self._supervisor_client.get_model_providers() if p.enabled
            ]

            model_data = [
                (p.id, p.name or p.model_name or self._t("chat.unknown"), p.api_mode)
                for p in providers
            ]

            # Only keep the current selection if it is still valid;
            # do NOT auto-select the first provider — the user must
            # explicitly pick one from the dropdown.
            active_id = self._current_provider_id
            valid_ids = {p.id for p in providers}
            if active_id not in valid_ids:
                active_id = None
                self._current_provider_id = None

            self._provider_selector.update_providers(model_data, active_id)
        except Exception:
            self._provider_selector.update_providers([], None)

    def _refresh_skills(self) -> None:
        """Resolve active skills from DB (settings-managed)."""
        try:
            if self._skill_resolver:
                # Auto-apply the first enabled skill if any
                skills = self._skill_resolver.list_available()
                if skills and self._current_skill_id is None:
                    self._current_skill_id = skills[0]["id"]
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Stream event handlers
    # ------------------------------------------------------------------

    def _on_run_started(self) -> None:
        self._current_assistant_content = ""
        self._message_list.show_thinking()

    def _on_token(self, payload: dict) -> None:
        chunk = payload.get("content", "")
        self._current_assistant_content += chunk
        self._message_list.hide_thinking()
        self._message_list.append_chunk(chunk)

    def _on_tool_start(self, payload: dict) -> None:
        tool_name = payload.get("tool_name", self._t("chat.tool.unknown"))
        args = payload.get("args", {})
        args_text = ""
        if args:
            try:
                import json
                args_text = json.dumps(args, ensure_ascii=False)
            except (TypeError, ValueError):
                args_text = str(args)
        # Hide thinking indicator so the preceding text segment is visible
        self._message_list.hide_thinking()
        self._message_list.add_tool_trace(
            tool_name, self._t("chat.tool.running"), args_text=args_text
        )

    def _on_tool_result(self, payload: dict) -> None:
        tool_name = payload.get("tool_name", "")
        result = payload.get("result", "")
        summary = result[:100] if result else self._t("chat.tool.done")
        self._message_list.update_last_tool_trace(
            tool_name, self._t("chat.tool.completed"), summary, result=result
        )

    def _on_tool_error(self, payload: dict) -> None:
        tool_name = payload.get("tool_name", "")
        error = payload.get("error", self._t("chat.tool.unknown_error"))
        self._message_list.update_last_tool_trace(
            tool_name, self._t("chat.tool.failed"), error[:100], result=error
        )

    def _on_run_completed(self, payload: dict) -> None:
        self._is_running = False
        self._composer.set_running(False)
        self._composer.clear_input()
        self._message_list.hide_thinking()

        if self._current_conversation_id and self._persistence:
            conv = self._persistence.get_conversation(self._current_conversation_id)
            if conv:
                self._sidebar.update_conversation(conv)

    def _on_run_failed(self, payload: dict) -> None:
        self._is_running = False
        self._composer.set_running(False)
        self._message_list.hide_thinking()
        error = payload.get("error", self._t("chat.tool.unknown_error"))
        self._message_list.append_message(
            "assistant", self._t("chat.error.prefix", error=error)
        )

    # ------------------------------------------------------------------
    # Slot wrapper
    # ------------------------------------------------------------------

    def _on_stream_event(self, event_dict: dict) -> None:
        self.on_stream_event(event_dict)
