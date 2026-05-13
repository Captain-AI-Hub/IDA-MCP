"""Chat service — QThread + asyncio orchestration for the agent runtime.

The ChatService runs in a QThread with its own asyncio event loop.
The UI communicates via Qt signals/slots.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from PySide6.QtCore import QObject, Signal, QThread

from app.chat.agent_runner import AgentRunner
from app.chat.agent_factory import AgentFactory
from app.chat.errors import AgentBuildError, McpConnectionError
from app.chat.history_compactor import HistoryCompactor
from app.chat.mcp_pool import McpClientPool
from app.chat.models import (
    ChatMessage,
    Conversation,
    ResolvedSkill,
    StreamEvent,
)
from app.chat.message_persister import MessagePersister
from app.chat.persistence import ChatPersistence
from app.chat.prompts import build_system_prompt
from app.chat.streaming import (
    make_run_completed_event,
    make_run_failed_event,
    make_run_started_event,
)
from shared.database import DatabaseStore

logger = logging.getLogger(__name__)


def _uid() -> str:
    return uuid.uuid4().hex[:12]


class ChatServiceWorker(QObject):
    """Runs inside a QThread, owns the asyncio event loop and agent runtime."""

    # Signals emitted to the UI thread
    event_received = Signal(dict)  # StreamEvent.to_dict()
    conversation_updated = Signal(dict)  # Conversation.to_dict()

    def __init__(
        self, db: DatabaseStore, workspace_path: str = ""
    ) -> None:
        super().__init__()
        self._db = db
        self._persistence = ChatPersistence(db)
        self._pool = McpClientPool()
        self._factory = AgentFactory(self._pool, workspace_path=workspace_path)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._running = False
        self._active_turn: str | None = None
        self._cancel_event: asyncio.Event | None = None

    # ------------------------------------------------------------------
    # QThread lifecycle
    # ------------------------------------------------------------------

    def start_loop(self) -> None:
        """Called when the hosting QThread starts. Runs the asyncio loop."""
        self._running = True
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._run_forever())
        finally:
            self._loop.close()
            self._loop = None
            self._running = False

    async def _run_forever(self) -> None:
        """Keep the event loop alive to process submitted coroutines."""
        while self._running:
            await asyncio.sleep(0.1)

    def stop_loop(self) -> None:
        """Signal the loop to stop."""
        self._running = False
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._running.__class__.__bool__, False)

    # ------------------------------------------------------------------
    # Public methods (called from UI thread via QMetaObject.invokeMethod
    # or queued connection)
    # ------------------------------------------------------------------

    def submit_message(
        self,
        conversation_id: str,
        user_message: str,
        provider: dict[str, Any],
        skill: dict[str, Any] | None,
        mcp_servers: list[dict[str, Any]],
        message_history: list[dict[str, Any]],
    ) -> None:
        """Submit a user message for agent processing.

        Thread-safe: schedules work on the asyncio loop.
        """
        if self._loop is None:
            return

        asyncio.run_coroutine_threadsafe(
            self._handle_message(
                conversation_id=conversation_id,
                user_message=user_message,
                provider_dict=provider,
                skill_dict=skill,
                mcp_server_dicts=mcp_servers,
                message_history_dicts=message_history,
            ),
            self._loop,
        )

    def cancel_turn(self) -> None:
        """Cancel the active agent turn."""
        if self._cancel_event and self._loop:
            self._loop.call_soon_threadsafe(self._cancel_event.set)

    async def shutdown(self) -> None:
        """Clean shutdown of all resources."""
        self._running = False
        await self._pool.disconnect()

    # ------------------------------------------------------------------
    # Core agent execution
    # ------------------------------------------------------------------

    async def _handle_message(
        self,
        conversation_id: str,
        user_message: str,
        provider_dict: dict[str, Any],
        skill_dict: dict[str, Any] | None,
        mcp_server_dicts: list[dict[str, Any]],
        message_history_dicts: list[dict[str, Any]],
    ) -> None:
        """Run one agent turn: build agent, stream response, persist."""
        turn_id = _uid()
        # Local cancel_event so concurrent turns don't interfere with each other.
        cancel_event = asyncio.Event()
        self._active_turn = turn_id
        self._cancel_event = cancel_event

        self._emit(make_run_started_event(conversation_id, turn_id))

        provider = self._parse_provider(provider_dict)
        skill = self._parse_skill(skill_dict)
        history = [ChatMessage.from_dict(d) for d in message_history_dicts]
        history = HistoryCompactor(
            self._persistence, provider.max_context_tokens
        ).compact(conversation_id, history)
        persister = MessagePersister(self._persistence)

        persister.save_user_message(conversation_id, turn_id, user_message)

        system_prompt = build_system_prompt(
            skill=skill,
            override=None,
        )

        self._persistence.update_conversation_by_pk(
            conversation_id, status="running"
        )

        runner = AgentRunner(
            factory=self._factory,
            pool=self._pool,
            provider_dict=provider_dict,
            servers_list=mcp_server_dicts,
            skill_dict=skill_dict,
            history=history,
            system_prompt=system_prompt,
            conversation_id=conversation_id,
            turn_id=turn_id,
        )

        try:
            async for stream_event in runner.run(user_message):
                if cancel_event.is_set():
                    self._emit(
                        make_run_failed_event(
                            conversation_id,
                            turn_id,
                            "Cancelled by user",
                            partial_content=runner.assistant_content,
                        )
                    )
                    break

                if stream_event.type == "tool_start" and runner.assistant_content:
                    persister.save_assistant_message(
                        conversation_id,
                        turn_id,
                        runner.assistant_content,
                        runner.reasoning_content or None,
                    )
                    runner.assistant_content = ""
                    runner.reasoning_content = ""

                if stream_event.type in (
                    "tool_start", "tool_result", "tool_error"
                ):
                    persister.save_tool_execution(stream_event)

                self._emit(stream_event)

            else:
                self._emit(
                    make_run_completed_event(
                        conversation_id, turn_id, runner.assistant_content
                    )
                )

                persister.save_assistant_message(
                    conversation_id,
                    turn_id,
                    runner.assistant_content,
                    runner.reasoning_content or None,
                )

                updates: dict[str, Any] = {
                    "status": "idle",
                    "updated_at": ChatMessage().created_at,
                }
                inferred = self._infer_title(
                    user_message, runner.assistant_content
                )
                if inferred:
                    updates["title"] = inferred
                self._persistence.update_conversation_by_pk(
                    conversation_id,
                    **updates,
                )

        except McpConnectionError as exc:
            logger.error("MCP connection failed: %s", exc)
            error_detail = str(exc)
            if (
                "ConnectError" in error_detail
                or "connection attempts failed" in error_detail
            ):
                error_text = (
                    f"MCP 连接失败：无法连接到 {exc.server_name}，请确认服务已启动。"
                )
            else:
                error_text = error_detail.splitlines()[0]
            self._emit(
                make_run_failed_event(
                    conversation_id,
                    turn_id,
                    error_text,
                    runner.assistant_content,
                )
            )
            self._persistence.update_conversation_by_pk(
                conversation_id, status="failed"
            )

        except AgentBuildError as exc:
            logger.error("Agent build failed: %s", exc)
            self._emit(
                make_run_failed_event(
                    conversation_id,
                    turn_id,
                    str(exc),
                    runner.assistant_content,
                )
            )
            self._persistence.update_conversation_by_pk(
                conversation_id, status="failed"
            )

        except Exception as exc:
            logger.exception("Unexpected error during agent run")
            error_text = str(exc)
            if exc.__class__.__name__ == "GraphRecursionError":
                max_steps = 100_000
                if runner.run_config is not None:
                    max_steps = runner.run_config.max_steps
                error_text = (
                    f"Agent stopped after reaching the step limit "
                    f"({max_steps}). Try asking a narrower question "
                    "or increase the agent step limit."
                )
            self._emit(
                make_run_failed_event(
                    conversation_id,
                    turn_id,
                    error_text,
                    runner.assistant_content,
                )
            )
            self._persistence.update_conversation_by_pk(
                conversation_id, status="failed"
            )

        finally:
            # Only clear shared state if this turn is still the active one.
            if self._active_turn == turn_id:
                self._active_turn = None
                self._cancel_event = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _emit(self, event: StreamEvent) -> None:
        """Emit a StreamEvent to the UI thread."""
        self.event_received.emit(event.to_dict())

    @staticmethod
    def _parse_provider(data: dict[str, Any]) -> Any:
        """Parse provider dict into a ModelProvider-like object."""
        from supervisor.models import ModelProvider

        return ModelProvider.from_dict(data)

    @staticmethod
    def _parse_skill(data: dict[str, Any] | None) -> ResolvedSkill | None:
        """Parse skill dict into a ResolvedSkill."""
        if not data:
            return None

        import json

        allowlist = None
        denylist = None

        allow_json = data.get("tool_allowlist_json")
        if allow_json:
            try:
                allowlist = set(json.loads(allow_json))
            except (json.JSONDecodeError, TypeError):
                pass

        deny_json = data.get("tool_denylist_json")
        if deny_json:
            try:
                denylist = set(json.loads(deny_json))
            except (json.JSONDecodeError, TypeError):
                pass

        return ResolvedSkill(
            id=data.get("id"),
            name=data.get("name", ""),
            system_prompt_suffix=data.get("system_prompt_template", ""),
            tool_allowlist=allowlist,
            tool_denylist=denylist,
            preferred_model_name=data.get("model_override") or None,
            temperature_override=data.get("temperature_override"),
        )

    @staticmethod
    def _parse_servers(data_list: list[dict[str, Any]]) -> list[Any]:
        """Parse server dicts into McpServerEntry-like objects."""
        from supervisor.models import McpServerEntry

        return [McpServerEntry.from_dict(d) for d in data_list]

    @staticmethod
    def _infer_title(user_message: str, assistant_content: str) -> str:
        """Infer a conversation title from the first exchange."""
        # Take first line of user message, truncated
        first_line = user_message.strip().split("\n")[0]
        if len(first_line) > 60:
            first_line = first_line[:57] + "..."
        return first_line


class ChatService(QObject):
    """UI-facing chat service. Owns the worker thread.

    Usage:
        service = ChatService(db)
        service.start()
        service.send_message(...)
        service.stop()
    """

    event_received = Signal(dict)
    conversation_updated = Signal(dict)

    def __init__(
        self,
        db: DatabaseStore | None = None,
        workspace_path: str = "",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._db = db or DatabaseStore()
        self._workspace_path = workspace_path
        self._thread: QThread | None = None
        self._worker: ChatServiceWorker | None = None

    @property
    def is_running(self) -> bool:
        return (
            self._thread is not None
            and self._thread.isRunning()
        )

    def start(self) -> None:
        """Start the worker thread."""
        if self.is_running:
            return

        self._thread = QThread(self)
        self._worker = ChatServiceWorker(
            self._db, workspace_path=self._workspace_path
        )
        self._worker.moveToThread(self._thread)

        # Wire signals
        self._worker.event_received.connect(self.event_received.emit)
        self._worker.conversation_updated.connect(
            self.conversation_updated.emit
        )

        # Start the asyncio loop when thread starts
        self._thread.started.connect(self._worker.start_loop)
        self._thread.start()

    def stop(self) -> None:
        """Stop the worker thread cleanly."""
        if self._worker and self._loop():
            asyncio.run_coroutine_threadsafe(
                self._worker.shutdown(), self._loop()
            )
        if self._worker:
            self._worker.stop_loop()
        if self._thread:
            self._thread.quit()
            self._thread.wait(3000)
            self._thread = None
        self._worker = None

    def _loop(self) -> asyncio.AbstractEventLoop | None:
        if self._worker:
            return self._worker._loop
        return None

    # ------------------------------------------------------------------
    # Persistence helpers (run on UI thread, SQLite is fast enough)
    # ------------------------------------------------------------------

    def get_persistence(self) -> ChatPersistence:
        return ChatPersistence(self._db)

    def create_conversation(
        self,
        provider_id: int | None = None,
        model_name: str = "",
        skill_id: int | None = None,
    ) -> Conversation:
        """Create a new conversation and persist it."""
        persistence = self.get_persistence()
        conv = Conversation(
            provider_id=provider_id,
            model_name_snapshot=model_name,
            skill_id=skill_id,
        )
        persistence.create_conversation(conv)
        return conv

    # ------------------------------------------------------------------
    # Message submission
    # ------------------------------------------------------------------

    def send_message(
        self,
        conversation_id: str,
        user_message: str,
        provider: dict[str, Any],
        skill: dict[str, Any] | None = None,
        mcp_servers: list[dict[str, Any]] | None = None,
        message_history: list[dict[str, Any]] | None = None,
    ) -> None:
        """Submit a user message to the agent.

        Args:
            conversation_id: Active conversation.
            user_message: User's text input.
            provider: ModelProvider.to_dict().
            skill: Skill config dict or None.
            mcp_servers: List of enabled McpServerEntry.to_dict().
            message_history: List of ChatMessage.to_dict() for context.
        """
        if not self._worker:
            logger.warning("ChatService not started, cannot send message")
            return

        self._worker.submit_message(
            conversation_id=conversation_id,
            user_message=user_message,
            provider=provider,
            skill=skill,
            mcp_servers=mcp_servers or [],
            message_history=message_history or [],
        )

    def cancel_turn(self) -> None:
        """Cancel the active agent turn."""
        if self._worker:
            self._worker.cancel_turn()
