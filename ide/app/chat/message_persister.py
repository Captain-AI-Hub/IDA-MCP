"""Persistence helpers for chat messages and tool execution events."""

from __future__ import annotations

import json

from app.chat.models import ChatMessage, StreamEvent
from app.chat.persistence import ChatPersistence


class MessagePersister:
    """Persist user, assistant, and tool messages for a single turn."""

    def __init__(self, persistence: ChatPersistence) -> None:
        self._persistence = persistence
        self._pending_tool_msgs: dict[str, ChatMessage] = {}

    def save_user_message(
        self, conversation_id: str, turn_id: str, content: str
    ) -> ChatMessage:
        msg = ChatMessage(
            conversation_id=conversation_id,
            turn_id=turn_id,
            role="user",
            content=content,
        )
        self._persistence.save_message(msg)
        return msg

    def save_assistant_message(
        self,
        conversation_id: str,
        turn_id: str,
        content: str,
        reasoning_content: str | None = None,
    ) -> ChatMessage:
        msg = ChatMessage(
            conversation_id=conversation_id,
            turn_id=turn_id,
            role="assistant",
            content=content,
            reasoning_content=reasoning_content,
        )
        self._persistence.save_message(msg)
        return msg

    def save_tool_execution(self, stream_event: StreamEvent) -> None:
        if stream_event.type == "tool_start":
            self._save_tool_start(stream_event)
        elif stream_event.type in ("tool_result", "tool_error"):
            self._save_tool_result(stream_event)

    def _save_tool_start(self, stream_event: StreamEvent) -> None:
        tool_name = stream_event.payload.get("tool_name", "")
        tool_call_id = stream_event.payload.get("tool_call_id", "")
        args = stream_event.payload.get("args", {})
        try:
            args_json = json.dumps(args, ensure_ascii=False)
        except (TypeError, ValueError):
            args_json = str(args)

        msg = ChatMessage(
            conversation_id=stream_event.conversation_id,
            turn_id=stream_event.turn_id,
            role="tool",
            content=args_json,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
        )
        self._persistence.save_message(msg)
        self._pending_tool_msgs[tool_call_id or tool_name] = msg

    def _save_tool_result(self, stream_event: StreamEvent) -> None:
        tool_call_id = stream_event.payload.get("tool_call_id", "")
        tool_name = stream_event.payload.get("tool_name", "")
        key = tool_call_id or tool_name
        if key not in self._pending_tool_msgs:
            return

        result = stream_event.payload.get("result", "")
        error = stream_event.payload.get("error", "")
        combined = result or error or ""
        msg = self._pending_tool_msgs[key]
        old_content = msg.content or ""
        try:
            combined_data = {
                "args": json.loads(old_content),
                "result": combined,
            }
            new_content = json.dumps(combined_data, ensure_ascii=False)
        except (ValueError, TypeError, json.JSONDecodeError):
            new_content = f"Args: {old_content}\nResult: {combined}"
        self._persistence.update_message_content(msg.id, new_content)
        del self._pending_tool_msgs[key]
