"""LangGraph event stream → StreamEvent normalization."""

from __future__ import annotations

import time
from typing import Any

from app.chat.models import StreamEvent


def normalize_langgraph_event(
    event_type: str,
    event_data: Any,
    conversation_id: str,
    turn_id: str,
) -> StreamEvent | None:
    """Convert a raw LangGraph stream event into a StreamEvent.

    LangGraph stream_mode="messages" yields (AIMessageChunk, metadata) tuples.
    stream_mode="updates" yields node-name → state-delta dicts.

    Args:
        event_type: The stream mode that produced this event ("messages", "updates", etc.)
        event_data: The raw event data from LangGraph.
        conversation_id: Active conversation ID.
        turn_id: Active turn ID.

    Returns:
        A StreamEvent, or None if the event should be skipped.
    """
    if event_type == "messages":
        return _normalize_message_event(event_data, conversation_id, turn_id)
    elif event_type == "updates":
        return _normalize_update_event(event_data, conversation_id, turn_id)
    return None


def _normalize_message_event(
    data: Any,
    conversation_id: str,
    turn_id: str,
) -> StreamEvent | None:
    """Handle stream_mode="messages" events.

    data is a tuple of (message_chunk, metadata).
    """
    if not isinstance(data, tuple) or len(data) < 2:
        return None

    msg, _metadata = data[0], data[1]

    # Token streaming from LLM
    if hasattr(msg, "content") and msg.content:
        # Check for tool calls — but still emit the token content
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            # Emit tool_start events are handled via updates mode,
            # so just emit the token here
            pass

        return StreamEvent(
            type="token",
            conversation_id=conversation_id,
            turn_id=turn_id,
            payload={"content": msg.content},
            timestamp=time.time(),
        )

    # Tool result message
    if hasattr(msg, "tool_call_id") and msg.tool_call_id:
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        event_type = "tool_result"
        payload: dict[str, Any] = {
            "tool_call_id": msg.tool_call_id,
            "result": content[:2000],  # Truncate large results
        }
        # Check if it's an error result
        if hasattr(msg, "status") and msg.status == "error":
            event_type = "tool_error"
            payload["error"] = content

        return StreamEvent(
            type=event_type,
            conversation_id=conversation_id,
            turn_id=turn_id,
            payload=payload,
            timestamp=time.time(),
        )

    return None


def _normalize_update_event(
    data: Any,
    conversation_id: str,
    turn_id: str,
) -> StreamEvent | None:
    """Handle stream_mode="updates" events.

    data is a dict mapping node name → state delta.
    """
    if not isinstance(data, dict):
        return None

    for node_name, state_delta in data.items():
        if node_name == "tools":
            # Tool node finished — extract results and tool starts
            messages = state_delta.get("messages", [])
            for msg in messages:
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    # AIMessage with tool call requests → tool_start events
                    for tc in msg.tool_calls:
                        return StreamEvent(
                            type="tool_start",
                            conversation_id=conversation_id,
                            turn_id=turn_id,
                            payload={
                                "tool_name": tc.get("name", ""),
                                "args": tc.get("args", {}),
                            },
                            timestamp=time.time(),
                        )
                if hasattr(msg, "name") and hasattr(msg, "tool_call_id"):
                    # ToolMessage → tool_result
                    content = msg.content if isinstance(msg.content, str) else str(msg.content)
                    is_error = hasattr(msg, "status") and msg.status == "error"
                    return StreamEvent(
                        type="tool_error" if is_error else "tool_result",
                        conversation_id=conversation_id,
                        turn_id=turn_id,
                        payload={
                            "tool_name": getattr(msg, "name", ""),
                            "tool_call_id": getattr(msg, "tool_call_id", ""),
                            "result": content[:2000],
                            **({"error": content} if is_error else {}),
                        },
                        timestamp=time.time(),
                    )
        elif node_name == "agent":
            pass

    return None


def make_run_started_event(
    conversation_id: str, turn_id: str
) -> StreamEvent:
    return StreamEvent(
        type="run_started",
        conversation_id=conversation_id,
        turn_id=turn_id,
        payload={},
        timestamp=time.time(),
    )


def make_run_completed_event(
    conversation_id: str,
    turn_id: str,
    assistant_content: str = "",
) -> StreamEvent:
    return StreamEvent(
        type="run_completed",
        conversation_id=conversation_id,
        turn_id=turn_id,
        payload={"assistant_message": assistant_content},
        timestamp=time.time(),
    )


def make_run_failed_event(
    conversation_id: str,
    turn_id: str,
    error: str,
    partial_content: str = "",
) -> StreamEvent:
    return StreamEvent(
        type="run_failed",
        conversation_id=conversation_id,
        turn_id=turn_id,
        payload={"error": error, "partial_message": partial_content},
        timestamp=time.time(),
    )
