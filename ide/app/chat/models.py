"""Chat data models."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


def _uid() -> str:
    return uuid.uuid4().hex[:12]


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Conversation
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Conversation:
    id: str = field(default_factory=_uid)
    title: str = ""
    provider_id: int | None = None
    model_name_snapshot: str = ""
    skill_id: int | None = None
    system_prompt_override: str | None = None
    status: str = "idle"  # idle | running | failed
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Conversation:
        if not data:
            return cls()
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in allowed})


# ---------------------------------------------------------------------------
# ChatMessage
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ChatMessage:
    id: str = field(default_factory=_uid)
    conversation_id: str = ""
    turn_id: str = ""
    role: str = ""  # system | user | assistant | tool
    content: str = ""
    tool_name: str | None = None
    tool_call_id: str | None = None
    metadata_json: str | None = None
    reasoning_content: str | None = None
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ChatMessage:
        if not data:
            return cls()
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in allowed})

    def to_langchain_message(self) -> Any:
        """Convert to a langchain BaseMessage so extra fields survive."""
        from langchain_core.messages import (
            AIMessage,
            HumanMessage,
            SystemMessage,
        )

        if self.role == "tool":
            # Always degrade to text to avoid orphan ToolMessage issues.
            # The preceding AIMessage in history may lack tool_calls
            # (e.g. after compaction or summarization), which breaks
            # providers that require tool_calls before every ToolMessage.
            return AIMessage(content=self._tool_history_fallback_text())

        extra: dict[str, Any] = {}
        # Thinking-mode LLMs (DeepSeek-R1 etc.) require reasoning_content
        # to be passed back verbatim on subsequent calls.
        if self.reasoning_content:
            extra["additional_kwargs"] = {
                "reasoning_content": self.reasoning_content
            }

        if self.role == "assistant":
            return AIMessage(content=self.content, **extra)
        if self.role == "user":
            return HumanMessage(content=self.content)
        if self.role == "system":
            return SystemMessage(content=self.content)

        # Fallback for unknown roles
        return {"role": self.role, "content": self.content, **extra}

    def _tool_history_fallback_text(self) -> str:
        """Serialize persisted tool history without tool_call_id as plain text.

        Older rows and partial tool traces may not have a valid tool_call_id.
        Those cannot be reconstructed as protocol-correct ToolMessage objects,
        so we degrade them into assistant text instead of crashing replay.
        """
        tool_label = self.tool_name or "tool"
        content = self.content or ""

        try:
            data = json.loads(content)
        except (TypeError, ValueError):
            data = None

        if isinstance(data, dict):
            args = data.get("args")
            result = data.get("result")
            parts = [f"Previous tool call: {tool_label}"]
            if args not in (None, "", {}, []):
                parts.append(
                    f"Args: {json.dumps(args, ensure_ascii=False, sort_keys=True)}"
                )
            if result not in (None, ""):
                parts.append(f"Result: {result}")
            return "\n".join(parts)

        if content:
            return f"Previous tool call: {tool_label}\nResult: {content}"
        return f"Previous tool call: {tool_label}"


# ---------------------------------------------------------------------------
# Conversation <-> MCP Server binding
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ConversationMcpBinding:
    conversation_id: str = ""
    mcp_server_id: int = 0
    enabled: bool = True
    tool_allowlist_json: str | None = None  # null = allow all

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ConversationMcpBinding:
        if not data:
            return cls()
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in allowed})


# ---------------------------------------------------------------------------
# Tool execution trace
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ToolExecution:
    id: str = field(default_factory=_uid)
    conversation_id: str = ""
    turn_id: str = ""
    mcp_server_id: int | None = None
    server_name: str = ""
    tool_name: str = ""
    args_json: str = ""
    result_summary: str | None = None
    status: str = "started"  # started | succeeded | failed
    error_text: str | None = None
    started_at: str = field(default_factory=_now_iso)
    finished_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ToolExecution:
        if not data:
            return cls()
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in allowed})


# ---------------------------------------------------------------------------
# Stream events (runtime → UI)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class StreamEvent:
    type: str  # token | tool_start | tool_result | tool_error |
               # run_started | run_completed | run_failed | status | usage
    conversation_id: str = ""
    turn_id: str = ""
    payload: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> StreamEvent:
        if not data:
            return cls()
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in allowed})


# ---------------------------------------------------------------------------
# Resolved Skill (runtime)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ResolvedSkill:
    """Runtime-resolved Skill configuration (prompt overlay + tool filter)."""

    id: int | None = None
    name: str = ""
    system_prompt_suffix: str = ""
    tool_allowlist: set[str] | None = None  # None = allow all
    tool_denylist: set[str] | None = None   # None = deny none
    preferred_model_name: str | None = None
    temperature_override: float | None = None


# ---------------------------------------------------------------------------
# Agent run config (single turn)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AgentRunConfig:
    """Complete configuration for a single agent run."""

    conversation_id: str
    provider: Any  # ModelProvider
    skill: ResolvedSkill | None
    enabled_servers: list[Any]  # list[McpServerEntry]
    message_history: list[ChatMessage]
    user_message: str
    system_prompt: str
    # LangGraph needs a finite recursion_limit; use a very high value so long
    # reverse-engineering traces are effectively bounded by context/tool limits.
    max_steps: int = 100_000
