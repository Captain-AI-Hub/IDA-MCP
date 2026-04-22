"""Chat data models."""

from __future__ import annotations

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
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ChatMessage:
        if not data:
            return cls()
        allowed = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in allowed})

    def to_langchain_message(self) -> dict[str, Any]:
        """Convert to a langchain-compatible message dict."""
        return {
            "role": self.role,
            "content": self.content,
        }


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
    max_steps: int = 12
