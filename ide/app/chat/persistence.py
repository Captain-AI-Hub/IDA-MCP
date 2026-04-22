"""SQLite persistence layer for chat conversations, messages, and tool traces."""

from __future__ import annotations

from typing import Any

from shared.database import DatabaseStore

from .models import (
    ChatMessage,
    Conversation,
    ConversationMcpBinding,
    ToolExecution,
)


class ChatPersistence:
    """Thin wrapper around DatabaseStore for chat-related CRUD."""

    def __init__(self, db: DatabaseStore) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Conversations
    # ------------------------------------------------------------------

    def create_conversation(self, conv: Conversation) -> str:
        self._db.insert_row(
            "conversations",
            id=conv.id,
            title=conv.title,
            provider_id=conv.provider_id,
            model_name_snapshot=conv.model_name_snapshot,
            skill_id=conv.skill_id,
            system_prompt_override=conv.system_prompt_override or "",
            status=conv.status,
            created_at=conv.created_at,
            updated_at=conv.updated_at,
        )
        return conv.id

    def get_conversation(self, conv_id: str) -> Conversation | None:
        rows = self._db.load_rows("conversations")
        for row in rows:
            if row["id"] == conv_id:
                return Conversation.from_dict(row)
        return None

    def list_conversations(self) -> list[Conversation]:
        rows = self._db.load_rows("conversations")
        # Most recent first
        rows.sort(key=lambda r: r.get("updated_at", ""), reverse=True)
        return [Conversation.from_dict(r) for r in rows]

    def update_conversation(self, conv_id: str, **updates: Any) -> bool:
        return self._db.update_row("conversations", conv_id, **updates)
        # Note: update_row uses integer id, but our id is TEXT PRIMARY KEY.
        # We need a custom approach for text PKs.

    def update_conversation_by_pk(self, conv_id: str, **updates: Any) -> bool:
        """Update a conversation by its text primary key."""
        if not updates:
            return False
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        serialized = [DatabaseStore._serialize(v) for v in updates.values()]
        serialized.append(conv_id)
        with self._db._connect() as conn:
            cursor = conn.execute(
                f"UPDATE conversations SET {set_clause} WHERE id = ?",
                serialized,
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_conversation(self, conv_id: str) -> bool:
        """Delete a conversation and all its messages/bindings/traces."""
        with self._db._connect() as conn:
            conn.execute(
                "DELETE FROM tool_executions WHERE conversation_id = ?",
                (conv_id,),
            )
            conn.execute(
                "DELETE FROM conversation_messages WHERE conversation_id = ?",
                (conv_id,),
            )
            conn.execute(
                "DELETE FROM conversation_mcp_servers WHERE conversation_id = ?",
                (conv_id,),
            )
            conn.execute(
                "DELETE FROM conversations WHERE id = ?",
                (conv_id,),
            )
            conn.commit()
            return True

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    def save_message(self, msg: ChatMessage) -> str:
        self._db.insert_row(
            "conversation_messages",
            id=msg.id,
            conversation_id=msg.conversation_id,
            turn_id=msg.turn_id,
            role=msg.role,
            content=msg.content,
            tool_name=msg.tool_name or "",
            tool_call_id=msg.tool_call_id or "",
            metadata_json=msg.metadata_json or "",
            created_at=msg.created_at,
        )
        return msg.id

    def save_messages(self, messages: list[ChatMessage]) -> None:
        for msg in messages:
            self.save_message(msg)

    def load_messages(
        self, conversation_id: str, limit: int = 100
    ) -> list[ChatMessage]:
        with self._db._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM conversation_messages "
                "WHERE conversation_id = ? "
                "ORDER BY created_at ASC LIMIT ?",
                (conversation_id, limit),
            )
            columns = [desc[0] for desc in cursor.description]
            rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return [ChatMessage.from_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Conversation ↔ MCP Server bindings
    # ------------------------------------------------------------------

    def save_binding(self, binding: ConversationMcpBinding) -> None:
        self._db.insert_row(
            "conversation_mcp_servers",
            conversation_id=binding.conversation_id,
            mcp_server_id=binding.mcp_server_id,
            enabled=binding.enabled,
            tool_allowlist_json=binding.tool_allowlist_json or "",
        )

    def load_bindings(self, conversation_id: str) -> list[ConversationMcpBinding]:
        with self._db._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM conversation_mcp_servers "
                "WHERE conversation_id = ?",
                (conversation_id,),
            )
            columns = [desc[0] for desc in cursor.description]
            rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return [ConversationMcpBinding.from_dict(r) for r in rows]

    def save_bindings(
        self, conversation_id: str, bindings: list[ConversationMcpBinding]
    ) -> None:
        with self._db._connect() as conn:
            conn.execute(
                "DELETE FROM conversation_mcp_servers WHERE conversation_id = ?",
                (conversation_id,),
            )
            conn.commit()
        for b in bindings:
            self.save_binding(b)

    # ------------------------------------------------------------------
    # Tool executions
    # ------------------------------------------------------------------

    def save_tool_execution(self, trace: ToolExecution) -> str:
        self._db.insert_row(
            "tool_executions",
            id=trace.id,
            conversation_id=trace.conversation_id,
            turn_id=trace.turn_id,
            mcp_server_id=trace.mcp_server_id or 0,
            server_name=trace.server_name,
            tool_name=trace.tool_name,
            args_json=trace.args_json,
            result_summary=trace.result_summary or "",
            status=trace.status,
            error_text=trace.error_text or "",
            started_at=trace.started_at,
            finished_at=trace.finished_at or "",
        )
        return trace.id

    def update_tool_execution(self, trace_id: str, **updates: Any) -> bool:
        """Update a tool execution trace by its text primary key."""
        if not updates:
            return False
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        serialized = [DatabaseStore._serialize(v) for v in updates.values()]
        serialized.append(trace_id)
        with self._db._connect() as conn:
            cursor = conn.execute(
                f"UPDATE tool_executions SET {set_clause} WHERE id = ?",
                serialized,
            )
            conn.commit()
            return cursor.rowcount > 0
