"""Conversation history compaction for chat agent runs."""

from __future__ import annotations

from app.chat.models import ChatMessage
from app.chat.persistence import ChatPersistence


class HistoryCompactor:
    """Keep recent message history within a provider context budget."""

    def __init__(
        self, persistence: ChatPersistence, max_context_tokens: int
    ) -> None:
        self._persistence = persistence
        self._max_context_tokens = max_context_tokens

    def compact(
        self, conversation_id: str, messages: list[ChatMessage]
    ) -> list[ChatMessage]:
        """Return history with older messages summarized when needed."""
        if self._max_context_tokens <= 0 or not messages:
            return messages

        budget = max(512, int(self._max_context_tokens * 0.55))
        used = 0
        kept: list[ChatMessage] = []
        omitted: list[ChatMessage] = []

        for msg in reversed(messages):
            cost = self._estimate_message_tokens(msg)
            if used + cost > budget:
                omitted.append(msg)
                continue
            kept.append(msg)
            used += cost

        kept.reverse()
        omitted.reverse()

        while kept and kept[0].role == "tool":
            omitted.append(kept.pop(0))

        if not omitted:
            return kept

        return [
            ChatMessage(
                conversation_id=conversation_id,
                role="system",
                content=self._build_compaction_summary(omitted),
            ),
            *kept,
        ]

    @staticmethod
    def _estimate_message_tokens(msg: ChatMessage) -> int:
        text = msg.content or ""
        if msg.reasoning_content:
            text += "\n" + msg.reasoning_content
        if msg.tool_name:
            text += "\n" + msg.tool_name
        return HistoryCompactor._estimate_text_tokens(text) + 8

    @staticmethod
    def _estimate_text_tokens(text: str) -> int:
        return max(1, (len(text) + 3) // 4)

    @staticmethod
    def _build_compaction_summary(messages: list[ChatMessage]) -> str:
        lines = [
            "Earlier conversation was compacted to fit the model context.",
            "Use this summary as background; ask for details if needed.",
        ]
        char_budget = 3000
        used = sum(len(line) for line in lines)
        for msg in messages:
            role = msg.role
            if msg.tool_name:
                role = f"{role}:{msg.tool_name}"
            content = " ".join((msg.content or "").split())
            if not content:
                continue
            line = f"- {role}: {content[:400]}"
            if used + len(line) > char_budget:
                lines.append("- ... additional older messages omitted ...")
                break
            lines.append(line)
            used += len(line)
        return "\n".join(lines)
