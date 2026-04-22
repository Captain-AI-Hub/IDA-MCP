"""System prompt assembly for the chat agent."""

from __future__ import annotations

from app.chat.models import ResolvedSkill

BASE_SYSTEM_PROMPT = """\
You are Sarma, an AI assistant for binary reverse engineering in IDA Pro.

You have access to IDA Pro analysis tools via MCP. Use them to help the user:
- Decompile and disassemble functions
- Analyze cross-references and call graphs
- Identify strings, imports, exports
- Rename functions/variables
- Understand program structure and control flow

Guidelines:
- Always explain your reasoning before and after tool calls.
- When you call a tool, briefly state what you expect to learn.
- Present decompiled code and disassembly in formatted code blocks.
- If a tool call fails, explain the error and suggest alternatives.
- Be concise but thorough in your analysis.
"""

SKILL_PROMPT_SEPARATOR = "\n\n---\n\n"


def build_system_prompt(
    skill: ResolvedSkill | None = None,
    override: str | None = None,
) -> str:
    """Assemble the full system prompt from base + skill + user override.

    Order of composition:
      1. BASE_SYSTEM_PROMPT (always present)
      2. User override (conversation-level)
      3. Skill prompt suffix
    """
    parts: list[str] = [BASE_SYSTEM_PROMPT]

    if override:
        parts.append(override)

    if skill and skill.system_prompt_suffix:
        parts.append(skill.system_prompt_suffix)

    return SKILL_PROMPT_SEPARATOR.join(parts)
