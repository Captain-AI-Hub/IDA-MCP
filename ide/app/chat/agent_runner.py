"""Agent construction and streaming execution for chat turns."""

from __future__ import annotations

from typing import Any, AsyncIterator

from app.chat.agent_factory import AgentFactory
from app.chat.mcp_pool import McpClientPool
from app.chat.models import AgentRunConfig, ChatMessage, ResolvedSkill, StreamEvent
from app.chat.streaming import normalize_langgraph_events


class AgentRunner:
    """Build a LangGraph agent, run it with streaming, and yield events."""

    def __init__(
        self,
        factory: AgentFactory,
        pool: McpClientPool,
        provider_dict: dict[str, Any],
        servers_list: list[dict[str, Any]],
        skill_dict: dict[str, Any] | None,
        history: list[ChatMessage],
        system_prompt: str,
        conversation_id: str,
        turn_id: str,
    ) -> None:
        self._factory = factory
        self._pool = pool
        self._provider_dict = provider_dict
        self._servers_list = servers_list
        self._skill_dict = skill_dict
        self._history = history
        self._system_prompt = system_prompt
        self._conversation_id = conversation_id
        self._turn_id = turn_id
        self.assistant_content = ""
        self.reasoning_content = ""
        self.tool_calls: list[StreamEvent] = []
        self.run_config: AgentRunConfig | None = None

    async def run(self, message: str) -> AsyncIterator[StreamEvent]:
        provider = self._parse_provider(self._provider_dict)
        skill = self._parse_skill(self._skill_dict)
        servers = self._parse_servers(self._servers_list)
        self.run_config = AgentRunConfig(
            conversation_id=self._conversation_id,
            provider=provider,
            skill=skill,
            enabled_servers=servers,
            message_history=self._history,
            user_message=message,
            system_prompt=self._system_prompt,
        )

        agent, _tools = await self._factory.build(self.run_config)
        input_messages = self._build_input_messages(self._history, message)

        async for event_bundle in agent.astream(
            {"messages": input_messages},
            stream_mode=["messages", "updates"],
            config={"recursion_limit": self.run_config.max_steps},
        ):
            if not isinstance(event_bundle, tuple) or len(event_bundle) < 2:
                continue

            mode, data = event_bundle[0], event_bundle[1]
            self._accumulate_reasoning(mode, data)

            stream_events = normalize_langgraph_events(
                mode, data, self._conversation_id, self._turn_id
            )
            for stream_event in stream_events:
                self._accumulate_event(stream_event)
                yield stream_event

    def _accumulate_reasoning(self, mode: str, data: Any) -> None:
        if mode != "messages":
            return
        msg = data[0] if isinstance(data, tuple) and len(data) > 0 else None
        if msg is None:
            return
        reasoning_content = getattr(msg, "reasoning_content", None)
        if not reasoning_content and hasattr(msg, "additional_kwargs"):
            reasoning_content = msg.additional_kwargs.get("reasoning_content")
        if reasoning_content and isinstance(reasoning_content, str):
            self.reasoning_content += reasoning_content

    def _accumulate_event(self, stream_event: StreamEvent) -> None:
        if stream_event.type == "token":
            chunk = stream_event.payload.get("content", "")
            if isinstance(chunk, list):
                parts = []
                for block in chunk:
                    if isinstance(block, str):
                        parts.append(block)
                    elif isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
                chunk = "".join(parts)
            if chunk:
                self.assistant_content += chunk
        elif stream_event.type == "tool_start":
            self.tool_calls.append(stream_event)

    @staticmethod
    def _build_input_messages(
        history: list[ChatMessage], user_message: str
    ) -> list[Any]:
        from langchain_core.messages import HumanMessage

        messages: list[Any] = [msg.to_langchain_message() for msg in history]
        messages.append(HumanMessage(content=user_message))
        return messages

    @staticmethod
    def _parse_provider(data: dict[str, Any]) -> Any:
        from supervisor.models import ModelProvider

        return ModelProvider.from_dict(data)

    @staticmethod
    def _parse_skill(data: dict[str, Any] | None) -> ResolvedSkill | None:
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
        from supervisor.models import McpServerEntry

        return [McpServerEntry.from_dict(d) for d in data_list]
