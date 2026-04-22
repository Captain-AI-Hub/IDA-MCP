"""LangGraph ReAct Agent factory."""

from __future__ import annotations

import logging
from typing import Any

from app.chat.errors import AgentBuildError, ProviderNotConfiguredError
from app.chat.mcp_pool import McpClientPool
from app.chat.models import AgentRunConfig, ResolvedSkill

logger = logging.getLogger(__name__)


def _build_openai_model(
    *,
    model_name: str,
    api_key: str,
    base_url: str,
    temperature: float,
    top_p: float,
) -> Any:
    from langchain_openai import ChatOpenAI

    kwargs: dict[str, Any] = {
        "model": model_name,
        "temperature": temperature,
        "top_p": top_p,
    }
    if api_key:
        kwargs["api_key"] = api_key
    if base_url:
        kwargs["base_url"] = base_url
    return ChatOpenAI(**kwargs)


def _build_anthropic_model(
    *,
    model_name: str,
    api_key: str,
    base_url: str,
    temperature: float,
    top_p: float,
) -> Any:
    from langchain_anthropic import ChatAnthropic

    kwargs: dict[str, Any] = {
        "model": model_name,
        "temperature": temperature,
        "top_p": top_p,
    }
    if api_key:
        kwargs["api_key"] = api_key
    if base_url:
        kwargs["base_url"] = base_url
    return ChatAnthropic(**kwargs)


# Maps api_mode → builder function.
_MODEL_BUILDERS: dict[str, Any] = {
    "openai_responses": _build_openai_model,
    "openai_compatible": _build_openai_model,
    "anthropic": _build_anthropic_model,
}


class AgentFactory:
    """Builds a LangGraph ReAct agent from runtime configuration."""

    def __init__(self, pool: McpClientPool) -> None:
        self._pool = pool

    async def build(
        self, config: AgentRunConfig
    ) -> tuple[Any, list[Any]]:
        """Build and return (compiled_graph, tools).

        Args:
            config: Full run configuration.

        Returns:
            Tuple of (compiled LangGraph agent, list of LangChain tools).

        Raises:
            ProviderNotConfiguredError: If the provider is invalid.
            AgentBuildError: If agent construction fails.
        """
        provider = config.provider

        # Validate provider has minimum fields
        if not provider.model_name:
            raise ProviderNotConfiguredError(
                "Model name is required for the selected provider."
            )

        # 1. Build MCP server configs from enabled servers
        server_configs: dict[str, dict[str, Any]] = {}
        for server in config.enabled_servers:
            server_configs[server.name] = server.to_langchain_config()

        # 2. Connect / reuse MCP client pool and get tools
        all_tools = await self._pool.connect(server_configs)

        # 3. Apply skill tool filter
        tools = self._apply_skill_filter(all_tools, config.skill)

        if not tools:
            logger.warning(
                "No tools available after filtering. "
                "Agent will run without tool access."
            )

        # 4. Initialize LLM
        try:
            model = self._init_model(provider, config.skill)
        except Exception as exc:
            raise AgentBuildError(
                f"Failed to initialize model: {exc}"
            ) from exc

        # 5. Build ReAct agent
        try:
            from langgraph.prebuilt import create_react_agent

            agent = create_react_agent(
                model,
                tools,
                prompt=config.system_prompt,
            )
        except Exception as exc:
            raise AgentBuildError(
                f"Failed to create ReAct agent: {exc}"
            ) from exc

        logger.info(
            "Agent built: model=%s, tools=%d, skill=%s",
            provider.model_name,
            len(tools),
            config.skill.name if config.skill else "none",
        )

        return agent, tools

    def _init_model(self, provider: Any, skill: ResolvedSkill | None) -> Any:
        """Initialize a langchain chat model directly based on api_mode."""
        api_mode = provider.api_mode
        builder = _MODEL_BUILDERS.get(api_mode)
        if builder is None:
            raise ProviderNotConfiguredError(
                f"Unsupported api_mode: {api_mode!r}"
            )

        model_name = (
            skill.preferred_model_name
            if skill and skill.preferred_model_name
            else provider.model_name
        )

        temperature = provider.temperature
        if skill and skill.temperature_override is not None:
            temperature = skill.temperature_override

        return builder(
            model_name=model_name,
            api_key=provider.api_key,
            base_url=provider.base_url,
            temperature=temperature,
            top_p=provider.top_p,
        )

    def _apply_skill_filter(
        self,
        tools: list[Any],
        skill: ResolvedSkill | None,
    ) -> list[Any]:
        """Filter tools based on skill allow/deny lists."""
        if skill is None:
            return tools
        return self._pool.filter_tools(
            tools,
            allowlist=skill.tool_allowlist,
            denylist=skill.tool_denylist,
        )
