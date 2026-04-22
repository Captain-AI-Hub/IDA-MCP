# Sarma Chat — Architecture & Roadmap

## Overview

Chat feature for the Sarma IDE that lets users interact with IDA Pro via natural language.
Backend: LangGraph ReAct Agent + `langchain-mcp-adapters` MCP tools.
Frontend: PySide6 Chat page with streaming token rendering.

---

## Architecture

### Layering

```
PySide6 UI  (app/ui/chat/)
     │  Qt Signal/Slot
ChatController  (app/chat/chat_service.py)
     │  QThread + asyncio event loop
AgentFactory  →  create_react_agent(model, tools, prompt)
     │
McpClientPool  →  MultiServerMCPClient  →  MCP Servers (IDA-MCP, etc.)
     │
Persistence   →  SQLite (conversations, messages, tool_executions)
```

### Data Flow

```
User → Composer → ChatController → ChatService (QThread)
                                          │
                                   AgentFactory.build()
                                   ├── init_chat_model(provider)
                                   ├── McpClientPool.get_tools(servers)
                                   ├── SkillResolver.filter_tools(skill)
                                   └── create_react_agent(model, tools, prompt)
                                          │
                                   agent.astream(input, stream_mode="messages")
                                          │
                                   StreamEvent normalization
                                          │
                                   Qt Signal → MessageList / ToolTracePanel
                                          │
                                   Persistence (async save messages/traces)
```

### Key Design Decisions

1. **Agent**: `create_react_agent` (v1); custom `StateGraph` or deepagents (v2+).
2. **Runtime**: QThread + embedded asyncio loop (v1); subprocess IPC (v3).
3. **MCP lifecycle**: Persistent client pool, lazy connect, reconnect on failure.
4. **Skills**: Declarative — system prompt overlay + tool allow/deny list + optional model/temperature override.
5. **Streaming**: Event-based (`StreamEvent`); LangGraph `messages` mode → normalized events → Qt signals.
6. **Sessions**: Multi-conversation from day 1, persisted in SQLite.
7. **Error handling**: 3-layer (connection → tool call → run). Tool failures don't crash turns.

---

## Module Structure (New Files)

```
app/chat/
├── __init__.py
├── models.py              # Conversation, ChatMessage, StreamEvent, AgentRunConfig, ResolvedSkill
├── prompts.py             # BASE_SYSTEM_PROMPT + build_system_prompt()
├── skill_resolver.py      # Skill → prompt overlay + tool filter
├── mcp_pool.py            # MCP client pool (MultiServerMCPClient lifecycle)
├── agent_factory.py       # build LangGraph ReAct agent from config
├── streaming.py           # LangGraph events → StreamEvent normalization
├── chat_service.py        # ChatService: QThread + asyncio orchestration
├── persistence.py         # SQLite CRUD for conversations/messages/traces
├── errors.py              # Chat-specific exceptions

app/ui/chat/
├── __init__.py            # (exists)
├── page.py                # ChatPage: layout + child widgets
├── message_list.py        # MessageList: renders chat bubbles
├── composer.py            # Composer: input area + send button
├── tool_trace_panel.py    # ToolTracePanel: tool call timeline
├── session_sidebar.py     # SessionSidebar: conversation list
├── provider_selector.py   # ProviderSelector: model dropdown
└── skill_selector.py      # SkillSelector: skill dropdown
```

## Database Schema (Migration v5)

New tables: `conversations`, `conversation_messages`, `conversation_mcp_servers`, `tool_executions`.
Extended `skills` table: `system_prompt_template`, `tool_allowlist_json`, `tool_denylist_json`, `model_override`, `temperature_override`.

---

## Roadmap

### Phase 1 — Minimum Viable Chat

Goal: Basic working chat with a single LLM provider and MCP tool calling.

- [ ] Data models (`app/chat/models.py`)
- [ ] Database migration v5 + persistence (`shared/database.py`, `app/chat/persistence.py`)
- [ ] System prompts (`app/chat/prompts.py`)
- [ ] MCP client pool (`app/chat/mcp_pool.py`)
- [ ] Agent factory (`app/chat/agent_factory.py`)
- [ ] Streaming event normalization (`app/chat/streaming.py`)
- [ ] Errors (`app/chat/errors.py`)
- [ ] Chat service with QThread + asyncio (`app/chat/chat_service.py`)
- [ ] Chat page UI — page, message list, composer (`app/ui/chat/`)
- [ ] Integration into MainWindow
- [ ] i18n entries for Chat UI

### Phase 2 — Complete Experience

- [ ] Tool trace panel
- [ ] Session sidebar (multi-conversation)
- [ ] Skill resolver + skill selector
- [ ] Provider selector
- [ ] Markdown rendering + code highlighting
- [ ] Extended SkillEntry model + settings UI for Chat config

### Phase 3 — Production Hardening

- [ ] Migrate to subprocess (`chat_runtime/`)
- [ ] IPC protocol (stdin/stdout JSON Lines)
- [ ] Cancel/retry mechanism
- [ ] Token usage tracking
- [ ] Error recovery and degraded mode
- [ ] Large result truncation/summarization
- [ ] Performance tuning

### Phase 4 — Advanced Features (On Demand)

- [ ] deepagents multi-agent orchestration
- [ ] Custom StateGraph (plan/execute split)
- [ ] Human-in-the-loop tool confirmation
- [ ] Skill import/export/marketplace
- [ ] Conversation branching/comparison

---

## Dependencies

Already declared in `ide/requirements.txt`:
- `langgraph==1.1.6`
- `deepagents==0.5.3`
- `pydantic==2.13.1`

Runtime dependency (pulled by langgraph/langchain):
- `langchain-mcp-adapters` — MCP → LangChain Tool bridge
- `langchain-core` — Base abstractions

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Qt + asyncio conflict | UI freeze | QThread isolation; v3 → subprocess |
| Too many MCP tools | Agent quality drop | Skill tool allowlists |
| Large tool outputs | Token cost spike | Truncate/summarize before re-inject |
| MCP server instability | Chat interruption | Structured errors + reconnect + degraded mode |
| Provider API differences | Inconsistent behavior | `init_chat_model` abstraction + config snapshot |
| LangGraph API drift | Maintenance burden | `StreamEvent` isolation layer |
