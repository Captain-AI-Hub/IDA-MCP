# IDA-MCP Project Map

## Responsibility

IDA-MCP is the standalone IDA Pro plugin + stdio MCP server project. It owns
the in-instance JSON-RPC bridge, headless idalib workers, the shared instance
registry, MCP tool composition and forwarding, the official IDAPython
reference index, the CLI, and live/headless integration tests.

It does not own the desktop IDE, chat/workspace state, installer UI, or other
Sarma application code.

## Entry Points

| Entry | Responsibility |
| --- | --- |
| `ida_mcp.py` | IDA plugin file exposing `PLUGIN_ENTRY()`; starts/stops the bridge |
| `ida_mcp/plugin_runtime.py` | Bridge lifecycle inside IDA (bind, publish, touch, stop) |
| `ida_mcp/bridge_server.py` | Stdlib JSON-RPC bridge served by every IDA process |
| `ida_mcp/worker.py` | Headless idalib worker process (`python -m ida_mcp.worker`) |
| `ida_mcp/mcp_server.py` | Standalone FastMCP server (stdio only) + management tools |
| `ida_mcp/command.py` | `idamcp` CLI: stdio / instances / open / close / tool / reference |
| `API.md` | Bridge protocol, registry format, tool catalog contract |

## Directory Map

| Path | Responsibility |
| --- | --- |
| `ida_mcp/instances.py` | Shared JSON instance registry (atomic writes, pid pruning) |
| `ida_mcp/lifecycle.py` | open/attach/launch/save/close, bundle staging |
| `ida_mcp/bridge_client.py` | HTTP client for the in-instance bridge |
| `ida_mcp/idapython_docs.py` | Official IDAPython reference snapshots + BM25 search |
| `ida_mcp/api_*.py` | Backend tool catalog executed inside the IDA process |
| `ida_mcp/sync.py` | `@idaread/@idawrite` main-thread dispatch (GUI + idalib modes) |
| `test/` | pytest suite: unit tests (no IDA) + bridge-direct live tests |

## Runtime Boundaries

- IDA runtime (GUI or worker): all SDK calls execute on the IDA main thread
  via `@idaread/@idawrite`; idalib workers serialize through the main-queue
  executor. The bridge itself is stdlib-only.
- Standalone runtime: any Python ≥3.11 with fastmcp; never imports IDA SDK
  modules; discovers instances only through the registry + bridge HTTP.
- Test runtime: spawns a headless worker on `test/samples/complex.exe` when
  an idalib Python is available; otherwise backend tests skip.

## Tool Registration

1. Implement in the appropriate `ida_mcp/api_*.py` module.
2. Decorate with `@tool` plus `@idaread` or `@idawrite`.
3. New modules must be imported from `ida_mcp/api_loader.py`.
4. Update `API.md` when contracts change.

The standalone server forwards every registered tool automatically and adds
`instance_id`/`timeout` overrides; no per-tool proxy work is needed.

## Relationship To Sarma

Sarma vendors this repository as `ide/resources/ida_mcp`. Sarma may launch the
CLI, copy plugin files into IDA's plugin directory, and call the bridge, but
this repository must not import Sarma IDE modules.
