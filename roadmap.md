# IDA-MCP Roadmap

## Current Baseline (v0.9)

- stdio-only MCP server (`uvx idamcp stdio`) with fastmcp 4.x; all 93 tools
  exposed with no unsafe gating (the bridge binds loopback by default).
- Per-instance stdlib JSON-RPC bridge; shared JSON instance registry; no
  gateway, no port-registration forwarding, no HTTP transport, no `ida://`
  resources (all removed in v0.9).
- Lifecycle tools: open_database (attach / headless idalib
  worker that creates+analyzes .i64 / GUI launch), list/select/save/close.
- `ida_python_reference`: BM25 index over the attached runtime's IDAPython
  modules (~21k entries).
- idalib Python auto-detection (config → ida_python → ida-config.json →
  ida-python → managed/legacy venvs) cached into the user config.
- pytest suite: unit tests run without IDA; backend tests run live against a
  headless worker when idalib is available (200 passed / 19 skipped on the
  dev machine).

## Priorities

### P0 — stabilization
- Ship `idamcp` to PyPI; pin CI to run the unit suite.
- Worker crash/timeout hardening: reap orphan workers, cap retry storms.

### P1 — headless depth
- idalib worker env isolation (`idalib-venv` bootstrap + py-activate-idalib
  automation when no candidate interpreter is found).
- Wait-for-analysis progress reporting in open_database results.

### P2 — tool surface
- dbg_* currently require a GUI instance with a configured debugger; revisit
  local debuggers under idalib workers if supported.
- Consider batch tool calls to reduce round-trips over the bridge.

### P3 — docs
- Cache the IDAPython reference index per IDA version on disk.
- Expose module summaries through `ida_python_reference("modules")` UX polish.

## Non-goals

- No HTTP/SSE transport, no gateway/proxy resurrection.
- No PySide6 UI or Sarma IDE code in this repository.
