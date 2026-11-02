# IDA-MCP Roadmap

## Current Baseline (v1.0)

- Pure idalib architecture: no GUI plugin, no IDA executable path; headless
  workers only, spawned and routed per call (stateless routing; explicit
  instance_id wins, sole live instance implicit, several live instances
  require an id).
- stdio-only MCP server (`uvx idamcp-hub stdio`) with fastmcp 4.x; all tools
  exposed with no unsafe gating (the bridge binds loopback by default).
- Per-worker stdlib JSON-RPC bridge; shared JSON instance registry; operation
  interruption (async-exception injection + IDA native cancel) on timeouts.
- Headless debugger works (`dbg_start` loads the platform debugger); the
  call stack is rebuilt from frame pointers on IDA 9.
- `ida_python_reference`: BM25 index over the attached runtime's IDAPython
  modules (~21k entries).
- pytest suite: 233 tests including a real headless debugger session on a
  compiled ELF sample.

## Priorities

### P1 (v1.1) — terminal UI (r2-style, host-side)

`idamcp-hub tui <path>` — an interactive terminal front-end over the same
workers/bridge (the `uvx` side, not inside the worker):
- disassembly / pseudocode panes (ANSI colors), seek (g), xref jump (x),
  rename/comment (n/c) calling the existing tools;
- function list / imports / strings sidebar (list_* catalogs);
- call graph navigation; optional ASCII/Unicode CFG rendering from
  get_basic_blocks (graphviz optional);
- multi-instance tabs by instance_id (reuses the routing rules verbatim).
- Design notes: a `textual`/`prompt_toolkit` app in `ida_mcp/tui/`, talking to
  the bridge through bridge_client; zero new deps inside the worker. A
  lightweight `idamcp-hub dump` (idalib-dump style asm/pseudo export, no
  interaction) ships alongside for CI use.

### P1 — worker depth
- idalib worker env isolation (`idalib-venv` bootstrap when no candidate
  interpreter is found); wait-for-analysis progress in open_database results.
- Worker crash/timeout hardening: reap orphan workers, cap retry storms.

### P2 — tool surface
- Batch tool calls to reduce round-trips over the bridge.
- Docker image for CI workers (libidalib is Qt-free; headless-proven on this
  machine; debugger via gdbserver).

### P3 — docs
- Cache the IDAPython reference index per IDA version on disk.

## Non-goals

- No HTTP/SSE transport, no gateway/proxy resurrection.
- No GUI plugin, no PySide6/Qt anywhere in this repository (incl. the TUI —
  terminal rendering only).
