# IDA-MCP

**[English](README.md)** | **[中文](README_CN.md)**

<img src="ida-mcp.png" width="50%">

[![MCP Badge](https://lobehub.com/badge/mcp/captain-ai-hub-ida-mcp)](https://lobehub.com/mcp/captain-ai-hub-ida-mcp)

[wiki](https://github.com/jelasin/IDA-MCP/wiki) [deepwiki](https://deepwiki.com/jelasin/IDA-MCP)

## IDA-MCP (FastMCP + Multi-instance Gateway)

* Each IDA instance starts its own **FastMCP Streamable HTTP** endpoint at `/mcp`
* A standalone gateway daemon maintains the in-memory instance registry and forwards tool calls
* The gateway serves both the internal API at `/internal` and the client-facing MCP proxy at `/mcp` on `127.0.0.1:11338` by default
* The stdio proxy is a separate subprocess entrypoint that reuses the same proxy tool set
* MCP Resources are exposed by each IDA instance directly, not by the gateway/proxy

## Architecture

The project uses a modular architecture:

### Core Infrastructure

* `rpc.py` - `@tool` / `@resource` / `@unsafe` decorators and registration
* `sync.py` - `@idaread` / `@idawrite` IDA thread synchronization decorators
* `utils.py` - Address parsing, pagination, pattern filtering utilities
* `compat.py` - IDA 8.x/9.x compatibility layer

### API Modules (IDA Backend)

* `api_core.py` - IDB metadata, function/string/global lists
* `api_analysis.py` - Decompilation, disassembly, cross-references
* `api_memory.py` - Memory reading operations
* `api_modeling.py` - Database shaping (functions, code/data/string creation)
* `api_types.py` - Type operations (prototypes, local types)
* `api_modify.py` - Comments, renaming
* `api_stack.py` - Stack frame operations
* `api_debug.py` - Debugger control (marked unsafe)
* `api_python.py` - Python execution in IDA context (marked unsafe)
* `api_resources.py` - MCP Resources (`ida://` URI patterns)

### Key Features

* **Decorator Chain Pattern**: `@tool` + `@idaread`/`@idawrite` for clean API definitions
* **Batch Operations**: Most tools accept lists for batch processing
* **MCP Resources**: REST-like `ida://` URI patterns for read-only data access on direct instance connections
* **Multi-instance Support**: A standalone gateway on port 11338 manages multiple IDA instances
* **HTTP-first Defaults**: The bundled config defaults to `enable_http=true`, `enable_stdio=false`, and `enable_unsafe=true`
* **IDA 8.x/9.x Compatible**: Compatibility layer handles API differences

## Current Tools

### Core Tools (`api_core.py`)

* `check_connection` – Health check (ok/count)
* `list_instances` – List all registered IDA instances
* `get_metadata` – IDB metadata (hash/arch/bits/endian)
* `list_functions` – Paginated function list with optional pattern filter
* `get_function` – Find function by name or address
* `list_globals` – Global symbols (non-functions)
* `list_strings` – Extracted strings
* `list_local_types` – Local type definitions
* `get_entry_points` – Program entry points
* `convert_number` – Number format conversion
* `list_imports` – List imported functions with module names
* `list_exports` – List exported functions/symbols
* `list_segments` – List memory segments with permissions
* `get_cursor` – Get current cursor position and context

### Analysis Tools (`api_analysis.py`)

* `decompile` – Batch decompile functions (Hex-Rays)
* `disasm` – Batch disassemble functions
* `linear_disasm` – Linear disassembly from arbitrary address
* `xrefs_to` – Batch cross-references to addresses
* `xrefs_from` – Batch cross-references from addresses
* `xrefs_to_field` – Heuristic struct field references
* `find_bytes` – Search for byte patterns with wildcards
* `get_basic_blocks` – Get basic blocks with control flow

### Memory Tools (`api_memory.py`)

* `get_bytes` – Read raw bytes
* `get_u8` / `get_u16` / `get_u32` / `get_u64` – Read integers
* `get_string` – Read null-terminated strings

### Modeling Tools (`api_modeling.py`)

* `create_function` – Create a function at an address
* `delete_function` – Delete an existing function
* `make_code` – Convert bytes at an address into code
* `undefine_items` – Undefine a byte range
* `make_data` – Create typed data items
* `make_string` – Create a string literal
* `create_array` – Create an array of typed data items

### Type Tools (`api_types.py`)

* `declare_type` – Create/update local types
* `set_function_prototype` – Set function signature
* `set_local_variable_type` – Set local variable type (Hex-Rays)
* `set_global_variable_type` – Set global variable type
* `list_structs` – List all structures/unions
* `get_struct_info` – Get structure definition with fields

### Modify Tools (`api_modify.py`)

* `set_comment` – Batch set comments
* `rename_function` – Rename function
* `rename_local_variable` – Rename local variable (Hex-Rays)
* `rename_global_variable` – Rename global symbol
* `patch_bytes` – Patch bytes at addresses

### Stack Tools (`api_stack.py`)

* `stack_frame` – Get stack frame variables
* `declare_stack` – Create stack variables
* `delete_stack` – Delete stack variables

### Python Tools (`api_python.py`) - Unsafe

* `py_eval` – Execute Python code in IDA context and return `result` / `stdout` / `stderr`

### Debug Tools (`api_debug.py`) - Unsafe

* `dbg_regs` – Get all registers
* `dbg_callstack` – Get call stack
* `dbg_list_bps` – List breakpoints
* `dbg_start` – Start debugging
* `dbg_exit` – Terminate debug
* `dbg_continue` – Continue execution
* `dbg_run_to` – Run to address
* `dbg_add_bp` – Add breakpoint
* `dbg_delete_bp` – Delete breakpoint
* `dbg_enable_bp` – Enable/disable breakpoint
* `dbg_step_into` – Step into instruction
* `dbg_step_over` – Step over instruction
* `dbg_read_mem` – Read debugger memory
* `dbg_write_mem` – Write debugger memory

### MCP Resources (`api_resources.py`)

* `ida://idb/metadata` – IDB metadata
* `ida://functions` – Function list
* `ida://function/{addr}` – Single function details
* `ida://function/{addr}/decompile` – Function decompilation snapshot
* `ida://function/{addr}/disasm` – Function disassembly snapshot
* `ida://function/{addr}/basic_blocks` – Function CFG/basic block view
* `ida://function/{addr}/stack` – Function stack/local-variable view
* `ida://strings` – Strings
* `ida://globals` – Global symbols
* `ida://types` – Local types
* `ida://segments` / `ida://segment/{name_or_addr}` – Segment list and detail
* `ida://imports` / `ida://imports/{module}` – Imports list and per-module view
* `ida://exports` – Export list
* `ida://entry_points` – Entry points
* `ida://structs` / `ida://struct/{name}` – Struct list and detail
* `ida://xrefs/to/{addr}` – Cross-references to address
* `ida://xrefs/to/{addr}/summary` – Aggregated incoming xref summary
* `ida://xrefs/from/{addr}` – Cross-references from address
* `ida://xrefs/from/{addr}/summary` – Aggregated outgoing xref summary
* `ida://memory/{addr}?size=N` – Read memory

## Directory Structure

```text
IDA-MCP/
  ida_mcp.py              # Plugin entry: start/stop per-instance HTTP MCP server + register with gateway
  ida_mcp/
    __init__.py           # Package initialization, auto-discovery, exports
    config.py             # Configuration loader (config.conf parser)
    config.conf           # User configuration file
    rpc.py                # @tool/@resource/@unsafe decorators
    sync.py               # @idaread/@idawrite thread sync
    utils.py              # Utility functions
    compat.py             # IDA 8.x/9.x compatibility layer
    api_core.py           # Core API (metadata, lists)
    api_analysis.py       # Analysis API (decompile, disasm, xrefs)
    api_memory.py         # Memory API
    api_modeling.py       # Modeling API (functions, code/data/string creation)
    api_types.py          # Type API
    api_modify.py         # Modification API
    api_stack.py          # Stack frame API
    api_debug.py          # Debugger API (unsafe)
    api_python.py         # Python execution API (unsafe)
    api_lifecycle.py      # IDA-instance lifecycle API (shutdown/exit)
    api_resources.py      # MCP Resources
    registry.py           # Gateway client helpers / multi-instance registration
    proxy/                # stdio-based MCP proxy
      __init__.py         # Proxy module exports
      ida_mcp_proxy.py    # Main entry point (stdio MCP server)
      lifecycle.py        # Proxy-side lifecycle operations
      _http.py            # HTTP helpers for gateway communication
      _state.py           # State management and port validation
      register_tools.py   # Consolidated forwarding tool registration
      http_server.py      # HTTP transport wrapper (reuses ida_mcp_proxy.server)
  mcp.json                # MCP client configuration (both modes)
  roadmap.md              # Phased plan for reducing py_eval dependence
  README.md               # README
  requirements.txt        # fastmcp dependencies
```

## Startup Steps

1. Copy `ida_mcp.py` + `ida_mcp` folder to IDA's `plugins/`.
2. Open a target binary and wait for initial analysis.
3. Start the plugin manually from IDA, or call `open_in_ida` from the proxy.
4. On startup, the instance:
   * selects a free instance port starting from `10000`
   * serves MCP over `http://127.0.0.1:<instance_port>/mcp/`
   * ensures the standalone gateway daemon is reachable on `127.0.0.1:11338`
   * registers itself with the gateway's internal API at `http://127.0.0.1:11338/internal`
5. Trigger the plugin again to stop the instance server and deregister it.

Closing an IDA instance only deregisters that instance. The standalone gateway keeps running and can accept later instances.

`open_in_ida` is a proxy-side lifecycle tool. It launches the IDA binary resolved from `IDA_PATH` or `config.conf` (`ida_path`) and sets `IDA_MCP_AUTO_START=1` so the plugin comes up automatically. It keeps IDA in normal interactive GUI mode by default; if you want batch/autonomous startup, pass `-A` explicitly in `extra_args`.

IDA-MCP is WSL-compatible. In a WSL environment, `open_in_ida` can launch a Windows IDA installation from Linux-side tooling, and it automatically converts the target file path into a Windows path before spawning IDA.

## Transport Overview

There are two gateway-facing endpoints plus one per-instance endpoint in this project, and the distinction matters:

* `127.0.0.1:11338/internal` - internal gateway HTTP API used for instance registry and tool forwarding
* `127.0.0.1:11338/mcp` - client-facing HTTP MCP proxy exposed by the same standalone gateway process
* `127.0.0.1:<instance_port>/mcp/` - direct MCP endpoint owned by one specific IDA instance

The bundled `mcp.json` and the current default config are centered on the HTTP proxy on port `11338`.

## Proxy Usage

### Transport Modes

| Mode | Description | Configuration |
|------|-------------|---------------|
| **HTTP proxy** (recommended) | Connects to the standalone gateway MCP proxy on `11338` | Only requires `url` |
| **stdio proxy** | MCP client launches `ida_mcp/proxy/ida_mcp_proxy.py` as a subprocess | Requires `command` and `args` |
| **Direct instance HTTP** | Connects straight to one IDA instance, mainly useful for `ida://` resources | Requires the selected instance port |

**Proxy Tools:**

| Category | Tools |
|----------|-------|
| Management | `check_connection`, `list_instances`, `select_instance` |
| Lifecycle | `open_in_ida`, `close_ida` |
| Core | `list_functions`, `get_metadata`, `list_strings`, `list_globals`, `list_local_types`, `get_entry_points`, `get_function`, `list_imports`, `list_exports`, `list_segments`, `get_cursor` |
| Analysis | `decompile`, `disasm`, `linear_disasm`, `xrefs_to`, `xrefs_from`, `xrefs_to_field`, `find_bytes`, `get_basic_blocks` |
| Modeling | `create_function`, `delete_function`, `make_code`, `undefine_items`, `make_data`, `make_string`, `create_array` |
| Modify | `set_comment`, `rename_function`, `rename_global_variable`, `rename_local_variable`, `patch_bytes` |
| Memory | `get_bytes`, `get_u8`, `get_u16`, `get_u32`, `get_u64`, `get_string` |
| Types | `set_function_prototype`, `set_local_variable_type`, `set_global_variable_type`, `declare_type`, `list_structs`, `get_struct_info` |
| Stack | `stack_frame`, `declare_stack`, `delete_stack` |
| Python | `py_eval` |
| Debug | `dbg_start`, `dbg_continue`, `dbg_step_into`, `dbg_step_over`, `dbg_regs`, `dbg_add_bp`, `dbg_delete_bp`, ... |

You can use it on Codex / Claude Code / LangChain / Cursor / VSCode / etc - any MCP client.

Parameter schema is shared between the proxy and direct instance tools. For example, `rename_function` uses `address` on both sides and accepts either a symbol name or a numeric address. For multi-instance usage, prefer passing `port` explicitly on proxy tools instead of relying on a process-wide selected instance.

### Configuration File

Edit `ida_mcp/config.conf` to customize settings:

```ini
enable_stdio = false
enable_http = true
enable_unsafe = true

# coordinator_port = 11337  # legacy compatibility key; internal API now shares http_port

# HTTP proxy settings
# http_host = "127.0.0.1"
# http_port = 11338
# http_path = "/mcp"

# IDA instance settings
# ida_default_port = 10000
# ida_path = "C:\\Path\\To\\ida.exe"

# General settings
# request_timeout = 30
# debug = false
```

Notes:

* The gateway host and direct instance host are fixed to `127.0.0.1` for client connections in code.
* `IDA_PATH` overrides `ida_path` from `config.conf`.
* `IDA_MCP_ENABLE_UNSAFE=1|0` overrides `enable_unsafe` from `config.conf`.
* `open_in_ida` no longer accepts an `ida_path` tool argument; configure the IDA executable through `IDA_PATH` or `config.conf`.
* WSL is supported: you can run the tooling inside WSL and still launch a Windows IDA binary through `open_in_ida`.
* If both `enable_stdio` and `enable_http` are disabled, the plugin will not start the gateway/transport stack.

### Method 1: HTTP Proxy Mode (Recommended)

When the standalone gateway is running and HTTP proxying is enabled, the client only needs the proxy URL.

**Claude / Cherry Studio / Cursor example:**

```json
{
  "mcpServers": {
    "ida-mcp": {
      "url": "http://127.0.0.1:11338/mcp"
    }
  }
}
```

**LangChain example:**

```json
{
  "mcpServers": {
    "ida-mcp": {
      "transport": "streamable-http",
      "url": "http://127.0.0.1:11338/mcp"
    }
  }
}
```

**VSCode example:**

```json
{
  "servers": {
    "ida-mcp": {
      "url": "http://127.0.0.1:11338/mcp"
    }
  }
}
```

### Method 2: stdio Proxy Mode

The client launches the proxy as a subprocess. This proxy talks to the standalone gateway on `11338` and exposes the same proxy-side tools as HTTP mode.

**Claude / Cherry Studio / Cursor example:**

```json
{
  "mcpServers": {
    "ida-mcp-proxy": {
      "command": "path of python (IDA's python)",
      "args": ["path of ida_mcp/proxy/ida_mcp_proxy.py"]
    }
  }
}
```

**VSCode example:**

```json
{
  "servers": {
    "ida-mcp-proxy": {
      "command": "path of python (IDA's python)",
      "args": ["path of ida_mcp/proxy/ida_mcp_proxy.py"]
    }
  }
}
```

## Resources

`ida://` resources are registered on the direct IDA instance server, not on the proxy server. That means:

* `list_resources` / `read_resource` must connect to `http://127.0.0.1:<instance_port>/mcp/`
* the HTTP proxy on `11338` forwards tools, but does not forward resources
* resource payloads are returned as JSON text content, so MCP clients typically need to parse the resource text as JSON
* resources are read-only and cover stable context views, not the full tool surface

Resource payload conventions:

* list resources return JSON objects shaped like `{kind, count, items}`
* detail resources return JSON objects shaped like `{kind, address|name, ...}`
* resource errors return `{error: {code, message, details?}}`
* the old pattern-style resource URIs such as `ida://functions/{pattern}` were removed in favor of canonical list/detail URIs

Typical flow:

1. Call `list_instances` via the proxy to find the target instance port.
2. Open a direct MCP client to `http://127.0.0.1:<instance_port>/mcp/`.
3. Use `list_resources` / `read_resource("ida://...")` there.

## Automated Install

Run:

```bash
python install.py
```

The installer:

* discovers the local IDA installation on Windows, Linux, or macOS
* uses IDA's bundled Python to run `pip install -r requirements.txt`
* copies `ida_mcp.py` and `ida_mcp/` into IDA's `plugins/` directory
* interactively generates the destination `ida_mcp/config.conf`

Use `python install.py --dry-run` to verify detection and configuration choices without making changes.

## Command Helper

Use `command.py` for local control, scripting, and CI-friendly access:

```bash
python command.py gateway start
python command.py gateway restart
python command.py gateway status
python command.py ida list
python command.py ida open ./test/samples/simple.exe
python command.py ida select --port 10000
python command.py tool call get_metadata --port 10000
python command.py resource read ida://functions --port 10000
python command.py gateway stop --force
```

Add `--json` to any command when you need machine-readable output. Human-readable output is the default.

## Dependencies

Need to install using IDA's Python environment:

```bash
python -m pip install -r requirements.txt
```

## Development

It's not about having many tools, but about having precise ones; the power of the API is what truly matters. Additionally, the tools should be comprehensive, and the more tools there are, the more obstacles there are for the model to call them. If certain tools can be achieved through existing ones, then those tools are unnecessary. What I need are the missing tools—the ones that existing tools cannot accomplish.

## Future Plans

Add UI interface, support internal model calls, add multi-agent A2A automated reverse engineering functionality after langchain officially updates to 1.0.0.

