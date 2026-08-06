# IDA-MCP

IDA-MCP is an IDA Pro plugin that exposes IDA analysis, database modification,
debugger, and lifecycle operations through MCP. Each IDA instance runs a local
FastMCP HTTP server, and a standalone gateway provides a stable
multi-instance MCP endpoint.

## Layout

```text
IDA-MCP/
├── ida_mcp.py          # IDA plugin entry point, exposes PLUGIN_ENTRY()
├── ida-plugin.json     # IDA plugin metadata
├── ida_mcp/            # plugin package, gateway, proxy, tools, resources
├── install.py          # interactive installer
├── test/               # live-IDA pytest suite
├── API.md              # MCP, tool, resource, and internal HTTP contract
├── project.md          # repository map and boundaries
├── roadmap.md          # current direction and milestones
└── requirements.txt    # IDA Python runtime dependencies
```

## Runtime Model

- IDA loads `ida_mcp.py`, which starts `ida_mcp/plugin_runtime.py`.
- Each IDA instance chooses a free port starting at `ida_default_port` and serves MCP at `/mcp/`.
- The standalone gateway listens on `127.0.0.1:11338`, registers instances under `/internal/*`, and exposes the proxy MCP endpoint at `/mcp`.
- Tool registration is decorator based: use `@tool` plus `@idaread` or `@idawrite`.
- Gateway requests require `gateway_token`; an empty token fails closed.
- `py_eval`, `patch_bytes`, `apply_patch`, and `dbg_*` tools are unsafe and gated by `enable_unsafe=false` by default in `ida_mcp/config.conf`.

## Installation

Requirements:

- Python > 3.11

### Install with HCLI

Install the packaged plugin archive attached to the latest GitHub Release:

```bash
hcli plugin install https://github.com/Captain-AI-Hub/IDA-MCP/releases/latest/download/main.zip
```

Alternatively, install from a local checkout with machine-aware path detection:

```bash
git clone https://github.com/Captain-AI-Hub/IDA-MCP.git
cd IDA-MCP
python scripts/package_hcli.py --output dist/main.zip
python scripts/hcli_install.py dist/main.zip
```

The wrapper asks for or detects the IDA executable, runs that installation's
`idapyswitch`, and starts HCLI with a temporary personalized archive. The HCLI
prompt therefore shows the actual interpreter in both the label and default, for
example:

```text
IDAPython interpreter path (C:\Users\name\AppData\Local\Python\pythoncore-3.12-64\python.exe)
```

Specify IDA explicitly when automatic discovery selects the wrong installation:

```bash
python scripts/hcli_install.py dist/main.zip --ida D:\IDAPro9.4\ida.exe
```

For plugin development, use `hcli plugin install --editable .` so source changes
are picked up without reinstalling. HCLI installs the plugin files and Python
runtime dependencies declared in `ida-plugin.json`. Dependency resolution can
take a while on the first installation and may produce little output; wait for
the final `Installed plugin` message.

Starting with v0.6.0, HCLI prompts for the IDA paths, gateway host, port and
path, request timeout, automatic startup, autonomous launch mode, unsafe-tool
policy, and debug logging. A portable Release ZIP has static metadata and cannot
embed a path from the destination machine. Direct URL installation therefore
uses `ida_python=auto` and reports the resolved path on first IDA launch. Use
`scripts/hcli_install.py` when the actual detected path must appear during the
HCLI installation prompts.

The gateway token is not shared in the package and is not requested during a new
installation. On first IDA launch, IDA-MCP generates a random per-machine token,
saves it through `ida-settings`, and displays it once together with the effective
gateway endpoint and detected IDAPython path. To review or change the settings
later, run:

```bash
hcli plugin config IDA-MCP setup
```

Retrieve the generated token later with:

```bash
hcli plugin config IDA-MCP get gateway_token
```

Manually supplied replacement tokens must contain at least 20 characters. Existing
non-empty tokens are preserved during upgrades. To test first-run generation after
upgrading an existing installation, remove the old token and reset Python detection:

```bash
hcli plugin config IDA-MCP del gateway_token
hcli plugin config IDA-MCP set ida_python auto
```

Then restart IDA. The plugin displays the generated token, effective gateway URL,
and detected IDAPython executable once initialization completes.

GitHub's automatically generated `archive/refs/heads/main.zip` source archive is
not an HCLI single-plugin archive. Use the Release asset above or build the
correct archive locally:

```bash
python scripts/package_hcli.py --output dist/main.zip
hcli plugin lint dist/main.zip
python scripts/hcli_install.py dist/main.zip
```

### Install with the interactive installer

Run the interactive installer from the repository root:

```bash
python install.py
```

The installer performs the full setup flow:

1. Locate the IDA installation directory.
2. Locate the IDAPython interpreter used by that IDA installation.
3. Optionally install `requirements.txt` into IDA's Python environment.
4. Copy `ida_mcp.py`, `ida-plugin.json`, and the `ida_mcp/` package into IDA's `plugins/` directory.
5. Review and write `ida_mcp/config.conf`, including an auto-generated gateway token.

For manual installation, copy `ida_mcp.py`, `ida-plugin.json`, and the
`ida_mcp/` directory into IDA's plugin directory, then install dependencies into
IDA's Python environment:

```bash
<ida_python> -m pip install -r requirements.txt
```

Open a database in IDA and wait for initial analysis. The plugin starts its
per-instance MCP server automatically when the gateway is enabled.

## HCLI Packaging

`.github/workflows/package-hcli.yml` builds `dist/main.zip` on every push to
`main`, on published Releases, and on manual dispatch. Every run uploads the ZIP
as an Actions artifact. Release-triggered runs also attach `main.zip` to that
Release.

To attach the package to an already-published Release such as `v0.6.0`, push the
workflow first and run:

```bash
gh workflow run package-hcli.yml -f release_tag=v0.6.0
```

The archive deliberately places `ida-plugin.json` at the ZIP root, which is the
layout required for HCLI URL installation.

## Gateway And CLI

```bash
# Start the standalone gateway
python ida_mcp/command.py gateway start --json

# Status, stop, open IDA, call a tool directly
python ida_mcp/command.py gateway status
python ida_mcp/command.py gateway stop
python ida_mcp/command.py ida open ./target.exe
python ida_mcp/command.py tool call get_metadata --port 10000
```

Default endpoints:

- Gateway MCP proxy: `http://127.0.0.1:11338/mcp`
- Gateway internal API: `http://127.0.0.1:11338/internal/*`
- Direct IDA instance MCP: `http://127.0.0.1:<instance_port>/mcp/`

## Tests

Tests require a running gateway and at least one registered IDA instance.

```bash
python test/test.py
python test/test.py --core --analysis

pytest -m "core or analysis"
pytest -m "not debug"
```

The `debug` marker is excluded by default because it requires an active
debugger. API call logs are written to `.artifacts/api_logs/`.

## Documentation

- `API.md` documents the MCP tools, resources, proxy behavior, and internal HTTP routes.
- `project.md` explains repository responsibilities and module boundaries.
- `roadmap.md` tracks current stabilization work.
