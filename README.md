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
- Loopback gateway requests (`127.0.0.1` / `::1`) do not require `gateway_token`; non-loopback requests require a matching token and fail closed when it is empty.
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

The wrapper asks for or detects the IDA executable, probes that installation's
`idat` runtime, and falls back to parsing `idapyswitch` only when the runtime
probe is unavailable. It then sets `HCLI_CURRENT_IDA_PYTHON_EXE` while launching
HCLI, so dependency installation cannot fall back to HCLI's/system Python. The
wrapper uses the detected interpreter internally; the direct HCLI install does
not prompt for or overwrite `ida_python`:

```text
IDAPython interpreter path (C:\Users\name\AppData\Local\Python\pythoncore-3.12-64\python.exe)
```

Specify IDA explicitly when automatic discovery selects the wrong installation:

```bash
python scripts/hcli_install.py dist/main.zip --ida D:\IDAPro9.4\ida.exe
```

On Linux, the wrapper also reads `$IDAUSR/ida-config.json` (default:
`~/.idapro/ida-config.json`) and searches common `/opt`, home, and local
application paths. To use HCLI directly while forcing a known IDAPython
interpreter, set the override explicitly:

```bash
HCLI_CURRENT_IDA_PYTHON_EXE=/path/to/idapython/bin/python3 \
  hcli plugin install https://github.com/Captain-AI-Hub/IDA-MCP/releases/latest/download/main.zip
```

If IDAPython cannot be detected, `scripts/hcli_install.py` stops instead of
allowing dependency installation through the system Python. The wrapper also
generates a per-install token and prints a copy/paste-ready `mcp.json`. This does
not apply to the direct URL form: `hcli plugin install ...` does not execute
IDA-MCP, so it cannot generate or print a machine-specific token during
installation.

For plugin development, use `hcli plugin install --editable .` so source changes
are picked up without reinstalling. HCLI installs the plugin files and Python
runtime dependencies declared in `ida-plugin.json`. Dependency resolution can
take a while on the first installation and may produce little output; wait for
the final `Installed plugin` message.

Starting with v0.6.3, HCLI prompts for the IDA executable, IDAPython
interpreter, automatic instance startup, gateway host/port/path, autonomous
launch mode, unsafe-tool policy, request timeout, and debug logging. The
IDAPython default remains `auto`, but the prompt is retained because detection
can be wrong for non-standard IDA layouts. `auto_start` is also prompted and
defaults to `No`. The hidden gateway lifecycle action defaults to `idle`, so a
fresh installation performs no server startup unless requested.

## Get the gateway token and configure an MCP client

`hcli plugin install` only installs the plugin metadata, files, and Python
dependencies. It does not load IDA-MCP, so the install command cannot generate
or print the machine-specific gateway token.

### 1. Generate the token on the first IDA launch

After installation:

1. Start IDA and open a database.
2. Wait for IDA-MCP to load.
3. On its first load, IDA-MCP generates a random gateway token and shows it in
   the IDA output window and, in interactive mode, a dialog.
4. Copy the displayed token and the generated MCP client configuration.

Retrieve a previously generated token with:

```bash
hcli plugin config IDA-MCP get gateway_token
```

If this command returns `__AUTO_GENERATE_GATEWAY_TOKEN__`, IDA-MCP has not
completed first-launch initialization, or it could not write to the HCLI
settings store. Start IDA and check the IDA output window. If IDA-MCP reports
that it saved the token to `ida_mcp/config.conf`, use the token displayed in IDA
or read it from that installed plugin configuration file.

To set your own token, use a random value of at least 20 characters:

```bash
hcli plugin config IDA-MCP set gateway_token YOUR_RANDOM_TOKEN
```

Do not commit a real gateway token to a repository or paste it into public logs.

### 2. Start IDA-MCP when automatic startup is disabled

`auto_start` defaults to `No`. Open the target database and run the IDA-MCP
plugin once from IDA to start its instance server. Start the standalone gateway
with:

```bash
hcli plugin config IDA-MCP set gateway start
```

To enable automatic instance startup later:

```bash
hcli plugin config IDA-MCP set auto_start true
```

The default gateway MCP endpoint is:

```text
http://127.0.0.1:11338/mcp
```

If you changed `http_host`, `http_port`, or `http_path` during installation,
use those values instead.

### 3. Claude Code and Cursor `mcpServers` format

Claude Code project configuration uses `.mcp.json` in the project root. Cursor
uses `.cursor/mcp.json` for a project or `~/.cursor/mcp.json` globally. These
clients use the common top-level `mcpServers` object:

```json
{
  "mcpServers": {
    "ida-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:11338/mcp",
      "headers": {
        "Authorization": "Bearer REPLACE_WITH_GATEWAY_TOKEN"
      }
    }
  }
}
```

IDA-MCP also accepts the following header as an alternative:

```json
{
  "X-IDA-MCP-Token": "REPLACE_WITH_GATEWAY_TOKEN"
}
```

Use one authentication header; `Authorization: Bearer ...` is recommended for
normal HTTP MCP clients.

For Claude Code, avoid storing the token directly in a project `.mcp.json` by
using an environment variable. Claude Code expands `${VAR}` in HTTP URLs and
headers:

```bash
export IDA_MCP_TOKEN='YOUR_GATEWAY_TOKEN'
```

```json
{
  "mcpServers": {
    "ida-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:11338/mcp",
      "headers": {
        "Authorization": "Bearer ${IDA_MCP_TOKEN}"
      }
    }
  }
}
```

The equivalent Claude Code CLI command is:

```bash
claude mcp add --transport http ida-mcp http://127.0.0.1:11338/mcp \
  --header "Authorization: Bearer $IDA_MCP_TOKEN"
```

For Cursor, if environment-variable interpolation is unavailable in the client
version being used, place the literal token only in the personal global file
`~/.cursor/mcp.json`; do not commit that file.

### 4. VS Code `.vscode/mcp.json` format

VS Code uses a top-level `servers` object rather than `mcpServers`. The example
below prompts for the token and stores it in VS Code's input/secret flow instead
of committing it to the workspace file:

```json
{
  "inputs": [
    {
      "id": "ida-mcp-token",
      "type": "promptString",
      "description": "IDA-MCP gateway token",
      "password": true
    }
  ],
  "servers": {
    "ida-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:11338/mcp",
      "headers": {
        "Authorization": "Bearer ${input:ida-mcp-token}"
      }
    }
  }
}
```

### 5. Reset first-launch values

To generate a new token and retry IDAPython detection:

```bash
hcli plugin config IDA-MCP del gateway_token
hcli plugin config IDA-MCP set ida_python auto
```

Restart IDA afterward. IDA-MCP displays the new token, effective gateway URL,
detected IDAPython executable, and a copy/paste-ready MCP configuration.

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

Open a database in IDA and wait for initial analysis. If `auto_start` is
`false`, run the IDA-MCP plugin once from IDA; otherwise its per-instance MCP
server starts automatically.

## HCLI Packaging

`.github/workflows/package-hcli.yml` builds `dist/main.zip` on every push to
`main`, on published Releases, and on manual dispatch. Every run uploads the ZIP
as an Actions artifact. Release-triggered runs also attach `main.zip` to that
Release.

To attach the package to a Release such as `v0.6.3`, push the workflow first and
run the command below. If that Release does not exist, the workflow creates it at
the dispatched commit before uploading `main.zip`:

```bash
gh workflow run package-hcli.yml -f release_tag=v0.6.3
```

The archive deliberately places `ida-plugin.json` at the ZIP root, which is the
layout required for HCLI URL installation.

## Gateway Control Through HCLI

Gateway lifecycle actions use HCLI's existing cross-platform plugin config
command, so no `.cmd`, shell script, PATH modification, or HCLI extension is
required:

```bash
hcli plugin config IDA-MCP set gateway start
hcli plugin config IDA-MCP set gateway stop
hcli plugin config IDA-MCP set gateway restart
```

The `gateway` setting defaults to `idle`, so a fresh installation does not
start the standalone gateway automatically. IDA-MCP resets explicit start, stop,
or restart requests to `idle` before executing them. The command is consumed by
a lightweight watcher in the IDA plugin. If
IDA is not currently running, the action remains stored and is executed the next
time IDA-MCP loads. Start and restart use the configured `request_timeout`.

The standalone `command.py` remains available for complete lifecycle, instance,
tool, and resource operations:

```bash
python ida_mcp/command.py gateway status
python ida_mcp/command.py ida list
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
