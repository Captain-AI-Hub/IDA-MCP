"""Non-interactive dump export (idalib-dump style), host-side.

Walks the target's function list through the bridge and writes assembly /
Hex-Rays pseudocode listings to stdout or files. No TUI framework, no new
dependencies inside workers — this is plain text rendering for humans and
CI over the same tools the MCP catalog exposes.

Usage (via idamcp-hub):
    idamcp-hub dump <path>                    # asm + pseudocode to stdout
    idamcp-hub dump --pseudo-only -f 'parse_.*' <path>
    idamcp-hub dump --asm-only -o dump.txt <path>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import bridge_client, lifecycle


class _Stop(Exception):
    """Internal: error already reported to output; abort the walk."""


class DumpClient:
    """Bridge client wrapper with error-to-exception translation."""

    def __init__(self, entry: Dict[str, Any]):
        self._entry = entry

    def call(self, tool: str, params: Optional[dict] = None, timeout: float = 120.0) -> Any:
        try:
            return bridge_client.call_tool(self._entry, tool, params or {}, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - dump boundary
            described = bridge_client.describe_error(exc)
            raise _Stop(described.get("error", {}).get("message", str(exc))) from exc


def _function_entries(client: DumpClient, name_filter: Optional[str]) -> List[Dict[str, Any]]:
    """Parse list_functions text lines into {start, end, name} records."""
    result = client.call("list_functions", {"offset": 0, "count": 1000})
    entries: List[Dict[str, Any]] = []
    pattern = re.compile(name_filter) if name_filter else None
    for line in str(result.get("items", "")).splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.match(r"^(0x[0-9A-Fa-f]+)-(0x[0-9A-Fa-f]+)\s+(.+)$", line)
        if not match:
            continue
        name = match.group(3).strip()
        if pattern and not pattern.search(name):
            continue
        entries.append(
            {
                "start_ea": int(match.group(1), 16),
                "end_ea": int(match.group(2), 16),
                "name": name,
            }
        )
    return entries


def render_function(
    client: DumpClient,
    entry: Dict[str, Any],
    *,
    asm: bool = True,
    pseudo: bool = True,
) -> str:
    """Render one function's listing header + asm + pseudocode."""
    name = entry.get("name", "?")
    start = entry.get("start_ea", 0)
    end = entry.get("end_ea", 0)
    out: List[str] = [f"// {name}  0x{start:X}-0x{end:X}"]

    if asm:
        result = client.call("disasm", {"addr": name})
        if isinstance(result, list):
            for item in result:
                if isinstance(item, dict) and not item.get("error"):
                    out.append(str(item.get("disasm", "")))
                elif isinstance(item, dict):
                    out.append(f"// disassembly failed: {item.get('error')}")
        elif isinstance(result, dict) and result.get("error"):
            out.append(f"// disassembly failed: {result['error']}")

    if pseudo:
        result = client.call("decompile", {"addr": name})
        text = result if isinstance(result, str) else ""
        if text:
            out.append(text)
        else:
            out.append("// decompilation failed or unavailable")

    return "\n".join(out)


def run_dump(
    path: str,
    *,
    name_filter: Optional[str] = None,
    asm: bool = True,
    pseudo: bool = True,
    output: Optional[str] = None,
    open_timeout: float = 300.0,
) -> int:
    """Open (or attach to) the target and dump listings. Returns exit code."""
    local = str(path)
    result = lifecycle.open_database(local, wait_for_analysis=True, timeout=open_timeout)
    if isinstance(result, dict) and result.get("error"):
        print(f"error: {result['error']}", file=sys.stderr)
        return 1
    entry = result.get("instance") or {}
    client = DumpClient(entry)

    try:
        functions = _function_entries(client, name_filter)
    except _Stop as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not functions:
        print("no functions matched", file=sys.stderr)
        return 1

    chunks: List[str] = []
    failures = 0
    for fn in functions:
        chunk = render_function(client, fn, asm=asm, pseudo=pseudo)
        if "decompilation failed" in chunk or "disassembly failed" in chunk:
            failures += 1
        chunks.append(chunk)

    text = "\n\n".join(chunks) + "\n"
    if output:
        target = Path(output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        print(
            f"dumped {len(functions)} functions to {target} ({failures} failures)",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(text)
    return 0