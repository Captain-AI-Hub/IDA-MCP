"""Interactive r2-style terminal UI over the IDA-MCP bridge.

A small textual app, host-side: disassembly/pseudocode panes, function
sidebar, seek and xref navigation, rename and comments — everything rendered
from the existing tool catalog via ``bridge_client``. Requires
textual ships as a default dependency; never loaded inside a worker.

Usage (via idamcp-hub):
    idamcp-hub tui <path>          # open (or attach) and browse
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .. import bridge_client

try:
    from textual.app import App, ComposeResult
    from textual.widgets import Footer, Header, Input, Static, Tree
except ImportError as exc:  # pragma: no cover - optional dependency
    raise ImportError(
        "the interactive TUI needs textual; reinstall idamcp-hub "
        "(pip install --upgrade idamcp-hub or uv tool upgrade idamcp-hub)"
    ) from exc


HELP_TEXT = """\
// keys
//   g        goto address or name (seek)
//   x        xrefs to current address
//   p        toggle disasm / pseudocode pane
//   f        follow xref under cursor (if it resolves)
//   n        rename function under cursor
//   m        set comment at cursor address
//   G        call graph of current function
//   b        ASCII CFG of current function
//   TAB / Shift+TAB  cycle focus
//   q        quit
"""


class BridgeUI:
    """Thin error-tolerant wrapper over bridge_client for the app."""

    def __init__(self, entry: Dict[str, Any]):
        self.entry = entry
        self.instance_id = entry.get("instance_id")

    def call(self, tool: str, params: Optional[dict] = None, timeout: float = 120.0) -> Any:
        try:
            return bridge_client.call_tool(
                self.entry, tool, params or {}, timeout=timeout
            )
        except Exception as exc:  # noqa: BLE001 - UI boundary
            described = bridge_client.describe_error(exc)
            err = described.get("error", {})
            return {"error": err.get("message", str(exc))}

    def functions(self) -> List[Dict[str, Any]]:
        result = self.call("list_functions", {"offset": 0, "count": 1000})
        items = str(result.get("items", "")) if isinstance(result, dict) else ""
        entries = []
        for line in items.splitlines():
            m = re.match(r"^(0x[0-9A-Fa-f]+)-(0x[0-9A-Fa-f]+)\s+(.+)$", line.strip())
            if m:
                entries.append(
                    {
                        "start_ea": int(m.group(1), 16),
                        "end_ea": int(m.group(2), 16),
                        "name": m.group(3).strip(),
                    }
                )
        return entries

    def strings(self) -> List[str]:
        result = self.call("list_strings", {"offset": 0, "count": 200})
        items = str(result.get("items", "")) if isinstance(result, dict) else ""
        return [line for line in items.splitlines() if line.strip()]

    def disasm(self, target: str) -> str:
        result = self.call("disasm", {"addr": target})
        if isinstance(result, list):
            parts = []
            for item in result:
                if isinstance(item, dict):
                    if item.get("error"):
                        parts.append(f"// disassembly failed: {item['error']}")
                    else:
                        parts.append(str(item.get("disasm", "")))
            return "\n".join(parts)
        if isinstance(result, dict) and result.get("error"):
            return f"// disassembly failed: {result['error']}"
        return "// no output"

    def decompile(self, target: str) -> str:
        result = self.call("decompile", {"addr": target})
        if isinstance(result, dict) and result.get("error"):
            return f"// decompile failed: {result['error']}"
        return str(result) if result else "// decompilation unavailable"

    def xrefs_to(self, target: str) -> str:
        result = self.call("xrefs_to", {"addr": target})
        if isinstance(result, list):
            parts = []
            for item in result:
                if isinstance(item, dict):
                    refs = item.get("xrefs") or []
                    parts.append(
                        f"xrefs to {item.get('address')}: {len(refs)}"
                    )
                    for ref in refs:
                        if isinstance(ref, dict):
                            parts.append(
                                f"  from {ref.get('frm')}  type={ref.get('type')}"
                                f"  code={bool(ref.get('iscode'))}"
                            )
            return "\n".join(parts)
        return "// no xrefs"

    def rename(self, address: str, new_name: str) -> str:
        result = self.call("rename_function", {"address": address, "new_name": new_name})
        if isinstance(result, dict) and result.get("error"):
            return f"// rename failed: {result['error']}"
        return f"// renamed {address} -> {new_name}"

    def set_comment(self, address: str, comment: str) -> str:
        result = self.call(
            "set_comment", {"items": [{"address": address, "comment": comment}]}
        )
        if isinstance(result, list) and result and isinstance(result[0], dict):
            if result[0].get("error"):
                return f"// comment failed: {result[0]['error']}"
        return f"// comment set at {address}"

    def callgraph(self, target: str) -> str:
        result = self.call("callgraph", {"roots": target, "max_depth": 1, "max_nodes": 50})
        if isinstance(result, dict) and result.get("error"):
            return f"// callgraph failed: {result['error']}"
        nodes = str(result.get("nodes", "")).replace("\n", "\n  ")
        edges = str(result.get("edges", "")).replace("\n", "\n  ")
        return f"call graph of {target} ({result.get('node_count')} nodes):\n  {nodes}\n  edges:\n  {edges}"

    def cfg(self, target: str) -> str:
        result = self.call("get_basic_blocks", {"addr": target})
        if isinstance(result, dict) and result.get("error"):
            return f"// cfg failed: {result['error']}"
        blocks = [line.strip() for line in str(result.get("blocks", "")).splitlines() if line.strip()]
        if not blocks:
            return "// no basic blocks"
        # Render blocks as an ASCII chain; type=2 marks a normal block,
        # anything else (retn/until) is a terminal box.
        lines = [f"CFG of {result.get('function')}  ({len(blocks)} blocks)"]
        for i, block in enumerate(blocks):
            m = re.match(r"^(0x[0-9A-Fa-f]+)-(0x[0-9A-Fa-f]+)\s+\[(.*)\]$", block)
            if m:
                start, end, meta = m.groups()
                terminal = "retn" in meta or "until" in meta
                lines.append(f"+{'[T]' if terminal else '[ ]'}--------------------------------+")
                lines.append(f"| blk {i}: {start}-{end}  {meta}")
                lines.append("+" + "-" * 34 + "+")
                if i < len(blocks) - 1:
                    lines.append("        |")
                    lines.append("        v")
        return "\n".join(lines)


class IDATuiApp(App):
    """r2-style browsing over one worker instance."""

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("g", "seek", "Goto"),
        ("x", "xrefs", "Xrefs"),
        ("p", "toggle_pane", "Disasm/Pseudo"),
        ("f", "follow", "Follow xref"),
        ("n", "rename", "Rename"),
        ("m", "comment", "Comment"),
        ("G", "callgraph", "Call graph"),
        ("b", "cfg", "CFG"),
    ]
    CSS = """
    #sidebar { width: 32; border-right: solid; }
    #main { }
    #statusbar { dock: bottom; height: 1; background: $panel; }
    """

    def __init__(self, ui: BridgeUI):
        super().__init__()
        self.ui = ui
        self.current: str = "entry"
        self.mode = "disasm"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        tree: Tree[None] = Tree("functions", id="sidebar")
        for fn in self.ui.functions()[:500]:
            tree.root.add(
                f"0x{fn['start_ea']:X}  {fn['name']}", data=fn["name"]
            )
        tree.root.expand()
        yield tree
        yield Static("", id="main")
        yield Static("", id="statusbar")
        yield Input(placeholder="target (name or address)", id="prompt")
        yield Footer()

    def on_mount(self) -> None:
        self.render_main(HELP_TEXT)
        self.update_status("ready — g to seek, TAB to cycle panes")

    # -- rendering ---------------------------------------------------------

    def render_main(self, text: str) -> None:
        self.query_one("#main", Static).update(text)

    def update_status(self, text: str) -> None:
        ident = self.ui.instance_id or "?"
        self.query_one("#statusbar", Static).update(
            f"[{ident}] {self.current} ({self.mode})"
            f"  |  {text}"
        )

    def show_target(self, target: str) -> None:
        self.current = target
        if self.mode == "disasm":
            self.render_main(self.ui.disasm(target))
        else:
            self.render_main(self.ui.decompile(target))
        self.update_status("ok")

    # -- actions -------------------------------------------------------------

    def action_toggle_pane(self) -> None:
        self.mode = "pseudo" if self.mode == "disasm" else "disasm"
        self.show_target(self.current)

    def action_seek(self) -> None:
        prompt = self.query_one("#prompt", Input)
        prompt.placeholder = "goto: name or 0xADDR"
        prompt.value = ""
        self.set_focus(prompt)

    def action_xrefs(self) -> None:
        self.render_main(self.ui.xrefs_to(self.current))
        self.update_status("xrefs")

    def action_follow(self) -> None:
        xrefs = self.ui.xrefs_to(self.current)
        m = re.search(r"from (0x[0-9A-Fa-f]+)", str(xrefs))
        if m:
            self.show_target(m.group(1))
        else:
            self.update_status("no resolvable xref")

    # rename/comment reuse the single prompt line: 'n' enters name mode,
    # 'c' enters comment mode; the submitted value applies to self.current.
    def action_rename(self) -> None:
        self._prompt_mode = "rename"
        prompt = self.query_one("#prompt", Input)
        prompt.placeholder = f"rename {self.current} to:"
        prompt.value = ""
        self.set_focus(prompt)

    def action_comment(self) -> None:
        self._prompt_mode = "comment"
        prompt = self.query_one("#prompt", Input)
        prompt.placeholder = f"comment at {self.current}:"
        prompt.value = ""
        self.set_focus(prompt)

    def action_callgraph(self) -> None:
        self.render_main(self.ui.callgraph(self.current))
        self.update_status("call graph")

    def action_cfg(self) -> None:
        self.render_main(self.ui.cfg(self.current))
        self.update_status("cfg")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        value = str(event.value).strip()
        prompt = self.query_one("#prompt", Input)
        prompt.value = ""
        self.set_focus(self.query_one("#main", Static))
        mode = getattr(self, "_prompt_mode", None)
        self._prompt_mode = None
        if not value:
            return
        if mode == "rename":
            self.render_main(self.ui.rename(self.current, value))
            self.update_status("renamed")
        elif mode == "comment":
            self.render_main(self.ui.set_comment(self.current, value))
            self.update_status("commented")
        else:
            self.show_target(value)


def run_tui(path: str, *, open_timeout: float = 300.0) -> int:
    """Open (or attach) the target and run the interactive app."""
    import sys

    from .. import lifecycle

    result = lifecycle.open_database(str(path), wait_for_analysis=True, timeout=open_timeout)
    if isinstance(result, dict) and result.get("error"):
        print(f"error: {result['error']}", file=sys.stderr)
        return 1
    entry = result.get("instance") or {}
    IDATuiApp(BridgeUI(entry)).run()
    return 0

    def __init__(self, label: str):
        self.label = label