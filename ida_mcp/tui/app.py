"""Interactive r2-style terminal UI over the IDA-MCP bridge.

A textual app, host-side: scrollable disassembly/pseudocode viewer,
searchable function sidebar, seek and xref navigation, rename and
comments — everything rendered from the existing tool catalog via
``bridge_client``. textual ships as a default dependency; nothing here is
loaded inside a worker.

Usage (via idamcp-hub):
    idamcp-hub tui <path>              # open (or attach) and browse
    idamcp-hub tui <path> --keep-open  # leave the worker alive on exit
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .. import bridge_client

try:
    from textual.app import App, ComposeResult
    from textual.widgets import Footer, Header, Input, RichLog, Static, ListView, ListItem, Label
except ImportError as exc:  # pragma: no cover - default dependency
    raise ImportError(
        "the interactive TUI needs textual; reinstall idamcp-hub "
        "(pip install --upgrade idamcp-hub or uv tool upgrade idamcp-hub)"
    ) from exc


HELP_TEXT = """\
// keys (main pane focused)
//   g        goto: function name or 0xADDR (same as the sidebar filter)
//   p        toggle disasm / pseudocode for the current function
//   x        xrefs to the current function
//   f        follow the first xref
//   G        call graph of the current function
//   b        ASCII CFG of the current function
//   n        rename the current function
//   m        comment at the current function entry
//   r        refresh sidebar (re-read function list)
//   ESC      back to the current function view
//   q        quit (worker is closed if this TUI was its last user)
// sidebar: type to filter by name, UP/DOWN to walk, ENTER to open
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

    def functions(self, pattern: Optional[str] = None, count: int = 1000) -> Dict[str, Any]:
        """Query functions; returns {"total": int, "items": [entry...]}.

        The bridge's list_functions supports server-side name filtering and
        reports the true total, so the sidebar never needs to page through
        everything on huge binaries.
        """
        params: Dict[str, Any] = {"offset": 0, "count": count}
        if pattern:
            params["pattern"] = pattern
        result = self.call("list_functions", params)
        if isinstance(result, dict) and result.get("error"):
            return {"total": 0, "items": [], "error": result["error"]}
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
        total = result.get("total", len(entries)) if isinstance(result, dict) else len(entries)
        # Real functions first: extern/import thunks (dots, __libc__, etc.)
        # clutter firmware lists where they vastly outnumber real code.
        entries.sort(key=lambda fn: (fn["name"].startswith(".") or fn["name"].startswith("__"), fn["start_ea"]))
        return {"total": int(total or 0), "items": entries}

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
                    parts.append(f"xrefs to {item.get('address')}: {len(refs)}")
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


class FunctionSidebar:
    """Searchable function list backed by server-side list_function filtering.

    Big binaries hold tens of thousands of functions; pulling them all
    (even in pages) freezes the UI and the 1000-per-call cap silently
    hides anything past the first page. The bridge already supports a
    server-side ``pattern`` filter, so the sidebar asks the worker to
    narrow instead: empty filter shows the first page plus the true total;
    typing re-queries with the pattern. Local resolution (seek by address
    inside a listed function) works off whatever is currently listed.
    """

    PAGE = 1000

    def __init__(self, ui: BridgeUI):
        self.ui = ui
        self.filtered: List[Dict[str, Any]] = []
        self.total = 0
        self.current_pattern: Optional[str] = None

    def reload(self, pattern: Optional[str] = None) -> int:
        self.current_pattern = pattern
        result = self.ui.functions(pattern=pattern, count=self.PAGE)
        self.total = result.get("total", 0)
        self.filtered = result.get("items", [])
        return len(self.filtered)

    def apply_filter(self, text: str) -> List[Dict[str, Any]]:
        text = text.strip()
        if not text:
            return self.reload(None) and self.filtered
        # hex-address input narrows locally against the shown page; names
        # go to the server so renamed functions are always findable.
        try:
            int(text, 16)
        except ValueError:
            return self.reload(text) and self.filtered
        return self.reload(text) and self.filtered

    def resolve(self, query: str) -> Optional[Dict[str, Any]]:
        """Resolve a seek target: listed name, listed prefix, or any
        address — the address case asks the server which function
        contains it, so it works even for functions never listed."""
        q = query.strip()
        # exact or prefix among the currently listed items first (fast)
        for fn in self.filtered:
            if fn["name"] == q:
                return fn
        prefix = [fn for fn in self.filtered if fn["name"].lower().startswith(q.lower())]
        if len(prefix) == 1:
            return prefix[0]
        # address (with or without 0x): find its containing function
        addr: Optional[int]
        try:
            addr = int(q, 16) if q.lower().startswith("0x") else int(q)
        except ValueError:
            addr = None
        if addr is None:
            return None
        for fn in self.filtered:
            if fn["start_ea"] <= addr < fn["end_ea"]:
                return fn
        result = self.ui.call("get_function_signature", {"addr": f"0x{addr:x}"})
        if isinstance(result, dict) and not result.get("error"):
            start = result.get("start_ea")
            try:
                start_ea = int(str(start), 16) if start is not None else None
            except ValueError:
                start_ea = None
            if start_ea is None and result.get("function"):
                # signature tool reports the name; seek by it directly
                return {"start_ea": addr, "end_ea": addr + 1, "name": result["function"]}
            if start_ea is not None:
                return {
                    "start_ea": start_ea,
                    "end_ea": start_ea + 1,
                    "name": result.get("function") or f"0x{addr:x}",
                }
        return None


class IDATuiApp(App):
    """r2-style browsing over one worker instance."""

    # q exits and closes the worker when this TUI was its last user;
    # ctrl+q force-quits the app without closing (--keep-open semantics).
    BINDINGS = [
        ("ctrl+q", "quit", "Quit (keep worker)"),
        ("q", "close_and_quit", "Quit (close worker)"),
        ("g", "seek", "Goto"),
        ("x", "xrefs", "Xrefs"),
        ("p", "toggle_pane", "Disasm/Pseudo"),
        ("f", "follow", "Follow xref"),
        ("n", "rename", "Rename"),
        ("m", "comment", "Comment"),
        ("G", "callgraph", "Call graph"),
        ("b", "cfg", "CFG"),
        ("r", "reload_sidebar", "Refresh list"),
    ]
    CSS = """
    #body { height: 1fr; }
    #sidebar { width: 40; border-right: solid $primary; }
    #sidebar-column { height: 1fr; }
    #sidebar-filter { dock: top; height: 3; border-bottom: solid $primary; }
    #sidebar-list { height: 1fr; }
    #main { width: 1fr; }
    #statusbar { dock: bottom; height: 1; background: $panel; }
    #prompt { dock: bottom; height: 3; border-top: solid $primary; }
    """

    def __init__(self, ui: BridgeUI, *, keep_open: bool = False):
        super().__init__()
        self.ui = ui
        self.sidebar = FunctionSidebar(ui)
        self.current_fn: Optional[Dict[str, Any]] = None
        self.mode = "disasm"
        self.keep_open = keep_open

    # -- layout --------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Static(id="body"):
            with Static(id="sidebar"):
                yield Input(placeholder="filter functions...", id="sidebar-filter")
                yield ListView(id="sidebar-list")
            yield RichLog(id="main", highlight=False, markup=False, wrap=True)
        yield Static("", id="statusbar")
        yield Input(placeholder="command line (g to focus)", id="prompt")
        yield Footer()

    def on_mount(self) -> None:
        self.render_main(HELP_TEXT)
        self.update_status("loading function list...")
        # Initial load off the UI thread: huge binaries take ~1s for the
        # first page; blocking here makes the app look frozen on startup.
        import threading

        def work() -> None:
            from functools import partial

            shown = self.sidebar.reload()
            self.call_later(partial(self._apply_initial_sidebar, shown))

        threading.Thread(target=work, daemon=True, name="IDA-MCP-TuiInit").start()

    def _apply_initial_sidebar(self, shown: int) -> None:
        self.rebuild_sidebar()
        self.update_status(
            f"{shown} shown / {self.sidebar.total} functions — "
            "type in the sidebar to search, g to seek"
        )

    # How many rows the sidebar renders at once. Building 1000 ListItems
    # per keystroke is itself a visible stall; a visible window plus the
    # count hint keeps scrolling fast and the list informative.
    _SIDEBAR_ROWS = 200

    def rebuild_sidebar(self) -> None:
        listing = self.query_one("#sidebar-list", ListView)
        listing.clear()
        for fn in self.sidebar.filtered[: self._SIDEBAR_ROWS]:
            listing.append(
                ListItem(Label(f"0x{fn['start_ea']:X}  {fn['name']}"), name=fn["name"])
            )
        extra = self.sidebar.total - len(self.sidebar.filtered)
        if len(self.sidebar.filtered) >= self._SIDEBAR_ROWS:
            listing.append(ListItem(Label(f"... showing {self._SIDEBAR_ROWS} of {self.sidebar.total} — keep typing to narrow")))
        elif extra > 0:
            listing.append(ListItem(Label(f"... {extra} more — keep typing to narrow")))

    # -- rendering ------------------------------------------------------------

    def render_main(self, text: str) -> None:
        log = self.query_one("#main", RichLog)
        log.clear()
        log.write(text)

    def update_status(self, text: str) -> None:
        ident = self.ui.instance_id or "?"
        current = self.current_fn["name"] if self.current_fn else "-"
        self.query_one("#statusbar", Static).update(
            f"[{ident}] {current} ({self.mode})  |  {text}"
        )

    def show_function(self, fn: Dict[str, Any]) -> None:
        """Open a function in the main pane (fetches off the UI thread)."""
        self.current_fn = fn
        self.update_status(f"loading {fn['name']}...")
        import threading
        from functools import partial

        target = fn["name"]
        mode = self.mode

        def work() -> None:
            text = (
                self.ui.disasm(target) if mode == "disasm" else self.ui.decompile(target)
            )
            self.call_later(partial(self._apply_show, fn, text))

        threading.Thread(target=work, daemon=True, name="IDA-MCP-TuiLoad").start()

    def _apply_show(self, fn: Dict[str, Any], text: str) -> None:
        # Only apply if the user hasn't moved on to another function.
        if self.current_fn is not fn:
            return
        self.render_main(text)
        self.update_status("ok")

    # -- sidebar interaction ----------------------------------------------------

    _FILTER_DEBOUNCE = 0.25

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "sidebar-filter":
            return
        # Debounced server-side search: every keystroke is a ~1s bridge
        # round-trip on huge binaries; running it synchronously freezes the
        # UI, so debounce, then query off-thread and rebuild on arrival.
        value = event.value
        self._filter_seq = getattr(self, "_filter_seq", 0) + 1
        seq = self._filter_seq
        self.update_status(f"searching '{value}'...")
        self.set_timer(self._FILTER_DEBOUNCE, lambda: self._run_filter(seq, value))

    def _run_filter(self, seq: int, value: str) -> None:
        if seq != getattr(self, "_filter_seq", 0):
            return  # superseded by a newer keystroke
        import threading
        from functools import partial

        def work() -> None:
            self.sidebar.apply_filter(value)
            self.call_later(partial(self._apply_filter_result, seq))

        threading.Thread(target=work, daemon=True, name="IDA-MCP-TuiFilter").start()

    def _apply_filter_result(self, seq: int) -> None:
        if seq != getattr(self, "_filter_seq", 0):
            return
        self.rebuild_sidebar()
        shown = len(self.sidebar.filtered)
        self.update_status(
            f"{shown} shown / {self.sidebar.total} total — ENTER on a match opens it"
        )

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        # textual posts ListView.Selected; the old handler name
        # (on_list_item_selected) never fired, so clicking/entering a
        # function did nothing.
        index = event.list_view.index if event.list_view.index is not None else 0
        items = self.sidebar.filtered
        if 0 <= index < len(items):
            self.show_function(items[index])
            self.set_focus(self.query_one("#main", RichLog))

    # -- actions -----------------------------------------------------------------

    def action_toggle_pane(self) -> None:
        self.mode = "pseudo" if self.mode == "disasm" else "disasm"
        if self.current_fn:
            self.show_function(self.current_fn)

    def action_seek(self) -> None:
        prompt = self.query_one("#prompt", Input)
        prompt.placeholder = "goto: function name or 0xADDR"
        prompt.value = ""
        self.set_focus(prompt)

    def action_reload_sidebar(self) -> None:
        shown = self.sidebar.reload(self.sidebar.current_pattern)
        self.rebuild_sidebar()
        self.update_status(f"{shown} shown / {self.sidebar.total} total — list refreshed")

    def action_xrefs(self) -> None:
        if not self.current_fn:
            return
        self.render_main(self.ui.xrefs_to(self.current_fn["name"]))
        self.update_status("xrefs (ESC/g to go back)")

    def action_follow(self) -> None:
        if not self.current_fn:
            return
        xrefs = self.ui.xrefs_to(self.current_fn["name"])
        m = re.search(r"from (0x[0-9A-Fa-f]+)", str(xrefs))
        if not m:
            self.update_status("no resolvable xref")
            return
        fn = self.sidebar.resolve(m.group(1))
        if fn:
            self.show_function(fn)
        else:
            self.update_status(f"xref {m.group(1)} outside known functions")

    def action_rename(self) -> None:
        if not self.current_fn:
            return
        prompt = self.query_one("#prompt", Input)
        prompt.placeholder = f"rename {self.current_fn['name']} to:"
        prompt.value = ""
        self._prompt_mode = "rename"
        self.set_focus(prompt)

    def action_comment(self) -> None:
        if not self.current_fn:
            return
        prompt = self.query_one("#prompt", Input)
        prompt.placeholder = f"comment at {self.current_fn['name']}:"
        prompt.value = ""
        self._prompt_mode = "comment"
        self.set_focus(prompt)

    def action_callgraph(self) -> None:
        if not self.current_fn:
            return
        self.render_main(self.ui.callgraph(self.current_fn["name"]))
        self.update_status("call graph (ESC/g to go back)")

    def action_cfg(self) -> None:
        if not self.current_fn:
            return
        self.render_main(self.ui.cfg(self.current_fn["name"]))
        self.update_status("cfg (ESC/g to go back)")

    async def action_close_and_quit(self) -> None:
        if not self.keep_open:
            from .. import lifecycle

            try:
                lifecycle.close_database(
                    self.ui.entry, terminate=False, save=True
                )
            except Exception:  # noqa: BLE001 - shutdown is best effort
                pass
        self.exit()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        value = str(event.value).strip()
        prompt = self.query_one("#prompt", Input)
        prompt.value = ""
        if not value:
            self.set_focus(self.query_one("#main", RichLog))
            return
        mode = getattr(self, "_prompt_mode", None)
        self._prompt_mode = None
        if mode == "rename" and self.current_fn:
            old_name = self.current_fn["name"]
            self.render_main(self.ui.rename(old_name, value))
            # refresh immediately so the new name is searchable/visible
            self.current_fn = dict(self.current_fn, name=value)
            self.sidebar.reload(self.sidebar.current_pattern)
            self.rebuild_sidebar()
            self.update_status(f"renamed {old_name} -> {value}")
        elif mode == "comment" and self.current_fn:
            self.render_main(self.ui.set_comment(self.current_fn["name"], value))
            self.update_status("commented")
        else:
            fn = self.sidebar.resolve(value)
            if fn:
                self.show_function(fn)
                self.set_focus(self.query_one("#main", RichLog))
            else:
                self.update_status(f"no function matches {value!r}")


def run_tui(path: str, *, keep_open: bool = False, open_timeout: float = 300.0) -> int:
    """Open (or attach) the target and run the interactive app.

    Unless keep_open is set, quitting (q) saves and closes the worker when
    this TUI is its last user; ctrl+q leaves the worker for other clients.
    """
    import sys

    from .. import lifecycle

    result = lifecycle.open_database(str(path), wait_for_analysis=True, timeout=open_timeout)
    if isinstance(result, dict) and result.get("error"):
        print(f"error: {result['error']}", file=sys.stderr)
        return 1
    entry = result.get("instance") or {}
    IDATuiApp(BridgeUI(entry), keep_open=keep_open).run()
    return 0
