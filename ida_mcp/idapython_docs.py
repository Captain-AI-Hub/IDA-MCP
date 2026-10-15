"""Official IDAPython API documentation lookup.

The in-instance half introspects the live IDAPython runtime (the official
Hex-Rays ``ida_*`` modules shipping with the running IDA) and returns per-
module documentation snapshots through the bridge. The standalone half builds
a BM25 index (name field weighted 2:1 over docstrings, following the approach
used by Hex-Rays' own ida-nexus ``reference`` implementation) and answers
``ida_python_reference`` queries.

Because the index is built from the installed runtime, results always match
the exact IDA/IDAPython version in use.
"""

from __future__ import annotations

import inspect
import math
import re
import sys
import threading
from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Sequence

_MAX_DOC_CHARS = 4000

_MODULE_NAME_RE = re.compile(r"^ida(_[a-z0-9_]+)?$")


# ============================================================================
# In-instance introspection (executed inside IDA / idalib worker)
# ============================================================================


def _iter_candidate_modules() -> List[str]:
    """Already-imported IDAPython modules only.

    Importing ida_* modules from a bridge handler thread can violate IDA's
    main-thread rule, so unknown modules are skipped rather than imported.
    """
    names = {name for name, module in sys.modules.items() if _MODULE_NAME_RE.match(name)}
    names.update(
        name for name in ("idc", "idaapi", "idautils") if sys.modules.get(name) is not None
    )
    return sorted(names)


def list_modules() -> List[Dict[str, Any]]:
    """Modules available for documentation snapshots, with entry counts."""
    modules = []
    for name in _iter_candidate_modules():
        module = sys.modules.get(name)
        if module is None:
            continue
        entry_count = sum(
            1
            for attr_name, attr in vars(module).items()
            if not attr_name.startswith("_")
            and (inspect.isclass(attr) or inspect.isroutine(attr) or callable(attr))
        )
        doc = (inspect.getdoc(module) or "").strip().splitlines()
        modules.append(
            {
                "module": name,
                "entries": entry_count,
                "description": doc[0] if doc else "",
            }
        )
    return modules


def _signature_of(obj: Any, fallback_doc: str) -> str:
    try:
        return str(inspect.signature(obj))
    except (TypeError, ValueError):
        pass
    first_line = fallback_doc.strip().splitlines()[0] if fallback_doc.strip() else ""
    if "(" in first_line:
        return first_line.strip()
    return ""


def _doc_of(obj: Any) -> str:
    doc = inspect.getdoc(obj) or ""
    if len(doc) > _MAX_DOC_CHARS:
        doc = doc[:_MAX_DOC_CHARS] + "\n... (truncated)"
    return doc


def snapshot_module(module_name: str) -> Dict[str, Any]:
    """Documentation snapshot for one already-imported IDAPython module."""
    module = sys.modules.get(module_name)
    if module is None:
        raise KeyError(module_name)

    entries: List[Dict[str, Any]] = []
    module_doc = _doc_of(module)

    for attr_name in sorted(vars(module)):
        if attr_name.startswith("_"):
            continue
        attr = getattr(module, attr_name)
        if inspect.isclass(attr):
            entries.append(
                {
                    "kind": "class",
                    "module": module_name,
                    "name": attr_name,
                    "qualname": f"{module_name}.{attr_name}",
                    "signature": "",
                    "doc": _doc_of(attr),
                }
            )
            for method_name, method in sorted(vars(attr).items()):
                if method_name.startswith("_") or not callable(method):
                    continue
                entries.append(
                    {
                        "kind": "method",
                        "module": module_name,
                        "name": method_name,
                        "qualname": f"{module_name}.{attr_name}.{method_name}",
                        "signature": _signature_of(method, _doc_of(method)),
                        "doc": _doc_of(method),
                    }
                )
            continue
        if inspect.isroutine(attr) or callable(attr):
            doc = _doc_of(attr)
            entries.append(
                {
                    "kind": "function",
                    "module": module_name,
                    "name": attr_name,
                    "qualname": f"{module_name}.{attr_name}",
                    "signature": _signature_of(attr, doc),
                    "doc": doc,
                }
            )

    return {"module": module_name, "module_doc": module_doc, "entries": entries}


# ============================================================================
# Standalone search index (BM25, name field weighted over docstrings)
# ============================================================================

_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "do", "for",
    "from", "how", "i", "in", "is", "it", "of", "on", "or", "the", "to",
    "with",
}


def _tokenize(text: str) -> List[str]:
    return [
        token
        for token in re.findall(r"[a-z0-9_]+", text.casefold())
        if token not in _STOPWORDS
    ]


class _BM25Field:
    """BM25 statistics for one field (k1=1.2, b=0.75)."""

    def __init__(self, texts: Sequence[str]):
        frequencies = [Counter(_tokenize(text)) for text in texts]
        document_frequency: Counter[str] = Counter()
        for frequency in frequencies:
            document_frequency.update(frequency.keys())
        count = len(frequencies)
        lengths = [sum(frequency.values()) for frequency in frequencies]
        average = sum(lengths) / count if count else 0.0
        self._frequencies = frequencies
        self._norms = [
            1.2 * (0.25 + 0.75 * length / average) if average else 1.2
            for length in lengths
        ]
        self._idf = {
            term: math.log1p((count - df + 0.5) / (df + 0.5))
            for term, df in document_frequency.items()
        }

    def score(self, document: int, terms: set) -> float:
        frequency = self._frequencies[document]
        norm = self._norms[document]
        return math.fsum(
            self._idf[term] * frequency[term] * 2.2 / (frequency[term] + norm)
            for term in terms
            if frequency[term]
        )


class DocsIndex:
    """Searchable IDAPython reference built from bridge snapshots."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []
        self._name_field: Optional[_BM25Field] = None
        self._doc_field: Optional[_BM25Field] = None
        self._module_docs: Dict[str, str] = {}

    @property
    def built(self) -> bool:
        return self._name_field is not None

    @property
    def size(self) -> int:
        return len(self._entries)

    def build(
        self,
        fetch_modules: Callable[[], List[Dict[str, Any]]],
        fetch_snapshot: Callable[[str], Dict[str, Any]],
        progress: Optional[Callable[[str], None]] = None,
    ) -> int:
        """Collect snapshots for every module exposed by the instance."""
        modules = fetch_modules()
        entries: List[Dict[str, Any]] = []
        module_docs: Dict[str, str] = {}
        for info in modules:
            name = info.get("module", "")
            if not name:
                continue
            if progress:
                progress(name)
            try:
                snapshot = fetch_snapshot(name)
            except Exception:  # noqa: BLE001 - skip unavailable modules
                continue
            module_docs[name] = str(snapshot.get("module_doc") or "")
            entries.extend(snapshot.get("entries") or [])

        with self._lock:
            self._entries = entries
            self._module_docs = module_docs
            self._name_field = _BM25Field(
                [e.get("qualname") or e.get("name") or "" for e in entries]
            )
            self._doc_field = _BM25Field([e.get("doc") or "" for e in entries])
        return len(entries)

    def search(
        self,
        query: str,
        module: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        if self._name_field is None or self._doc_field is None:
            return []
        terms = set(_tokenize(query))
        module_filter = _normalize_module_name(module) if module else None
        matches = []
        for index, entry in enumerate(self._entries):
            if module_filter and entry.get("module") != module_filter:
                continue
            score = 2 * self._name_field.score(index, terms)
            score += self._doc_field.score(index, terms)
            if score > 0:
                matches.append((score, str(entry.get("qualname", "")), entry))
        matches.sort(key=lambda match: (-match[0], match[1]))
        return [entry for _, _, entry in matches[:limit]]

    def module_summary(self) -> List[Dict[str, Any]]:
        counts: Dict[str, Dict[str, Any]] = {}
        for entry in self._entries:
            name = str(entry.get("module") or "")
            bucket = counts.setdefault(name, {"module": name, "entries": 0, "description": ""})
            bucket["entries"] += 1
            if not bucket["description"]:
                doc = self._module_docs.get(name, "")
                bucket["description"] = doc.strip().splitlines()[0] if doc.strip() else ""
        return sorted(counts.values(), key=lambda item: item["module"])


def _normalize_module_name(module: str) -> str:
    """Accept ``funcs``, ``ida_funcs``, ``idc``, ``idautils`` style input."""
    name = module.strip().replace(".", "_")
    if not name:
        return name
    if name in {"idc", "idaapi", "idautils"} or name.startswith("ida_"):
        return name
    return f"ida_{name}"


def format_entries(entries: Sequence[Dict[str, Any]], query: str) -> str:
    """Render search results the way the official reference tool does."""
    sections = [f"IDAPython 官方 API 参考（来自当前 IDA 运行时）", f"Query: {query}"]
    if not entries:
        sections.append(
            "没有匹配的 API 条目。可尝试具体的模块名或概念，例如 "
            "ida_funcs、decompile、xref、rename function、struct。"
        )
        return "\n\n".join(sections)

    rendered = []
    for entry in entries:
        signature = str(entry.get("signature") or "").strip()
        heading = f"{entry.get('kind', 'function')} {entry.get('qualname', '')}{signature}"
        doc = str(entry.get("doc") or "").strip()
        rendered.append(f"{heading}\n{doc}".strip())
    sections.append("API entries:\n\n" + "\n\n---\n\n".join(rendered))
    return "\n\n".join(sections)
