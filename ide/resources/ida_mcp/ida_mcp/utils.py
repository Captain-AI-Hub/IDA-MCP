"""General utility functions.

Provides:
    parse_address()        - unified address parsing
    hex_addr()             - format address as hex string
    normalize_list_input() - normalize bulk input
    paginate()             - pagination helper
    pattern_filter()       - glob pattern filtering
    is_valid_c_identifier() - C identifier validation
    display_path()         - path display normalization (presentation layer only)
"""

from __future__ import annotations

import os
import re
import string
import fnmatch
from typing import Any, List, Dict, Optional, Union, TypedDict

# ---------------------------------------------------------------------------
# Platform detection — resolved once at import time
# ---------------------------------------------------------------------------

IS_WINDOWS: bool = os.name == "nt"
"""True on Windows (including MSYS / Cygwin Python)."""


# ---------------------------------------------------------------------------
# Display-path helper (presentation layer only)
# ---------------------------------------------------------------------------

def display_path(path: Optional[str]) -> str:
    """Return a path string using the OS-native separator for display.

    On Windows, forward slashes are replaced with backslashes (``\\``).
    On macOS / Linux, the path is returned as-is (already ``/``).
    ``None`` returns ``""``.

    .. warning::

       This function is **only** for human-facing output (CLI text,
       log lines, UI labels).  Do *not* use it in machine-readable
       API payloads or return structs consumed by other tools or tests.
    """
    if path is None:
        return ""
    text = str(path)
    if IS_WINDOWS and "/" in text:
        text = text.replace("/", "\\")
    return text


class ParseResult(TypedDict):
    """Address parsing result."""

    ok: bool
    value: Optional[int]
    error: Optional[str]


class Page(TypedDict):
    """Pagination result."""

    total: int
    offset: int
    count: int
    items: List[Any]


def parse_address(value: Union[int, str]) -> ParseResult:
    """Unified address parsing.

    Supported formats:
        - 1234                (decimal)
        - 0x401000 / 0X401000 (hex prefix)
        - 401000h / 401000H   (trailing h/H hex)
        - 0x40_10_00          (underscore-separated)

    Args:
        value: address value (int or str)

    Returns:
        ParseResult: { ok, value, error }

    Notes:
        - Negative values are not accepted
        - Returns ok=False on parse failure
    """
    if isinstance(value, int):
        if value < 0:
            return {"ok": False, "value": None, "error": "invalid address"}
        return {"ok": True, "value": int(value), "error": None}

    if isinstance(value, str):
        txt = value.strip()
        if not txt:
            return {"ok": False, "value": None, "error": "invalid address"}

        txt = txt.replace("_", "")
        neg = False

        if txt.startswith(("+", "-")):
            if txt[0] == "-":
                neg = True
            txt = txt[1:]

        try:
            val: Optional[int] = None

            # trailing h form
            if txt.lower().endswith("h") and len(txt) > 1:
                core = txt[:-1]
                if all(c in string.hexdigits for c in core):
                    val = int(core, 16)
                else:
                    return {"ok": False, "value": None, "error": "invalid address"}
            else:
                # base=0 supports 0x / 0o / 0b
                val = int(txt, 0)

            if neg:
                val = -val  # type: ignore

            if val is None or val < 0:
                return {"ok": False, "value": None, "error": "invalid address"}

            return {"ok": True, "value": int(val), "error": None}
        except Exception:
            return {"ok": False, "value": None, "error": "invalid address"}

    return {"ok": False, "value": None, "error": "invalid address type"}


def hex_addr(addr: Union[int, str]) -> str:
    """Format an integer address as a hexadecimal string.

    Uses 0x prefix with uppercase letters.

    Args:
        addr: integer address or already-formatted hex string

    Returns:
        string in "0x401000" format
    """
    if isinstance(addr, str):
        return addr
    return f"0x{addr:X}"


def normalize_list_input(input_value: Union[int, str, List[Any]]) -> List[str]:
    """Normalize bulk input.

    Converts comma-separated strings, integers, or lists into a string list.

    Args:
        input_value: "0x401000, main" or ["0x401000", "main"] or 0x401000

    Returns:
        ["0x401000", "main"]
    """
    if isinstance(input_value, str):
        return [s.strip() for s in input_value.split(",") if s.strip()]
    elif isinstance(input_value, list):
        return [str(item).strip() for item in input_value if item]
    else:
        return [str(input_value)]


def paginate(
    items: List[Any], offset: int = 0, count: int = 100, max_count: int = 1000
) -> Page:
    """Pagination helper.

    Args:
        items: full item list
        offset: start offset (>=0)
        count: items per page (1..max_count)
        max_count: maximum allowed count

    Returns:
        Page: { total, offset, count, items }
    """
    total = len(items)

    # argument validation
    offset = max(0, offset)
    count = max(1, min(count, max_count))

    # slice
    slice_items = items[offset : offset + count]

    return {
        "total": total,
        "offset": offset,
        "count": len(slice_items),
        "items": slice_items,
    }


def pattern_filter(
    items: List[Dict[str, Any]],
    key: str,
    pattern: Optional[str],
    case_sensitive: bool = False,
) -> List[Dict[str, Any]]:
    """Glob pattern filtering.

    Args:
        items: list of dicts
        key: key name to match against
        pattern: glob pattern (e.g. "sub_*", "*main*"); None or empty means no filter
        case_sensitive: whether matching is case-sensitive

    Returns:
        filtered list
    """
    if not pattern:
        return items

    if not case_sensitive:
        pattern = pattern.lower()

    result = []
    for item in items:
        value = item.get(key, "")
        if value is None:
            continue
        value_str = str(value)
        if not case_sensitive:
            value_str = value_str.lower()

        # support glob patterns and substring matching
        if fnmatch.fnmatch(value_str, pattern) or pattern in value_str:
            result.append(item)

    return result


def is_valid_c_identifier(name: str) -> bool:
    """Check whether the name is a valid C identifier.

    Args:
        name: name to validate

    Returns:
        True if it is a valid C identifier
    """
    if not name:
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name))


def normalize_arch(raw: Optional[str], bits: int) -> Optional[str]:
    """Normalize architecture name.

    Args:
        raw: raw architecture name from IDA
        bits: bit width (32/64)

    Returns:
        normalized architecture name (x86/x86_64/arm/arm64/...)
    """
    if not raw:
        return None

    r = raw.lower()

    # x86 family
    if r in ("pc", "metapc", "i386", "x86"):
        return "x86_64" if bits == 64 else "x86"
    if r in ("amd64", "x86_64", "x64"):
        return "x86_64"

    # ARM family
    if r in ("aarch64", "arm64") or r.startswith("arm64"):
        return "arm64"
    if r.startswith("arm"):
        return "arm"

    # MIPS
    if r in ("mips64", "mips64el"):
        return "mips64"
    if r.startswith("mips"):
        return "mips"

    # PowerPC
    if r in ("powerpc64", "ppc64") or r.startswith("ppc64"):
        return "ppc64"
    if r.startswith("ppc") or r.startswith("powerpc"):
        return "ppc"

    return raw
