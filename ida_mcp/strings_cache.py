"""Shared string list cache used by tools and resources."""
from __future__ import annotations

from typing import Any

from .sync import wait_for_auto_analysis

try:
    import idautils  # type: ignore
except ImportError:  # pragma: no cover
    idautils = None


_strings_cache: list[tuple[int, int, Any, str]] | None = None


def get_strings_cache() -> list[tuple[int, int, Any, str]]:
    """Return cached strings, building the cache on first access."""
    global _strings_cache

    if _strings_cache is not None:
        return _strings_cache

    wait_for_auto_analysis()
    items: list[tuple[int, int, Any, str]] = []

    if idautils is None:
        _strings_cache = items
        return _strings_cache

    try:
        strs = idautils.Strings()
        try:
            _ = len(strs)  # type: ignore[arg-type]
        except Exception:
            try:
                strs.setup(strs.default_setup)  # type: ignore[attr-defined]
            except Exception:
                pass

        for s in strs:  # type: ignore[assignment]
            try:
                text = str(s)
            except Exception:
                continue
            ea = int(getattr(s, "ea", 0))
            length = int(getattr(s, "length", 0))
            stype = getattr(s, "strtype", None)
            items.append((ea, length, stype, text))
    except Exception:
        items = []

    items.sort(key=lambda item: item[0])
    _strings_cache = items
    return _strings_cache


def invalidate_strings_cache() -> None:
    global _strings_cache
    _strings_cache = None


def init_strings_cache() -> int:
    return len(get_strings_cache())
