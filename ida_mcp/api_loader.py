"""API module loading helpers."""
from __future__ import annotations


def ensure_api_modules_loaded() -> None:
    """Import all api_* modules to populate the tool and resource registries.

    This triggers the @tool and @resource decorator side-effects that
    populate ``_tools``, ``_tool_specs``, and ``_resources``.  It is safe
    to call multiple times (subsequent calls are no-ops).
    """
    from . import api_analysis  # noqa: F401
    from . import api_core  # noqa: F401
    from . import api_debug  # noqa: F401
    from . import api_lifecycle  # noqa: F401
    from . import api_memory  # noqa: F401
    from . import api_modeling  # noqa: F401
    from . import api_modify  # noqa: F401
    from . import api_python  # noqa: F401
    from . import api_resources  # noqa: F401
    from . import api_stack  # noqa: F401
    from . import api_types  # noqa: F401
