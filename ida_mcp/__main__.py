"""``python -m ida_mcp`` entry point (serves MCP; stdio by default)."""

import sys

from .command import main

if __name__ == "__main__":
    sys.exit(main())
