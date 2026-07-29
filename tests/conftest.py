"""Put the plugin's mcp/ dir on sys.path so tests can import scope, db, registry.

The hook and server import these modules by adding the same dir at runtime;
tests mirror that so we test the real modules, not copies.
"""
import sys
from pathlib import Path

MCP_DIR = Path(__file__).resolve().parent.parent / "plugin" / "mcp"
if str(MCP_DIR) not in sys.path:
    sys.path.insert(0, str(MCP_DIR))
