"""Smoke test: the MCP server imports, its tools are registered, and they work
end-to-end against a temp store. Guards against 'server won't boot' regressions
without needing a live MCP client.
"""
import os
import tempfile
import importlib

import pytest

pytest.importorskip("mcp", reason="mcp SDK not installed")


def _reload_with_tmp(tmp):
    os.environ["BB_DATA_DIR"] = tmp
    import db, registry, server
    importlib.reload(db)
    importlib.reload(registry)
    importlib.reload(server)
    return server


def test_server_imports_and_registers_tools():
    import server
    assert server.mcp.name == "bb"
    # tool functions are exposed as callables on the module
    for name in ("create_target", "switch_target", "list_targets",
                 "set_scope_rules", "check_scope", "scope_status", "scope_override"):
        assert callable(getattr(server, name)), f"missing tool: {name}"


def test_tools_work_end_to_end():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)
        server.create_target("acme", "hackerone", "public")
        server.set_scope_rules("acme", [
            {"pattern": "*.acme.com", "in_scope": True},
            {"pattern": "blog.acme.com", "in_scope": False},
        ])
        assert server.check_scope("api.acme.com")["in_scope"] is True
        assert server.check_scope("blog.acme.com")["in_scope"] is False
        assert server.check_scope("evil.com")["in_scope"] is False

        st = server.scope_status("acme")
        assert st["in_scope_rules"] == 1 and st["out_of_scope_rules"] == 1

        # one-time override
        server.scope_override("evil.com", "hand-verified")
        assert server.check_scope("evil.com")["in_scope"] is True
        assert server.check_scope("evil.com")["in_scope"] is False

        assert any(t["handle"] == "acme" for t in server.list_targets())
