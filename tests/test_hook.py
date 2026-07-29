"""Tests for the PreToolUse scope-guard hook.

Two layers:
  1. extract_targets() — the best-effort host extraction (unit).
  2. decide() — the deny/defer decision against a real temp registry (integration).

The hook is security-critical: a wrong 'defer' lets an out-of-scope command run.
"""
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MCP_DIR = ROOT / "plugin" / "mcp"
sys.path.insert(0, str(MCP_DIR))


def _load_hook():
    # hyphen in filename => load by path, not import
    spec = importlib.util.spec_from_file_location(
        "scope_guard", ROOT / "plugin" / "hooks" / "scope-guard.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hook = _load_hook()
import registry  # noqa: E402


# ---- extraction --------------------------------------------------------------

def test_extract_url_with_path():
    got = hook.extract_targets("Bash", {"command": "curl https://api.example.com/v1/users"})
    assert ("api.example.com", "/v1/users") in got


def test_extract_bare_domain():
    got = dict(hook.extract_targets("Bash", {"command": "nuclei -u sub.example.com"}))
    assert "sub.example.com" in got


def test_extract_ipv4():
    got = dict(hook.extract_targets("Bash", {"command": "ffuf -u http://10.0.0.5/FUZZ"}))
    assert "10.0.0.5" in got


def test_no_host_in_plain_command():
    got = hook.extract_targets("Bash", {"command": "ls -la ./notes"})
    assert got == []


def test_strips_userinfo_and_port():
    got = dict(hook.extract_targets("Bash", {"command": "curl https://u:p@api.example.com:8443/x"}))
    assert "api.example.com" in got


# ---- decision (integration against a temp registry) --------------------------

def _fresh_registry(tmp):
    os.environ["BB_DATA_DIR"] = tmp
    # reload registry/db so data_dir() re-resolves under the temp path
    import db
    importlib_reload(db)
    importlib_reload(registry)
    importlib_reload(hook)


def importlib_reload(m):
    import importlib
    importlib.reload(m)


def _setup(tmp, rules):
    os.environ["BB_DATA_DIR"] = tmp
    import importlib, db as _db
    importlib.reload(_db)
    importlib.reload(registry)
    registry.create_target("acme", "hackerone", "public")
    registry.set_scope_rules("acme", rules)


def test_defer_when_no_active_target():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["BB_DATA_DIR"] = tmp
        import importlib, db as _db
        importlib.reload(_db); importlib.reload(registry)
        out = hook.decide({"tool_name": "Bash", "tool_input": {"command": "curl https://x.com"}})
        assert out is None


def test_deny_out_of_scope_host():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl https://evil.com/x"}})
        assert out is not None
        assert out["permissionDecision"] == "deny"
        assert "evil.com" in out["permissionDecisionReason"]


def test_allow_in_scope_host_defers():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        # fresh scope => not stale => defer (None)
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl https://api.acme.com/v1"}})
        assert out is None


def test_deny_if_any_candidate_out_of_scope():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "Bash", "tool_input":
                           {"command": "curl https://api.acme.com && curl https://evil.com"}})
        assert out["permissionDecision"] == "deny"
        assert "evil.com" in out["permissionDecisionReason"]


def test_out_of_scope_rule_denies_subdomain():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True},
                     {"pattern": "internal.acme.com", "in_scope": False}])
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl https://internal.acme.com"}})
        assert out["permissionDecision"] == "deny"


def test_override_allows_once_then_denies():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        registry.add_override("evil.com", "hand-verified authorized")
        out1 = hook.decide({"tool_name": "Bash", "tool_input": {"command": "curl https://evil.com"}})
        assert out1 is None or out1.get("permissionDecision") != "deny"
        out2 = hook.decide({"tool_name": "Bash", "tool_input": {"command": "curl https://evil.com"}})
        assert out2["permissionDecision"] == "deny"
