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

import pytest

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


@pytest.mark.parametrize("cmd", [
    "cat plugin/mcp/server.py",
    "python -m pytest tests/test_hook.py -q",
    "python -c \"import json; json.load(open('x'))\"",
    "git log --oneline",
    "cat plugin.json && cat report.py",
    "grep -rn urllib.parse plugin/mcp",
    "ls dist/build.js node_modules/.bin",
])
def test_filenames_and_code_are_not_hosts(cmd):
    """The regression that made the tool unusable: routine commands full of
    dotted tokens (filenames, module refs) must NOT be read as out-of-scope
    hosts. If any of these extracts a host, a live target would block the command."""
    assert hook.extract_targets("Bash", {"command": cmd}) == [], cmd


def test_bare_domain_needs_network_context():
    # same token, two contexts: a host after curl vs a filename after cat
    assert dict(hook.extract_targets("Bash", {"command": "curl evil.com"}))
    assert hook.extract_targets("Bash", {"command": "cat evil.com"}) == []


def test_compound_command_only_flags_the_network_target():
    got = dict(hook.extract_targets(
        "Bash", {"command": "curl https://api.acme.com/x && cat notes.txt"}))
    assert "api.acme.com" in got
    assert "notes.txt" not in got  # filename after cat, not a network target


def test_url_still_extracted_without_network_tool_word():
    # a raw URL with no recognised tool name still counts (unambiguous)
    got = dict(hook.extract_targets("Bash", {"command": "xdg-open https://evil.com/p"}))
    assert "evil.com" in got


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


def test_burp_send_out_of_scope_denied():
    """Burp send tools put traffic on the wire; an out-of-scope targetHostname
    must be blocked, same as a Bash curl."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "mcp__burp__send_http1_request",
                           "tool_input": {"targetHostname": "evil.com", "targetPort": 443,
                                          "usesHttps": True, "content": "GET / HTTP/1.1\r\n"}})
        assert out is not None and out["permissionDecision"] == "deny"
        assert "evil.com" in out["permissionDecisionReason"]


def test_burp_send_in_scope_allowed():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "mcp__burp__send_http1_request",
                           "tool_input": {"targetHostname": "api.acme.com", "targetPort": 443,
                                          "usesHttps": True, "content": "GET / HTTP/1.1\r\n"}})
        assert out is None  # in scope, fresh -> defer


def test_burp_send_does_not_scan_request_body():
    """THE reason we gate on targetHostname only: a request to an IN-scope host
    that carries an OUT-of-scope URL in its body (a legitimate SSRF test) must
    NOT be blocked. If this fails, the hook blocks real in-scope testing."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "mcp__burp__send_http1_request",
                           "tool_input": {
                               "targetHostname": "api.acme.com", "targetPort": 443,
                               "usesHttps": True,
                               "content": "POST /fetch HTTP/1.1\r\nHost: api.acme.com\r\n\r\n"
                                          "url=http://169.254.169.254/latest/meta-data/"}})
        assert out is None, "in-scope Burp send with an SSRF payload in the body was wrongly blocked"


def test_burp_send_to_intruder_gated():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "mcp__burp__send_to_intruder",
                           "tool_input": {"targetHostname": "out-of-scope.net", "targetPort": 443,
                                          "usesHttps": True, "content": "GET / HTTP/1.1\r\n"}})
        assert out["permissionDecision"] == "deny"


def test_burp_read_tools_not_gated():
    """Reading proxy history is safe and must never be blocked."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        # a read tool carries no targetHostname; even if history mentions other
        # hosts, reading it generates no traffic and must defer
        out = hook.decide({"tool_name": "mcp__burp__get_proxy_http_history",
                           "tool_input": {"count": 50}})
        assert out is None


def test_extract_targets_burp_ignores_body_hosts():
    got = hook.extract_targets("mcp__burp__send_http1_request", {
        "targetHostname": "api.acme.com", "targetPort": 443, "usesHttps": True,
        "content": "GET /x HTTP/1.1\r\nHost: evil.example.org\r\n"})
    hosts = {h for h, _ in got}
    assert hosts == {"api.acme.com"}, f"burp extraction must use targetHostname only, got {hosts}"


def test_override_allows_once_then_denies():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        registry.add_override("evil.com", "hand-verified authorized")
        out1 = hook.decide({"tool_name": "Bash", "tool_input": {"command": "curl https://evil.com"}})
        assert out1 is None or out1.get("permissionDecision") != "deny"
        out2 = hook.decide({"tool_name": "Bash", "tool_input": {"command": "curl https://evil.com"}})
        assert out2["permissionDecision"] == "deny"
