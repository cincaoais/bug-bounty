"""Tests for the PreToolUse scope-guard hook.

Two layers:
  1. extract_targets() — the best-effort host extraction (unit).
  2. decide() — the deny/defer decision against a real temp registry (integration).

The hook is security-critical: a wrong 'defer' lets an out-of-scope command run.
"""
import importlib.util
import io
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
    assert ("api.example.com", 443, "/v1/users") in got


def test_extract_bare_domain():
    hosts = {h for h, _, _ in hook.extract_targets("Bash", {"command": "nuclei -u sub.example.com"})}
    assert "sub.example.com" in hosts


def test_extract_ipv4():
    hosts = {h for h, _, _ in hook.extract_targets("Bash", {"command": "ffuf -u http://10.0.0.5/FUZZ"})}
    assert "10.0.0.5" in hosts


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
    assert hook.extract_targets("Bash", {"command": "curl evil.com"})
    assert hook.extract_targets("Bash", {"command": "cat evil.com"}) == []


def test_compound_command_only_flags_the_network_target():
    hosts = {h for h, _, _ in hook.extract_targets(
        "Bash", {"command": "curl https://api.acme.com/x && cat notes.txt"})}
    assert "api.acme.com" in hosts
    assert "notes.txt" not in hosts  # filename after cat, not a network target


def test_url_still_extracted_without_network_tool_word():
    # a raw URL with no recognised tool name still counts (unambiguous)
    hosts = {h for h, _, _ in hook.extract_targets("Bash", {"command": "xdg-open https://evil.com/p"})}
    assert "evil.com" in hosts


def test_strips_userinfo_and_port():
    hosts = {h for h, _, _ in hook.extract_targets(
        "Bash", {"command": "curl https://u:p@api.example.com:8443/x"})}
    assert "api.example.com" in hosts


# ---- port-carry ----------------------------------------------------------

def test_extract_url_explicit_port():
    got = hook.extract_targets("Bash", {"command": "curl http://x.example:8443/p"})
    assert ("x.example", 8443, "/p") in got


def test_extract_url_https_default_port():
    got = hook.extract_targets("Bash", {"command": "curl https://x.example/p"})
    assert ("x.example", 443, "/p") in got


def test_extract_url_http_default_port():
    got = hook.extract_targets("Bash", {"command": "curl http://x.example/p"})
    assert ("x.example", 80, "/p") in got


# ---- bare non-dotted-quad numeric IP extraction (closes the bare-IP gap) --

def test_extract_bare_decimal_loopback_with_port():
    got = hook.extract_targets("Bash", {"command": "curl 2130706433:3000/x"})
    hosts = {(h, p) for h, p, _ in got}
    assert ("127.0.0.1", 3000) in hosts


def test_extract_bare_short_dotted_loopback():
    got = hook.extract_targets("Bash", {"command": "curl 127.1/x"})
    hosts = {h for h, _, _ in got}
    assert "127.0.0.1" in hosts


def test_bare_numeric_host_needs_network_context():
    # same token, two contexts: a host after curl vs an arg after an unrelated flag
    assert hook.extract_targets("Bash", {"command": "curl 2130706433:3000/x"})
    got = hook.extract_targets("Bash", {"command": "curl --max-time 2130706433 http://in-scope.example/x"})
    hosts = {h for h, _, _ in got}
    assert "127.0.0.1" not in hosts
    assert "in-scope.example" in hosts


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


def _setup(tmp, rules, attest=True):
    os.environ["BB_DATA_DIR"] = tmp
    import importlib, db as _db
    importlib.reload(_db)
    importlib.reload(registry)
    registry.create_target("acme", "hackerone", "public")
    registry.set_scope_rules("acme", rules)
    # Live bounty traffic now requires a one-time legal attestation (legal-gate).
    # Existing scope tests are about the HOST axis, so they attest by default;
    # the attestation gate itself is exercised by attest=False tests below.
    if attest:
        registry.set_attestation("acme", jurisdiction="MY", tester_location="MY",
                                 cssp_licensed=True, authorization_ref="test-authz")


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
    hosts = {h for h, _, _ in got}
    assert hosts == {"api.acme.com"}, f"burp extraction must use targetHostname only, got {hosts}"


def test_extract_targets_burp_carries_port():
    got = hook.extract_targets("mcp__burp__send_http1_request", {
        "targetHostname": "api.acme.com", "targetPort": 8443, "usesHttps": True,
        "content": "GET /x HTTP/1.1\r\n"})
    assert ("api.acme.com", 8443, None) in got


def test_override_allows_once_then_denies():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        registry.add_override("evil.com", "hand-verified authorized")
        out1 = hook.decide({"tool_name": "Bash", "tool_input": {"command": "curl https://evil.com"}})
        assert out1 is None or out1.get("permissionDecision") != "deny"
        out2 = hook.decide({"tool_name": "Bash", "tool_input": {"command": "curl https://evil.com"}})
        assert out2["permissionDecision"] == "deny"


# ---- bare-IP gap (real-program scope, not sandbox) ----------------------

def test_bare_decimal_loopback_denied_when_not_in_scope():
    """A decimal-encoded 127.0.0.1 previously slipped through extraction
    entirely (no candidate => defer). It must now be evaluated and denied
    against a real (bounty) target whose scope does not include loopback."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "Bash", "tool_input": {"command": "curl 2130706433:3000/x"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_bare_short_dotted_loopback_denied_when_not_in_scope():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "Bash", "tool_input": {"command": "curl 127.1/x"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_numeric_flag_value_does_not_cause_spurious_denial():
    """Regression guard for the bare-IP gap fix: a large decimal number that
    is a FLAG VALUE (--max-time), not a network-tool/url-flag target, must
    not be misread as a host and must not deny an otherwise in-scope command."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "in-scope.example", "in_scope": True}])
        out = hook.decide({"tool_name": "Bash", "tool_input": {
            "command": "curl --max-time 2130706433 http://in-scope.example/x"}})
        assert out is None, f"expected defer, got {out}"


# ---- sandbox mode (docs/02-PLAN.md Slice 2.2) ---------------------------------
#
# A completely separate decision path from everything above: when the active
# target is mode='sandbox', decide() auto-allows active-testing tool calls to
# the declared sandbox host:port ONLY, denies everything else, never consults
# scope_override, and denies (rather than defers) on ambiguity or zero
# candidates. Every allow/deny is appended to the sandbox_audit table.

_SANDBOX_PATTERNS = [
    {"pattern": "127.0.0.1:3000", "in_scope": True},
    {"pattern": "localhost:3000", "in_scope": True},
    {"pattern": "[::1]:3000", "in_scope": True},
]


def _setup_sandbox(tmp, patterns=None):
    os.environ["BB_DATA_DIR"] = tmp
    import importlib, db as _db
    importlib.reload(_db)
    importlib.reload(registry)
    registry.create_target("juice-shop", mode="sandbox", sandbox_app="juice-shop")
    registry.set_scope_rules("juice-shop", patterns if patterns is not None else _SANDBOX_PATTERNS)


def _audit_rows(handle="juice-shop"):
    import db as _db
    conn = _db.connect(_db.target_db_path(handle))
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM sandbox_audit ORDER BY id").fetchall()]
    finally:
        conn.close()


# -- allow: sandbox host+port, schemed and schemeless, incl. WebFetch ----------

def test_sandbox_allow_schemed_curl():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl http://localhost:3000/x"}})
        assert out is not None and out["permissionDecision"] == "allow"


def test_sandbox_allow_schemeless_curl():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl localhost:3000/x"}})
        assert out is not None and out["permissionDecision"] == "allow"


def test_sandbox_allow_bare_ipv4_loopback():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl 127.0.0.1:3000/x"}})
        assert out is not None and out["permissionDecision"] == "allow"


def test_sandbox_allow_webfetch():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "WebFetch",
                           "tool_input": {"url": "http://localhost:3000/x"}})
        assert out is not None and out["permissionDecision"] == "allow"


# -- deny: wrong port, wrong host, ambiguity, zero-candidate --------------------

def test_sandbox_deny_wrong_port():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl localhost:9999/x"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_sandbox_deny_non_sandbox_host():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl http://evil.com/x"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_sandbox_deny_non_loopback_rule_cannot_allow_traffic():
    """CRITICAL (finding #1): even if the target's declared scope_rules name
    a non-loopback host:port, sandbox_allows must still deny it — loopback is
    enforced unconditionally, not merely by convention of what gets declared."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp, patterns=_SANDBOX_PATTERNS + [
            {"pattern": "evil.com:443", "in_scope": True}])
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl http://evil.com:443/x"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_sandbox_deny_second_scheme_url_port_not_dropped_by_host_dedup():
    """CRITICAL (finding #2): extract_targets dedups its OWN output by HOST
    ALONE, so two scheme'd URLs to the same host on different ports must
    still both surface as candidates via the independent URL_RE re-scan --
    otherwise the second (out-of-allow-list) port silently disappears and
    the whole command is wrongly allowed."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)   # only :3000 is on the allow-list
        out = hook.decide({"tool_name": "Bash", "tool_input": {
            "command": "curl http://localhost:3000/a && curl http://localhost:9999/b"}})
        assert out is not None and out["permissionDecision"] == "deny"
        assert "9999" in out["permissionDecisionReason"]


def test_sandbox_deny_curl_proxy_flag():
    """CRITICAL (finding #3): -x/--proxy redirects traffic to an unevaluated
    proxy the hook never checked."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash", "tool_input": {
            "command": "curl -x proxyhost:8080 http://localhost:3000/x"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_sandbox_deny_when_any_port_out_of_allow_list():
    """The dedup-by-host bug this milestone fixes: a command touching the
    sandbox host on two different ports must have BOTH ports evaluated, not
    just the first-seen one. If the second port were silently dropped, this
    would wrongly allow."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash", "tool_input": {
            "command": "curl localhost:3000 && curl localhost:9999"}})
        assert out is not None and out["permissionDecision"] == "deny"
        assert "9999" in out["permissionDecisionReason"]


def test_sandbox_deny_network_tool_with_no_resolvable_target():
    """A Python/Node harness with no visible URL in the command text yields
    zero candidates. Sandbox mode denies this outright rather than deferring
    (docs/02-PLAN.md Slice 2.2, finding #3) — an unreadable target is not a
    safe default."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "python3 harness.py"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_sandbox_deny_command_substitution_ambiguous():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl $(cat u)"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_sandbox_deny_curl_resolve_ambiguous():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash", "tool_input": {
            "command": "curl --resolve x:1:2 http://localhost:3000"}})
        assert out is not None and out["permissionDecision"] == "deny"


# -- chrome tools: structured URL extraction + ambiguity (finding #7 / #9) ------

def test_sandbox_allow_chrome_navigate_schemeless_url():
    """#9: navigate(url='localhost:3000') stringifies to JSON whose quoting
    corrupts the old text-scan (trailing '"}' breaks port parsing), so this
    was WRONGLY DENIED before the structured tool_input['url'] extraction."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__claude-in-chrome__navigate",
                           "tool_input": {"url": "localhost:3000"}})
        assert out is not None and out["permissionDecision"] == "allow"


def test_sandbox_allow_chrome_navigate_schemed_url():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__claude-in-chrome__navigate",
                           "tool_input": {"url": "http://localhost:3000/rest/x"}})
        assert out is not None and out["permissionDecision"] == "allow"


def test_sandbox_deny_chrome_navigate_wrong_port():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__claude-in-chrome__navigate",
                           "tool_input": {"url": "localhost:9999"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_sandbox_allow_chrome_tabs_create_schemeless_url():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__claude-in-chrome__tabs_create_mcp",
                           "tool_input": {"url": "localhost:3000"}})
        assert out is not None and out["permissionDecision"] == "allow"


def test_sandbox_deny_chrome_javascript_command_substitution():
    """#7: the ambiguity matcher now also runs over chrome-tool tool_input,
    catching a $(...)/backtick/decode-pipe/proxy shape hidden inside a JS
    string that a pure structured-URL read would never see."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__claude-in-chrome__javascript_tool",
                           "tool_input": {"code": "fetch($(cat host.txt))"}})
        assert out is not None and out["permissionDecision"] == "deny"


# -- override cannot rescue a sandbox deny --------------------------------------

def test_sandbox_override_cannot_rescue_denied_host():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        registry.add_override("evil.com", "hand-verified authorized")
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl http://evil.com/x"}})
        assert out is not None and out["permissionDecision"] == "deny"


# -- non-network shell defers ----------------------------------------------------

def test_sandbox_non_network_shell_defers():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash", "tool_input": {"command": "ls -la"}})
        assert out is None


# -- audit trail ------------------------------------------------------------------

def test_sandbox_decision_writes_audit_row():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        hook.decide({"tool_name": "Bash",
                     "tool_input": {"command": "curl http://localhost:3000/x"}})
        rows = _audit_rows()
        assert len(rows) >= 1
        assert rows[-1]["decision"] == "allow"
        assert rows[-1]["host"] == "localhost" and rows[-1]["port"] == 3000


def test_sandbox_deny_also_writes_audit_row():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        hook.decide({"tool_name": "Bash",
                     "tool_input": {"command": "curl http://evil.com/x"}})
        rows = _audit_rows()
        assert any(r["decision"] == "deny" and r["host"] == "evil.com" for r in rows)


# -- SessionStart -------------------------------------------------------------------

def test_session_start_announces_sandbox_mode():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash", "tool_input": {"command": "ls"}})  # unrelated call, ignore
        ss = hook._decide_session_start({"hook_event_name": "SessionStart"})
        assert ss is not None
        assert ss["hookEventName"] == "SessionStart"
        assert "sandbox" in ss["additionalContext"].lower()
        assert "juice-shop" in ss["additionalContext"]


def test_session_start_defers_for_bounty_target():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        ss = hook._decide_session_start({"hook_event_name": "SessionStart"})
        assert ss is None


def test_main_emits_session_start_output_for_sandbox_target(monkeypatch, capsys):
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        import json as _json
        payload = _json.dumps({"hook_event_name": "SessionStart"})
        monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
        hook.main()
        captured = capsys.readouterr()
        assert "sandbox" in captured.out.lower()


# -- HexStrike AI MCP tools (mcp__hexstrike__*) ---------------------------------
#
# HexStrike carries its destination in a STRUCTURED argument, not a shell string,
# and its own MCP tools (mcp__hexstrike__*) previously matched NO PreToolUse
# matcher at all -> they bypassed the guard entirely. These assert the wiring:
# structured-field extraction (real-program scope), and the sandbox path that
# treats every hexstrike tool as network-capable + fail-closed.

# ---- real-program (bounty) scope: structured-field extraction ----

def test_hexstrike_extract_target_field():
    got = hook.extract_targets("mcp__hexstrike__nmap_scan", {"target": "scanme.example.com"})
    hosts = {h for h, _, _ in got}
    assert "scanme.example.com" in hosts


def test_hexstrike_extract_url_field_with_port():
    got = hook.extract_targets("mcp__hexstrike__nuclei_scan",
                               {"url": "https://api.example.com:8443/v1"})
    assert ("api.example.com", 8443, "/v1") in got


def test_hexstrike_extract_multi_host_rhosts_field():
    """hydra-style rhosts holds several space/comma-separated hosts; each must
    surface, not just the first."""
    got = hook.extract_targets("mcp__hexstrike__hydra",
                               {"rhosts": "10.0.0.1, 10.0.0.2 10.0.0.3"})
    hosts = {h for h, _, _ in got}
    assert {"10.0.0.1", "10.0.0.2", "10.0.0.3"} <= hosts


def test_hexstrike_extract_target_smuggled_in_args_blob():
    """A URL hidden in a free-form flag string is still caught by the embedded
    URL scan, so it can't slip past the real-program scope check."""
    got = hook.extract_targets("mcp__hexstrike__generic",
                               {"additional_args": "-u http://evil.example.com/x --rate 50"})
    hosts = {h for h, _, _ in got}
    assert "evil.example.com" in hosts


def test_hexstrike_bounty_deny_out_of_scope():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "mcp__hexstrike__nmap_scan",
                           "tool_input": {"target": "evil.com"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_hexstrike_bounty_allow_in_scope_defers():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "mcp__hexstrike__nuclei_scan",
                           "tool_input": {"url": "https://api.acme.com/v1"}})
        assert out is None  # in scope -> defer to normal flow


# ---- sandbox path: allow only localhost:3000, fail-closed otherwise ----

def test_hexstrike_sandbox_allow_schemed_target():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__hexstrike__nuclei_scan",
                           "tool_input": {"url": "http://localhost:3000/rest/products"}})
        assert out is not None and out["permissionDecision"] == "allow"


def test_hexstrike_sandbox_allow_schemeless_loopback_target():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__hexstrike__ffuf",
                           "tool_input": {"target": "127.0.0.1:3000"}})
        assert out is not None and out["permissionDecision"] == "allow"


def test_hexstrike_sandbox_deny_wrong_port():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__hexstrike__nmap_scan",
                           "tool_input": {"target": "localhost:9999"}})
        assert out is not None and out["permissionDecision"] == "deny"
        assert "9999" in out["permissionDecisionReason"]


def test_hexstrike_sandbox_deny_offbox_host():
    """The exact prompt-injection risk: tool output steers the agent to point a
    hexstrike tool at a real host. The guard denies it regardless of bypass
    permissions, because it runs below the model."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__hexstrike__nmap_scan",
                           "tool_input": {"target": "scanme.nmap.org"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_hexstrike_sandbox_deny_second_port_in_multi_target():
    """(host,port)-keyed extraction: two ports on the sandbox host must BOTH be
    evaluated; the out-of-list one denies the whole call. Uses nmap_scan (not
    gated by name) so this exercises the sandbox host/port dedup, not the
    legal-gate DoS-by-tool-name path — that is covered separately below."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__hexstrike__nmap_scan",
                           "tool_input": {"target": "localhost:3000 localhost:9999"}})
        assert out is not None and out["permissionDecision"] == "deny"
        assert "9999" in out["permissionDecisionReason"]


def test_hexstrike_sandbox_deny_zero_candidate_fail_closed():
    """A hexstrike tool with no resolvable target is DENIED, not deferred — an
    unreadable destination is not a safe default in sandbox mode."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__hexstrike__list_tools",
                           "tool_input": {}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_hexstrike_sandbox_deny_ambiguous_args():
    """$(...)/proxy/decode shapes hidden in a hexstrike args blob deny outright,
    same as for Bash/chrome."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "mcp__hexstrike__generic",
                           "tool_input": {"target": "localhost:3000",
                                          "additional_args": "-x $(cat /tmp/proxy)"}})
        assert out is not None and out["permissionDecision"] == "deny"


def test_hexstrike_sandbox_decision_writes_audit_row():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        hook.decide({"tool_name": "mcp__hexstrike__nuclei_scan",
                     "tool_input": {"url": "http://localhost:3000/x"}})
        rows = _audit_rows()
        assert rows[-1]["decision"] == "allow"
        assert rows[-1]["host"] == "localhost" and rows[-1]["port"] == 3000


# -- regression: bounty-mode decisions are byte-for-byte unchanged --------------
#
# Every pre-existing test above this section already asserts real-program
# (mode='bounty', the default) behavior; this milestone only ADDS an early
# `if registry.is_sandbox():` branch to decide() and leaves the rest of the
# function verbatim. Re-running the whole module (including the tests above)
# is the regression proof: nothing in this file's assertions for a bounty
# target was changed to make sandbox mode pass.

def test_bounty_target_untouched_by_sandbox_branch():
    """A bounty-mode target must never take the sandbox branch, even though
    the sandbox branch now runs first in decide()."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        assert registry.is_sandbox() is False
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl https://api.acme.com/v1"}})
        assert out is None  # identical to test_allow_in_scope_host_defers above
        out2 = hook.decide({"tool_name": "Bash",
                            "tool_input": {"command": "curl https://evil.com/x"}})
        assert out2["permissionDecision"] == "deny"  # identical to test_deny_out_of_scope_host


# ---- legal action-class gate (legalgate) --------------------------------------
#
# A THIRD decision axis (after host-scope and sandbox host/port): the SHAPE of
# the action, mapped to Malaysian statute. Runs in both modes, before host logic,
# independent of whether a network target is present. Deny + single-use logged
# override (mcp__bb__legal_override), mirroring the host scope_override pattern.

def test_legal_gate_denies_destructive_even_in_scope():
    """The whole point: a destructive verb against an IN-SCOPE host is still
    blocked (CCA s.5 is about modification, not destination)."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl -X DELETE https://api.acme.com/users/1"}})
        assert out is not None and out["permissionDecision"] == "deny"
        assert "destructive" in out["permissionDecisionReason"]
        assert "s.5" in out["permissionDecisionReason"]


def test_legal_gate_denies_dos_credential_pii():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        for cmd, cls in [("hydra -l a -P w ssh://api.acme.com", "dos"),
                         ("hashcat -m 0 h.txt w", "credential"),
                         ("sqlmap -u https://api.acme.com/x --dump -T users", "pii")]:
            out = hook.decide({"tool_name": "Bash", "tool_input": {"command": cmd}})
            assert out is not None and out["permissionDecision"] == "deny", cmd
            assert cls in out["permissionDecisionReason"], cmd


def test_legal_override_clears_then_redenies():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        registry.add_legal_override("destructive", "authorized destructive PoC step")
        cmd = {"command": "curl -X DELETE https://api.acme.com/users/1"}
        out1 = hook.decide({"tool_name": "Bash", "tool_input": cmd})
        assert out1 is None or out1.get("permissionDecision") != "deny"  # override cleared it
        out2 = hook.decide({"tool_name": "Bash", "tool_input": cmd})
        assert out2 is not None and out2["permissionDecision"] == "deny"  # single-use


def test_legal_gate_defers_when_no_active_target():
    """Documented boundary: with no bounty/sandbox session active, the hook does
    not police local actions — even a catastrophic one."""
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["BB_DATA_DIR"] = tmp
        import importlib, db as _db
        importlib.reload(_db); importlib.reload(registry)
        out = hook.decide({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
        assert out is None


def test_hexstrike_hydra_denied_by_wrapper_name():
    """mcp__hexstrike__hydra carries the tool identity in the MCP name, not args;
    it must still be gated as a brute-force (DoS) action."""
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}])
        out = hook.decide({"tool_name": "mcp__hexstrike__hydra",
                           "tool_input": {"target": "api.acme.com"}})
        assert out is not None and out["permissionDecision"] == "deny"
        assert "dos" in out["permissionDecisionReason"]


def test_legal_gate_enforces_in_sandbox_and_audits():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl -X DELETE http://localhost:3000/api/x"}})
        assert out is not None and out["permissionDecision"] == "deny"
        assert "destructive" in out["permissionDecisionReason"]
        rows = _audit_rows()
        assert any(r["decision"] == "legal-deny" for r in rows)


def test_legal_override_works_in_sandbox_then_host_check_runs():
    """An overridden destructive call in sandbox still has to hit the allowed
    sandbox host:port — the legal and host axes are independent. (Uses WebGoat's
    destructive restartlesson.mvc rather than `-X DELETE`, because `-X` collides
    with is_ambiguous's case-insensitive `-x`/proxy check in sandbox mode.)"""
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)
        registry.add_legal_override("destructive", "training: destructive PoC on disposable app")
        out = hook.decide({"tool_name": "Bash", "tool_input": {
            "command": "curl http://localhost:3000/WebGoat/service/restartlesson.mvc/SqlInjection"}})
        assert out is not None and out["permissionDecision"] == "allow"  # cleared, host in allow-list


# ---- attestation gate (bounty/live mode) --------------------------------------

def test_bounty_network_action_denied_until_attested():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}], attest=False)
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl https://api.acme.com/v1"}})
        assert out is not None and out["permissionDecision"] == "deny"
        assert "attest" in out["permissionDecisionReason"].lower()


def test_bounty_allows_after_attestation():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}], attest=False)
        registry.set_attestation("acme", jurisdiction="MY", tester_location="MY",
                                 cssp_licensed=True, authorization_ref="h1/acme")
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl https://api.acme.com/v1"}})
        assert out is None


def test_attestation_not_required_for_non_network_action():
    with tempfile.TemporaryDirectory() as tmp:
        _setup(tmp, [{"pattern": "*.acme.com", "in_scope": True}], attest=False)
        out = hook.decide({"tool_name": "Bash", "tool_input": {"command": "cat notes.txt"}})
        assert out is None


def test_sandbox_never_requires_attestation():
    with tempfile.TemporaryDirectory() as tmp:
        _setup_sandbox(tmp)   # sandbox targets are not attested
        out = hook.decide({"tool_name": "Bash",
                           "tool_input": {"command": "curl http://localhost:3000/x"}})
        assert out is not None and out["permissionDecision"] == "allow"
