"""Truth table for the sandbox allow-list, canonicalization, and ambiguity
matcher. Security-critical: this is the code path that decides whether
autonomous sandbox traffic is confined to localhost + declared ports.

Every case is deliberately explicit rather than parametrized in bulk, mirroring
tests/test_scope.py's style, so a failing assertion names exactly what broke.
"""
import os

import sandbox
from sandbox import (SandboxRule, canonical_host, is_ambiguous, network_isolation_check,
                      proxy_env_set, sandbox_allows)


def _rules(*pairs):
    return [SandboxRule(host=h, port=p) for h, p in pairs]


# ---- sandbox_allows: basic allow/deny -----------------------------------------

def test_allow_localhost_when_declared():
    ok, _ = sandbox_allows("localhost", 3000, _rules(("localhost", 3000)))
    assert ok is True


def test_deny_localhost_wrong_port():
    ok, reason = sandbox_allows("localhost", 9999, _rules(("localhost", 3000)))
    assert ok is False
    assert "not on sandbox allow-list" in reason


def test_deny_non_sandbox_host():
    ok, reason = sandbox_allows("evil.com", 3000, _rules(("localhost", 3000)))
    assert ok is False
    assert "not on sandbox allow-list" in reason


def test_deny_when_port_none():
    ok, reason = sandbox_allows("localhost", None, _rules(("localhost", 3000)))
    assert ok is False
    assert "no port" in reason


def test_deny_empty_rules():
    ok, _ = sandbox_allows("localhost", 3000, [])
    assert ok is False


def test_allow_127_0_0_1_when_declared():
    ok, _ = sandbox_allows("127.0.0.1", 8080, _rules(("127.0.0.1", 8080)))
    assert ok is True


def test_allow_ipv6_loopback_when_declared():
    ok, _ = sandbox_allows("::1", 8080, _rules(("::1", 8080)))
    assert ok is True


def test_localhost_and_127_0_0_1_are_distinct_identities():
    # a rule for localhost:3000 does NOT authorize 127.0.0.1:3000 — the plan
    # treats {127.0.0.1, ::1, localhost} as three distinct declared identities
    ok, _ = sandbox_allows("127.0.0.1", 3000, _rules(("localhost", 3000)))
    assert ok is False


def test_deny_by_default_no_wildcards():
    # a rule for one port never authorizes a neighboring port
    ok, _ = sandbox_allows("localhost", 3001, _rules(("localhost", 3000)))
    assert ok is False


def test_numeric_loopback_form_matches_dotted_rule():
    # 2130706433 canonicalizes to 127.0.0.1, which must match a rule declared
    # in the ordinary dotted form
    ok, _ = sandbox_allows("2130706433", 3000, _rules(("127.0.0.1", 3000)))
    assert ok is True


def test_rule_declared_in_numeric_form_still_matches_dotted_host():
    ok, _ = sandbox_allows("127.0.0.1", 3000, _rules(("0x7f000001", 3000)))
    assert ok is True


def test_empty_host_denied():
    ok, reason = sandbox_allows("", 3000, _rules(("localhost", 3000)))
    assert ok is False
    assert "empty/invalid host" in reason


def test_deny_non_loopback_host_even_when_rule_declares_it():
    """CRITICAL (finding #1): a declared rule for a non-loopback host must
    NEVER authorize traffic. Sandbox mode is loopback-only unconditionally —
    a rule can only narrow the loopback allow-list, never widen it off-box."""
    ok, reason = sandbox_allows("evil.com", 443, _rules(("evil.com", 443)))
    assert ok is False
    assert "not on sandbox allow-list" in reason


def test_deny_non_loopback_ip_even_when_rule_declares_it():
    ok, _ = sandbox_allows("10.0.0.5", 8080, _rules(("10.0.0.5", 8080)))
    assert ok is False


# ---- canonical_host: loopback forms --------------------------------------------

def test_canonical_dotted_loopback():
    assert canonical_host("127.0.0.1") == "127.0.0.1"


def test_canonical_decimal_loopback():
    assert canonical_host("2130706433") == "127.0.0.1"


def test_canonical_short_dotted_loopback():
    assert canonical_host("127.1") == "127.0.0.1"


def test_canonical_three_part_short_dotted_loopback():
    assert canonical_host("127.0.1") == "127.0.0.1"


def test_canonical_hex_loopback():
    assert canonical_host("0x7f000001") == "127.0.0.1"


def test_canonical_octal_dotted_loopback():
    assert canonical_host("0177.0.0.1") == "127.0.0.1"


def test_canonical_ipv4_mapped_ipv6_loopback():
    assert canonical_host("::ffff:127.0.0.1") == "127.0.0.1"


def test_canonical_ipv6_loopback():
    assert canonical_host("::1") == "::1"


def test_canonical_ipv6_loopback_bracketed():
    assert canonical_host("[::1]") == "::1"


def test_canonical_localhost():
    assert canonical_host("localhost") == "localhost"


def test_canonical_localhost_case_insensitive():
    assert canonical_host("LOCALHOST") == "localhost"


def test_canonical_other_loopback_octet_still_loopback():
    # 127.0.0.0/8 is entirely loopback, not just 127.0.0.1
    assert canonical_host("127.5.5.5") == "127.0.0.1"


# ---- canonical_host: passthrough / garbage -------------------------------------

def test_canonical_normal_hostname_lowercased():
    assert canonical_host("Evil.COM") == "evil.com"


def test_canonical_non_loopback_ip_passthrough():
    assert canonical_host("10.0.0.5") == "10.0.0.5"


def test_canonical_empty_is_none():
    assert canonical_host("") is None


def test_canonical_whitespace_only_is_none():
    assert canonical_host("   ") is None


def test_canonical_internal_whitespace_is_garbage():
    assert canonical_host("not a host") is None


def test_canonical_unmatched_bracket_is_garbage():
    assert canonical_host("[::1") is None


def test_canonical_none_input_is_none():
    assert canonical_host(None) is None


# ---- is_ambiguous: banned constructs --------------------------------------------

def test_ambiguous_command_substitution_dollar_paren():
    ok, reason = is_ambiguous("curl $(cat host.txt)")
    assert ok is True
    assert "substitution" in reason


def test_ambiguous_command_substitution_backtick():
    ok, _ = is_ambiguous("curl `cat host.txt`")
    assert ok is True


def test_ambiguous_base64_decode_short_flag():
    ok, reason = is_ambiguous("echo aHR0cA== | base64 -d | xargs curl")
    assert ok is True
    assert "decode" in reason


def test_ambiguous_base64_decode_long_flag():
    ok, _ = is_ambiguous("echo aHR0cA== | base64 --decode | xargs curl")
    assert ok is True


def test_ambiguous_xxd_reverse():
    ok, _ = is_ambiguous("echo 687474703a2f2f | xxd -r -p")
    assert ok is True


def test_ambiguous_printf_hex_escape():
    ok, _ = is_ambiguous("printf '\\x68\\x74\\x74\\x70' ")
    assert ok is True


def test_ambiguous_curl_resolve():
    ok, reason = is_ambiguous("curl --resolve evil.com:443:127.0.0.1 https://evil.com")
    assert ok is True
    assert "resolve" in reason


def test_ambiguous_curl_connect_to():
    ok, _ = is_ambiguous("curl --connect-to evil.com:443:127.0.0.1:443 https://evil.com")
    assert ok is True


def test_ambiguous_curl_location_long_flag():
    ok, reason = is_ambiguous("curl --location http://localhost:3000/redirect")
    assert ok is True
    assert "location" in reason.lower() or "-L" in reason


def test_ambiguous_curl_location_short_flag():
    ok, _ = is_ambiguous("curl -L http://localhost:3000/redirect")
    assert ok is True


def test_ambiguous_curl_location_combined_short_flags():
    # the extremely common curl -fsSL idiom
    ok, _ = is_ambiguous("curl -fsSL http://localhost:3000/install.sh")
    assert ok is True


def test_ambiguous_inline_http_proxy():
    ok, reason = is_ambiguous("HTTP_PROXY=http://evil.com:8080 curl http://localhost:3000")
    assert ok is True
    assert "PROXY" in reason.upper()


def test_ambiguous_inline_https_proxy_lowercase():
    ok, _ = is_ambiguous("https_proxy=http://evil.com:8080 curl http://localhost:3000")
    assert ok is True


def test_ambiguous_inline_all_proxy():
    ok, _ = is_ambiguous("ALL_PROXY=socks5://evil.com:1080 curl http://localhost:3000")
    assert ok is True


def test_ambiguous_curl_short_proxy_flag():
    """CRITICAL (finding #3): curl -x hands traffic to an unevaluated proxy."""
    ok, reason = is_ambiguous("curl -x proxyhost:8080 http://localhost:3000/x")
    assert ok is True
    assert "proxy" in reason.lower()


def test_ambiguous_curl_long_proxy_flag():
    ok, reason = is_ambiguous("curl --proxy attacker.example:9090 http://localhost:3000/x")
    assert ok is True
    assert "proxy" in reason.lower()


def test_not_ambiguous_proxy_var_without_network_tool():
    # a proxy assignment isn't inherently dangerous without a network-capable
    # tool present in the same command to feed it to
    ok, _ = is_ambiguous("HTTP_PROXY=http://evil.com:8080 ls -la")
    assert ok is False


# ---- is_ambiguous: clean commands -----------------------------------------------

def test_not_ambiguous_clean_curl():
    ok, reason = is_ambiguous("curl http://localhost:3000/x")
    assert ok is False
    assert reason == ""


def test_not_ambiguous_clean_curl_schemeless():
    ok, _ = is_ambiguous("curl localhost:3000/x")
    assert ok is False


def test_not_ambiguous_non_network_shell():
    ok, _ = is_ambiguous("ls -la && cat notes.txt")
    assert ok is False


def test_not_ambiguous_python_harness_with_url_arg():
    ok, _ = is_ambiguous("python3 harness.py http://localhost:3000")
    assert ok is False


def test_not_ambiguous_empty_command():
    ok, _ = is_ambiguous("")
    assert ok is False


# ---- proxy_env_set: both branches -----------------------------------------------

def test_proxy_env_set_false_when_unset(monkeypatch):
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                 "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    ok, which = proxy_env_set()
    assert ok is False
    assert which == ""


def test_proxy_env_set_true_when_http_proxy_set(monkeypatch):
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                 "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://evil.com:8080")
    ok, which = proxy_env_set()
    assert ok is True
    assert which == "HTTP_PROXY"


def test_proxy_env_set_true_when_lowercase(monkeypatch):
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                 "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("all_proxy", "socks5://evil.com:1080")
    ok, which = proxy_env_set()
    assert ok is True
    assert which.upper() == "ALL_PROXY"


# ---- SandboxRule shape ------------------------------------------------------------

def test_sandbox_rule_is_frozen():
    rule = SandboxRule(host="localhost", port=3000)
    try:
        rule.port = 4000
        assert False, "SandboxRule must be frozen"
    except AttributeError:
        pass


def test_sandbox_rule_requires_port_positional():
    # port has no default — constructing without it must fail
    try:
        SandboxRule(host="localhost")  # type: ignore[call-arg]
        assert False, "port must be mandatory"
    except TypeError:
        pass


# ---- network_isolation_check: Slice 6.2 sandbox_preflight ---------------------

def test_network_isolation_warn_when_both_params_empty():
    status, detail = network_isolation_check("", "")
    assert status == "warn"
    assert "unconfirmed" in detail


def test_network_isolation_pass_on_internal_and_loopback_bind():
    status, _ = network_isolation_check("internal", "127.0.0.1:3000->3000/tcp", "EGRESS_BLOCKED")
    assert status == "pass"


def test_network_isolation_pass_on_caller_declared_internal_net_name():
    # a custom network literally named "bb_internal" still contains "internal"
    status, _ = network_isolation_check("bb_internal", "127.0.0.1:3000->3000/tcp", "EGRESS_BLOCKED")
    assert status == "pass"


def test_network_isolation_fail_on_0_0_0_0_bind():
    status, reason = network_isolation_check("internal", "0.0.0.0:3000->3000/tcp")
    assert status == "fail"
    assert "non-loopback" in reason


def test_network_isolation_fail_on_egress_open_even_if_loopback_bound():
    # the network NAME is advisory now; an EGRESS_OPEN probe is a hard fail even with a
    # loopback bind and an "internal"-looking name (the Docker Desktop reality).
    status, reason = network_isolation_check("bb-internal", "127.0.0.1:3000->3000/tcp", "EGRESS_OPEN")
    assert status == "fail"
    assert "reach the internet" in reason


def test_network_isolation_pass_ignores_non_internal_name_when_egress_blocked():
    # a plain "bridge" network still PASSES when egress is empirically blocked
    status, _ = network_isolation_check("bridge", "127.0.0.1:3000->3000/tcp", "EGRESS_BLOCKED")
    assert status == "pass"


def test_network_isolation_warn_when_egress_unconfirmed():
    # loopback bind but no egress probe yet -> warn (not ready), never pass
    status, _ = network_isolation_check("internal", "127.0.0.1:3000->3000/tcp", "")
    assert status == "warn"


def test_network_isolation_fail_on_routable_lan_bind():
    status, reason = network_isolation_check("internal", "192.168.1.5:3000->3000/tcp")
    assert status == "fail"
    assert "non-loopback" in reason


def test_network_isolation_fail_when_only_one_param_present():
    # partial evidence is not confirmation — fail closed, not warn
    status, _ = network_isolation_check("internal", "")
    assert status == "fail"
