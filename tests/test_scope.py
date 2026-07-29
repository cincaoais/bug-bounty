"""Truth table for the scope matcher. This is the security-critical core:
if is_in_scope() is wrong, the user tests something they are not authorized to.

Every case is (host, path, rules) -> expected in_scope bool, with a note on why.
Deny-by-default and out-of-scope precedence are the two invariants that must hold.
"""
import scope
from scope import Rule, is_in_scope


def _in(*patterns):
    return [Rule(pattern=p, in_scope=True) for p in patterns]


def _out(*patterns):
    return [Rule(pattern=p, in_scope=False) for p in patterns]


# ---- exact host --------------------------------------------------------------

def test_exact_host_in_scope():
    ok, _ = is_in_scope("example.com", None, _in("example.com"))
    assert ok is True


def test_unknown_host_denied_by_default():
    ok, reason = is_in_scope("other.com", None, _in("example.com"))
    assert ok is False
    assert "deny-by-default" in reason


def test_empty_rules_denies():
    ok, _ = is_in_scope("example.com", None, [])
    assert ok is False


# ---- wildcard ----------------------------------------------------------------

def test_wildcard_matches_subdomain():
    assert is_in_scope("api.example.com", None, _in("*.example.com"))[0] is True


def test_wildcard_matches_deep_subdomain():
    assert is_in_scope("a.b.example.com", None, _in("*.example.com"))[0] is True


def test_wildcard_does_not_match_apex():
    # *.example.com must NOT authorize example.com itself
    assert is_in_scope("example.com", None, _in("*.example.com"))[0] is False


def test_wildcard_needs_own_apex_rule():
    assert is_in_scope("example.com", None, _in("*.example.com", "example.com"))[0] is True


def test_suffix_confusion_rejected():
    # notexample.com must not match *.example.com or example.com
    assert is_in_scope("notexample.com", None, _in("*.example.com", "example.com"))[0] is False


def test_sibling_domain_via_suffix_rejected():
    assert is_in_scope("x.example.com.evil.com", None, _in("*.example.com"))[0] is False


# ---- out-of-scope precedence -------------------------------------------------

def test_out_of_scope_beats_wildcard_in_scope():
    rules = _in("*.example.com") + _out("internal.example.com")
    ok, reason = is_in_scope("internal.example.com", None, rules)
    assert ok is False
    assert "out-of-scope" in reason


def test_out_of_scope_wildcard_beats_in_scope_wildcard():
    rules = _in("*.example.com") + _out("*.dev.example.com")
    assert is_in_scope("x.dev.example.com", None, rules)[0] is False


def test_out_of_scope_order_independent():
    # order of rules in the list must not change the verdict
    rules = _out("internal.example.com") + _in("*.example.com")
    assert is_in_scope("internal.example.com", None, rules)[0] is False


# ---- normalization -----------------------------------------------------------

def test_case_insensitive():
    assert is_in_scope("API.Example.COM", None, _in("*.example.com"))[0] is True


def test_port_stripped():
    assert is_in_scope("example.com:8443", None, _in("example.com"))[0] is True


def test_trailing_dot_stripped():
    assert is_in_scope("example.com.", None, _in("example.com"))[0] is True


def test_url_as_host_normalized():
    assert is_in_scope("https://api.example.com/x", None, _in("*.example.com"))[0] is True


def test_userinfo_stripped():
    assert is_in_scope("user@example.com", None, _in("example.com"))[0] is True


def test_empty_host_denied():
    assert is_in_scope("", None, _in("*.example.com"))[0] is False


# ---- IP / CIDR ---------------------------------------------------------------

def test_exact_ip():
    assert is_in_scope("192.168.1.10", None, _in("192.168.1.10"))[0] is True


def test_cidr_membership():
    assert is_in_scope("10.1.2.3", None, _in("10.0.0.0/8"))[0] is True


def test_cidr_non_membership_denied():
    assert is_in_scope("11.1.2.3", None, _in("10.0.0.0/8"))[0] is False


def test_out_of_scope_ip_beats_in_cidr():
    rules = _in("10.0.0.0/8") + _out("10.0.0.1")
    assert is_in_scope("10.0.0.1", None, rules)[0] is False


def test_domain_not_matched_by_cidr():
    assert is_in_scope("example.com", None, _in("10.0.0.0/8"))[0] is False


# ---- path-scoped rules -------------------------------------------------------

def test_path_scoped_in_scope_match():
    assert is_in_scope("example.com", "/api/users", _in("example.com/api"))[0] is True


def test_path_scoped_no_match_other_path():
    # a path-scoped in-scope rule does not authorize a different path
    assert is_in_scope("example.com", "/admin", _in("example.com/api"))[0] is False


def test_path_scoped_out_beats_host_in():
    rules = _in("example.com") + _out("example.com/admin")
    assert is_in_scope("example.com", "/admin/panel", rules)[0] is False
    # but a non-admin path on the same host is still in scope
    assert is_in_scope("example.com", "/public", rules)[0] is True


def test_path_scoped_rule_needs_path_to_match():
    # with no path provided, a path-scoped rule cannot match (neither in nor out)
    assert is_in_scope("example.com", None, _in("example.com/api"))[0] is False
