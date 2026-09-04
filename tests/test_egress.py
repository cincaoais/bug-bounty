# tests/test_egress.py
import egress
from egress import Rule, Allowlist


def test_allowlist_allows_exact_host_and_port():
    al = Allowlist([Rule("example.com", 443)])
    assert al.allows("example.com", 443)[0] is True


def test_allowlist_denies_wrong_port():
    al = Allowlist([Rule("example.com", 443)])
    ok, reason = al.allows("example.com", 80)
    assert ok is False and "allowlist" in reason.lower()


def test_allowlist_denies_off_allowlist_host():
    al = Allowlist([Rule("example.com", 443)])
    assert al.allows("evil.example", 443)[0] is False


def test_allowlist_empty_denies_all():
    assert Allowlist([]).allows("example.com", 443)[0] is False


def test_allowlist_none_port_rule_allows_any_port():
    al = Allowlist([Rule("example.com", None)])
    assert al.allows("example.com", 8443)[0] is True


def test_allowlist_folds_loopback_spelling():
    # canonical_host folds 2130706433 -> 127.0.0.1
    al = Allowlist([Rule("127.0.0.1", 3000)])
    assert al.allows("2130706433", 3000)[0] is True


def test_allowlist_denies_invalid_host():
    assert Allowlist([Rule("example.com", 443)]).allows("", 443)[0] is False
