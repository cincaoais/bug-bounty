"""Deterministic scope matcher. Pure functions, no I/O, no network, no LLM.

Security-critical: this decides whether a host is authorized to test.

Two invariants, enforced by evaluation order:
  1. Explicit out-of-scope always wins over any in-scope match.
  2. Anything not matched by an in-scope rule is DENIED (deny-by-default).

The same function backs both the MCP `check_scope` tool and the PreToolUse hook,
so there is exactly one definition of "in scope" in the system.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    pattern: str            # "*.example.com" | "example.com" | "example.com/admin" | "10.0.0.0/8"
    in_scope: bool          # True = in scope, False = explicitly out of scope
    asset_type: str = ""    # informational only
    source: str = ""        # informational only


def _normalize_host(host: str) -> str:
    """Lowercase, strip scheme/userinfo/path/port/trailing-dot. Best-effort IDNA."""
    h = (host or "").strip().lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]          # drop any path
    if "@" in h:
        h = h.rsplit("@", 1)[1]     # drop userinfo
    if h.startswith("["):           # IPv6 literal: [::1]:8080
        h = h[1:].split("]", 1)[0]
    else:
        h = h.split(":", 1)[0]      # drop port
    h = h.rstrip(".")
    try:
        # ponytail: naive idna; unicode-pattern matching is a v2 concern if it ever comes up
        h = h.encode("idna").decode("ascii")
    except Exception:
        pass
    return h


def _split_pattern(pattern: str) -> tuple[str, str]:
    """Return (host_pattern, path_prefix). path_prefix is '' when the rule is host-only."""
    p = (pattern or "").strip().lower()
    if "://" in p:
        p = p.split("://", 1)[1]
    if _as_network(p) is not None:      # CIDR like 10.0.0.0/8: the /8 is a prefix, not a path
        return p, ""
    if "/" in p:
        host, path = p.split("/", 1)
        return host.rstrip("."), "/" + path.rstrip("/")
    return p.rstrip("."), ""


def _as_network(pattern: str):
    try:
        return ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return None


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _host_matches(host: str, host_pattern: str) -> bool:
    net = _as_network(host_pattern)
    if net is not None:
        ip = _as_ip(host)
        return ip is not None and ip in net
    if host_pattern.startswith("*."):
        base = host_pattern[2:]
        return host.endswith("." + base)   # subdomain only; apex needs its own rule
    return host == host_pattern


def _rule_matches(host: str, path: str | None, host_pat: str, path_pat: str) -> bool:
    if not _host_matches(host, host_pat):
        return False
    if path_pat:
        if path is None:
            return False               # a path-scoped rule needs a path to decide
        return (path or "/").startswith(path_pat)
    return True


def is_in_scope(host: str, path: str | None, rules) -> tuple[bool, str]:
    """(authorized, reason). Deny-by-default; explicit out-of-scope wins."""
    h = _normalize_host(host)
    if not h:
        return (False, "empty host (deny-by-default)")

    for r in rules:                    # out-of-scope precedence: check denies first
        if not r.in_scope:
            hp, pp = _split_pattern(r.pattern)
            if _rule_matches(h, path, hp, pp):
                return (False, f"explicit out-of-scope: {r.pattern}")

    for r in rules:
        if r.in_scope:
            hp, pp = _split_pattern(r.pattern)
            if _rule_matches(h, path, hp, pp):
                return (True, f"matches in-scope: {r.pattern}")

    return (False, "no matching in-scope rule (deny-by-default)")


if __name__ == "__main__":  # tiny self-check; real coverage is tests/test_scope.py
    rs = [Rule("*.example.com", True), Rule("internal.example.com", False)]
    assert is_in_scope("api.example.com", None, rs)[0] is True
    assert is_in_scope("internal.example.com", None, rs)[0] is False
    assert is_in_scope("evil.com", None, rs)[0] is False
    print("scope self-check ok")
