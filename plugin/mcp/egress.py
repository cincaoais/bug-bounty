# plugin/mcp/egress.py
"""Active-lab egress policy (milestone 1): pure decision logic, no I/O.

Standalone; NOT wired into the live plugin. Unlike sandbox mode, non-loopback
hosts ARE allowed here — this is the active-lab posture (one authorized external
target, deny everything else). See
docs/superpowers/specs/2026-09-04-bb-egress-chokepoint-design.md
"""
from __future__ import annotations

from dataclasses import dataclass

import sandbox  # plugin/mcp on sys.path (conftest / proxy startup insert)


@dataclass(frozen=True)
class Rule:
    host: str
    port: int | None = None  # None = any port on this host


class Allowlist:
    """Destination allowlist. Deny-by-default."""

    def __init__(self, rules):
        self.rules = list(rules)

    def allows(self, host, port) -> tuple[bool, str]:
        ch = sandbox.canonical_host(host)
        if ch is None:
            return (False, "invalid/empty host (deny-by-default)")
        if not self.rules:
            return (False, "empty allowlist (deny-by-default)")
        for rule in self.rules:
            rh = sandbox.canonical_host(rule.host)
            if rh is not None and rh == ch and (rule.port is None or rule.port == port):
                shown = rule.port if rule.port is not None else "*"
                return (True, f"matches allowlist rule {rule.host}:{shown}")
        return (False, f"{ch}:{port} not on allowlist (deny-by-default)")


# append to plugin/mcp/egress.py
class TokenBucket:
    """Per-host token bucket. Deterministic: the caller passes `now` (seconds).
    One token consumed per request; refills at `refill_per_sec`."""

    def __init__(self, capacity, refill_per_sec):
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self._state: dict[str, tuple[float, float]] = {}  # host -> (tokens, last_ts)

    def try_consume(self, host, now) -> tuple[bool, float]:
        tokens, last = self._state.get(host, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
        if tokens >= 1.0:
            self._state[host] = (tokens - 1.0, now)
            return (True, 0.0)
        needed = 1.0 - tokens
        retry_after = needed / self.refill_per_sec if self.refill_per_sec > 0 else float("inf")
        self._state[host] = (tokens, now)
        return (False, retry_after)


# append to plugin/mcp/egress.py
@dataclass(frozen=True)
class PolicyDecision:
    allow: bool
    code: int          # 200 | 403 | 429
    reason: str
    gate: str          # "allow" | "destination" | "rate"
    host: str
    port: int | None


def decide(host, port, now, allowlist, buckets) -> PolicyDecision:
    ch = sandbox.canonical_host(host) or host
    ok, reason = allowlist.allows(host, port)
    if not ok:
        return PolicyDecision(False, 403, reason, "destination", ch, port)
    allowed, retry = buckets.try_consume(ch, now)
    if not allowed:
        return PolicyDecision(False, 429, f"rate limit exceeded (retry after {retry:.2f}s)",
                              "rate", ch, port)
    return PolicyDecision(True, 200, reason, "allow", ch, port)
