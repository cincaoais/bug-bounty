"""Active-lab preflight posture checker (active-mode milestone 2): pure, no I/O.

Returns whether the active-testing containment posture is fully verified. Makes
NO network/subprocess call and reads NO state — the MCP tool gathers registry
facts + human-run probe evidence and passes them here. Fail-closed: any missing
or ambiguous input fails its check and forces ready=False.

Nothing consumes `ready` to grant traffic — the scope-guard hook is unchanged.
See docs/superpowers/specs/2026-09-05-bb-active-lab-preflight-design.md
"""
from __future__ import annotations


def _check(name, ok, detail):
    return {"name": name, "status": "pass" if ok else "fail", "detail": detail}


def active_lab_preflight(
    attested: bool,
    active_permitted: bool,
    allowlist_hosts,
    offscope_allowlist_hosts,
    proxy_reachable: str = "",
    firewall_direct_egress: str = "",
    proxy_to_target: str = "",
) -> dict:
    allow = list(allowlist_hosts or [])
    offscope = list(offscope_allowlist_hosts or [])
    sealed = firewall_direct_egress == "BLOCKED" and proxy_to_target == "OK"
    checks = [
        _check("legal-attestation", bool(attested),
               "legal posture recorded" if attested
               else "no legal attestation on record (run legal_attest)"),
        _check("roe-gate", bool(active_permitted),
               "program ROE permits active testing" if active_permitted
               else "active testing not permitted for this program (run set_active_permission)"),
        _check("allowlist-in-scope", bool(allow) and not offscope,
               f"{len(allow)} allowlist host(s), all in scope" if (allow and not offscope)
               else ("allowlist is empty" if not allow
                     else "allowlist has out-of-scope host(s): " + ", ".join(offscope))),
        _check("proxy-reachable", proxy_reachable == "UP",
               "egress proxy is up" if proxy_reachable == "UP"
               else f"proxy not confirmed up (evidence: {proxy_reachable or 'none'})"),
        _check("firewall-sealed", sealed,
               "direct egress blocked and proxy path works" if sealed
               else (f"firewall not sealed (direct egress: {firewall_direct_egress or 'none'}, "
                     f"proxy->target: {proxy_to_target or 'none'})")),
    ]
    return {"ready": all(c["status"] == "pass" for c in checks), "checks": checks}


def rate_step(tokens, elapsed_sec, capacity, refill_per_sec):
    """Token-bucket step: refill by elapsed, then try to consume 1 token.
    Returns (allowed: bool, new_tokens: float, retry_after: float). Pure — no clock, no I/O."""
    tokens = min(float(capacity), float(tokens) + float(elapsed_sec) * float(refill_per_sec))
    if tokens >= 1.0:
        return (True, tokens - 1.0, 0.0)
    needed = 1.0 - tokens
    retry = needed / refill_per_sec if refill_per_sec > 0 else float("inf")
    return (False, tokens, retry)
