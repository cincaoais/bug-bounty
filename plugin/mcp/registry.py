"""Target registry + active-target state + scope rules + overrides.

Higher-level operations over db.py. Shared by the MCP server (server.py) and the
PreToolUse hook (scope-guard.py) so both agree on "which target is active" and
"what is its scope". No network, no LLM.

Timestamps are passed in by callers (the MCP server supplies them) so this module
stays pure-storage and easy to test; when omitted we fall back to UTC now.
"""
from __future__ import annotations

import datetime as _dt

import db
import sandbox
import scope as scopelib


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _ensure_registry():
    db.init_registry()


# ---- targets -----------------------------------------------------------------

def create_target(handle: str, platform: str = "", confidentiality: str = "public",
                  mode: str = "bounty", sandbox_app: str = "") -> dict:
    _ensure_registry()
    path = db.target_db_path(handle)          # validates handle (raises on unsafe)
    db.init_target_db(path)
    conn = db.connect(db.registry_path())
    try:
        conn.execute(
            "INSERT INTO target (handle, platform, confidentiality, db_path, created_at, active, "
            "mode, sandbox_app) VALUES (?,?,?,?,?,0,?,?)",
            (handle, platform, confidentiality, str(path), _now(), mode, sandbox_app),
        )
        conn.commit()
    finally:
        conn.close()
    switch_target(handle)
    return {"handle": handle, "db_path": str(path), "confidentiality": confidentiality,
            "mode": mode, "sandbox_app": sandbox_app}


def switch_target(handle: str) -> dict:
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        row = conn.execute("SELECT id FROM target WHERE handle=?", (handle,)).fetchone()
        if row is None:
            raise ValueError(f"no such target: {handle}")
        conn.execute("UPDATE target SET active=0")
        conn.execute("UPDATE target SET active=1 WHERE id=?", (row["id"],))
        conn.commit()
    finally:
        conn.close()
    return {"active": handle}


def list_targets() -> list[dict]:
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        rows = conn.execute(
            "SELECT handle, platform, confidentiality, scope_fetched_at, active "
            "FROM target ORDER BY handle"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def active_target() -> dict | None:
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        r = conn.execute(
            "SELECT handle, platform, confidentiality, db_path, scope_fetched_at, "
            "mode, sandbox_app FROM target WHERE active=1"
        ).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def is_sandbox() -> bool:
    """True iff the active target's mode is 'sandbox'. False (not an error) when
    there is no active target — same fail-closed posture as check_scope."""
    t = active_target()
    return t is not None and t["mode"] == "sandbox"


# ---- scope rules -------------------------------------------------------------

def set_scope_rules(handle: str, rules: list[dict], fetched_at: str | None = None) -> int:
    """Replace the target's scope rules. `rules` = [{pattern, in_scope, asset_type?, source?}]."""
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        conn.execute("DELETE FROM scope_rule")
        conn.executemany(
            "INSERT INTO scope_rule (pattern, asset_type, in_scope, source, added_at) VALUES (?,?,?,?,?)",
            [
                (r["pattern"], r.get("asset_type", ""), 1 if r.get("in_scope", True) else 0,
                 r.get("source", ""), _now())
                for r in rules
            ],
        )
        conn.commit()
    finally:
        conn.close()
    reg = db.connect(db.registry_path())
    try:
        reg.execute("UPDATE target SET scope_fetched_at=? WHERE handle=?",
                    (fetched_at or _now(), handle))
        reg.commit()
    finally:
        reg.close()
    return len(rules)


def scope_rules(handle: str) -> list[scopelib.Rule]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        rows = conn.execute("SELECT pattern, asset_type, in_scope, source FROM scope_rule").fetchall()
        return [
            scopelib.Rule(pattern=r["pattern"], in_scope=bool(r["in_scope"]),
                          asset_type=r["asset_type"] or "", source=r["source"] or "")
            for r in rows
        ]
    finally:
        conn.close()


def active_scope_rules() -> list[scopelib.Rule]:
    t = active_target()
    return scope_rules(t["handle"]) if t else []


def _parse_sandbox_pattern(pattern: str) -> tuple[str | None, int | None]:
    """Parse a scope_rule pattern into (host, port) for the sandbox allow-list.

    The sandbox skill stores allow-list entries as plain host:port patterns —
    `localhost:3000`, `127.0.0.1:3000`, or the IPv6 bracket form `[::1]:3000`.
    A port is mandatory for a sandbox rule (sandbox.SandboxRule enforces the
    same invariant); a pattern with no parseable port returns (None, None) and
    is skipped by the caller rather than guessed at.
    """
    p = (pattern or "").strip()
    if not p:
        return (None, None)
    if p.startswith("["):
        end = p.find("]")
        if end == -1:
            return (None, None)
        host = p[1:end].strip().lower()
        tail = p[end + 1:]
        if not tail.startswith(":"):
            return (None, None)
        port_s = tail[1:]
    elif ":" in p:
        host, _, port_s = p.rpartition(":")
        host = host.strip().lower()
    else:
        return (None, None)
    if not host:
        return (None, None)
    try:
        port = int(port_s)
    except (TypeError, ValueError):
        return (None, None)
    if not (0 <= port <= 65535):
        return (None, None)
    return (host, port)


def sandbox_rules(handle: str | None = None) -> list[sandbox.SandboxRule]:
    """Build the sandbox allow-list from the target's in-scope scope_rule rows.

    Reads the active target's rules by default, or `handle`'s if given. Only
    `in_scope=1` rows are considered; each `pattern` is parsed as host:port
    (see `_parse_sandbox_pattern`). Patterns with no parseable port are
    skipped — a sandbox rule without a port is meaningless (sandbox.py's own
    invariant: `port is None` is always a deny, never a defer).
    """
    if handle is None:
        t = active_target()
        if t is None:
            return []
        handle = t["handle"]
    rules: list[sandbox.SandboxRule] = []
    for r in scope_rules(handle):
        if not r.in_scope:
            continue
        host, port = _parse_sandbox_pattern(r.pattern)
        if host is None or port is None:
            continue
        rules.append(sandbox.SandboxRule(host, port))
    return rules


def check_scope(host: str, path: str | None = None, port: int | None = None) -> tuple[bool, str]:
    """Scope check against the ACTIVE target. Single source of truth for tool + hook.

    `port` is accepted so callers (the PreToolUse hook) can thread it through
    uniformly now that extraction carries a port.

    Sandbox targets (`mode=='sandbox'`) answer via `sandbox.sandbox_allows`
    against `sandbox_rules()` — NOT `take_override`-then-`is_in_scope`. This
    keeps the check_scope tool's answer consistent with what the hook actually
    enforces in sandbox mode (docs/02-PLAN.md Slice 2.2, finding #10): a
    denied sandbox host is the thing being contained, never a false positive
    an override should be able to clear.

    Real-program (bounty) targets keep the EXACT prior behavior:
    override-then-is_in_scope, port ignored.
    """
    t = active_target()
    if t is None:
        return (False, "no active target")
    if t["mode"] == "sandbox":
        return sandbox.sandbox_allows(host, port, sandbox_rules(t["handle"]))
    if take_override(host):
        return (True, f"one-time override for {host}")
    return scopelib.is_in_scope(host, path, scope_rules(t["handle"]))


def is_host_in_scope(host: str) -> bool:
    """Non-consuming, rules-only scope check for the ACTIVE target. Unlike
    check_scope it does NOT consume a one-time override — safe for a dry-run
    verify (active_lab_preflight). An override-gated host reads as NOT in scope,
    which is correct: a burnable override is not a stable allow-list entry."""
    t = active_target()
    if t is None or t["mode"] == "sandbox":
        return False
    ok, _ = scopelib.is_in_scope(host, None, scope_rules(t["handle"]))
    return ok


def scope_status(handle: str | None = None) -> dict:
    t = active_target() if handle is None else {"handle": handle}
    if t is None:
        return {"active": None}
    conn = db.connect(db.registry_path())
    try:
        r = conn.execute("SELECT handle, scope_fetched_at FROM target WHERE handle=?",
                         (t["handle"],)).fetchone()
    finally:
        conn.close()
    fetched = r["scope_fetched_at"] if r else None
    stale = _is_stale(fetched)
    rules = scope_rules(t["handle"])
    return {
        "handle": t["handle"], "fetched_at": fetched, "stale": stale,
        "in_scope_rules": sum(1 for x in rules if x.in_scope),
        "out_of_scope_rules": sum(1 for x in rules if not x.in_scope),
    }


def _is_stale(fetched_at: str | None, days: int = 7) -> bool:
    if not fetched_at:
        return True
    try:
        ts = _dt.datetime.fromisoformat(fetched_at)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=_dt.timezone.utc)
        return (_dt.datetime.now(_dt.timezone.utc) - ts).days >= days
    except ValueError:
        return True


# ---- overrides (single-use, logged) ------------------------------------------

def add_override(host: str, reason: str = "") -> dict:
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        conn.execute("INSERT INTO scope_override (host, reason, created_at, used) VALUES (?,?,?,0)",
                     (host.strip().lower(), reason, _now()))
        conn.commit()
    finally:
        conn.close()
    return {"host": host.strip().lower(), "reason": reason}


def take_override(host: str) -> bool:
    """Consume one unused override for host. Returns True if one was found + consumed."""
    _ensure_registry()
    h = (host or "").strip().lower()
    conn = db.connect(db.registry_path())
    try:
        r = conn.execute(
            "SELECT id FROM scope_override WHERE host=? AND used=0 ORDER BY id LIMIT 1", (h,)
        ).fetchone()
        if r is None:
            return False
        conn.execute("UPDATE scope_override SET used=1 WHERE id=?", (r["id"],))
        conn.commit()
        return True
    finally:
        conn.close()


# ---- legal action-class overrides (single-use, logged) -----------------------
#
# The legalgate layer of the PreToolUse hook denies gated ACTION CLASSES
# (destructive|dos|credential|pii) independently of host scope. These mirror the
# scope_override trio above but are keyed by class, and stamp used_at so the
# consumption is a legal audit trail, not just a boolean.

_LEGAL_CLASSES = ("destructive", "dos", "credential", "pii")


def add_legal_override(gate_class: str, reason: str = "") -> dict:
    _ensure_registry()
    gc = (gate_class or "").strip().lower()
    if gc not in _LEGAL_CLASSES:
        raise ValueError(f"unknown gate_class {gate_class!r}; expected one of {_LEGAL_CLASSES}")
    conn = db.connect(db.registry_path())
    try:
        conn.execute(
            "INSERT INTO legal_override (gate_class, reason, created_at, used) VALUES (?,?,?,0)",
            (gc, reason, _now()),
        )
        conn.commit()
    finally:
        conn.close()
    return {"gate_class": gc, "reason": reason}


def has_legal_override(gate_class: str) -> bool:
    """Peek: is there an unused override for this class? Does NOT consume it, so
    the hook can check that EVERY violated class is covered before burning any."""
    _ensure_registry()
    gc = (gate_class or "").strip().lower()
    conn = db.connect(db.registry_path())
    try:
        r = conn.execute(
            "SELECT 1 FROM legal_override WHERE gate_class=? AND used=0 LIMIT 1", (gc,)
        ).fetchone()
        return r is not None
    finally:
        conn.close()


def take_legal_override(gate_class: str) -> bool:
    """Consume one unused override for the class, stamping used_at. Returns True
    if one was found + consumed."""
    _ensure_registry()
    gc = (gate_class or "").strip().lower()
    conn = db.connect(db.registry_path())
    try:
        r = conn.execute(
            "SELECT id FROM legal_override WHERE gate_class=? AND used=0 ORDER BY id LIMIT 1", (gc,)
        ).fetchone()
        if r is None:
            return False
        conn.execute("UPDATE legal_override SET used=1, used_at=? WHERE id=?", (_now(), r["id"]))
        conn.commit()
        return True
    finally:
        conn.close()


def unused_legal_overrides() -> dict:
    """Count of unused overrides per class — for legal_status()."""
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        rows = conn.execute(
            "SELECT gate_class, COUNT(*) AS n FROM legal_override WHERE used=0 GROUP BY gate_class"
        ).fetchall()
        return {r["gate_class"]: r["n"] for r in rows}
    finally:
        conn.close()


# ---- legal attestation (standing per-target status) --------------------------
#
# The one-time posture recorded before live traffic: CSSP-licence status (Cyber
# Security Act 2024) and jurisdiction/extraterritorial exposure (CCA 1997 s.9).
# Stored on the target row (guarded ALTER columns added in db.init_registry).

def set_attestation(handle: str, jurisdiction: str = "", tester_location: str = "",
                    cssp_licensed: bool = False, authorization_ref: str = "",
                    attested_at: str | None = None) -> dict:
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        row = conn.execute("SELECT id FROM target WHERE handle=?", (handle,)).fetchone()
        if row is None:
            raise ValueError(f"no such target: {handle}")
        conn.execute(
            "UPDATE target SET jurisdiction=?, tester_location=?, cssp_licensed=?, "
            "authorization_ref=?, attested_at=? WHERE handle=?",
            (jurisdiction, tester_location, 1 if cssp_licensed else 0,
             authorization_ref, attested_at or _now(), handle),
        )
        conn.commit()
    finally:
        conn.close()
    return get_attestation(handle)


def get_attestation(handle: str) -> dict:
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        r = conn.execute(
            "SELECT handle, jurisdiction, tester_location, cssp_licensed, "
            "authorization_ref, attested_at FROM target WHERE handle=?", (handle,)
        ).fetchone()
    finally:
        conn.close()
    if r is None:
        return {"handle": handle, "attested": False}
    d = dict(r)
    d["cssp_licensed"] = bool(d["cssp_licensed"])
    d["attested"] = bool((d.get("attested_at") or "").strip())
    return d


def is_attested(handle: str) -> bool:
    return get_attestation(handle).get("attested", False)


# ---- active-lab ROE gate (standing per-target permission) ---------------------
#
# Whether the PROGRAM's published ROE permits active/automated testing. Distinct
# from the legal attestation above (that is the tester's posture). Default: NOT
# permitted — recorded once, deliberately. Stored on the target row (guarded
# ALTER columns added in db.init_registry, v4). Grants no traffic by itself.

def set_active_permission(handle: str, permitted: bool, note: str = "",
                          permitted_at: str | None = None) -> dict:
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        row = conn.execute("SELECT id FROM target WHERE handle=?", (handle,)).fetchone()
        if row is None:
            raise ValueError(f"no such target: {handle}")
        conn.execute(
            "UPDATE target SET active_testing_permitted=?, active_permitted_note=?, "
            "active_permitted_at=? WHERE handle=?",
            (1 if permitted else 0, note, permitted_at or _now(), handle),
        )
        conn.commit()
    finally:
        conn.close()
    return get_active_permission(handle)


def get_active_permission(handle: str) -> dict:
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        r = conn.execute(
            "SELECT handle, active_testing_permitted, active_permitted_note, "
            "active_permitted_at FROM target WHERE handle=?", (handle,)
        ).fetchone()
    finally:
        conn.close()
    if r is None:
        return {"handle": handle, "active_testing_permitted": False, "note": "", "at": ""}
    return {
        "handle": r["handle"],
        "active_testing_permitted": bool(r["active_testing_permitted"]),
        "note": r["active_permitted_note"] or "",
        "at": r["active_permitted_at"] or "",
    }


def active_testing_permitted(handle: str) -> bool:
    return get_active_permission(handle).get("active_testing_permitted", False)


if __name__ == "__main__":
    import os, tempfile
    os.environ["BB_DATA_DIR"] = tempfile.mkdtemp()
    create_target("acme", "hackerone", "public")
    set_scope_rules("acme", [{"pattern": "*.acme.com", "in_scope": True},
                             {"pattern": "blog.acme.com", "in_scope": False}])
    assert check_scope("api.acme.com")[0] is True
    assert check_scope("blog.acme.com")[0] is False
    assert check_scope("evil.com")[0] is False
    add_override("evil.com", "confirmed authorized by hand")
    assert check_scope("evil.com")[0] is True     # override consumed
    assert check_scope("evil.com")[0] is False    # only once
    assert scope_status("acme")["in_scope_rules"] == 1
    # legal overrides: peek is non-consuming; take consumes once
    assert has_legal_override("destructive") is False
    add_legal_override("destructive", "authorized destructive PoC step")
    assert has_legal_override("destructive") is True
    assert has_legal_override("destructive") is True     # peek didn't consume
    assert take_legal_override("destructive") is True
    assert take_legal_override("destructive") is False    # only once
    # attestation round-trip
    assert is_attested("acme") is False
    set_attestation("acme", jurisdiction="MY", tester_location="MY",
                    cssp_licensed=True, authorization_ref="https://h1/acme")
    assert is_attested("acme") is True
    assert get_attestation("acme")["cssp_licensed"] is True
    print("registry self-check ok")
