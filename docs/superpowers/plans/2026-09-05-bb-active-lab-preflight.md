# bb Active-Lab Verified Posture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-program "active testing permitted?" gate and a pure `active_lab_preflight` posture checker (with its MCP tools and firewall-setup docs) that let a user set up and *verify* an active-testing containment posture — without granting any traffic.

**Architecture:** Storage mirrors the existing legal-attestation pattern (guarded-ALTER columns on `target`, `set_/get_` registry functions). The checker is a new pure module `plugin/mcp/activelab.py` (no I/O), surfaced by an MCP tool that mirrors `sandbox_preflight`. `scope-guard.py` is not touched; nothing reads the `ready` verdict to grant traffic.

**Tech Stack:** Python 3.13 standard library + the existing `mcp` SDK. No new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-09-05-bb-active-lab-preflight-design.md`

## Global Constraints

- **Python 3.13, stdlib + existing `mcp` only** — no new runtime dependency.
- **INVARIANT — the valve stays closed:** do NOT modify `plugin/hooks/scope-guard.py`. Nothing may read `active_lab_preflight`'s `ready` to grant traffic. Ingest-only stays the default.
- **Fail-closed:** the ROE gate defaults to *not permitted*; any missing/ambiguous preflight input fails its check; an empty or out-of-scope allowlist fails.
- **Storage pattern:** new per-target facts are guarded-ALTER columns on `target` (like attestation), added in `db.init_registry`; `SCHEMA_VERSION` goes 3 → 4.
- **Distinctness:** the ROE gate (program permits active testing) is independent of legal attestation (tester's posture); both are separate facts.
- Commit after every task. End each commit body with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

---

## File Structure

- `plugin/mcp/db.py` — MODIFY: bump `SCHEMA_VERSION` to 4; add 3 guarded-ALTER columns to `target` in `init_registry`.
- `plugin/mcp/registry.py` — MODIFY: add `set_active_permission` / `get_active_permission` / `active_testing_permitted` (mirror `set_attestation` / `get_attestation` / `is_attested`).
- `plugin/mcp/activelab.py` — CREATE: pure `active_lab_preflight(...)` checker.
- `plugin/mcp/server.py` — MODIFY: `import activelab`; add `set_active_permission` and `active_lab_preflight` MCP tools.
- `plugin/skills/bb-start/SKILL.md` — MODIFY: add a short ROE-permission capture step.
- `docs/active-lab-setup.md` — CREATE: VM firewall setup + the 3-probe contract.
- `tests/test_activelab.py` — CREATE: checker unit tests, registry-gate tests, migration/idempotency, and MCP-tool smoke tests.

---

### Task 1: ROE gate storage (db columns + registry functions)

**Files:**
- Modify: `plugin/mcp/db.py`
- Modify: `plugin/mcp/registry.py`
- Test: `tests/test_activelab.py`

**Interfaces:**
- Consumes: `db.connect`, `db.registry_path`, `db.init_registry`, `registry._ensure_registry`, `registry._now` (existing).
- Produces:
  - `registry.set_active_permission(handle: str, permitted: bool, note: str = "", permitted_at: str | None = None) -> dict`
  - `registry.get_active_permission(handle: str) -> dict` → `{handle, active_testing_permitted: bool, note, at}`
  - `registry.active_testing_permitted(handle: str) -> bool`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_activelab.py
import importlib
import pytest


def _fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("BB_DATA_DIR", str(tmp_path))
    import db, registry
    importlib.reload(db)
    importlib.reload(registry)
    return db, registry


def test_active_permission_defaults_to_not_permitted(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    assert registry.active_testing_permitted("acme") is False
    d = registry.get_active_permission("acme")
    assert d["active_testing_permitted"] is False and d["note"] == ""


def test_set_active_permission_roundtrip(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    out = registry.set_active_permission("acme", True, note="policy allows <=5rps")
    assert out["active_testing_permitted"] is True
    assert out["note"] == "policy allows <=5rps" and out["at"]
    assert registry.active_testing_permitted("acme") is True


def test_set_active_permission_false_returns_to_not_permitted(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.set_active_permission("acme", True, note="x")
    registry.set_active_permission("acme", False, note="reconsidered")
    assert registry.active_testing_permitted("acme") is False


def test_get_active_permission_unknown_target_is_not_permitted(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    d = registry.get_active_permission("does-not-exist")
    assert d["active_testing_permitted"] is False


def test_set_active_permission_unknown_target_raises(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        registry.set_active_permission("nope", True)


def test_gate_columns_present_and_init_idempotent(tmp_path, monkeypatch):
    db, _ = _fresh(tmp_path, monkeypatch)
    db.init_registry()
    db.init_registry()  # guarded ALTER: must not raise on re-run
    conn = db.connect(db.registry_path())
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(target)")}
    conn.close()
    assert {"active_testing_permitted", "active_permitted_note",
            "active_permitted_at"} <= cols
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_activelab.py -q`
Expected: FAIL (`AttributeError: module 'registry' has no attribute 'set_active_permission'`, and the columns are absent).

- [ ] **Step 3a: Add the columns in `plugin/mcp/db.py`**

Change the constant near the top of the file from `SCHEMA_VERSION = 3` to:

```python
SCHEMA_VERSION = 4
```

In `init_registry()`, immediately after the attestation `_add_column_if_missing(... "attested_at" ...)` line and before `conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")`, add:

```python
        # Active-lab ROE gate (v4): whether the PROGRAM's published policy permits
        # active/automated testing — distinct from the tester's legal attestation
        # above. Default 0 = NOT permitted (fail-closed). Same guarded-ALTER pattern.
        _add_column_if_missing(conn, "target", "active_testing_permitted INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(conn, "target", "active_permitted_note TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(conn, "target", "active_permitted_at TEXT NOT NULL DEFAULT ''")
```

- [ ] **Step 3b: Add the registry functions in `plugin/mcp/registry.py`**

Append after `is_attested` (end of the legal-attestation section):

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_activelab.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add plugin/mcp/db.py plugin/mcp/registry.py tests/test_activelab.py
git commit -m "feat(activelab): per-program ROE active-testing gate (schema v4, fail-closed)"
```

---

### Task 2: Pure `active_lab_preflight` checker

**Files:**
- Create: `plugin/mcp/activelab.py`
- Test: `tests/test_activelab.py`

**Interfaces:**
- Produces: `activelab.active_lab_preflight(attested: bool, active_permitted: bool, allowlist_hosts: list[str], offscope_allowlist_hosts: list[str], proxy_reachable: str = "", firewall_direct_egress: str = "", proxy_to_target: str = "") -> dict` → `{"ready": bool, "checks": [{"name", "status", "detail"}]}`. Statuses are `"pass"`/`"fail"`. Five checks: `legal-attestation`, `roe-gate`, `allowlist-in-scope`, `proxy-reachable`, `firewall-sealed`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_activelab.py
import activelab


def _all_good_kwargs(**over):
    base = dict(attested=True, active_permitted=True,
                allowlist_hosts=["api.acme.com"], offscope_allowlist_hosts=[],
                proxy_reachable="UP", firewall_direct_egress="BLOCKED",
                proxy_to_target="OK")
    base.update(over)
    return base


def _status(result, name):
    return {c["name"]: c["status"] for c in result["checks"]}[name]


def test_preflight_ready_when_all_pass():
    r = activelab.active_lab_preflight(**_all_good_kwargs())
    assert r["ready"] is True
    assert all(c["status"] == "pass" for c in r["checks"])


def test_preflight_fails_without_attestation():
    r = activelab.active_lab_preflight(**_all_good_kwargs(attested=False))
    assert r["ready"] is False and _status(r, "legal-attestation") == "fail"


def test_preflight_fails_without_roe_gate():
    r = activelab.active_lab_preflight(**_all_good_kwargs(active_permitted=False))
    assert r["ready"] is False and _status(r, "roe-gate") == "fail"


def test_preflight_fails_on_empty_allowlist():
    r = activelab.active_lab_preflight(**_all_good_kwargs(allowlist_hosts=[]))
    assert r["ready"] is False and _status(r, "allowlist-in-scope") == "fail"


def test_preflight_fails_on_offscope_allowlist_host():
    r = activelab.active_lab_preflight(
        **_all_good_kwargs(allowlist_hosts=["api.acme.com", "evil.example"],
                           offscope_allowlist_hosts=["evil.example"]))
    assert r["ready"] is False and _status(r, "allowlist-in-scope") == "fail"


def test_preflight_fails_closed_on_missing_proxy_evidence():
    r = activelab.active_lab_preflight(**_all_good_kwargs(proxy_reachable=""))
    assert r["ready"] is False and _status(r, "proxy-reachable") == "fail"


def test_preflight_fails_when_direct_egress_open():
    r = activelab.active_lab_preflight(**_all_good_kwargs(firewall_direct_egress="OPEN"))
    assert r["ready"] is False and _status(r, "firewall-sealed") == "fail"


def test_preflight_fails_when_proxy_to_target_fails():
    r = activelab.active_lab_preflight(**_all_good_kwargs(proxy_to_target="FAIL"))
    assert r["ready"] is False and _status(r, "firewall-sealed") == "fail"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_activelab.py -k preflight -q`
Expected: FAIL (`ModuleNotFoundError: No module named 'activelab'`).

- [ ] **Step 3: Write minimal implementation**

```python
# plugin/mcp/activelab.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_activelab.py -q`
Expected: PASS (14 passed).

- [ ] **Step 5: Commit**

```bash
git add plugin/mcp/activelab.py tests/test_activelab.py
git commit -m "feat(activelab): pure active_lab_preflight checker, 5 fail-closed checks"
```

---

### Task 3: MCP tools (`set_active_permission`, `active_lab_preflight`)

**Files:**
- Modify: `plugin/mcp/server.py`
- Test: `tests/test_activelab.py`

**Interfaces:**
- Consumes: `registry.active_target`, `registry.is_attested`, `registry.active_testing_permitted`, `registry.set_active_permission`, `registry.check_scope`, `activelab.active_lab_preflight`.
- Produces (module-level callables, per the `@mcp.tool()` pattern): `server.set_active_permission(permitted: bool, note: str = "", handle: str = "") -> dict`; `server.active_lab_preflight(allowlist_hosts: list[str], proxy_reachable: str = "", firewall_direct_egress: str = "", proxy_to_target: str = "") -> dict`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_activelab.py
import os
import tempfile


def _reload_server(tmp):
    os.environ["BB_DATA_DIR"] = tmp
    import db, registry, server
    importlib.reload(db)
    importlib.reload(registry)
    importlib.reload(server)
    return server


def test_tools_registered_and_callable():
    import server
    assert callable(getattr(server, "set_active_permission"))
    assert callable(getattr(server, "active_lab_preflight"))


def test_active_lab_preflight_tool_ready_end_to_end():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        server.set_scope_rules("acme", [{"pattern": "*.acme.com", "in_scope": True}])
        server.legal_attest(jurisdiction="MY", tester_location="MY", authorization_ref="hackerone.com/acme")
        server.set_active_permission(True, note="policy permits automated testing")
        r = server.active_lab_preflight(["api.acme.com"], proxy_reachable="UP",
                                        firewall_direct_egress="BLOCKED", proxy_to_target="OK")
        assert r["ready"] is True


def test_active_lab_preflight_tool_flags_offscope_allowlist():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        server.set_scope_rules("acme", [{"pattern": "*.acme.com", "in_scope": True}])
        server.legal_attest(authorization_ref="x")
        server.set_active_permission(True)
        r = server.active_lab_preflight(["api.acme.com", "evil.example"],
                                        proxy_reachable="UP",
                                        firewall_direct_egress="BLOCKED", proxy_to_target="OK")
        by = {c["name"]: c["status"] for c in r["checks"]}
        assert by["allowlist-in-scope"] == "fail" and r["ready"] is False


def test_active_lab_preflight_tool_no_target_is_not_ready():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        r = server.active_lab_preflight(["api.acme.com"], proxy_reachable="UP",
                                        firewall_direct_egress="BLOCKED", proxy_to_target="OK")
        assert r["ready"] is False


def test_set_active_permission_tool_no_target_errors():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        assert "error" in server.set_active_permission(True)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_activelab.py -k tool -q`
Expected: FAIL (`AttributeError: module 'server' has no attribute 'set_active_permission'`).

- [ ] **Step 3a: Add the import**

In `plugin/mcp/server.py`, add `import activelab` to the existing block of local imports (e.g. next to `import correlate`).

- [ ] **Step 3b: Add the two tools**

Add near the other `@mcp.tool()` definitions (e.g. after `legal_attest`):

```python
@mcp.tool()
def set_active_permission(permitted: bool, note: str = "", handle: str = "") -> dict:
    """Record whether the ACTIVE program's published ROE permits active/automated testing.
    Distinct from legal_attest (that records YOUR legal posture). Default until set: NOT
    permitted. `note` should quote the policy text and any rate ceiling. This is
    verified-posture bookkeeping — it does NOT itself grant any traffic (the scope-guard
    hook is unchanged); never set permitted=True from the user's say-so alone."""
    target = registry.active_target()
    h = handle or (target["handle"] if target else "")
    if not h:
        return {"error": "no active target; create/switch to one first"}
    return registry.set_active_permission(h, permitted=permitted, note=note)


@mcp.tool()
def active_lab_preflight(allowlist_hosts: list[str], proxy_reachable: str = "",
                         firewall_direct_egress: str = "", proxy_to_target: str = "") -> dict:
    """Verify the active-lab containment posture for the ACTIVE target -> {ready, checks}.
    Fail-closed. Reads attestation + ROE gate + scope from the ledger; takes human-run probe
    evidence (this tool makes NO network call):
      proxy_reachable: 'UP' when the M1 egress proxy answers on its loopback port.
      firewall_direct_egress: 'BLOCKED' when a direct (non-proxy) egress from the VM FAILS.
      proxy_to_target: 'OK' when a request to the target THROUGH the proxy SUCCEEDS.
    `ready` is advisory — nothing grants traffic on it (see docs/active-lab-setup.md)."""
    target = registry.active_target()
    if target is None:
        return {"ready": False,
                "checks": [{"name": "active-target", "status": "fail", "detail": "no active target"}]}
    h = target["handle"]
    allow = list(allowlist_hosts or [])
    offscope = [x for x in allow if not registry.check_scope(x, "")[0]]
    return activelab.active_lab_preflight(
        attested=registry.is_attested(h),
        active_permitted=registry.active_testing_permitted(h),
        allowlist_hosts=allow,
        offscope_allowlist_hosts=offscope,
        proxy_reachable=proxy_reachable,
        firewall_direct_egress=firewall_direct_egress,
        proxy_to_target=proxy_to_target,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_activelab.py -q`
Expected: PASS (19 passed).

- [ ] **Step 5: Commit**

```bash
git add plugin/mcp/server.py tests/test_activelab.py
git commit -m "feat(activelab): set_active_permission + active_lab_preflight MCP tools"
```

---

### Task 4: Capture step (bb-start) + firewall setup docs

**Files:**
- Modify: `plugin/skills/bb-start/SKILL.md`
- Create: `docs/active-lab-setup.md`

**Interfaces:** none (skill prose + docs). References the `set_active_permission` and `active_lab_preflight` tools from Task 3.

- [ ] **Step 1: Add the capture step to `plugin/skills/bb-start/SKILL.md`**

Append this section at the end of the file (it references a fact `bb-start` Step 2 already extracts — the program's automation/rate-limit policy):

```markdown
## Step — record active-testing permission (ROE gate)

After scope and legal posture, record whether the PROGRAM's published ROE permits
active/automated testing — a fact distinct from your own legal posture. You already
extracted the automation/rate-limit policy in Step 2; turn it into the gate:

- If the policy explicitly permits active/automated testing, call
  `set_active_permission(permitted=true, note="<quote the policy + any rate ceiling>")`.
- If it forbids it, is silent, or you could not verify it, call
  `set_active_permission(permitted=false, note="<what the policy says, or 'unverified'>")`.
  The default is NOT permitted, and staying there is correct whenever you are unsure.

This is bookkeeping for a future, opt-in active-lab mode; it grants no traffic now, and
`active_lab_preflight` will only read `ready` after the containment posture is verified.
Never set `permitted=true` from the user's say-so alone — it must trace to the published
policy, the same iron rule as scope.
```

- [ ] **Step 2: Create `docs/active-lab-setup.md`**

```markdown
# Active-lab setup — verified containment posture (milestone 2)

> Active-lab lets you *set up and verify* a contained environment for active testing of
> ONE authorized target. It grants no traffic on its own: `active_lab_preflight` returns a
> `ready` verdict for a human to read. Opening the valve (the hook granting rate-limited
> active traffic) is a later milestone.

## The two enforcement layers

1. **The M1 egress proxy** (`plugin/tools/egress_proxy.py`) — a deny-by-default forward
   proxy: tools point `HTTPS_PROXY`/`HTTP_PROXY` at it, and it refuses any destination not
   on its allowlist before resolving it. This contains a *cooperating* tool.
2. **The VM egress firewall (this doc)** — the hard backstop that contains a tool which
   ignores the proxy env. Without it, a raw-socket tool bypasses layer 1.

## VM firewall — default-deny egress except via the proxy

Run active-lab tooling inside a Linux VM (VirtualBox), never on the host — the same reason
sandbox mode uses a VM: Docker Desktop cannot truly block egress. Inside the VM, allow
outbound only from the proxy process to the single target, and drop everything else. With
nftables:

```
# Replace <TARGET_IP> with the one authorized target's IP, <PROXY_UID> with the uid the
# egress proxy runs as. Everything else outbound is dropped.
nft add table inet activelab
nft add chain inet activelab out '{ type filter hook output priority 0 ; policy drop ; }'
nft add rule inet activelab out ct state established,related accept
nft add rule inet activelab out oif lo accept
nft add rule inet activelab out meta skuid <PROXY_UID> ip daddr <TARGET_IP> accept
```

The proxy (running as `<PROXY_UID>`) may reach the target; no other process may reach
anything off-box. Adjust for iptables if you prefer; the property is what matters:
**direct egress is dropped; only the proxy reaches the target.**

## The three preflight probes

`active_lab_preflight` takes these three human-run verdicts (it makes no network call):

| Argument | Probe (run inside the VM) | Report |
|---|---|---|
| `proxy_reachable` | the proxy answers on its loopback port: `curl -sx http://127.0.0.1:<PORT> http://<TARGET>/ -o /dev/null -w '%{http_code}'` returns a code | `UP` (else `DOWN`) |
| `firewall_direct_egress` | a DIRECT request bypassing the proxy FAILS: `curl --noproxy '*' --max-time 5 http://1.1.1.1/` times out / is refused | `BLOCKED` (else `OPEN`) |
| `proxy_to_target` | a request to the target THROUGH the proxy SUCCEEDS: `curl -x http://127.0.0.1:<PORT> --max-time 10 http://<TARGET>/ -o /dev/null -w '%{http_code}'` returns a live code | `OK` (else `FAIL`) |

## Running the check

```
set_active_permission(permitted=true, note="<program policy quote>")   # ROE gate
legal_attest(...)                                                       # tester posture
# configure the proxy allowlist to the one target; apply the VM firewall; run the 3 probes
active_lab_preflight(allowlist_hosts=["<TARGET>"], proxy_reachable="UP",
                     firewall_direct_egress="BLOCKED", proxy_to_target="OK")
```

`ready: true` means all five checks hold: legal attestation present, ROE gate = yes, the
allowlist is entirely in scope and non-empty, the proxy is up, and the firewall is sealed.
Any missing or unsafe evidence fails closed.
```

- [ ] **Step 3: Verify the additions**

Run: `grep -c "set_active_permission" plugin/skills/bb-start/SKILL.md docs/active-lab-setup.md`
Expected: both files reference the tool (each count ≥ 1).
Run: `test -f docs/active-lab-setup.md && echo OK`
Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
git add plugin/skills/bb-start/SKILL.md docs/active-lab-setup.md
git commit -m "docs(activelab): bb-start ROE capture step + VM firewall/probe setup guide"
```

---

### Task 5: Verification & invariant check

**Files:** none (verification only).

- [ ] **Step 1: Full Python suite**

Run: `python -m pytest -q`
Expected: all prior tests still pass PLUS the new `tests/test_activelab.py` (was 476; now 476 + 19).

- [ ] **Step 2: Node skill-verify unaffected**

Run: `node --test tools/verify-ported-skills.test.js`
Expected: `# pass 4  # fail 0` (skill counts unchanged — no new pb-*/bb-* skill dir; only bb-start text edited).

- [ ] **Step 3: INVARIANT — scope-guard.py untouched, no valve wiring**

Run: `git diff --name-only main -- plugin/hooks/scope-guard.py`
Expected: EMPTY (the hook was not modified).
Run: `grep -rn "active_lab_preflight\|active_testing_permitted" plugin/hooks/`
Expected: EMPTY (no decision path reads the gate or the verdict).

- [ ] **Step 4: Commit (only if a verification-driven fix was needed; else skip)**

```bash
git add -A
git commit -m "chore(activelab): milestone-2 verification green (pytest + node), invariant held"
```

---

## Self-Review

**1. Spec coverage:**
- §4.1 ROE gate (columns + registry funcs + capture) → Task 1 (storage) + Task 4 (bb-start capture). ✓
- §4.2 pure checker + MCP tool → Task 2 (pure) + Task 3 (tools). ✓
- §4.3 firewall backstop docs + probe contract → Task 4 (`docs/active-lab-setup.md`). ✓
- §6 invariant (scope-guard unchanged, nothing reads `ready`, ingest-only default) → Global Constraints + Task 5 Step 3. ✓
- §7 testing (checker unit, gate storage, migration, server smoke, regression) → Tasks 1–3 tests + Task 5. ✓
- §2 zero new deps → Global Constraints; only stdlib + existing `mcp`. ✓

**2. Placeholder scan:** none — every code/doc step has full content.

**3. Type consistency:** `set_active_permission(handle, permitted, note, permitted_at)` / `get_active_permission -> {handle, active_testing_permitted, note, at}` / `active_testing_permitted(handle)->bool` are identical across Tasks 1 and 3; `activelab.active_lab_preflight(attested, active_permitted, allowlist_hosts, offscope_allowlist_hosts, proxy_reachable, firewall_direct_egress, proxy_to_target)->{ready,checks}` is identical in Tasks 2 and 3; the five check names (`legal-attestation`, `roe-gate`, `allowlist-in-scope`, `proxy-reachable`, `firewall-sealed`) match across the checker, its tests, and the tool tests. ✓

**Executor note:** if any existing test asserts `PRAGMA user_version == 3` or `db.SCHEMA_VERSION == 3`, update it to 4 (the bump is intentional and part of Task 1). A quick `grep -rn "user_version\|SCHEMA_VERSION" tests/` before starting Task 1 will surface it.
