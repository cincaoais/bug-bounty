# bb Active-Lab State + Rate Mechanism Implementation Plan (inert)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the inert active-lab state (engaged/paused/ready/rate), a ledger-backed per-host token-bucket rate mechanism, and the MCP tools to drive them — with `scope-guard.py` untouched and nothing reading the state to grant traffic.

**Architecture:** State columns on `target` (guarded-ALTER, v4→v5) + a `active_lab_rate` registry table; a pure `activelab.rate_step` plus a persisted `registry.active_lab_rate_consume`; five MCP tools plus a side-effect on `active_lab_preflight` (store its verdict when engaged). All inert — the future, separately-authorized hook edit will read this; this plan does not touch the hook.

**Tech Stack:** Python 3.13 stdlib + existing `mcp`. No new dependency.

**Spec:** `docs/superpowers/specs/2026-09-06-bb-active-lab-state-design.md`

## Global Constraints

- **Python 3.13, stdlib + existing `mcp` only** — no new runtime dependency.
- **INVARIANT — do NOT modify `plugin/hooks/scope-guard.py`.** No code path may read `active_lab_engaged/paused/ready/rate` or call `active_lab_rate_consume` from the hook. The state is inert; ingest-only stays the default; bounty mode unchanged.
- **Fail-closed:** all new flags default off / not-ready; `rate_per_min` defaults 0; `active_lab_rate_consume` denies when `rate_per_min <= 0`; `active_lab_engage` rejects `rate_per_min <= 0`; `active_lab_resume` resets `ready` to 0.
- **Storage pattern:** target columns via `_add_column_if_missing` in `db.init_registry`; `SCHEMA_VERSION` 4 → 5; the rate table added to `SCHEMA_REGISTRY` (idempotent CREATE).
- Commit after every task. End each commit body with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

---

## File Structure

- `plugin/mcp/db.py` — MODIFY: `SCHEMA_VERSION` 5; 6 guarded-ALTER columns on `target`; add `active_lab_rate` table to `SCHEMA_REGISTRY`.
- `plugin/mcp/registry.py` — MODIFY: active-lab state accessors + `active_lab_rate_consume` + `_elapsed_seconds`; `import activelab`.
- `plugin/mcp/activelab.py` — MODIFY: add pure `rate_step`.
- `plugin/mcp/server.py` — MODIFY: 5 tools + `active_lab_preflight` side effect.
- `plugin/skills`/... — none.
- `docs/active-lab-setup.md` — MODIFY: add the state/tools workflow + deferred-enforcement note.
- `tests/test_activelab.py` — MODIFY: state, rate, tools, migration tests.
- `tests/test_legal_state.py` — MODIFY: schema assertion 4 → 5.

---

### Task 1: Active-lab state (schema v5 + registry accessors)

**Files:**
- Modify: `plugin/mcp/db.py`
- Modify: `plugin/mcp/registry.py`
- Modify: `tests/test_legal_state.py` (schema assertion 4 → 5)
- Test: `tests/test_activelab.py`

**Interfaces:**
- Produces: `registry.active_lab_engage(handle, rate_per_min)`, `active_lab_disengage(handle)`, `active_lab_pause(handle, reason="")`, `active_lab_resume(handle)`, `set_active_lab_ready(handle, ready)`, `get_active_lab(handle) -> {handle, engaged, paused, pause_reason, ready, rate_per_min, engaged_at}`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_activelab.py
def test_active_lab_state_defaults(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    st = registry.get_active_lab("acme")
    assert st == {"handle": "acme", "engaged": False, "paused": False, "pause_reason": "",
                  "ready": False, "rate_per_min": 0, "engaged_at": ""}


def test_active_lab_engage_sets_rate_and_clears_flags(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.set_active_lab_ready("acme", True)
    st = registry.active_lab_engage("acme", 30)
    assert st["engaged"] is True and st["rate_per_min"] == 30
    assert st["paused"] is False and st["ready"] is False and st["engaged_at"]


def test_active_lab_pause_resume(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.active_lab_engage("acme", 10)
    registry.set_active_lab_ready("acme", True)
    p = registry.active_lab_pause("acme", "5xx spike")
    assert p["paused"] is True and p["pause_reason"] == "5xx spike"
    r = registry.active_lab_resume("acme")
    assert r["paused"] is False and r["ready"] is False and r["pause_reason"] == ""


def test_active_lab_disengage(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.active_lab_engage("acme", 10)
    assert registry.active_lab_disengage("acme")["engaged"] is False


def test_active_lab_accessors_unknown_target_raise(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    import pytest as _pt
    with _pt.raises(ValueError):
        registry.active_lab_engage("nope", 10)


def test_active_lab_columns_and_rate_table_present(tmp_path, monkeypatch):
    db, _ = _fresh(tmp_path, monkeypatch)
    db.init_registry(); db.init_registry()  # idempotent
    conn = db.connect(db.registry_path())
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(target)")}
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert {"active_lab_engaged", "active_lab_paused", "active_lab_pause_reason",
            "active_lab_ready", "active_lab_rate_per_min", "active_lab_engaged_at"} <= cols
    assert "active_lab_rate" in tables
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_activelab.py -k active_lab_state -q` (and the others) — Expected: FAIL (`AttributeError: ... 'get_active_lab'`).

- [ ] **Step 3a: `plugin/mcp/db.py`**

Change `SCHEMA_VERSION = 4` to `SCHEMA_VERSION = 5`. Add the rate table to the `SCHEMA_REGISTRY` string (inside it, after the `legal_override` table's `);`):

```sql
CREATE TABLE IF NOT EXISTS active_lab_rate (
  handle TEXT NOT NULL, host TEXT NOT NULL,
  tokens REAL NOT NULL, last_ts TEXT NOT NULL,
  PRIMARY KEY (handle, host)
);
```

In `init_registry()`, after the M2 active-permission ALTERs and before `PRAGMA user_version`, add:

```python
        # Active-lab state (v5): per-target engagement/pause/ready + rate ceiling.
        # All fail-closed. INERT — scope-guard does NOT read these (deferred hook edit).
        _add_column_if_missing(conn, "target", "active_lab_engaged INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(conn, "target", "active_lab_paused INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(conn, "target", "active_lab_pause_reason TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(conn, "target", "active_lab_ready INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(conn, "target", "active_lab_rate_per_min INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(conn, "target", "active_lab_engaged_at TEXT NOT NULL DEFAULT ''")
```

- [ ] **Step 3b: `plugin/mcp/registry.py`**

Append after the M2 active-permission section:

```python
# ---- active-lab state (M3, INERT — scope-guard does not read these) -----------

def _set_active_lab_fields(handle: str, fields: dict) -> None:
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        row = conn.execute("SELECT id FROM target WHERE handle=?", (handle,)).fetchone()
        if row is None:
            raise ValueError(f"no such target: {handle}")
        assigns = ", ".join(f"{k}=?" for k in fields)   # keys are hardcoded column names
        conn.execute(f"UPDATE target SET {assigns} WHERE handle=?", (*fields.values(), handle))
        conn.commit()
    finally:
        conn.close()


def active_lab_engage(handle: str, rate_per_min: int) -> dict:
    _set_active_lab_fields(handle, {
        "active_lab_engaged": 1, "active_lab_paused": 0, "active_lab_ready": 0,
        "active_lab_pause_reason": "", "active_lab_rate_per_min": int(rate_per_min),
        "active_lab_engaged_at": _now(),
    })
    return get_active_lab(handle)


def active_lab_disengage(handle: str) -> dict:
    _set_active_lab_fields(handle, {"active_lab_engaged": 0})
    return get_active_lab(handle)


def active_lab_pause(handle: str, reason: str = "") -> dict:
    _set_active_lab_fields(handle, {"active_lab_paused": 1, "active_lab_pause_reason": reason})
    return get_active_lab(handle)


def active_lab_resume(handle: str) -> dict:
    _set_active_lab_fields(handle, {"active_lab_paused": 0, "active_lab_ready": 0,
                                    "active_lab_pause_reason": ""})
    return get_active_lab(handle)


def set_active_lab_ready(handle: str, ready: bool) -> dict:
    _set_active_lab_fields(handle, {"active_lab_ready": 1 if ready else 0})
    return get_active_lab(handle)


def get_active_lab(handle: str) -> dict:
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        r = conn.execute(
            "SELECT handle, active_lab_engaged, active_lab_paused, active_lab_pause_reason, "
            "active_lab_ready, active_lab_rate_per_min, active_lab_engaged_at "
            "FROM target WHERE handle=?", (handle,)
        ).fetchone()
    finally:
        conn.close()
    if r is None:
        return {"handle": handle, "engaged": False, "paused": False, "pause_reason": "",
                "ready": False, "rate_per_min": 0, "engaged_at": ""}
    return {
        "handle": r["handle"],
        "engaged": bool(r["active_lab_engaged"]),
        "paused": bool(r["active_lab_paused"]),
        "pause_reason": r["active_lab_pause_reason"] or "",
        "ready": bool(r["active_lab_ready"]),
        "rate_per_min": int(r["active_lab_rate_per_min"] or 0),
        "engaged_at": r["active_lab_engaged_at"] or "",
    }
```

- [ ] **Step 3c: `tests/test_legal_state.py` schema assertion**

Change `assert ver == 4` to `assert ver == 5` in the schema-version test (rename the function to `..._v5_...` optionally; the assertion value is the load-bearing change).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_activelab.py tests/test_legal_state.py -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add plugin/mcp/db.py plugin/mcp/registry.py tests/test_legal_state.py tests/test_activelab.py
git commit -m "feat(activelab): inert active-lab state (schema v5, fail-closed accessors)"
```

---

### Task 2: Per-host rate mechanism

**Files:**
- Modify: `plugin/mcp/activelab.py`
- Modify: `plugin/mcp/registry.py`
- Test: `tests/test_activelab.py`

**Interfaces:**
- Produces: `activelab.rate_step(tokens, elapsed_sec, capacity, refill_per_sec) -> (allowed, new_tokens, retry_after)`; `registry.active_lab_rate_consume(handle, host, now=None) -> {allowed, tokens, retry_after, capacity}`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_activelab.py
def test_rate_step_consume_refill_and_deny():
    import activelab
    ok, tok, retry = activelab.rate_step(3.0, 0.0, 3.0, 0.0)
    assert ok is True and abs(tok - 2.0) < 1e-9 and retry == 0.0
    ok, tok, retry = activelab.rate_step(0.0, 0.0, 3.0, 0.0)
    assert ok is False and retry == float("inf")
    ok, tok, _ = activelab.rate_step(0.0, 60.0, 3.0, 3.0 / 60.0)  # 60s * 0.05/s = 3 tokens
    assert ok is True and abs(tok - 2.0) < 1e-9


def test_rate_consume_persisted_allows_then_denies_then_refills(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.active_lab_engage("acme", 3)  # capacity 3, refill 3/60 per sec
    t0 = "2026-09-06T00:00:00+00:00"
    assert registry.active_lab_rate_consume("acme", "api.acme.com", now=t0)["allowed"] is True
    assert registry.active_lab_rate_consume("acme", "api.acme.com", now=t0)["allowed"] is True
    assert registry.active_lab_rate_consume("acme", "api.acme.com", now=t0)["allowed"] is True
    assert registry.active_lab_rate_consume("acme", "api.acme.com", now=t0)["allowed"] is False
    t1 = "2026-09-06T00:00:40+00:00"  # +40s -> +2 tokens
    assert registry.active_lab_rate_consume("acme", "api.acme.com", now=t1)["allowed"] is True


def test_rate_consume_per_host_isolated(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.active_lab_engage("acme", 1)
    t0 = "2026-09-06T00:00:00+00:00"
    assert registry.active_lab_rate_consume("acme", "a.acme.com", now=t0)["allowed"] is True
    assert registry.active_lab_rate_consume("acme", "b.acme.com", now=t0)["allowed"] is True
    assert registry.active_lab_rate_consume("acme", "a.acme.com", now=t0)["allowed"] is False


def test_rate_consume_fail_closed_when_no_ceiling(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")  # rate_per_min defaults 0
    out = registry.active_lab_rate_consume("acme", "api.acme.com", now="2026-09-06T00:00:00+00:00")
    assert out["allowed"] is False and out["capacity"] == 0.0
```

- [ ] **Step 2: Run to verify fail**

Run: `python -m pytest tests/test_activelab.py -k rate -q` — Expected: FAIL (`AttributeError: 'activelab' has no attribute 'rate_step'`).

- [ ] **Step 3a: `plugin/mcp/activelab.py`** — append the pure step:

```python
def rate_step(tokens, elapsed_sec, capacity, refill_per_sec):
    """Token-bucket step: refill by elapsed, then try to consume 1 token.
    Returns (allowed: bool, new_tokens: float, retry_after: float). Pure — no clock, no I/O."""
    tokens = min(float(capacity), float(tokens) + float(elapsed_sec) * float(refill_per_sec))
    if tokens >= 1.0:
        return (True, tokens - 1.0, 0.0)
    needed = 1.0 - tokens
    retry = needed / refill_per_sec if refill_per_sec > 0 else float("inf")
    return (False, tokens, retry)
```

- [ ] **Step 3b: `plugin/mcp/registry.py`** — add `import activelab` to the imports, then append:

```python
def _elapsed_seconds(t0: str, t1: str) -> float:
    try:
        a = _dt.datetime.fromisoformat(t0)
        b = _dt.datetime.fromisoformat(t1)
        if a.tzinfo is None:
            a = a.replace(tzinfo=_dt.timezone.utc)
        if b.tzinfo is None:
            b = b.replace(tzinfo=_dt.timezone.utc)
        return (b - a).total_seconds()
    except ValueError:
        return 0.0


def active_lab_rate_consume(handle: str, host: str, now: str | None = None) -> dict:
    """Consume one per-host active-lab rate token for `handle`. INERT in M3 — nothing in the
    hook calls this yet. Fail-closed: rate_per_min<=0 -> denied. Deterministic via `now` (ISO)."""
    cap = float(get_active_lab(handle)["rate_per_min"])
    ts_now = now or _now()
    if cap <= 0:
        return {"allowed": False, "tokens": 0.0, "retry_after": float("inf"), "capacity": 0.0}
    refill = cap / 60.0
    _ensure_registry()
    conn = db.connect(db.registry_path())
    try:
        r = conn.execute(
            "SELECT tokens, last_ts FROM active_lab_rate WHERE handle=? AND host=?",
            (handle, host)
        ).fetchone()
        tokens, last_ts = (float(r["tokens"]), r["last_ts"]) if r is not None else (cap, ts_now)
        elapsed = max(0.0, _elapsed_seconds(last_ts, ts_now))
        allowed, new_tokens, retry = activelab.rate_step(tokens, elapsed, cap, refill)
        conn.execute(
            "INSERT INTO active_lab_rate (handle, host, tokens, last_ts) VALUES (?,?,?,?) "
            "ON CONFLICT(handle, host) DO UPDATE SET tokens=excluded.tokens, last_ts=excluded.last_ts",
            (handle, host, new_tokens, ts_now),
        )
        conn.commit()
    finally:
        conn.close()
    return {"allowed": allowed, "tokens": new_tokens, "retry_after": retry, "capacity": cap}
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_activelab.py -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add plugin/mcp/activelab.py plugin/mcp/registry.py tests/test_activelab.py
git commit -m "feat(activelab): ledger-backed per-host token bucket (pure rate_step + persisted consume)"
```

---

### Task 3: MCP tools + preflight side effect

**Files:**
- Modify: `plugin/mcp/server.py`
- Test: `tests/test_activelab.py`

**Interfaces:**
- Produces (module-level callables): `server.active_lab_engage(rate_per_min)`, `active_lab_disengage()`, `active_lab_pause(reason="")`, `active_lab_resume()`, `active_lab_status()`; and `active_lab_preflight(...)` now stores `ready` into `active_lab_ready` when the active target is engaged.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_activelab.py
def test_active_lab_engage_tool_requires_positive_rate():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        assert "error" in server.active_lab_engage(0)
        assert server.active_lab_engage(20)["engaged"] is True


def test_active_lab_tools_pause_resume_status():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        server.active_lab_engage(10)
        assert server.active_lab_pause("waf")["paused"] is True
        r = server.active_lab_resume()
        assert r["paused"] is False and r["ready"] is False
        assert server.active_lab_status()["engaged"] is True
        assert server.active_lab_disengage()["engaged"] is False


def test_active_lab_preflight_stores_ready_when_engaged():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        server.set_scope_rules("acme", [{"pattern": "*.acme.com", "in_scope": True}])
        server.legal_attest(authorization_ref="x")
        server.set_active_permission(True)
        server.active_lab_engage(10)
        r = server.active_lab_preflight(["api.acme.com"], proxy_reachable="UP",
                                        firewall_direct_egress="BLOCKED", proxy_to_target="OK")
        assert r["ready"] is True
        assert server.active_lab_status()["ready"] is True  # stored


def test_active_lab_preflight_does_not_store_when_not_engaged():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        server.set_scope_rules("acme", [{"pattern": "*.acme.com", "in_scope": True}])
        server.legal_attest(authorization_ref="x")
        server.set_active_permission(True)
        server.active_lab_preflight(["api.acme.com"], proxy_reachable="UP",
                                    firewall_direct_egress="BLOCKED", proxy_to_target="OK")
        assert server.active_lab_status()["ready"] is False  # not engaged -> not stored
```

- [ ] **Step 2: Run to verify fail**

Run: `python -m pytest tests/test_activelab.py -k "active_lab_engage_tool or tools_pause or stores_ready or not_store" -q` — Expected: FAIL (`AttributeError: module 'server' has no attribute 'active_lab_engage'`).

- [ ] **Step 3a: Add the five tools to `plugin/mcp/server.py`** (near the M2 active-lab tools):

```python
@mcp.tool()
def active_lab_engage(rate_per_min: int) -> dict:
    """Engage active-lab BOOKKEEPING for the active target (engaged=1, ready=0, paused=0,
    per-host rate ceiling = rate_per_min req/min). This grants NO traffic — the scope-guard
    hook does not read active-lab state (enforcement is a future, separately-authorized
    milestone). rate_per_min must be > 0 (fail-closed)."""
    if rate_per_min is None or rate_per_min <= 0:
        return {"error": "rate_per_min must be > 0 (the per-host rate ceiling)"}
    target = registry.active_target()
    if target is None:
        return {"error": "no active target; create/switch to one first"}
    return registry.active_lab_engage(target["handle"], rate_per_min)


@mcp.tool()
def active_lab_disengage() -> dict:
    """Disengage active-lab bookkeeping for the active target."""
    target = registry.active_target()
    if target is None:
        return {"error": "no active target"}
    return registry.active_lab_disengage(target["handle"])


@mcp.tool()
def active_lab_pause(reason: str = "") -> dict:
    """Mark the active target's active-lab state paused, recording an anomaly reason. Inert
    bookkeeping in this milestone (no hook reads it)."""
    target = registry.active_target()
    if target is None:
        return {"error": "no active target"}
    return registry.active_lab_pause(target["handle"], reason)


@mcp.tool()
def active_lab_resume() -> dict:
    """Clear the active target's active-lab pause AND reset ready to 0 — a resumed target must
    re-run active_lab_preflight before it could ever be trusted. Inert bookkeeping here."""
    target = registry.active_target()
    if target is None:
        return {"error": "no active target"}
    return registry.active_lab_resume(target["handle"])


@mcp.tool()
def active_lab_status() -> dict:
    """Report the active target's active-lab state (engaged/paused/ready/rate/engaged_at)."""
    target = registry.active_target()
    if target is None:
        return {"error": "no active target"}
    return registry.get_active_lab(target["handle"])
```

- [ ] **Step 3b: Store the preflight verdict when engaged** — in `active_lab_preflight` (server.py), change the final `return activelab.active_lab_preflight(...)` to capture the result, store it when engaged, then return:

```python
    result = activelab.active_lab_preflight(
        attested=registry.is_attested(h),
        active_permitted=registry.active_testing_permitted(h),
        allowlist_hosts=allow,
        offscope_allowlist_hosts=offscope,
        proxy_reachable=proxy_reachable,
        firewall_direct_egress=firewall_direct_egress,
        proxy_to_target=proxy_to_target,
    )
    if registry.get_active_lab(h)["engaged"]:
        registry.set_active_lab_ready(h, bool(result.get("ready")))
    return result
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_activelab.py -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add plugin/mcp/server.py tests/test_activelab.py
git commit -m "feat(activelab): engage/pause/resume/status tools + preflight stores its verdict"
```

---

### Task 4: Docs — active-lab state workflow (enforcement deferred)

**Files:**
- Modify: `docs/active-lab-setup.md`

- [ ] **Step 1: Append this section to `docs/active-lab-setup.md`:**

```markdown
## Active-lab state & rate mechanism (bookkeeping — enforcement deferred)

These tools record an active-lab **posture** and a per-host **rate mechanism**. They are
**inert**: the scope-guard hook does NOT read this state, so nothing here grants or throttles
real traffic yet. Wiring the hook to enforce it (deny active traffic unless engaged + ready +
not-paused + rate-ok, as a strict superset of bounty-mode denials) is a separate,
explicitly-authorized milestone.

| Tool | Effect (bookkeeping only) |
|---|---|
| `active_lab_engage(rate_per_min)` | engaged=1, ready=0, paused=0, sets the per-host req/min ceiling (must be > 0) |
| `active_lab_preflight(...)` | when engaged, stores its `ready` verdict onto the target |
| `active_lab_pause(reason)` | paused=1 — record an anomaly (target 5xx, lockout, WAF) |
| `active_lab_resume()` | paused=0 AND ready=0 — a resumed target must re-run preflight |
| `active_lab_disengage()` | engaged=0 |
| `active_lab_status()` | engaged / paused / ready / rate / engaged_at |

The rate mechanism (`registry.active_lab_rate_consume`) is a ledger-backed per-host token
bucket: capacity = `rate_per_min`, refilling at `rate_per_min / 60` tokens per second, and it
fails closed (denies) when no ceiling is set. It is built and tested now so the future hook
edit only has to *call* it — it is not called by any live decision path in this milestone.
```

- [ ] **Step 2: Verify**

Run: `grep -c "active_lab_engage\|enforcement deferred\|inert" docs/active-lab-setup.md` — Expected ≥ 1.
Run: `git diff --name-only 63efea1 HEAD -- docs/active-lab-setup.md` is not needed; just confirm only this file changed for the task: `git status --porcelain docs/active-lab-setup.md`.

- [ ] **Step 3: Commit**

```bash
git add docs/active-lab-setup.md
git commit -m "docs(activelab): active-lab state/rate workflow (enforcement deferred)"
```

---

### Task 5: Verification & invariant check

**Files:** none.

- [ ] **Step 1: Full suite**

Run: `python -m pytest -q` — Expected: all prior pass PLUS the new `test_activelab.py` additions (was 496).

- [ ] **Step 2: Node skill-verify unaffected**

Run: `node --test tools/verify-ported-skills.test.js` — Expected: `# pass 4  # fail 0`.

- [ ] **Step 3: INVARIANT — scope-guard.py untouched, no hook wiring**

Run: `git diff --name-only main HEAD -- plugin/hooks/scope-guard.py` — Expected: EMPTY.
Run: `grep -rn "active_lab_engaged\|active_lab_ready\|active_lab_rate_consume\|active_lab_paused\|get_active_lab" plugin/hooks/` — Expected: EMPTY (no hook path reads the state).

- [ ] **Step 4: Commit (only if a verification-driven fix was needed; else skip)**

```bash
git add -A
git commit -m "chore(activelab): milestone-3 (inert) verification green; invariant held"
```

---

## Self-Review

**1. Spec coverage:**
- §4.1 state (columns + accessors) → Task 1. ✓
- §4.2 rate mechanism (pure `rate_step` + persisted `active_lab_rate_consume`) → Task 2. ✓
- §4.3 MCP tools + preflight side effect → Task 3. ✓
- §6 fail-closed + invariant → Global Constraints + Task 5 Step 3. ✓
- §7 testing (pure, state, rate persistence, preflight side effect, tools, migration, invariant) → Tasks 1–3 tests + Task 5. ✓
- §3 non-goals (no hook change) → Global Constraints + Task 5 Step 3. ✓

**2. Placeholder scan:** none — full code/content in every step.

**3. Type consistency:** `get_active_lab -> {handle, engaged, paused, pause_reason, ready, rate_per_min, engaged_at}` is identical across Tasks 1/3; `active_lab_rate_consume -> {allowed, tokens, retry_after, capacity}` and `rate_step -> (allowed, new_tokens, retry_after)` are identical across Tasks 2/3; the five tool names match across Task 3 and its tests. ✓

**Executor notes:** (1) `tests/test_legal_state.py` schema assertion goes 4 → 5 in Task 1 Step 3c (the only version-coupled test). (2) `tests/test_activelab.py` already defines the `_fresh(tmp_path, monkeypatch)` and `_reload_server(tmp)` helpers (from M2) — reuse them; do not redefine. (3) `registry.py` already imports `_dt` (used by `_is_stale`) and `_now`; Task 2 adds `import activelab`.
