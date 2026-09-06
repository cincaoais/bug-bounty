# Spec — bb active-lab state + rate mechanism (active-mode milestone 3, inert)

- **Date:** 2026-09-06
- **Status:** Approved design (inert scope), pre-implementation
- **Related:** `docs/field-notes/rnd-active-mode-containment-2026-09-02.md`; M1 (`2026-09-04-bb-egress-chokepoint-design.md`), M2 (`2026-09-05-bb-active-lab-preflight-design.md`)

## 1. Context & scope decision

M1 shipped the egress proxy; M2 shipped the ROE gate + `active_lab_preflight` verified-posture checker. The remaining roadmap step is the `scope-guard.py` active-lab decision branch that would *enforce* a rate-limited, preflight-gated container in the live path. That hook change is a security-critical, dual-use capability edit; the user chose to build **only the inert machinery now** and leave the one hook edit for a separate, explicit decision.

**This milestone (M3-inert) therefore builds:** the active-lab engagement/pause/ready state, the per-host rate-limiter mechanism (pure math + persistence), and the MCP tools to drive them — all **inert**, with `scope-guard.py` untouched and nothing in any decision path reading the new state. It is the exact M1/M2 pattern: build and test the mechanism now, so a future, separately-authorized hook edit becomes a small change that only *reads* this state.

## 2. Goals (M3-inert)

- Per-target **active-lab state**: engaged, paused (+reason), preflight-ready, and a rate ceiling — all fail-closed (default off / not-ready / rate 0).
- A **ledger-backed per-host token bucket** (pure refill/consume math + persisted state) — the rate mechanism a future hook would consume.
- **MCP tools** to manage the state: engage / disengage / pause / resume / status, and `active_lab_preflight` stores its verdict into `active_lab_ready` when engaged.
- **Zero new runtime dependencies.** Pure logic unit-testable with no I/O.

## 3. Non-goals (the deferred, separately-authorized hook edit + beyond)

- **No change to `plugin/hooks/scope-guard.py`.** Nothing reads the engaged/paused/ready/rate state to make a traffic decision. The state is inert bookkeeping + a tested mechanism.
- No enforcement of the rate bucket in the live path; no auto-pause wired into the hook.
- No guardian LLM (a future out-of-hook layer if ever wanted; bb's hook/MCP never call an LLM).
- Ingest-only stays the default; bounty mode is byte-for-byte unchanged.

> **Design note for the future hook edit (NOT built here):** when it is separately authorized, the active-lab branch must be a **strict superset of bounty-mode denials** — for any input its decision is deny-or-equal to plain bounty mode, so engaging active-lab can only ever deny more, never permit more. This spec builds the state that edit will read; it does not build the edit.

## 4. Architecture

### 4.1 State (schema + registry accessors)

- **Schema** (`plugin/mcp/db.py`, guarded-ALTER pattern; `SCHEMA_VERSION` 4 → 5):
  - Columns on `target` (all fail-closed defaults): `active_lab_engaged INTEGER NOT NULL DEFAULT 0`, `active_lab_paused INTEGER NOT NULL DEFAULT 0`, `active_lab_pause_reason TEXT NOT NULL DEFAULT ''`, `active_lab_ready INTEGER NOT NULL DEFAULT 0`, `active_lab_rate_per_min INTEGER NOT NULL DEFAULT 0`, `active_lab_engaged_at TEXT NOT NULL DEFAULT ''`.
  - A registry-db table for the per-host rate state (added to `SCHEMA_REGISTRY`, idempotent CREATE):
    ```
    CREATE TABLE IF NOT EXISTS active_lab_rate (
      handle TEXT NOT NULL, host TEXT NOT NULL,
      tokens REAL NOT NULL, last_ts TEXT NOT NULL,
      PRIMARY KEY (handle, host)
    );
    ```
- **Registry accessors** (`plugin/mcp/registry.py`, mirroring the attestation/permission pattern):
  - `active_lab_engage(handle, rate_per_min: int) -> dict` — engaged=1, paused=0, ready=0, rate_per_min, engaged_at=now.
  - `active_lab_disengage(handle) -> dict` — engaged=0 (leaves rate rows; harmless).
  - `active_lab_pause(handle, reason: str) -> dict` — paused=1, pause_reason=reason.
  - `active_lab_resume(handle) -> dict` — paused=0, ready=0 (forces a fresh preflight), pause_reason=''.
  - `set_active_lab_ready(handle, ready: bool) -> dict` — ready.
  - `get_active_lab(handle) -> dict` → `{handle, engaged, paused, pause_reason, ready, rate_per_min, engaged_at}` (bools for the flags).

### 4.2 The per-host rate mechanism

- **Pure math** (`plugin/mcp/activelab.py`): `rate_step(tokens, elapsed_sec, capacity, refill_per_sec) -> (allowed: bool, new_tokens: float, retry_after: float)` — refill by elapsed, try-consume 1, deny with `retry_after` when < 1 (∞ when `refill_per_sec <= 0`). No I/O, no clock.
- **Persisted consume** (`plugin/mcp/registry.py`): `active_lab_rate_consume(handle, host, now: str | None = None) -> dict` → reads `active_lab_rate_per_min` for the target (capacity = rate_per_min tokens, refill_per_sec = rate_per_min/60), loads `(tokens, last_ts)` for `(handle, host)` (default `(capacity, now)` when absent), computes elapsed, calls `activelab.rate_step`, writes the new `(tokens, last_ts)`, returns `{allowed, tokens, retry_after, capacity}`. Fail-closed: `rate_per_min <= 0` (not configured / not engaged) → `allowed=False`.

### 4.3 MCP tools (`plugin/mcp/server.py`)

- `active_lab_engage(rate_per_min: int) -> dict` — validates `rate_per_min > 0` (else `{"error": ...}`, fail-closed), calls `registry.active_lab_engage`. Returns status. Docstring states plainly this engages *bookkeeping only* — no traffic is granted, because the hook does not read this state yet.
- `active_lab_disengage() -> dict`, `active_lab_pause(reason: str = "") -> dict`, `active_lab_resume() -> dict`, `active_lab_status() -> dict` (returns `get_active_lab` for the active target).
- **Extend `active_lab_preflight(...)`** (from M2): when the active target is engaged, store the computed `ready` into `active_lab_ready` (side effect) so the future hook could read a persisted verdict; when not engaged, behave exactly as M2 (pure query, no write).

## 5. Data flow

```
active_lab_engage(rate_per_min=N)          # bookkeeping: engaged=1, ready=0
active_lab_preflight(allowlist, probes...) # (engaged) stores ready = verdict.ready
active_lab_status()                        # engaged / paused / ready / rate
active_lab_pause("target 5xx spike")       # paused=1
active_lab_resume()                        # paused=0, ready=0  (re-preflight required)
# registry.active_lab_rate_consume(handle, host)  # the mechanism, tested; NOT called by the hook
```

Nothing here reaches `scope-guard.py`. The state is inert; the rate consume is exercised only by tests and (in a future milestone) by the authorized hook edit.

## 6. Fail-closed & invariant

- Every new flag defaults off / not-ready; `rate_per_min` defaults 0; `active_lab_rate_consume` denies when the ceiling is unset. `resume` clears ready (a paused/anomalous target must re-verify before it could ever be trusted).
- **Invariant:** `scope-guard.py` is not modified and no decision path reads `active_lab_*`. Verified by diff + grep in the plan's final task, and by the whole-branch review.

## 7. Testing strategy

- **Pure** (`tests/test_activelab.py`): `rate_step` — refill, consume, deny-over-capacity, refill-over-time, `refill_per_sec<=0` → ∞ retry.
- **State/storage**: defaults (engaged/paused/ready 0, rate 0); engage sets rate + engaged + clears ready/paused; pause/resume roundtrip; resume resets ready to 0; `get_active_lab` shape.
- **Rate persistence**: `active_lab_rate_consume` allows up to capacity then denies; refills after simulated elapsed time (inject `now`); per-host isolation; fail-closed when `rate_per_min=0`.
- **Preflight side effect**: `active_lab_preflight` stores `ready` when engaged, writes nothing when not engaged.
- **Tools**: `active_lab_engage` rejects `rate_per_min<=0`; the five tools return the expected shape; `active_lab_preflight` tool still returns M2's verdict.
- **Migration**: fresh + re-init both expose the v5 columns and the `active_lab_rate` table; `test_legal_state.py` schema assertion updated 4 → 5.
- **Invariant/regression**: full `pytest` green; `scope-guard.py` unchanged vs `main`; no `plugin/hooks/` reference to `active_lab_*`.

## 8. Risks & open items

- **Inert by design** — the rate mechanism has no live consumer until the authorized hook edit. That is intentional (the user deferred the hook edit); the docs must say so plainly so no one assumes rate limiting is enforced yet.
- **Clock:** `active_lab_rate_consume` takes an injectable `now` (ISO string) for deterministic tests; production passes the real time. The pure `rate_step` never reads a clock.
- **Disengage leaves rate rows:** harmless (they refill to full and are ignored while disengaged); not worth a cascade delete in M3.

## 9. Milestone boundary / what comes next (separately authorized)

The deferred hook edit: a `scope-guard.py` active-lab branch that, when `active_lab_engaged`, denies active traffic unless `active_lab_ready` and not `active_lab_paused`, consumes an `active_lab_rate_consume` token per in-scope active call (deny + auto-pause on breach) — a **strict superset of bounty denials**, proven by a "never more permissive than bounty" property test. This spec deliberately does not build it.
