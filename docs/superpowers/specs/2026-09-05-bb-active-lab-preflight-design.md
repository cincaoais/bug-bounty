# Spec — bb active-lab verified posture + ROE gate (active-mode milestone 2)

- **Date:** 2026-09-05
- **Status:** Approved design, pre-implementation
- **Related:** `docs/field-notes/rnd-active-mode-containment-2026-09-02.md` (R&D + ROE check); `docs/superpowers/specs/2026-09-04-bb-egress-chokepoint-design.md` (M1, §9 names this milestone)

## 1. Context & motivation

M1 shipped an unwired, stdlib egress chokepoint proxy (destination allowlist + per-host token bucket + append-only audit, refuse-before-resolve). M2 builds the machinery that lets a user **set up and verify** an active-testing containment posture for a real authorized target — **without opening the valve**.

Two facts from reading the enforcement path shape this milestone:

1. **bb already has a live-traffic mode.** In `plugin/hooks/scope-guard.py:decide()`, a `bounty`-mode target that is legally *attested* and whose destination is *in scope* returns `None` (defer = allow). bb is "ingest-only" by skill convention and the human, not because the hook forbids all traffic. So M2 is not about unblocking traffic.
2. **Legal attestation is not the ROE fact.** The existing `set_attestation` records *the tester's* legal posture (jurisdiction, CSSP licence, authorization ref). The ROE check identified a *distinct* fact — *does this program's published policy permit active/automated testing, and at what rate* — which bb does not yet capture.

M2 delivers three things and changes **no decision logic**: a per-program "active testing permitted?" gate, a deterministic preflight posture checker, and the firewall-backstop verification the checker consumes. The M1 proxy assumed tools honour its env; the firewall backstop is what hard-contains a tool that does not.

## 2. Goals (milestone 2)

- A per-target **"active testing permitted?" gate** — a standing fact, absent = **NO**, distinct from legal attestation.
- A pure **`active_lab_preflight` posture checker** (bb's "what is true" style, like `sandbox.network_isolation_check`) returning `ready` only when five independent checks all hold: attestation present, ROE gate = YES, the proxy allowlist is entirely in-scope and non-empty, the M1 proxy is reachable, and the VM firewall egress is sealed (direct egress blocked, proxy path works).
- The firewall backstop as **VM documentation + a probe contract** the checker consumes — bb never runs the firewall, it verifies by probe (the sandbox-mode pattern).
- **Zero new runtime dependencies.** The checker is pure and unit-testable with no I/O.

## 3. Non-goals (explicitly deferred to M3+)

- **No change to `scope-guard.py` decision logic.** Nothing consumes the `ready` verdict to grant traffic. The valve stays closed.
- No proxy in the live enforcement path; no runtime rate enforcement wired into the hook.
- No guardian model, no health/auto-pause monitoring.
- The **ingest-only default is preserved**: new `target` columns default to *not-permitted*; new MCP tools are additive; no mode grants active traffic that bounty mode didn't already.

## 4. Architecture

Three components. New pure logic is isolated and unit-tested; storage follows the existing attestation pattern exactly.

### 4.1 The ROE gate (storage + capture)

- **Schema** (`plugin/mcp/db.py`, `init_registry`, via the existing `_add_column_if_missing` guarded-ALTER pattern; bump `SCHEMA_VERSION` 3 → 4):
  - `active_testing_permitted INTEGER NOT NULL DEFAULT 0` — 0 = not permitted (fail-closed), 1 = permitted.
  - `active_permitted_note TEXT NOT NULL DEFAULT ''` — the ROE evidence (e.g. "policy §Testing permits authenticated automated testing ≤ N req/s").
  - `active_permitted_at TEXT NOT NULL DEFAULT ''` — timestamp of the deliberate record.
- **Registry functions** (`plugin/mcp/registry.py`, mirroring `set_attestation`/`get_attestation`/`is_attested`):
  - `set_active_permission(handle, permitted: bool, note: str = "") -> dict` — writes the three columns, stamping `active_permitted_at` now.
  - `get_active_permission(handle) -> dict` → `{handle, active_testing_permitted: bool, note, at}`.
  - `active_testing_permitted(handle) -> bool` — True only when the column is 1 (deny-by-default otherwise).
- **Capture** (`plugin/skills/bb-start/SKILL.md`): a short step instructing the assistant, during onboarding, to record whether the program's ROE permits active/automated testing (default NO) via the new tool — placed alongside the existing scope + legal-posture capture. This is additive text; it does not change any default behaviour.

### 4.2 The active-lab preflight checker

- **Pure module** `plugin/mcp/activelab.py` (no I/O, no network, no clock):

  ```
  def active_lab_preflight(
      attested: bool,
      active_permitted: bool,
      allowlist_hosts: list[str],
      offscope_allowlist_hosts: list[str],   # subset of allowlist_hosts that are NOT in scope
      proxy_reachable: str,        # "UP" | "DOWN" | ""
      firewall_direct_egress: str, # "BLOCKED" | "OPEN" | ""
      proxy_to_target: str,        # "OK" | "FAIL" | ""
  ) -> dict   # {ready: bool, checks: [{name, status, detail}]}
  ```

  Five checks, all must pass, **fail-closed** on any missing/ambiguous evidence:
  1. `legal-attestation` — `attested` is True.
  2. `roe-gate` — `active_permitted` is True.
  3. `allowlist-in-scope` — `allowlist_hosts` non-empty AND `offscope_allowlist_hosts` empty (no allowlisted host is out of scope).
  4. `proxy-reachable` — `proxy_reachable == "UP"`.
  5. `firewall-sealed` — `firewall_direct_egress == "BLOCKED"` AND `proxy_to_target == "OK"`.

  `ready` is the AND of all five. Any status other than the exact safe value is a `fail`.

- **MCP tool** `active_lab_preflight(allowlist_hosts, proxy_reachable, firewall_direct_egress, proxy_to_target)` (`plugin/mcp/server.py`, analog of `sandbox_preflight`): resolves the active target (none → not ready, fail-closed), reads `attested = registry.is_attested(handle)` and `active_permitted = registry.active_testing_permitted(handle)`, computes `offscope_allowlist_hosts = [h for h in allowlist_hosts if not registry.is_host_in_scope(h)]`, then returns `activelab.active_lab_preflight(...)`. **`is_host_in_scope` is a non-consuming, rules-only scope check** (added to `registry.py`): unlike `check_scope`, it must NOT consume a one-time scope override — a dry-run verify has to be idempotent, and a host reachable only via a burnable override is correctly *not* a stable in-scope allowlist entry.

### 4.3 The firewall backstop (docs + probe contract)

`docs/active-lab-setup.md`: the VirtualBox-VM egress firewall setup (default-deny `OUTPUT`, allow only the proxy's outbound to the single target) and the exact human-run probes feeding checks 4–5:

- **proxy-reachable:** the M1 proxy answers on its loopback port → report `UP`.
- **firewall-direct-egress (negative):** from inside the VM, a direct request to a non-target host **bypassing** the proxy must FAIL → report `BLOCKED`.
- **proxy-to-target (positive):** a request to the target **through** the proxy must SUCCEED → report `OK`.

bb never applies the firewall; it consumes these verdicts, exactly as `sandbox_preflight` consumes the egress probe.

## 5. Data flow

```
bb-start → record ROE permission (set_active_permission; default NO)
         → set the proxy allowlist to the one target; apply the VM firewall
         → run 3 probes (proxy up / direct egress blocked / proxy-to-target ok)
         → active_lab_preflight(allowlist_hosts, proxy_reachable, firewall_direct_egress, proxy_to_target)
             ready:true  ⟺  attested ∧ roe-gate ∧ allowlist-in-scope ∧ proxy-up ∧ firewall-sealed
```

No traffic is sent by any of this. The output is a proof that the box is sealed — consumed by a human, and (in M3) by the valve.

## 6. Security properties & invariant

- **Fail-closed throughout:** absent ROE gate = NO; no active target = not ready; any missing/ambiguous probe = that check fails; over-broad allowlist (any out-of-scope host) fails check 3.
- **The valve stays closed:** `scope-guard.py` is not modified; `ready` is not read by any decision path. Ingest-only remains the default and bounty mode is unchanged.
- **Distinctness:** the ROE gate is independent of legal attestation — both are required for `ready`, and neither implies the other.

## 7. Testing strategy

- **Unit — `tests/test_activelab.py`** (pure, no I/O): each of the five checks passing and failing in isolation; fail-closed on empty/ambiguous evidence for checks 4–5; `allowlist-in-scope` rejects a non-empty allowlist with any out-of-scope host and rejects an empty allowlist; `ready` is True only when all five pass and False if any one fails.
- **Storage — registry gate tests** (in the existing registry test file, or `tests/test_activelab.py`): default is not-permitted; `set_active_permission(True, note)` then `active_testing_permitted()` is True and `get_active_permission()` round-trips note + timestamp; `set_active_permission(False, …)` returns to not-permitted.
- **Migration:** a fresh registry DB and an upgraded pre-v4 DB both expose the three new columns (the guarded-ALTER path), and existing rows read as not-permitted.
- **Server smoke** (`tests/test_server_smoke.py` or new): `set_active_permission` and `active_lab_preflight` tools are registered and return the expected shape; `active_lab_preflight` with all-safe evidence on an attested+permitted+in-scope target returns `ready: true`, and flipping any one input to unsafe returns `ready: false` with that check named.
- **Regression:** full `pytest` stays green; `scope-guard.py` unchanged (assert no diff to the hook).

## 8. Risks & open items

- **Allowlist provenance.** The checker takes `allowlist_hosts` as an argument (what the proxy was configured with) rather than reading the proxy's live config — the human must pass the same list the proxy runs. Documented; a future milestone could have the proxy expose its allowlist for direct comparison.
- **Probe honesty.** Checks 4–5 are only as good as the human-run probes, exactly like `sandbox_preflight`'s egress probe. The docs make the probe commands explicit and unambiguous.
- **Windows/VirtualBox specifics** of the egress firewall live in the VM (Linux iptables/nftables), not the Windows host — consistent with bb's existing sandbox guidance that Docker Desktop cannot truly block egress.

## 9. Milestone boundary / what comes next

Milestone 3 (separate spec) opens the valve: a `scope-guard.py` active-lab decision branch that grants in-scope active traffic **only** when `active_lab_preflight` is `ready`, routed through the M1 proxy with runtime rate enforcement, plus the guardian model and health/auto-pause the R&D pairs with real active traffic.
