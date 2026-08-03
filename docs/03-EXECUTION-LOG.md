# 03 — EXECUTION LOG

_System-builder Phase 3. One row per slice dispatch + commander verification. A fresh session resumes from here. Started 2026-08-01. No git commits yet (deferred to user say-so; will branch off `main` first)._

## Legend
- **Status:** dispatched → returned → **verified** (commander re-ran the test gate + full suite on the actual diff) / rejected.
- Commander never accepts a self-reported pass; every "verified" row has a pytest summary the commander reproduced.

## Wave 1 (parallel; disjoint files)

| Slice | What | Files | Agent status | Commander verification |
|-------|------|-------|--------------|------------------------|
| 1.1 | Target `mode`/`sandbox_app` column + registry gate | db.py, registry.py, server.py, tests/test_registry_mode.py | returned | **VERIFIED** — read diff: guarded ALTER re-raises non-dup errors, `SCHEMA_VERSION=2`, `is_sandbox()` fail-closed, real-program paths intact. |
| 1.2 | `sandbox.py` allow-list / ambiguity / proxy / canonical_host | plugin/mcp/sandbox.py, tests/test_sandbox.py | returned | **VERIFIED** — read full module: deny-by-default, mandatory port, CVE-aware legacy-IP canonicalization, ambiguity over-blocks safely (56 tests). |

**Commander full-suite run after Wave 1 (authoritative):** `python -m pytest -q` → `287 passed in 8.52s` (223 pre-existing + 8 + 56). Reproduced, not self-reported.

**Carry-forward:** `localhost`/`127.0.0.1`/`::1` are distinct canonical identities → sandbox target creation must declare allow-list rules for all three spellings on the port.

## Wave 2 (parallel; disjoint files)

| Slice | What | Files | Agent status | Commander verification |
|-------|------|-------|--------------|------------------------|
| 2.1 | Extraction → `(host,port,path)` + bare-IP gap fix | scope-guard.py, registry.py, tests/test_hook.py | returned | **VERIFIED** — read full test_hook.py: 8 modified tests are shape-only, assertions preserved/strengthened; all security integration tests intact; bare-IP closed w/o `--max-time` false-positive. Ran `pytest -q` → **321 passed**. |
| 3.1 | mission.py + 5 tables + guarded ALTERs | db.py, mission.py, tests/test_mission.py | returned | **VERIFIED** — read mission.py: scorecard uses `credited = solved AND NOT baseline_solved` (baseline never scores), monotonic downgrade-refusal, evidence-required-on-solve, freeze-once scorecard, attempt-cap accounting, `log_sandbox_decision` writer ready. |
| 3.3 | Juice Shop + WebGoat objective catalogs (JSON) | reference/juiceshop-challenges.json, webgoat-lessons.json | returned | **VERIFIED** — 113 JS (from live challenges.yml) + 107 WebGoat (source-enumerated); 0 dup ids, 0 bad keys, all `id==app:native_id`, difficulties JS 1-6 / WG {1,3,5}. Canonical app strings: `juice-shop`, `webgoat`. |

## Wave 3 (parallel; disjoint files — hook/plugin.json/registry vs server.py)

| Slice | What | Files | Agent status | Commander verification |
|-------|------|-------|--------------|------------------------|
| 2.2 | Hook sandbox branch (allow/deny), (host,port) keying, schemeless loopback, zero-candidate-deny, no-override, audit, matchers, SessionStart | scope-guard.py, plugin.json, registry.py, tests/test_hook.py | returned | **VERIFIED (read full logic)** — single `is_sandbox()` branch; real-program body character-identical under else; (host,port) keying + schemeless extractor + zero-candidate-deny + ambiguity-deny + no-override + fail-closed; audit wrapped. Authoritative `pytest -q` → **358 passed**; correlate wall intact. |

**Waves 1–3 COMPLETE & VERIFIED. Authoritative full suite: 358 passed.**
| 3.2 | Record-only MCP tools + attempt-cap surface + gated auto-confirm + after-action report | server.py, mission.py, tests | returned | **VERIFIED (inspection)** — `promote_to_finding` wrapper synthesizes `human_confirmed=True` ONLY after `is_sandbox()` + `result_solved()`; `correlate.py` wall untouched; `create_sandbox_mission` refuses unless `human_ack` + server-verified sandbox. Self-reported 352 passed (authoritative run pending after 2.2). |

**KNOWN GAP (review finding #13, deferred):** `correlate.py` `add_note/add_lead/add_primitive` do NOT yet write the `mission_id` column (I over-scoped 3.2's "don't touch correlate.py" to the whole file; meant only the human-confirm wall). Columns exist but are unpopulated. Low severity — `mission_attempt` already cross-links to the coverage ledger (endpoint_id/test_case_id). **TODO:** small commander edit adding optional `mission_id` to those three functions + a filter test (does not touch the wall).

**Canonical app strings:** `juice-shop` → juiceshop-challenges.json ; `webgoat` → webgoat-lessons.json. Skill + `seed_objectives` must use these exactly (baseline filter is `WHERE app=?`).

**Carry-forward to Slice 2.2 (from 2.1):**
1. Real-program extraction dedups by **host only** → in the sandbox branch, key candidates by **(host,port)** and deny if ANY is non-sandbox (else `curl localhost:3000 && curl localhost:9999` drops the bad port — a leak).
2. Schemeless loopback (`localhost:3000`, `127.0.0.1:3000`, `[::1]:3000`) is NOT yet extracted — 2.2 adds the schemeless extractor.
3. `sandbox.canonical_host` already imported in scope-guard.py; `registry.check_scope(host,path,port=None)` has an inert port param — sandbox branch should call `sandbox.sandbox_allows` directly.
4. `mission.log_sandbox_decision(handle, tool_name, decision, host, port, reason, command_excerpt)` is the audit writer; hook must resolve `handle` via `registry.active_target()["handle"]`.

## Wave 3 (planned)
- 2.2 hook sandbox branch (solo) — needs 1.1/1.2/2.1
- 3.2 record-only MCP tools + attempt-cap + gated auto-confirm — needs 3.1

## Wave 4–6 (final push)

| Slice | What | Files | Status | Commander verification |
|-------|------|-------|--------|------------------------|
| 4.1 | `bb-sandbox` run-loop SKILL (the brain) | skills/bb-sandbox/SKILL.md | **written by commander** | authored directly (full design context): preflight hard-gate, app-state oracle discipline, tool routing, attempt caps, command conventions, scoring. |
| 4.2/5.1 | Juice Shop + WebGoat references | skills/bb-sandbox/juiceshop.md, webgoat.md | dispatched (A) | pending |
| 6.1 | Setup runbook + version 0.2.0 + README | docs/sandbox-setup.md, plugin.json, README.md | returned (C2) | **VERIFIED** — version 0.2.0, hooks intact, `--internal`+127.0.0.1 topology + VM fallback documented. |
| 6.2 + #13 | `sandbox_preflight` tool + `network_isolation_check` + correlate `mission_id` cross-link | server.py, sandbox.py, correlate.py, tests | returned (C1) | **VERIFIED** — authoritative `pytest -q` → **375 passed**; correlate wall intact (line 247); #13 gap closed. |
| 5.2 | WebGoat run-loop adaptation | (folded into SKILL.md + webgoat.md) | covered | skill handles `reportcard.mvc` oracle + session auth generically; app selected via `sandbox_app`. |
| flow | Mocked end-to-end mission lifecycle test | tests/test_sandbox_flow.py | pending (B, after A) | — |

**Authoritative suite after C1/C2: 375 passed.**

| Slice | What | Files | Status | Commander verification |
|-------|------|-------|--------|------------------------|
| 4.2/5.1 refs | Juice Shop + WebGoat references | skills/bb-sandbox/juiceshop.md, webgoat.md | returned (A) | **VERIFIED** — cross-checked vs live source; corrected `restartlesson.mvc` (flyway clean+migrate) + uncatalogued-challenge scoring caveat. |
| flow | Mocked end-to-end mission lifecycle | tests/test_sandbox_flow.py | returned (B) | **VERIFIED** — 377 passed; full lifecycle, baseline-not-credited, freeze all correct; flagged post-completion AAR nuance (→ fixed as #6). |

## Phase 4 — Holistic review + fixes

Holistic reviewer found 3 CONFIRMED traffic-escapes (#1 non-loopback rule, #2 scheme'd two-port dedup, #3 curl -x/--proxy) + 2 HIGH gaps (#4 preflight ready-when-unconfirmed, #5 evidence presence-only) + 5 lower. **All fixed** (see docs/04-REVIEW.md) with revert-to-fail adversarial tests.

**Commander independent verification (not agent self-report):**
- `scratchpad/adv_verify.py` — planted a malicious `evil.com:443` rule; ALL escapes deny, real localhost allows, shell defers. **ALL PASSED.**
- Authoritative `python -m pytest -q` → **391 passed**. Bounty-mode unchanged.

**BUILD COMPLETE & VERIFIED (offline). Docs 00–04 written.**

## Post-build: git + live preview + containment fix (2026-08-01)
- **A (ship):** branch `feat/autonomous-sandbox-mode`; commit `35129b7` (docs) + `4bf2feb` (feature, 21 files). `docs/field-notes/` left untracked. Not pushed.
- **Live preview (reduced containment, Docker):** solved **11/113** Juice Shop challenges, scored through real `mission.py` (645/12980, grade D). Target stopped after.
- **Live findings:** (1) Docker Desktop can't do reachable+egress-locked (`--internal` won't publish; masquerade-off still egresses) → VM host-only is the real contained topology; (2) new MCP tools/hook need reinstall+restart to go live.
- **B (fix containment):** `sandbox_preflight` now requires an empirical **egress probe** (`EGRESS_BLOCKED`), not a network-name inference; runbook demotes Docker to preview-only + promotes VM to contained; RND erratum + review addendum added. Authoritative `pytest -q` → **394 passed**.

## Session 2026-08-03: doc topology fix + deeper preview + WebGoat pass
- **Doc topology fix (`c8df283`):** the contained-VM runbook told operators to run the target at its host-only IP and allow-list that IP — which review fix #1's unconditional loopback-only `sandbox_allows` denies (verified live: `sandbox_allows('192.168.56.101',3000,[rule])` → deny). Corrected `sandbox-setup.md` / `sandbox-quickstart.md` to the working topology (container bound to VM-loopback + `ssh -L` tunnel to a host loopback port) + `01-RND.md` ERRATUM 2.
- **Juice Shop, deeper Docker preview:** **29/113** (was 11), scored via `mission.py` → 1615/12980, grade D. All grounded against `/api/Challenges`; catalog-vs-live drift check clean (0 solved keys missing from catalog).
- **WebGoat, first live pass:** loop proven (register/login → discover `.lesson` form fields → solve → per-lesson `reportcard.mvc` flip; **HTTP Basics** False→True). Two live oracle findings recorded in `docs/04-REVIEW.md` addendum 2: (1) `numberOfAssignmentsSolved` unreliable (96/96 fresh); (2) oracle is per-lesson while catalog is per-assignment → WebGoat per-assignment scoring needs a lesson↔assignment mapping (deferred build item).

- **CONTAINED VM RUN DONE (2026-08-03):** existing Ubuntu 22 VirtualBox VM, NAT cable disconnected + host-only `192.168.56.103` → egress **verified BLOCKED** (`curl 1.1.1.1` → 000 from inside the VM). Juice Shop pushed to **45/113** scored via `mission.py` (2710/12980, grade D, 20.9%), driven hand-on from Windows straight at the host-only IP (no SSH tunnel needed for the hand-driven path). Covers essentially every common HTTP-reachable bug class (SQLi/NoSQL, IDOR/access-control, auth/JWT-`alg:none`/change-password, XXE, upload, redirect, mass-assign, data exposure, business logic). Unsolved 72 by bucket: 15 browser-needed (XSS — automation harness choked on `javascript:` payloads), 27 hard 5-6★, 17 not-bounty-relevant, small HTTP tail skipped. See `docs/04-REVIEW.md` addenda 3-4.

**NEXT (when user is ready): the *gated tool-backed* run — plugin reinstall + Claude Code restart so the `bb-sandbox` skill + scope-guard hook drive it (not hand-scripts), reached via the SSH loopback tunnel into the same egress-locked VM.**

## Notes / deviations
_(appended as slices return)_
