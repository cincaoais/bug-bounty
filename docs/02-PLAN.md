# Implementation Plan: Autonomous Sandbox Mode for the `bb` plugin

_System-builder Phase 2 output. Executable from `docs/00-BRIEF.md` + `docs/01-RND.md` + this file alone. Written 2026-08-01. **v2** — adversarial-review fixes folded in (see changelog)._

## Goal recap
Add an opt-in **sandbox mode** to the `bb` plugin so that, on a start command like _"find bugs in Juice Shop at http://localhost:3000"_, Claude autonomously discovers → exploits → **scores** vulnerabilities against local OWASP Juice Shop / WebGoat, narrating as it goes, with the score read from the app's own solve-state. Success = regression-free for real programs; autonomous traffic provably confined to the sandbox; grounded (non-self-graded) scorecard; works for both apps.

## Changelog — v2 (adversarial review fixes)
A fresh-eyes reviewer found the v1 plan's port-handling and zero-candidate paths would silently defeat the containment claim. All 17 findings folded in; the load-bearing ones:
- **Extraction now carries a port** end-to-end (`extract_targets` → `(host, port, path)`), and a **schemeless `localhost:PORT`/loopback path** is added — without these the `(host,port)` allow-list could never fire (findings #1, #2).
- **Zero network-candidate in sandbox mode = DENY, not defer** (finding #3); Python/interpreter harnesses must pass the target URL as an explicit CLI arg (new §Command conventions).
- **Containment is verified, not just documented** — the skill preflight runs `docker inspect` and aborts unless `--network internal` + `127.0.0.1` bind are actually in effect (finding #4).
- **Repeat-breaker/attempt-cap enforced in code** (`log_attempt` returns `over_cap`), not prose (finding #5).
- Sticky/monotonic solve credit (#9), `check_scope` sandbox-aware (#10), numeric-IP positional discipline to avoid false denies (#11), guarded-ALTER matches `"duplicate column"` only + `SCHEMA_VERSION→2` (#7,#8), `correlate.py`'s human-confirm wall is never edited (#17), and smaller items (#12–#16).

## Architecture overview

```
                          ┌─────────────────────────────────────────────┐
  User start prompt  ───▶ │  bb-sandbox SKILL (run loop, narrated)        │
  "find bugs in JS"       │  preflight→recon→hypothesize→exploit→verify→  │
                          │  record→score ; repeat-breaker + attempt caps │
                          └───────┬───────────────┬───────────────┬──────┘
        drives tools (sandbox-gated)              │ reads/writes state
   ┌──────────┬───────────┬─────────┐            │
   ▼          ▼           ▼         ▼             ▼
 Bash/curl  Python     Chrome    Burp      mcp__plugin_bb_bb__* (MCP server, NO network)
 (explicit  harness    MCP       MCP        create_sandbox_mission / seed_objectives /
  URLs)     (URL as arg)│        │          record_objective_result / log_attempt(cap) /
   │          │           │        │        mission_scorecard / complete_mission ...
   └──────────┴─────┬─────┴────────┘                       │
                    ▼                                       ▼
        PreToolUse hook: scope-guard.py            SQLite (per-target .db + registry.db)
        if target.mode=='sandbox':                 target(+mode,+sandbox_app) · mission ·
          extract (host,PORT) incl. schemeless     objective · mission_objective_result ·
            localhost:PORT + numeric loopback       mission_attempt · sandbox_audit ·
          sandbox_allows(host,port) → allow/deny    (+coverage ledger reuse, +mission_id)
          NO override · deny-on-ambiguity
          zero network-candidate → DENY
        else: existing real-program logic (UNCHANGED)
                    │
                    ▼
     REAL backstop, VERIFIED at preflight: targets run --network internal + -p 127.0.0.1:PORT
     (egress lockdown; the hook is the first layer, not the only one)
```

Two enforcement layers, deliberately: the **hook** (software allow-list, first line) and the **network** (`--network internal`, the true boundary that also catches what a hook structurally can't — SSRF from inside the container, browser click-nav, arbitrary harness code). Scoring is **grounded**: Claude fetches the app's own `/api/Challenges` (Juice Shop) or `reportcard.mvc` (WebGoat); the server only *records* it, never fetches.

## Command conventions (sandbox mode) — new in v2
So the hook can actually see the target of every request:
- **All HTTP requests carry an explicit, in-sandbox URL in the command text.** `curl http://localhost:3000/rest/...` or `curl localhost:3000/...` (schemeless allowed — see extraction). No target hidden behind a variable.
- **Python/Node harnesses receive the base URL as a CLI argument**: `python3 harness.py http://localhost:3000 ...` — never hardcode the target inside the script where the hook can't see it.
- **Banned in sandbox mode** (deny-on-ambiguity): command substitution `$(...)`/backticks, decode pipes (`base64 -d`, `xxd -r`), `curl --resolve/--connect-to`, `-L/--location` auto-follow, inline `HTTP(S)_PROXY=`/`ALL_PROXY=`.
- **A network-capable command that yields no in-sandbox candidate is DENIED**, not deferred. Non-network shell (ls/cat/grep/jq on local files) defers to normal flow as today.

## Tech stack & justification
- **Extend the existing Python/SQLite/FastMCP plugin** (no new runtime) — 01-RND §Theme 7: the design maps onto existing primitives (coverage ledger, evidence store, findings graph); recon-as-bottleneck (§Theme 3) is what the ledger already addresses.
- **Additive `target.mode` gate, real-program path untouched** — 00-BRIEF non-negotiable; 01-RND §Theme 6.
- **Hook `permissionDecision:"allow"` for auto-approve** — 01-RND §Theme 5 (only plugin-authored auto-approve path).
- **`--network internal` + `127.0.0.1` bind as the real containment, verified at preflight** — 01-RND §Theme 6 + the Anthropic incident (§Theme 4): instruction-based boundaries fail.
- **Grounded scoring via the app's own state, record-only tools** — 01-RND §Theme 1 + §Theme 4 (TrustedSec gameable-oracle); preserves the server no-network invariant (§Theme 7).
- **Juice Shop first, WebGoat second** — 01-RND §Theme 2.
- **Single-session narrated ReAct loop with a code-enforced repeat-breaker + attempt caps** — 01-RND §Theme 3 (tunnel-vision is the #1 failure); Option 3 (fan-out) rejected as overkill.

## Milestones & vertical slices

### Milestone 1 — Sandbox mode foundation (state + gate; no traffic)

**Slice 1.1 — Target mode column + registry gate**
- Delivers: `target` gains `mode` + `sandbox_app` via
  `ALTER TABLE target ADD COLUMN mode TEXT NOT NULL DEFAULT 'bounty'` and
  `ALTER TABLE target ADD COLUMN sandbox_app TEXT NOT NULL DEFAULT ''`,
  each guarded by a helper that runs the ALTER and **catches only `sqlite3.OperationalError` whose message contains `"duplicate column"` (re-raising anything else)** (finding #7); `create_target(..., mode="bounty", sandbox_app="")`; `registry.active_target()` returns `mode`/`sandbox_app`; `registry.is_sandbox()`. Bump `SCHEMA_VERSION` 1→2 (finding #8).
- Acceptance: existing targets read `mode='bounty'`; new sandbox target reads `mode='sandbox'`; every existing test passes unchanged.
- Test gate: `tests/test_registry_mode.py` + full suite green.
- Depends on: none. Parallel with: 1.2, 3.3.

**Slice 1.2 — Sandbox allow-list & ambiguity module (`sandbox.py`, pure functions)**
- Delivers: `sandbox_allows(host, port, rules) -> (bool, reason)` — `host ∈ {127.0.0.1, ::1, localhost}` AND `port` in the declared set; **`port` is mandatory (None → deny)**; no wildcard/CIDR. `is_ambiguous(command) -> (bool, reason)` (the banned constructs above). `proxy_env_set() -> (bool, which)`. `canonical_host(token) -> str|None` (decimal `2130706433`, octal, `127.1`, `::ffff:127.0.0.1` → `127.0.0.1`; non-loopback → passthrough/None).
- Acceptance: `('localhost',3000)` allow if declared; `('localhost',9999)` deny; `('evil.com',3000)` deny; `(host,None)` deny; numeric forms canonicalize; ambiguity + proxy detected.
- Test gate: `tests/test_sandbox.py` ≥25 cases incl. every escape form from 01-RND §Theme 6.
- Depends on: none. Parallel with: 1.1, 3.3.

### Milestone 2 — Scope-guard sandbox branch + hook hardening (safety core)

**Slice 2.1 — Extraction rework: carry the port, close the bare-IP gap**
- Delivers: `extract_targets` returns **`(host, port, path)`** at every site (finding #1) — `_split_url` keeps the port (default 80/http, 443/https when absent); IPv4/bare paths capture `:PORT` when present; Burp path uses `targetPort`. Bare non-dotted-quad numeric/short IP tokens are extracted **only under the same positional discipline used for bare domains** (immediately preceded by a network tool or `-u/--url/--target`) to avoid denying `--max-time 2130706433`-style flags (finding #11), canonicalized via `sandbox.canonical_host`. `decide()` and `registry.check_scope` updated to accept the port (real-program `is_in_scope` stays **port-agnostic** — it just ignores the extra value, so real behavior is unchanged).
- Acceptance: `curl 2130706433:3000` and `curl 127.1` now produce an evaluated candidate; `curl --max-time 2130706433 http://in-scope.example` is NOT falsely denied; all previously-working real-program cases unchanged.
- Test gate: extend `tests/test_hook.py` (bare-IP positive + numeric-flag negative + port-carry) ; full suite green.
- Depends on: 1.2. Parallel with: 3.1.

**Slice 2.2 — Sandbox branch in scope-guard + schemeless extraction + matchers + audit**
- Delivers: early `if registry.is_sandbox():` branch in `decide()`:
  - a **schemeless loopback extractor** (finding #2): tokens `localhost:PORT` / `127.0.0.1:PORT` / `[::1]:PORT` are candidates even without a dot or scheme;
  - run `sandbox.sandbox_allows(host, port, rules)` → **`allow`** in-sandbox host+port on active-testing tools; **`deny`** any non-sandbox host/port; **`deny`** on `is_ambiguous`; **`deny` when the command invokes a network-capable tool but yields zero in-sandbox candidate** (finding #3); **never** consult `take_override`; **`defer`** only for genuinely non-network shell;
  - append every allow/deny to a new **`sandbox_audit` SQLite table** (finding #12);
  - `plugin.json`: add matchers `WebFetch` and `mcp__claude-in-chrome__.*`; add a **`SessionStart` hook** (matcher `startup|resume`) that emits `additionalContext` "bb sandbox mode active for <handle>" when the active target is sandbox (finding #15).
  - `registry.check_scope`: when active target is sandbox, **skip `take_override` and answer via `sandbox_allows`** so the tool's answer matches enforcement (finding #10).
  - Real-program branch = the existing code path under the `else`, **verbatim**.
- Acceptance: sandbox target → `localhost:3000` allow, `localhost:9999`/`evil.com` deny, `python3 x.py` (no URL) deny, `$(...)`/`--resolve` deny, `scope_override` does NOT clear a sandbox deny; bounty target → output byte-for-byte identical to pre-change.
- Test gate: extend `tests/test_hook.py` (sandbox allow/deny/ambiguity/zero-candidate/override-skip/schemeless) + regression block (bounty output unchanged) + a `sandbox_audit` row-written assertion; full suite green. **The live smoke test of hook-`allow` uses a throwaway `python -m http.server` on a scratch port, NEVER the real apps** (finding #6).
- Depends on: 1.1, 1.2, 2.1. Run solo (touches hook + plugin.json + registry).

### Milestone 3 — Mission & scoring state layer

**Slice 3.1 — Mission/objective schema + `mission.py`**
- Delivers: new `CREATE TABLE IF NOT EXISTS`: `mission`, `objective`, `mission_objective_result` (with `baseline_solved`), `mission_attempt`, `sandbox_audit`; guarded ALTERs (same `"duplicate column"`-only guard) adding nullable `mission_id` to `note`/`lead`/`primitive` and `objective_id` to `lead` — placed in `init_target_db` (per-target DB), NOT `init_registry` (finding #7/4b). `mission.py`: CRUD + scoring (`POINTS_BY_DIFFICULTY={1:10,2:25,3:50,4:100,5:200,6:400}`, `SCORING_VERSION`, `credited = solved AND NOT baseline_solved`, scorecard, grade bands). **`record_objective_result` is monotonic**: once `solved=1` with evidence, a later `solved=0` for the same (mission,objective) is refused (finding #9).
- Acceptance: create mission → seed → record (incl. attempted downgrade rejected) → scorecard from fixtures; frozen scorecard stable.
- Test gate: `tests/test_mission.py`.
- Depends on: 1.1. Parallel with: 2.2.

**Slice 3.2 — Record-only MCP tools + attempt-cap + gated auto-confirm**
- Delivers `server.py` tools: `create_sandbox_mission` (refuses unless `human_ack` AND server-read `mode=='sandbox'`; snapshots baseline), `seed_objectives`, `list_objectives`, `record_objective_result` (requires `evidence_id` when `solved`; soft substring sanity check; monotonic), `log_attempt` (**server-side per-(mission,objective) attempt counter; returns `attempts_remaining`/`over_cap` with cap = 5** — finding #5; also writes `mission_id` on any linked note/lead — finding #13), `mission_log`, `mission_scorecard`, `complete_mission(force=False)` (freezes once), `list_missions`, `assemble_after_action_report`. Extend `promote_to_finding` **in `server.py`'s wrapper only** with `sandbox_auto_confirm=False`, honored only when the wrapper independently reads `mode=='sandbox'` AND the lead resolves to a solved objective, then calls the existing function with `human_confirmed=True`. **`correlate.py`'s `promote_to_finding` and its `if human_confirmed is not True: raise` wall are NOT modified** (finding #17).
- Acceptance: mission lifecycle via tools; `over_cap` returned after 5 attempts; auto-confirm refuses on bounty target and on unsolved objective; report assembles from stored data only.
- Test gate: extend `tests/test_mission.py` + `tests/test_server_smoke.py`.
- Depends on: 3.1. Parallel with: 3.3.

**Slice 3.3 — Objective catalogs (reference data)**
- Delivers `plugin/reference/juiceshop-challenges.json` + `webgoat-lessons.json` (`{id, app, native_id, name, category, difficulty, description, wstg_category_hint}`); Juice Shop difficulty from stars, WebGoat hand-tiered 1/3/5. Totals read live at runtime; unknown live challenges recorded gracefully, never dropped.
- Test gate: `tests/test_mission.py` seeding cases (incl. an uncatalogued-challenge path).
- Depends on: 3.1. Parallel with: 3.2.

### Milestone 4 — Autonomous run-loop skill + Juice Shop MVP

**Slice 4.1 — `bb-sandbox` SKILL (the run loop)**
- Delivers `plugin/skills/bb-sandbox/SKILL.md`:
  - **Preflight (hard gate, in-skill):** `proxy_env_set` clear; run `docker inspect <container> --format '{{.HostConfig.NetworkMode}}'` + port-binding check via Bash and **abort unless `--network internal` + `127.0.0.1` bind are confirmed** (finding #4); confirm/create sandbox target + allow-list rules; `create_sandbox_mission` with the start prompt as `human_ack`.
  - Baseline snapshot; recon (enumerate surface incl. Juice Shop's leaked `/snippets`,`/ftp`,`package.json.bak`; feed the coverage ledger).
  - ReAct loop with **explicit tool routing** (curl/python for HTTP per §Command conventions, Chrome for DOM, Burp for inspection); **consult `log_attempt`'s `over_cap`/`attempts_remaining` and move to the next objective when capped** (finding #5); **verification discipline** — an objective is solved ONLY when the app's own state confirms it, store request/response as evidence, never accept self-report either way.
  - `record_objective_result` + `log_attempt` narration; **before `complete_mission`, re-poll `/api/Challenges` once and confirm each credited objective still shows solved** (finding #14); then `mission_scorecard` → `complete_mission` → `assemble_after_action_report`.
- Acceptance: skill discoverable; a **mocked** mission (no live target) exercises tool wiring end-to-end → scorecard from injected results; over_cap path exercised.
- Test gate: `tests/test_sandbox_flow.py` (mocked lifecycle; no live traffic).
- Depends on: 2.2, 3.2, 3.3.

**Slice 4.2 — Juice Shop solve-methodology reference**
- Delivers `plugin/skills/bb-sandbox/juiceshop.md`: category map, API-first-then-browser routing, `/snippets` read-the-source assist, `/api/Challenges` oracle, continue-code snapshot, known browser-only classes.
- Test gate: referenced-file existence check in `test_sandbox_flow.py`.
- Depends on: 4.1.

### Milestone 5 — WebGoat slice

**Slice 5.1 — WebGoat catalog + methodology reference**
- Delivers `webgoat-lessons.json` (hand-tiered) + `plugin/skills/bb-sandbox/webgoat.md`: register/login, `JSESSIONID`+`X-Requested-With` discipline, `reportcard.mvc` oracle, per-lesson path/param table, ordered-assignment/session caveat, WebWolf note, **exclude `restartlesson.mvc` from retry paths**.
- Test gate: `tests/test_mission.py` WebGoat seeding + `test_sandbox_flow.py` mocked WebGoat mission.
- Depends on: 3.3, 4.1.

**Slice 5.2 — WebGoat run-loop adaptation**
- Delivers: `bb-sandbox` handles the `reportcard.mvc` oracle + session auth; app selected via `sandbox_app`.
- Test gate: `test_sandbox_flow.py` WebGoat path (mocked).
- Depends on: 5.1.

### Milestone 6 — Hardening, setup docs, packaging

**Slice 6.1 — Setup runbook + version bump**
- Delivers `docs/sandbox-setup.md`: Docker (`--network internal` + `-p 127.0.0.1:PORT:PORT`) default + VirtualBox host-only fallback, disposable Chrome profile + origin-scoped extension permission, proxy-preflight, "restart to reset state". Bump `plugin.json` to `0.2.0`; update README.
- Test gate: doc present; `plugin.json` valid JSON; version bumped.
- Depends on: all prior.

**Slice 6.2 — Sandbox preflight tool**
- Delivers `sandbox_preflight()` MCP tool: verifies proxy env unset, active target is sandbox, allow-list rules present; returns a structured checklist INCLUDING an explicit `network_isolation_verified` field the **skill** must satisfy by pasting the `docker inspect` result (the tool records/validates it; the server itself makes no network/subprocess call) (finding #4).
- Acceptance: returns fail when `HTTP_PROXY` set or target not sandbox or isolation unconfirmed.
- Test gate: `tests/test_sandbox.py` preflight cases.
- Depends on: 1.2, 2.2.

## File / module layout
```
plugin/
  mcp/
    db.py          (edit: guarded ALTERs [dup-column-only], new CREATE TABLEs, SCHEMA_VERSION→2)
    registry.py    (edit: mode/sandbox_app, is_sandbox, check_scope sandbox-aware, override-skip)
    sandbox.py     (NEW: allow-list, ambiguity, proxy, canonical_host)
    mission.py     (NEW: mission/objective/scoring, monotonic credit)
    server.py      (edit: new @mcp.tool()s, create_target/promote_to_finding WRAPPER only)
    correlate.py   (edit: add_note/add_lead/add_primitive accept + write mission_id)  ← firm, not hedge
    coverage.py    (edit: only if cross-link needs it)
  hooks/
    scope-guard.py (edit: (host,port,path) extraction, schemeless loopback, sandbox branch, audit)
  reference/
    juiceshop-challenges.json (NEW) · webgoat-lessons.json (NEW)
  skills/
    bb-sandbox/SKILL.md (NEW) + juiceshop.md + webgoat.md
  .claude-plugin/plugin.json (edit: matchers WebFetch + chrome, SessionStart, version 0.2.0)
docs/
  sandbox-setup.md (NEW)
tests/
  test_registry_mode.py, test_sandbox.py, test_mission.py, test_sandbox_flow.py (NEW)
  test_hook.py (edit: port-carry, bare-IP, schemeless, sandbox branch, regression block)
```

## Execution order & suggested subagent assignment
Parallel mode, ≤3 concurrent coding agents, only on non-conflicting files. **Fixes #1–#6 are in Waves 1–3 (before/at the hook branch) — the reviewer's blocking set.**
1. **Wave 1 (parallel):** 1.1 (db/registry) · 1.2 (sandbox.py) · 3.3 (catalogs).
2. **Wave 2 (parallel):** 2.1 (extraction rework, needs 1.2) · 3.1 (mission.py, needs 1.1).
3. **Wave 3:** 2.2 (hook sandbox branch — needs 1.1/1.2/2.1; solo) ‖ 3.2 (MCP tools + correlate mission_id — needs 3.1).
4. **Wave 4:** 4.1 (skill) → 4.2 (Juice Shop ref).
5. **Wave 5:** 5.1 → 5.2 (WebGoat).
6. **Wave 6:** 6.1 · 6.2.
Commander verifies each slice: read the actual diff + re-run the slice's test gate + full suite; never trust self-report.

## Risks & rollback
- **Regression in real-program mode** → every hook/registry slice ships a byte-for-byte regression assertion; rollback = revert the atomic slice commit.
- **Guarded ALTER** → dup-column-only guard re-raises real errors; columns are additive/nullable, safe to leave on rollback.
- **Hook `allow` misbehaves** → smoke-tested in 2.2 against a throwaway listener before anything builds on it; runbook documents a `bypassPermissions` fallback if needed.
- **Containment not actually applied** → preflight aborts the run (finding #4), so a mis-run fails closed rather than leaking.
- **App version drift** → catalogs are metadata-only; totals read live; unknown challenges recorded.

## Definition of done (Phase 4 checks against this)
1. Full existing suite + all new tests pass; bounty-mode output proven unchanged.
2. Sandbox target: `localhost:PORT` (schemed AND schemeless) auto-allowed; any other host/port denied; numeric-IP loopback forms handled; override cannot clear a sandbox deny; ambiguity/zero-network-candidate denied.
3. Real-program bare-IP gap closed with no new false denies (numeric-flag negative test passes).
4. Mission lifecycle + grounded, monotonic scorecard on mocked data; attempt-cap enforced; auto-confirm triple-gated; `correlate.py` wall untouched.
5. `bb-sandbox` preflight aborts unless containment verified; full narrated loop dry-run verified; Juice Shop + WebGoat references present/accurate.
6. Setup runbook documents `--network internal` + `127.0.0.1` bind + disposable Chrome profile; version 0.2.0.
7. **Gated live demo:** after explicit user permission, one real Juice Shop run solves a meaningful set of challenges with a grounded scorecard — Phase 4.
```
