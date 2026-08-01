# Review & Test Report: Autonomous Sandbox Mode

_System-builder Phase 4 output. Written 2026-08-01. Covers the built feature through the code-review + offline-test gate. The live scenario walkthrough is deliberately deferred to the user-gated run._

## Verdict
**Ready for a gated live run.** All build slices are implemented, verified, and regression-clean (391 tests pass). A holistic adversarial review found three confirmed traffic-escape paths and two guarantee-gaps; all five were fixed and each is now covered by an adversarial test that fails-without / passes-with the fix — independently re-confirmed by the commander against the live hook. Real-program (bounty) behavior is byte-for-byte unchanged. Two low-severity, fail-closed limitations remain, documented below; neither lets traffic leave the sandbox.

## Review findings
Holistic Phase 4 review (findings ranked as originally reported; all CONFIRMED by executing code):

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | Critical | `sandbox_allows` didn't require the host to be loopback → a planted `evil.com:443` allow-rule would permit real egress | **FIXED** — loopback enforced in `sandbox_allows` regardless of declared rules |
| 2 | Critical | `(host,port)` keying only covered schemeless tokens; two scheme'd URLs to same host/diff ports collapsed | **FIXED** — `_extract_sandbox_candidates` independently re-scans URLs keyed by `(host,port)` |
| 3 | Critical | `curl -x/--proxy <host>` routed to an unevaluated proxy, not flagged ambiguous | **FIXED** — `-x`/`--proxy` added to `is_ambiguous` |
| 4 | High | `sandbox_preflight` returned `ready:True` when isolation unconfirmed; skill never called it | **FIXED** — `ready` requires `network_isolation_verified=="pass"`; skill now runs `docker inspect`→`sandbox_preflight` and hard-aborts |
| 5 | High | Solve-evidence was a presence check only; a nonexistent `evidence_id` still credited points | **FIXED** — server refuses a solve whose `evidence_id` doesn't resolve to stored content |
| 6 | Medium | `record_objective_result` after `complete_mission` desynced the after-action report from the frozen score | **FIXED** — mission immutable after completion (unless `force=True`) |
| 7 | Medium | Ambiguity check was Bash-only; dynamically-built URLs in browser JS not hook-visible | **PARTIAL/DOCUMENTED** — chrome tool_input now ambiguity-checked + structured `url` extraction; residual (dynamic JS URLs) documented, mitigated operationally (see Known issues) |
| 8 | Low (fail-closed) | `http://[::1]:PORT` scheme'd form truncated by `URL_RE` → wrongly denied | **DOCUMENTED** — `URL_RE` (security-critical) left intact; skill/refs instruct using `127.0.0.1` or schemeless `[::1]:PORT` |
| 9 | Low (fail-closed) | schemeless `navigate(url="localhost:3000")` wrongly denied (JSON-artifact port parse) | **FIXED** — structured `url` field extraction for chrome/WebFetch tools |
| 10 | Low (doc) | `docs/sandbox-setup.md` stale "preflight not wired" claim | **FIXED** — doc corrected |

## Fixes applied
`sandbox.py` (#1 loopback enforcement, #3 proxy-flag ban) · `scope-guard.py` (#2 URL re-scan by pair, #7 chrome ambiguity + structured extraction, #9) · `server.py` (#4 preflight `ready`, #5 evidence existence, #6 `force` passthrough) · `mission.py` (#6 completed-mission guard) · `SKILL.md` + `docs/sandbox-setup.md` + `juiceshop.md` (#4/#7/#8/#10 docs). +14 tests.

## Test results
Commander-run, authoritative, on the final tree:
```
python -m pytest -q  →  391 passed in 19.77s
```
(Baseline before this milestone: 223 tests. Now 391 — all pre-existing pass unchanged; +168 new across sandbox, mission, hook, registry, flow, correlate, server-smoke.)

## Scenario walkthroughs (offline / mocked — live run is user-gated)
1. **Escape resistance (commander adversarial script, `scratchpad/adv_verify.py`)** — with a sandbox target whose allow-list was deliberately poisoned with `evil.com:443`:
   - `curl http://evil.com:443/x` → **deny** (loopback enforced) ✓
   - `curl http://localhost:3000/a && curl http://localhost:9999/b` → **deny** (both ports surfaced) ✓
   - `curl -x proxyhost:8080 http://localhost:3000/x` / `--proxy attacker.example:9090` → **deny** ✓
   - `curl 2130706433:9999/x` → **deny** ✓
   - `curl http://localhost:3000/...` and schemeless `curl localhost:3000/x` → **allow** ✓
   - `ls -la ./notes` → **defer** ✓
2. **Mission lifecycle (`test_sandbox_flow.py`)** — create sandbox target → seed 113-challenge catalog → baseline snapshot (2 pre-solved) → 3 evidence-backed solves → attempt-cap trips at 6th → scorecard credits only the 3 (baseline excluded) → freeze → after-action report with all sections. ✓
3. **Gate integrity** — `create_sandbox_mission` refuses without `human_ack` and on a bounty target; `promote_to_finding(sandbox_auto_confirm=True)` cannot bypass `correlate.py`'s wall on a bounty target or an unsolved objective. ✓
4. **Regression** — bounty-mode hook decisions (deny out-of-scope, allow in-scope, burp gating, override-once) all unchanged; 20/20 bounty subset + full suite green. ✓

## Plan conformance (Definition of Done, docs/02-PLAN.md)
| # | Item | Status |
|---|------|--------|
| 1 | Full suite + new tests pass; bounty unchanged | ✅ Met (391 passed; regression asserted) |
| 2 | Sandbox host:port allow, all else deny, override can't rescue, ambiguity/zero-candidate deny | ✅ Met (was falsified pre-fix by #1/#2/#3; now closed + adversarially verified) |
| 3 | Real-program bare-IP gap closed, no false denies | ✅ Met |
| 4 | Mission lifecycle + grounded monotonic scorecard; attempt-cap; auto-confirm triple-gated; correlate wall intact | ✅ Met (grounding hardened by #5 fix) |
| 5 | Preflight aborts unless containment verified; dry-run works; refs accurate | ✅ Met (was #4; now enforced) |
| 6 | Setup runbook + version 0.2.0 | ✅ Met |
| 7 | Gated live demo | ⏳ Awaiting user permission (this report's purpose) |

## Known issues & limitations (honest)
- **Browser JS egress is not fully hook-containable (#7).** The claude-in-chrome tools drive the user's *real* Windows Chrome, which is NOT inside the target's `--network internal` container, so a dynamically-constructed `fetch()` to an external host from injected JS could reach it. Mitigation is operational: a **disposable, origin-scoped Chrome profile** (per `docs/sandbox-setup.md`) so there's nothing to exfiltrate, plus preferring HTTP/API over browser JS. The hook catches the static forms; it cannot statically resolve all dynamic JS URLs.
- **IPv6 scheme'd form (#8).** `http://[::1]:PORT` fails closed (denied); use `127.0.0.1:PORT` or schemeless `[::1]:PORT`. Not a security issue.
- **Catalog vs live drift.** The scorecard scores against the bundled catalog (113 JS / 107 WebGoat); a challenge present live but absent from the catalog won't score (documented in `juiceshop.md`). Catalogs are current as of 2026-08-01.
- **Not yet exercised against a real container** — see Phase 7 below.

## Suggested next steps
1. **The gated live run** (below) — the true end-to-end validation.
2. WebGoat live pass (harder: per-lesson endpoints, session ordering, WebWolf) after Juice Shop proves out.
3. Optional: wire Juice Shop's `SOLUTIONS_WEBHOOK`/CTF-flag mode as a second oracle (stretch).
4. Commit to a branch once the user approves (nothing is committed yet).
