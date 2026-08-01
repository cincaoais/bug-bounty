---
name: bb-sandbox
description: Autonomously find, exploit, and SCORE vulnerabilities in a LOCAL, deliberately-vulnerable OWASP sandbox (Juice Shop or WebGoat). Use when the user says something like "try to find bugs in OWASP Juice Shop, it's at http://localhost:3000" / "run a WebGoat mission" / "score my sandbox run", or otherwise asks to autonomously hunt a local training target. This is the ONLY bb skill that sends real traffic — and only ever to a localhost sandbox, never a real program.
---

# bb-sandbox — autonomous sandbox mission runner

This skill runs an **autonomous, narrated** hunt against a local training app and produces a **grounded scorecard** read from the app's own solve-state. It is the deliberate exception to the plugin's ingest-only rule, and it is safe only because every layer below assumes a disposable, deliberately-vulnerable, network-isolated localhost target.

**Hard preconditions — refuse to run unless ALL hold:**
1. The active target is `mode == 'sandbox'` (check `mcp__plugin_bb_bb__list_targets` / create one below). If it is not sandbox mode, STOP — never run this loop against a real program.
2. The target URL is a loopback host (`localhost` / `127.0.0.1` / `[::1]`) on a declared port.
3. The user's start prompt IS the authorization for this run. Do not invent a target or start unprompted.

If any precondition fails, say so plainly and stop. Do not "work around" it.

Two references carry the app-specific details — read the one for your target:
- `juiceshop.md` — Juice Shop challenge API, oracle, leaked-source assist, driver routing.
- `webgoat.md` — WebGoat register/login, `reportcard.mvc` oracle, per-lesson caveats.

---

## Phase 0 — Preflight (a hard gate; abort on any failure)

Do these IN ORDER and stop if any fails. Narrate each check. Nothing in steps 1-2
sends any traffic (target/rule/catalog setup are local DB writes) — the hard gate
in step 3 runs BEFORE the first real network action (step 4's reachability curl).

1. **Target + allow-list.** If no sandbox target exists yet, create one and declare its allow-list (all three loopback spellings on the port, because they are distinct identities):
   ```
   mcp__plugin_bb_bb__create_target(handle="juiceshop", mode="sandbox", sandbox_app="juice-shop")
   mcp__plugin_bb_bb__set_scope_rules(handle="juiceshop", rules=[
     {"pattern":"127.0.0.1:3000","in_scope":true},
     {"pattern":"localhost:3000","in_scope":true},
     {"pattern":"[::1]:3000","in_scope":true}])
   ```
   (Use the real port; WebGoat is 8080 and also 9090 for WebWolf. `sandbox_app` must be exactly `juice-shop` or `webgoat`.)

2. **Seed the objective catalog:** `mcp__plugin_bb_bb__seed_objectives(handle, app)`.

3. **Full preflight gate — HARD-ABORT unless `ready` is `True`.** The hook is only the first layer; the real boundary is network isolation (an internet-connected sandbox once led an agent to attack real orgs — see docs/01-RND.md Theme 4/6). Gather THREE pieces of evidence yourself, then hand them to the preflight tool — do not "check yourself" as a substitute for calling it. Note: **the network name is NOT proof of egress-blocking** (Docker Desktop can label a network internal and still egress — see `docs/sandbox-setup.md`), so egress is verified by an actual probe:
   ```
   # (a) network mode + port bindings
   docker inspect <container> --format '{{.HostConfig.NetworkMode}} {{json .NetworkSettings.Ports}}'
   # (b) EGRESS PROBE — a throwaway container on the SAME network trying to reach the internet; must FAIL
   docker run --rm --network <net> alpine sh -c "wget -T5 -q -O/dev/null http://1.1.1.1 && echo EGRESS_OPEN || echo EGRESS_BLOCKED"
   ```
   Then call `mcp__plugin_bb_bb__sandbox_preflight(network_mode="<NetworkMode>", port_bindings="<port output>", egress_test="<EGRESS_BLOCKED or EGRESS_OPEN>")`. This one call checks proxy env is clear (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` unset), the active target is sandbox mode, an allow-list is declared, AND network isolation (loopback-only bind + egress **empirically** blocked) — all together. `ready` is only `True` when EVERY check passes AND `network_isolation_verified` is specifically `"pass"` (an unconfirmed `"warn"`, or an `EGRESS_OPEN` probe, is not good enough — on Docker Desktop egress can't be blocked, so use the VirtualBox host-only VM per `docs/sandbox-setup.md`). **If `ready` is not `True`, abort** — read each failing check's `detail`, fix it, and retry. Do not proceed on trust.

4. **Reachability.** `curl -s -o /dev/null -w '%{http_code}' http://localhost:<PORT>/` returns a live code. (Explicit URL — see Command conventions.)

5. **Baseline snapshot (anti-cheat).** Poll the app's own solve-state ONCE (Juice Shop `GET /api/Challenges/`; WebGoat `GET /WebGoat/service/reportcard.mvc`) and collect the objective ids ALREADY solved. Then start the mission with that baseline — a rerun on a not-yet-reset app must not claim prior work:
   ```
   mcp__plugin_bb_bb__create_sandbox_mission(handle, base_url="http://localhost:3000",
       human_ack=true, baseline=[<already-solved objective ids>])
   ```
   (Tip: `docs/01-RND.md` notes you can restart the container for a clean slate, or Juice Shop's `continue-code` to snapshot/restore.)

Only after all five pass do you begin hunting.

---

## Phase 1 — Recon (feed the coverage ledger)

Discovery is the empirical bottleneck, not exploitation (RND Theme 3) — spend real effort here.
- Enumerate the surface: crawl routes, read the SPA bundle / `robots.txt` / `security.txt`, and USE the app's deliberate leaks. Juice Shop serves the actual vulnerable source at `/snippets/<challengeKey>` and exposes `/ftp`, `package.json.bak` — read the vulnerable line rather than pure black-box probing.
- Record what you find with `mcp__plugin_bb_bb__add_endpoints`, then `mcp__plugin_bb_bb__seed_test_cases` and `mcp__plugin_bb_bb__list_objectives(handle, mission_id, unsolved_only=true)` to see the target set.
- Narrate the map: which categories are untouched, where the density is.

---

## Phase 2 — The hunt loop (autonomous + narrated)

For each objective (prefer `next_actions` ranking and unsolved objectives; interleave categories to avoid tunnel vision):

1. **Hypothesize.** State, in one or two lines the user can learn from, *why* this endpoint/param is a candidate and which technique class applies. Load the matching `pb-*` playbook (via `bb-hunt`) for the methodology — but note: in sandbox mode YOU carry the exploit through to the solve, you do not stop at detection.

2. **Exploit — route the tool to the task** (RND Theme 8):
   - **HTTP/API** (most Juice Shop + WebGoat work): `curl` or a Python harness. Keep the target URL explicit and in the command text.
   - **DOM/client-side** (sandbox-bypass XSS, UI-only challenges): drive it with the Chrome tools — HTTP diffing cannot see script execution.
   - **Inspection/replay:** Burp MCP send tools when you want the request in proxy history.

3. **Verify against the app's OWN state — never your own opinion.** A challenge is solved ONLY when the app reports it solved (Juice Shop `/api/Challenges` `solved:true` for that `key`; WebGoat `reportcard.mvc` / `lessonoverview.mvc`). Response-string matching is a gameable oracle (RND Theme 4) — do not use it. Equally: never accept your own "not exploitable" verdict without an app-state check.

4. **Record with evidence (mandatory on a solve).** Store the request/response: `mcp__plugin_bb_bb__store_evidence(...)` → get an `evidence_id` → `mcp__plugin_bb_bb__record_objective_result(handle, mission_id, objective_id, solved=true, evidence_id=<id>)`. `record_objective_result` refuses a solve without evidence, and credit is monotonic.

5. **Narrate every attempt, win or lose:** `mcp__plugin_bb_bb__log_attempt(handle, mission_id, phase, action_summary, reasoning_md, objective_id, tool_used, outcome, evidence_id?)`. This is what the user follows and learns from, and it's the after-action timeline.

6. **Respect the attempt cap.** `log_attempt` returns `over_cap` / `attempts_remaining` (cap = 5 per objective). When `over_cap` is true, STOP attacking that objective and move to the next — repeat-payload looping is the #1 failure mode (RND Theme 3, 6). Bank anything reusable as a primitive/lead for later.

Keep going until the unsolved set is exhausted, progress stalls across several objectives, or the user stops you.

## Command conventions (the hook enforces these in sandbox mode)
- Every HTTP request carries an explicit in-sandbox URL in the command text: `curl http://localhost:3000/rest/...` (schemeless `curl localhost:3000/...` is also fine).
- Python/Node harnesses take the target as a **CLI argument**: `python3 harness.py http://localhost:3000 ...` — never hide the URL inside the script (the hook denies a network command with no visible in-sandbox target).
- Banned (the hook denies): `$(...)`/backticks, `base64 -d`/`xxd -r` decode pipes, `curl --resolve/--connect-to`, `-L/--location`, `-x/--proxy`, inline `HTTP(S)_PROXY=`. If you hit a deny, it's telling you the command hides its target — rewrite it explicitly, don't try to bypass.
- Any host:port not on the declared allow-list is denied and cannot be rescued by `scope_override` — that's by design. This includes non-loopback hosts even if a scope rule somehow names one — sandbox mode only ever allows `127.0.0.1`/`::1`/`localhost`, never anything else, regardless of declared rules.
- **IPv6 loopback: use `127.0.0.1` or the schemeless `[::1]:PORT` form, not scheme'd `http://[::1]:PORT`.** The hook's URL matcher intentionally stops at a closing `]` (needed elsewhere to not swallow trailing punctuation) which means a scheme'd IPv6-literal URL currently fails closed — it gets read as a truncated, unmatchable target and denied, not allowed. This is a known, accepted gap (not fixed, to avoid loosening the URL matcher itself); route around it with `127.0.0.1` or the schemeless bracket form instead.

## Residual gap — browser-driven testing is not fully hook-visible
The scope-guard hook inspects tool-call *arguments*, not what a page's own JavaScript does once a Chrome tab is allowed to load: a dynamically-constructed URL built inside browser JS (e.g. from a template literal or string concatenation at runtime) is not something the hook can see or evaluate, the same way `$(...)`/decode-pipe obfuscation in a Bash command isn't. Sandbox mode now also runs `sandbox.is_ambiguous` over chrome-tool inputs (catching `$(...)`/backtick/decode-pipe/proxy shapes written literally into the tool call), but that is a text-level check, not JS execution analysis — it does not "see inside" what a script computes at runtime.

This is NOT closed by the hook, and the mitigation is NOT the hook: it is that Chrome here is the user's real, ordinary browser — it does **not** run inside the target's `--network internal` container, so a JS-driven navigation to somewhere unexpected is still a real request from the user's machine. The actual mitigations (per `docs/sandbox-setup.md`'s Browser containment section) are (1) a disposable, origin-scoped Chrome profile with the `claude-in-chrome` extension permission narrowed to the sandbox origin, and (2) preferring API/HTTP (`curl`/Python) over browser JS whenever a challenge is API-solvable, reserving browser drivers for cases that genuinely require DOM execution. Do not treat this as fully closed — it isn't.

---

## Phase 3 — Score & after-action report

1. **Re-poll before crediting (reproducibility).** Before completing, poll the app's state once more and confirm each credited objective still shows solved.
2. `mcp__plugin_bb_bb__mission_scorecard(handle, mission_id)` for the live read.
3. `mcp__plugin_bb_bb__complete_mission(handle, mission_id)` — freezes the scorecard (points come from difficulty; baseline-solved challenges are never credited).
4. `mcp__plugin_bb_bb__assemble_after_action_report(handle, mission_id)` and present it: what was solved and how, what was missed (with points foregone), the timeline, and "what to learn next" cross-referenced to the `pb-*` playbooks. Be honest about a quiet run — inflating it corrupts the record the next mission builds on.

## Firm rules
- Sandbox targets only. If the active target isn't `mode=='sandbox'`, this skill does not run.
- The app's own solve-state is the sole scoring authority. Your judgment feeds `coverage` (a working opinion), never the score.
- Evidence-backed solves only; monotonic credit; attempt caps respected; every step narrated.
- The two enforcement layers (the scope-guard hook + `--network internal`) are not optional — if preflight can't verify containment, you don't run.
