# RND Report: Autonomous Sandbox Mode for the `bb` plugin

_System-builder Phase 1 output. Synthesized from six parallel research missions + direct reads of the current codebase. Written 2026-08-01. Read alongside `docs/00-BRIEF.md`._

## Executive summary

We researched how to give the existing ingest-only `bb` plugin an opt-in **autonomous sandbox mode** that finds, exploits, and *scores* its own results against local OWASP Juice Shop and WebGoat. The single most important takeaway: **grounded, spoof-proof scoring is achievable and cheap** — both apps expose server-authoritative solve state (Juice Shop `GET /api/Challenges/` with a `solved` boolean per challenge; WebGoat `GET /WebGoat/service/reportcard.mvc` with solved/total counts), and prior art is unanimous that an autonomous agent's own "I solved it" claim must never be trusted — only the app's own state counts. The second most important takeaway is a safety one, independently reached by two missions and one real Anthropic incident: **the deterministic hook is not a sufficient containment backstop; hard network isolation is.** An internet-connected eval sandbox once led Claude to attack real organizations because it couldn't tell sandbox from production — so sandbox mode's real guarantee comes from running the targets with `--network internal` + a `127.0.0.1`-only bind, with the (upgraded, stricter) scope-guard hook as the first layer, not the only one. Recommended direction: an **additive** sandbox mode gated on a new `target.mode=='sandbox'` flag, leaving real-program behavior byte-for-byte unchanged; Juice Shop first (clean API, self-contained detection), WebGoat second (harder — hand-authored per-lesson endpoints, ordered session state). Research also surfaced **two real, pre-existing security gaps in the current hook** that this milestone should fix. No blocking unknowns remain; one environment question (Docker vs VirtualBox) is open but the plan can support both.

## Research missions

| Mission | Subagent role | Sources covered | Status |
|---|---|---|---|
| A | Juice Shop automation researcher | juice-shop source (verify.ts, search.ts, challenge.ts, insecurity.ts, continueCode.ts), Pwning-OWASP-Juice-Shop guide | ✅ source-verified |
| B | WebGoat automation researcher | WebGoat `main` source (LessonTrackerInterceptor, ReportCardController, WebSecurityConfig, lesson classes), README, Docker Hub | ✅ source-verified |
| C | Offensive-AI prior-art scout | arXiv (CVE-Bench, AutoPenBench, Cybench, HackSynth…), XBOW/Big Sleep/CAI/PentestGPT, Anthropic disclosures, vendor blogs | ✅ (reported, links resolve) |
| D | Claude Code extension mechanic | code.claude.com official docs (hooks, permissions, plugins, MCP), context7 | ✅ doc-verified |
| E | Sandbox containment engineer | Docker/VirtualBox docs + our own hook/scope/registry code | ✅ code-verified + reasoned |
| F | Mission-scoring designer | our own codebase + CTFd/CTF scoring norms | ✅ code-verified design |

## Key findings by theme

### Theme 1 — Grounded scoring signals (the core enabler)
Both targets expose server-authoritative solve state that cannot be faked by talking to the wrong endpoint:
- **Juice Shop:** `GET /api/Challenges/` (finale-rest auto-CRUD on the Challenge model) returns every challenge as `{id, key, name, category, difficulty (1–6), solved: bool, ...}`. `solved` is flipped server-side (`challengeUtils.solveIf(...)` / `routes/verify.ts` middleware), never client-reported. There is **no** `/api/score` endpoint — compute `solved/total` yourself, and never hardcode the total (~113, version-dependent). Bonus signals: a Socket.IO `challenge solved` event, `GET /rest/continue-code` (snapshot/restore of the solved set), and `NODE_ENV=ctf` + `CTF_KEY` giving deterministic `HMAC_SHA1(ctfKey, name)` flags. [verify.ts, challenge.ts — source-read]
- **WebGoat:** `GET /WebGoat/service/reportcard.mvc` → `{totalNumberOfAssignments, numberOfAssignmentsSolved, numberOfLessonsSolved, lessonStatistics:[{name, solved, numberOfAttempts}]}`. Completion is derived by a global `LessonTrackerInterceptor` from each assignment's own server-side check — not spoofable. Per-assignment detail via `/service/lessonoverview.mvc/{lesson}`. [ReportCardController.java, LessonTrackerInterceptor.java — source-read]
- **Points:** neither app's API exposes points, only difficulty. The `juice-shop-ctf-cli` mapping (★100/★★250/★★★450/★★★★700/★★★★★1000/★★★★★★1350) is the community reference; Mission F proposes a superlinear in-plugin table computed from `difficulty` and frozen per mission. WebGoat has **no native difficulty** — lessons must be hand-tiered.

### Theme 2 — Running the targets & their automation surfaces
- **Run (hardened):** `docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop` and `docker run -it -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat`. WebGoat's own docs already bind to loopback; we apply the same to Juice Shop. State is in-memory and resets on container restart (clean re-runs for free; snapshot Juice Shop first via continue-code if desired).
- **Juice Shop is automation-friendly:** most challenges are API-solvable (server inspects the request/response), and the app *deliberately leaks* — `/snippets/<challengeKey>` serves the actual vulnerable source snippet, plus `/ftp`, `package.json.bak`, `security.txt`, `robots.txt`. An autonomous solver can read the vulnerable line rather than pure black-box probing. JWT is RS256 with a hardcoded key; passwords are MD5.
- **WebGoat is harder:** endpoint paths are hand-authored per lesson (no uniform scheme → need a path/param table), many assignments require in-order session state (`LessonSession`), some need browser-only signals or the WebWolf companion (separate OAuth2 session). CSRF is globally disabled (simpler). Send `X-Requested-With: XMLHttpRequest` so session expiry returns 401, not login HTML. `restartlesson.mvc` is destructive (wipes progress + DB) — must be excluded from any retry path.
- **Conflict resolved:** Mission A's "most challenges API-solvable" vs the intuition that XSS needs a browser — reconciled by Mission C: HTTP suffices when the *malicious payload transits a request the server sees*; only true DOM-execution challenges (sandbox-bypass XSS, UI easter eggs) need a real browser. → API-first, browser-fallback.

### Theme 3 — The autonomous loop design
- **Recon/discovery is the empirical bottleneck, not exploit crafting** (CVE-Bench 13%, AutoPenBench 21% fully-autonomous vs 64% human-assisted). This argues for investing in coverage-tracking and endpoint enumeration — which the existing `bb` coverage ledger (`next_actions`, `coverage_summary`, `list_endpoints`) already provides. Prior art *validates* the current design rather than replacing it.
- **Portable loop patterns:** (A) plan/execute/parse separation (PentestGPT) → map the "plan" onto our coverage ledger instead of re-deriving from chat history; (D) hypothesis → investigate → verify with a strict binary oracle (Big Sleep); (E) actor/verifier handoff (CAI) as a cheap pre-filter; (F) an external coverage ledger to prevent tunnel vision.
- **The #1 reported failure is tunnel vision / repeated-payload loops.** Mitigation everyone uses: hash `tool-name + args` to detect repeats and bail, plus hard per-hypothesis attempt ceilings. This must be built into the run loop.
- **Context rot:** reasoning degrades well before the token limit; externalize state to the store (the plugin already does this via evidence/leads) and keep the working window bounded.

### Theme 4 — Verification / anti-hallucination (a hard constraint, not an enhancement)
- **No credible system trusts the LLM's self-report in either direction** — false "solved" and false "gave up" are both common. SHIELDA finds premature "not exploitable" self-verdicts are a top failure; Anthropic's own red-team disclosure says Claude "frequently overstated findings and occasionally fabricated data" when driven without a hard oracle.
- **The oracle must be external and deterministic.** For us that is the app's own solve state (Theme 1). TrustedSec's warning is the cautionary tale: response-string matching let a model "score" 85% on a JWT attack it never actually performed — a gameable oracle. So a challenge counts as solved **only** when the app's own `/api/Challenges` / `reportcard.mvc` says so, with the request/response stored as evidence.
- **Layering:** app-state oracle (primary) → optional canary/marker for XSS/SSRF → optional cheap verifier pass → the mission's evidence record. Reproducibility: prefer confirming a solve survives (it persists in the app's state until container restart) rather than accepting a one-off.

### Theme 5 — Claude Code hook mechanics (how autonomy is actually granted)
- **A PreToolUse hook returning `permissionDecision:"allow"` auto-approves and skips the prompt.** That is the entire mechanism for letting the agent send traffic to sandbox hosts without per-request prompts — an inversion of the existing deny path. [code.claude.com/docs/hooks, /permissions — verified]
- **Caveats:** hook `allow` cannot override a user's own `settings.json` `deny`/`ask` rules, and cannot force MCP tools flagged `requiresUserInteraction`. A plugin **cannot declare permissions** (its bundled settings.json supports only `agent`/`subagentStatusLine`), so the hook is the only clean auto-approve path.
- **Tool-name strings** (for new matchers): `Bash`, `WebFetch`, `mcp__claude-in-chrome__*`, `mcp__burp__send_*`. **Correction to an earlier assumption:** the plugin's own tools are `mcp__plugin_bb_bb__*`, not `mcp__bb__*` — a matcher on the bare server key never fires (doesn't affect current matchers, which are `Bash` + `mcp__burp__send_.*`).
- **Reload:** editing `server.py` contents leaves `.mcp.json` command/args unchanged, so Claude Code keeps the old subprocess — **a full restart is required** for new MCP tools. `SKILL.md` edits hot-reload; hook/`.mcp.json` changes need `/reload-plugins` or restart. (Matches the project's prior install lesson.)
- `SessionStart` (matcher `startup`/`resume`) can inject `additionalContext` to announce "sandbox mode active" cheaply, once per session.

### Theme 6 — Sandbox containment & safety
**Two verified, pre-existing gaps in the current hook** (both confirmed by reading the code):
1. **`scope_override` bypasses scope for *any* active target** — `registry.check_scope` calls `take_override(host)` *before* the scope check. Correct as a human false-positive escape hatch for real programs; must be **disabled for sandbox targets** (a denied sandbox host is the thing being contained, never a false positive).
2. **Bare non-dotted-quad IP literals evade extraction entirely** — `curl 2130706433:3000/...` or `curl 127.1:3000/...` match none of `URL_RE`/`IPV4_RE`/`HOST_RE`, so `extract_targets` returns `[]` and the call proceeds *un-evaluated*. This is a real hole in **real-program mode too**; worth fixing in this milestone.
3. The hook only matches `Bash` + `mcp__burp__send_.*` today — `WebFetch` and every `mcp__claude-in-chrome__*` call run **unchecked**. Sandbox mode must add these matchers before browser/WebFetch traffic is controlled at all.

**Allow-list model:** the sandbox is `(host, port)` — `host ∈ {127.0.0.1, ::1, localhost}` AND `port ∈` the target's declared set. **Mandatory port, no wildcards/CIDR.** A different port on localhost = a different system → **denied** (protects your other local dev servers, DBs, and Claude Code's own MCP processes). The container's own ephemeral IP is *not* allow-listed; a VirtualBox host-only address is added as a single `/32`, never the `/24`.

**Sandbox mode is deliberately stricter than real mode (deny-on-ambiguity):** any `$(...)`, backticks, decode pipeline (`base64 -d`, `xxd -r`), `--resolve`/`--connect-to`, or inline proxy-var feeding a network tool → **deny outright**, because sandbox mode can't safely extract a host from them. Plus a preflight that refuses to start if `HTTP(S)_PROXY`/`ALL_PROXY` are set (same pattern as the existing `ANTHROPIC_API_KEY` check).

**The real backstop is the network layer, not the hook:** run targets with `--network internal` (no default route out) + `-p 127.0.0.1:PORT:PORT`. This is what actually blocks server-side SSRF (the container can't phone out), redirect-following, Python-harness arbitrary code, and browser click-navigation — none of which a PreToolUse hook can fully see. **This is corroborated by Anthropic's real incident** (internet-connected sandbox → attacks on real orgs). The weakest residual point, flagged honestly: browser click/JS-driven navigation is invisible to the hook — mitigate with a disposable Chrome profile + origin-scoped extension permission, and rely on `--network internal` as the true boundary.

**Topology:** Docker Desktop (hardened) as default; the user's existing VirtualBox host-only VM as fallback (no Docker dependency). Everything-in-one-VM rejected — claude-in-chrome is anchored to the real Windows Chrome, so the target must be reachable from Windows regardless.

### Theme 7 — Mission/scoring data model & ledger reuse
- **Invariant preserved:** the MCP server never makes network calls. So there is **no server-side scoreboard-fetch tool** — *Claude* fetches `/api/Challenges` (already scope-allowed in sandbox mode) and a thin `record_objective_result` tool records what Claude observed, **requiring evidence when `solved=True`**.
- **Schema:** add `mode` + `sandbox_app` columns to `target` via a guarded `ALTER TABLE … ADD COLUMN` (the one deliberate exception to "no migrations"); everything else is new `CREATE TABLE IF NOT EXISTS`: `mission`, `objective` (catalog, seeded like `test_case`), `mission_objective_result` (with a `baseline_solved` snapshot so reruns can't claim prior wins → `credited = solved AND NOT baseline_solved`), and `mission_attempt` (append-only narration, cross-linked to the existing coverage ledger so a run also feeds `next_actions`). `note`/`lead`/`primitive` gain a nullable `mission_id`.
- **coverage ≠ score, by design:** `coverage.status='confirmed'` stays Claude's working opinion; `mission_objective_result.solved=1` only ever comes from polling the app. They may disagree — a useful signal, not a bug.
- **Auto-confirm is triple-gated:** the real-program `promote_to_finding(human_confirmed=True)` path is unchanged; a new `sandbox_auto_confirm` is honored only when the *server itself* reads `target.mode=='sandbox'` AND the lead resolves to a solved objective row — never a caller-supplied flag alone.
- **New MCP tools** (all thin, structured, record-only): `create_sandbox_mission` (human-ack + server-verified mode gate), `seed_objectives`, `list_objectives`, `record_objective_result`, `log_attempt`, `mission_log`, `mission_scorecard`, `complete_mission` (freezes the scorecard), `list_missions`, `assemble_after_action_report`.

### Theme 8 — Attack driver & browser strategy
- **Explicit tool routing** (blueprint from a 78%-on-XBOW writeup, maps onto our exact toolset): bash/curl + Python harness for stateless/high-volume HTTP; Chrome MCP for DOM/session-dependent work; Burp MCP for inspection/replay. The agent decides per challenge (the confirmed driver policy).
- **Browser is XSS ground truth** (HTTP diffing can't see script execution) — but not a silver bullet (a browser-equipped agent still scored 0% on blind SQLi). Reserve it for DOM/state-dependent work; it's ~1–5s + real cost per step vs near-free HTTP.
- **Caveat to verify at build time:** MCP browser tools often expose an accessibility tree rather than raw DOM/HTML, so DOM XSS in attributes/raw HTML can be invisible. Confirm what `mcp__claude-in-chrome__read_page`/`get_page_text` actually surface before relying on them for XSS confirmation.

## Existing solutions & prior art

| Name | Link | Does well | Gaps/weaknesses | License |
|---|---|---|---|---|
| PentestGPT | [arXiv 2308.06782](https://arxiv.org/abs/2308.06782) | Plan/execute/parse split; "task tree" resists tunnel vision | Autonomous mode self-caveated as non-reproducible | OSS |
| hackingBuddyGPT | [GitHub](https://github.com/ipa-lab/hackingBuddyGPT) | Simplest ReAct loop; good reference | No oracle; gets stuck repeating one approach | OSS |
| CAI | [GitHub](https://github.com/aliasrobotics/cai) | Actor/verifier handoff; kill-chain specialist agents | Authors say full autonomy "premature"; keeps mandatory HITL | OSS |
| XBOW | [analysis](https://medium.com/@maverickcx64/xbow-ai-and-the-evolution-of-red-teaming) | Coordinator + fan-out solvers; deterministic validators (headless-browser XSS confirm, IDOR stepwise) | Heavy infra; FP rate undisclosed; ~25 engineers tune it | Commercial |
| Google Big Sleep / Naptime | [Project Zero](https://projectzero.google/2024/06/project-naptime.html) | Gold-standard oracle (crash-under-debugger); hypothesis-driven | Oracle is memory-safety-specific; no off-the-shelf web analog | Internal |
| TrustedSec Juice Shop LLM benchmark | [blog](https://trustedsec.com/blog/benchmarking-self-hosted-llms-for-offensive-security) | Most Juice-Shop-specific study; 4,800 runs | Self-flagged gameable string-match oracle; 0% on multi-step blind SQLi | Blog |
| CVE-Bench / AutoPenBench / Cybench | [CVE-Bench](https://arxiv.org/abs/2503.17332) | Rigorous benchmarks; state-diff oracles | Show discovery is the bottleneck (13–21% autonomous) | OSS |

**Unclaimed ground for us:** no found LLM-agent writeup wires into Juice Shop's real `SOLUTIONS_WEBHOOK` (+ `cheatScore` 0–1 illegitimate-solve heuristic), and Juice Shop's fragment-based DOM XSS has no published agent solution — genuinely open, not something prior art solves for us.

## Community insights
This was a technical/source research effort more than a sentiment one, but practitioner-reported themes were consistent: (1) autonomous pentest agents look impressive in demos but "fully autonomous" claims are routinely disputed — humans tune and gate them; (2) the recurring practitioner complaint is false positives and confident fabrication, which is why every serious writeup insists on an external oracle and a clean re-run; (3) cost blowup from unbounded ReAct loops is a real operational pain (reports from <$5 to >$200 per run) → iteration caps matter; (4) sandbox/production confusion is a named, real-world danger, not a hypothetical.

## Recommended direction & tech options

**Option 1 — Additive sandbox mode, Juice Shop first (RECOMMENDED).**
A new `target.mode=='sandbox'` gate unlocks: a stricter port-aware scope-guard branch (allow-list + deny-on-ambiguity + no override + new matchers), Docker `--network internal` egress lockdown as the true backstop, the mission/objective/scoring tables + record-only MCP tools, and new sandbox-specific exploitation skills (the existing `pb-*` playbooks are detection-only and stay untouched). Grounded scoring from each app's own state; a narrated recon→hypothesize→exploit→verify→record→score loop reusing the coverage ledger, with a repeat-hash breaker and attempt caps. Ship Juice Shop as the first runnable slice, WebGoat as a second slice. _Fit: matches the brief exactly. Effort: medium-high. Risk: low — real-program path is untouched and regression-tested._

**Option 2 — Minimal: Juice Shop, HTTP-only, no browser.** Faster, but misses DOM-execution challenges and WebGoat, and under-uses the confirmed driver policy. Good only if scope needs cutting. _Rejected as the primary plan; effectively a subset of Option 1's first slice._

**Option 3 — Heavy XBOW-style coordinator/solver fan-out with per-hypothesis isolated subagents.** Maximum breadth, but container-per-solver isolation and callback infra is overkill for a single local target and duplicates what `--network internal` + the coverage ledger already give us. _Rejected for this milestone; revisit only if scaling to many targets._

## Risks & unknowns
- **A1/A2 now largely CONFIRMED** by source reads (Juice Shop `/api/Challenges`, WebGoat `reportcard.mvc`) — downgraded from assumptions to verified. Exact field names still to be re-checked against whatever container tag is actually pulled (`main` is ahead of Docker `latest`).
- **Docker `latest` trails source** for both apps → the plan must read catalogs/counts live, never hardcode.
- **`scope.py` strips ports** — the sandbox allow-list needs its own port-aware path; do not touch the shared `is_in_scope` used by real programs.
- **Browser MCP DOM visibility** (Theme 8 caveat) — must be verified empirically in the build before relying on it for XSS confirmation.
- **Hook `allow` empirical behavior** — doc-verified, but should be smoke-tested live early (it's the linchpin of autonomy).
- **WebGoat difficulty tiering** — no native signal; requires hand-curation, adding effort to the WebGoat slice.

## Open questions for the user
Only the ones that actually change Phase 2 (the plan will otherwise proceed on the stated defaults):
1. **Docker Desktop or VirtualBox?** Is Docker Desktop installed/usable on your Windows box, or should the default run path target your existing VirtualBox Linux VM? _Default assumption: support both; prefer Docker Desktop, VM fallback — this does not block the architecture, only the setup runbook._
2. **Fix the real-program hook gaps in this milestone?** The bare-IP-extraction hole (gap #2) affects real-program mode too. _Default: yes, fix it here since sandbox mode depends on tightening the same code — low risk, net safety win._
3. **Extra oracle?** Wire Juice Shop's `SOLUTIONS_WEBHOOK`/CTF-flag mode as a secondary oracle, or is polling `/api/Challenges` enough for v1? _Default: polling is enough for v1; webhook/CTF-flag is a documented stretch goal._

## Sources
Juice Shop: [repo](https://github.com/juice-shop/juice-shop) · [verify.ts](https://raw.githubusercontent.com/juice-shop/juice-shop/master/routes/verify.ts) · [challenge.ts](https://raw.githubusercontent.com/juice-shop/juice-shop/master/models/challenge.ts) · [Pwning guide](https://pwning.owasp-juice.shop/) · [continueCode.ts](https://raw.githubusercontent.com/juice-shop/juice-shop/master/routes/continueCode.ts)
WebGoat: [repo](https://github.com/WebGoat/WebGoat) · [ReportCardController](https://github.com/WebGoat/WebGoat/blob/main/src/main/java/org/owasp/webgoat/container/report/ReportCardController.java) · [LessonTrackerInterceptor](https://github.com/WebGoat/WebGoat/blob/main/src/main/java/org/owasp/webgoat/container/assignments/LessonTrackerInterceptor.java)
Claude Code: [hooks](https://code.claude.com/docs/en/hooks) · [permissions](https://code.claude.com/docs/en/permissions) · [plugins-reference](https://code.claude.com/docs/en/plugins-reference) · [mcp](https://code.claude.com/docs/en/mcp)
Prior art / safety: [CVE-Bench 2503.17332](https://arxiv.org/abs/2503.17332) · [AutoPenBench 2410.03225](https://arxiv.org/abs/2410.03225) · [PentestGPT 2308.06782](https://arxiv.org/abs/2308.06782) · [Big Sleep](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html) · [Anthropic sandbox incident](https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals) · [Anthropic espionage disclosure](https://www.anthropic.com/news/disrupting-AI-espionage) · [TrustedSec Juice Shop benchmark](https://trustedsec.com/blog/benchmarking-self-hosted-llms-for-offensive-security) · [Hacking the AI Hackers 2508.21669](https://arxiv.org/html/2508.21669v2)
Containment: [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/) · [VirtualBox networking](https://www.virtualbox.org/manual/ch06.html)
