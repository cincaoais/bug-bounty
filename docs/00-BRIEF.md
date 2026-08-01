# 00 — BRIEF (the contract)

_System-builder Phase 0 output. Every later phase is checked against this file. Written 2026-08-01._

## Goal

Add an **opt-in autonomous "sandbox mode"** to the existing `bb` bug-bounty plugin so that, given a start command like _"try to find bugs in OWASP Juice Shop, the system is at http://localhost:3000"_, Claude autonomously **discovers → exploits/solves → scores** vulnerabilities against a **local, deliberately-vulnerable sandbox** (OWASP Juice Shop and OWASP WebGoat), then reports a scorecard.

This is a training / reps-building tool for the user (infosec student, strong theory, few live reps). The value is a repeatable, watchable process for *how* bugs get found on a real-shaped app — not a definition dump.

## The core constraint (non-negotiable)

The current plugin is **ingest-only + human-in-the-loop**, enforced in code by three walls:
1. **Propose-only** — skills instruct "assistant proposes, human executes; never send traffic" (`bb-next` SKILL.md).
2. **Human-confirm gate** — `promote_to_finding` refuses unless `human_confirmed=True` (`server.py`).
3. **Deny-by-default scope hook** — `scope-guard.py` blocks any out-of-scope host in Bash / Burp-send calls.

**These three walls MUST remain fully intact for real programs.** Sandbox mode is a *separate, gated exception*, not a global change. If the active target is not a sandbox target, behavior is byte-for-byte the same as today.

## Decisions (confirmed with user 2026-08-01)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Safety scope | **Add sandbox mode now.** Full conversion of real-program hunting to autonomous is a DEFERRED future milestone (revisit after sandbox mode matures). |
| 2 | Autonomy level | **Autonomous + narrated** — runs discover→exploit→score end-to-end without stopping, but logs each attempt + reasoning so the user can follow and learn; pauses only when genuinely blocked. |
| 3 | Attack driver | **Claude picks per challenge** — curl/Python for HTTP/API, Chrome browser automation for SPA/DOM-dependent, Burp MCP available for inspection/learning. |
| 4 | Build process | **Multi-agent orchestration** (Sonnet subagents for research + coding). Token budget is NOT a constraint. |

## Scope

**In scope (this milestone):**
- A distinct **sandbox target type / mode** the plugin recognizes.
- Sandbox-mode unlocks: active testing (real traffic), self-confirmation of hits, exploitation payloads, and mission scoring — **only** against sandbox hosts.
- A hard **sandbox host allow-list** the scope-guard enforces (localhost + declared sandbox ports only; everything else, including the open internet, denied).
- An autonomous **run loop** (recon → plan → exploit → verify → record → score) that is narrated.
- **Grounded scoring** read from the target's own state where possible (Juice Shop `/api/Challenges` solved flags; WebGoat lesson progress), plus a local scorecard/mission record.
- Support for both **Juice Shop** (Angular SPA) and **WebGoat** (servlet app).
- Reuse of the existing coverage ledger / findings graph where it fits; new tables/tools only where needed.
- Tests for every new slice; a live end-to-end sandbox run as the final demo.

**Out of scope (this milestone):**
- Autonomous testing of any *real* / non-sandbox target (deferred future plan).
- Removing or weakening the three safety walls for real programs.
- Mobile / binary targets.
- Any change to the existing ingest-only real-program workflow beyond additive mode-branching.

## Success criteria

1. With no sandbox target active, the plugin behaves exactly as v0.1.1 (all existing tests still pass; the three walls still fire). **Regression-free.**
2. A user can register a sandbox target (e.g. Juice Shop @ localhost:3000), issue one start command, and Claude autonomously solves a meaningful set of challenges without per-step hand-holding, narrating as it goes.
3. Autonomous traffic provably cannot leave the sandbox allow-list — attempts to hit any non-sandbox host are denied by the same hook, even in sandbox mode.
4. The final scorecard is **grounded** in the target's own solved/progress state (not Claude's self-assessment) and is reproducible.
5. Works for both Juice Shop and WebGoat.

## Gate mode for the build

Per user ("cook powerfully, no worries, go deep"), the build phases (RND → Plan → Execute → Review) **flow with visibility**: each phase's doc (`docs/01`…`04`) is written and surfaced to the user, and I continue unless they object. There is exactly **one hard human gate**: **before the first live sandbox testing run against Juice Shop / WebGoat**, I stop and wait for explicit permission from a prompt (original user instruction). Phase-3 coding style: parallel Sonnet subagents, ~3 concurrent, only on non-conflicting slices.

## Open assumptions (to confirm/close during RND)

- **A1:** Juice Shop exposes solved-challenge state via `/api/Challenges` (JSON `solved` flags) usable as a scoring signal. _(verify in RND)_
- **A2:** WebGoat exposes per-user lesson/assignment progress via a queryable endpoint. _(verify in RND)_
- **A3:** The targets run locally on the user's Windows box via Docker Desktop (fallback: the existing VirtualBox Linux VM). Exact run topology decided in RND (Mission E). _(confirm host/port model)_
- **A4:** Chrome browser automation (claude-in-chrome) can reach a localhost SPA for the DOM-dependent challenges. _(verify in RND/build)_

## Runtime environment (from memory, still current)

Windows 11 + Python 3.13. Recon tools historically run in a VirtualBox Linux VM (not WSL). Plugin installed live as marketplace `bug-bounty-local`, plugin `bb`, currently v0.1.1. Case data lives outside the repo (`~/.bb-bounty`) — safety leak-guard must keep holding.
