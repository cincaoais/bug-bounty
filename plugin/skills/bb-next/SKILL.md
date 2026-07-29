---
name: bb-next
description: Answer "what should I do next on this target" with a ranked, explained list of untested in-scope actions. Use at the start of a testing session, after recording a result, or whenever the user is unsure where to focus.
---

# bb-next

## When to use this
- Start of a testing session on the active target.
- Immediately after recording a coverage result — the ranking changes.
- Whenever the user says something like "what should I test," "I don't know where to start," or is staring at the app without a next step.

## Step 1 — orient with coverage first
Call `mcp__bb__coverage_summary(handle)` before showing any actions. Give the user a short read, 2-3 lines, not a wall of stats:
- Roughly how much of the mapped surface has any coverage at all vs. is completely untouched.
- Which categories/areas are fully untested (these are where unmapped risk concentrates).

This is context for the list that follows, not the deliverable itself.

## Step 2 — get ranked actions
Call `mcp__bb__next_actions(handle, limit)`. Keep the limit small (roughly 8-10) — a 50-item dump defeats the purpose of "what should I do next."

## Step 3 — present grouped and explained, never a raw dump
Group returned items by category (auth, IDOR, injection, business logic, etc. — whatever groups them most naturally), ordered by score/tier within each group.

For every item, write a "why" that goes beyond restating the `why` field verbatim: name the actual thing that makes this endpoint × test-case pairing worth trying — a parameter shape, an auth pattern, a naming convention, a category with zero coverage, a state-changing action behind a weak check, whatever it is. The explanation is the point of this skill — the user is building pattern recognition for future targets, not just clearing a checklist.

### Worked example of the output shape
```
Coverage: 42 endpoints mapped, 6 tested (3 not-vulnerable, 2 suspicious, 1 confirmed).
36 untested — auth flows and file upload are completely untouched.

## Access Control (untested surface, high density)
1. [score 91] GET /api/v1/orders/{id} — IDOR: fetch another user's order
   why: numeric sequential ID, no ownership check visible in prior recon, and
   "resource by ID under an authenticated route" is the single highest-yield
   IDOR shape in bounty writeups. Untested.

2. [score 84] POST /api/v1/orders/{id}/cancel — IDOR: cancel another user's order
   why: same ID pattern as #1 but a state-changing action — mutating
   endpoints are frequently checked less carefully than the GET beside them.
   Worth testing even if #1 comes back clean.

## Authentication (0% coverage)
3. [score 78] POST /api/v1/password-reset — test-case: reset token reuse
   why: entire auth surface is untested, and password-reset token handling
   commonly diverges from the main login flow's protections (separate code
   path, easy to under-test internally).
```
Scores and items above are illustrative — always pull the real values from `next_actions`, never invent them.

## Step 4 — after the user tests something, record it
Every test the user actually runs gets logged with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)` before moving on. An unrecorded test is a wasted test: next session — or even the next `next_actions` call — the item still looks untested and gets re-suggested, burning limited hours re-testing the same thing.

### Status meanings

| Status | Meaning | Effect on ranking |
|---|---|---|
| `untested` | Not yet attempted | Eligible for suggestion |
| `testing` | In progress this session | Still surfaced |
| `not-vulnerable` | Tried, ruled out | Deprioritized — don't re-suggest without a new reason |
| `suspicious` | Partial signal, inconclusive, worth a second pass | Should resurface at the top next time — highest-value thing to return to |
| `confirmed` | User has verified it as real | Tracked for reporting, not re-suggested |
| `n-a` | Test case doesn't apply here (e.g. no auth by design, wrong content-type) | Removed from consideration — not the same as "clean" |

Actively call out `suspicious` items at the start of the next session's list — something already looked off there, and it's the highest-value place to spend limited time.

## Step 5 — if next_actions returns nothing
An empty result means the mapped surface is exhausted or was never built out — not that testing is done. Don't conclude "nothing to do." Instead:
- If few or no endpoints exist: the surface is unmapped. Route the user to ingest recon/proxy data (Burp/ZAP history, JS-discovered routes, sitemap/robots) via `mcp__bb__add_endpoints`.
- If endpoints exist but no test cases are attached: route to `mcp__bb__seed_test_cases`.
- Check `mcp__bb__list_endpoints(handle, untested_only=true)` directly if the result seems thin — it may just mean everything untested is currently out of scope, not that the surface is empty.

## Firm rules
- Only ever suggest in-scope, untested (or `suspicious`) items — never propose something the scope hook would block, and never re-suggest `not-vulnerable` or `n-a` items without a new reason to revisit them.
- The assistant proposes tests; the human executes them. Never run a test on the user's behalf.
- This system is ingest-only — it never sends traffic to any target. Every output here is instructions or ranked suggestions for the human to act on manually, nothing more.
- Never claim a finding is real. `suspicious` and `confirmed` reflect the user's own assessment recorded via `record_coverage` — this skill's job is to rank and explain, not to validate.
- Every test the user reports gets `record_coverage`'d before the session's suggestions are treated as current — results don't get to live only in conversation.
