---
name: bb-review
description: Close out a testing session with a retrospective that records unrecorded work and surfaces open threads, or produce a factual coverage report on the target. Use at the end of a session, when asked about coverage, or at the start of one to read back the last session's note.
---

# bb-review

## When to use this
- End of a testing session, before closing the laptop — this is what makes the next session start warm instead of cold.
- The user asks "what's my coverage," "how much of this target have I actually done," or similar.
- Start of a session, to read back the last session's note before deciding what to do.

## Two jobs, pick the one asked for
- **A. Retrospective** — close out *this* session. Six steps below.
- **B. Coverage report** — a factual read of the *whole target* right now. Own section below.

## A. Retrospective

### Step 1 — what actually got tested
Call `mcp__bb__session_activity(handle, since_hours?)`. Report exactly what it returned — coverage records, notes, leads, primitives, findings, endpoints added — not what you recall from the conversation. If the session tested three things and found nothing, say that. That is a normal session, not a failure to report around.

### Step 2 — unrecorded work sweep (the most valuable step)
Ask directly: "did you test anything that isn't showing up here?" Anything the user mentioned testing in conversation that isn't in `session_activity` gets `record_coverage`'d right now, in this step — not just acknowledged and left in the chat log. An unrecorded test looks untested next session, resurfaces in `next_actions`, and burns a slice of next week's few hours re-doing work already done. This is the single highest-leverage habit in this whole skill.

### Step 3 — open threads
Pull together what next session should start from:
- `suspicious` coverage results — partial signal, inconclusive, worth a second pass.
- `open` and `chasing` leads via `mcp__bb__list_leads(handle, status?)`.
- Banked primitives with no chain built on them yet, via `mcp__bb__list_primitives(handle, contains?)`.

### Step 4 — what was skipped and why
Ask what got avoided this session, and why — looked hard, looked boring, ran out of time, forgot it existed. Name it out loud rather than letting it pass silently. Beginners systematically avoid the same surfaces — auth flows, multi-step business logic, anything needing two accounts — without noticing the pattern; saying it turns a blind spot into something visible.

### Step 5 — one thing to do differently
Ask for a single concrete process change, not a list. "Record coverage right after each test instead of at the end of the session" is usable. Three suggestions at once is not — it won't survive to next session.

### Step 6 — session note
Write a short summary with `mcp__bb__add_note(handle, body)`: what got tested, the open threads, the one process change. This is what next session reads back in Step 1, or via `bb-next`.

Keep the whole thing to a couple of minutes. A heavyweight ritual gets skipped, and a skipped retrospective loses the session — that's the actual cost, not a lecture on discipline.

## B. Coverage report

Call `mcp__bb__coverage_summary(handle)` and `mcp__bb__scope_status(handle)`.

- State percent tested as context, not a score to maximize. Grinding coverage percentage on a low-value host is worse than leaving it untested and spending the hour on a surface that matters.
- Name the categories and hosts sitting at 0% explicitly — that's where unmapped risk concentrates, not the ones already at 40%.
- Flag scope stale by more than 7 days via `scope_status` — programs add and remove assets, and a stale scope means some of what's being tested may no longer be in-program.
- Flag imbalance: heavy coverage on one host and none on another usually means the second host was never actually looked at, not that it's low-value.

## Honesty requirements
- Report what the data says, including when a session accomplished little.
- Never congratulate progress the data doesn't show.
- Never invent activity that isn't in `session_activity`.
- If the user says they tested something, record it — don't just acknowledge it in conversation and move on.

## Firm rules
- Report only what the data shows — `session_activity`, `coverage_summary`, `scope_status` — never memory or conversation recall.
- Never inflate a quiet session; a session that tested three things and found nothing is normal, and dressing it up corrupts the record next session depends on.
- Unrecorded work gets recorded now, in the sweep, not just acknowledged and left in conversation.
- Percent-tested is context, never a score to maximize — coverage on a low-value surface is worse than an honest gap on one that matters.
- This system is ingest-only — it never sends traffic to any target. Everything here is reading back recorded state and drafting notes for the human.
