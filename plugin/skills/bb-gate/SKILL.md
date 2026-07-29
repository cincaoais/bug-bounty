---
name: bb-gate
description: Run the adversarial pre-submission gate on a finding — try to kill it on scope, duplication, reproducibility, self-infliction, impact, and severity before the user submits. Use right before submitting any report, or whenever a finding "feels ready" and needs a hostile check first.
---

# bb-gate

## When to use this
- Right before the user submits a report to the platform — this is the last stop, not one opinion among several.
- The user says something like "is this ready," "should I submit this," or "check my report."
- Even when the mechanical checklist says everything passed. A green checklist is necessary, not sufficient — this skill exists for the failures a checklist can't see.

## Step 1 — pull the mechanical checklist, then go past it
Call `mcp__bb__report_checklist(handle, finding_id, platform)` for `{checks, passed, failed, ready}`. Treat this as the floor: any `failed` item is an immediate stop, but `ready: true` only means the mechanical checks passed — it says nothing about duplication, self-infliction, or honest severity. Never report "ready" back to the user without working the full gate below.

Also call `mcp__bb__assemble_report(handle, finding_id, platform)` to get `{markdown, gaps, evidence_used, severity_proposed}` — this is the actual document a triager will read, and several gate items below are checks against its content.

## The gate

Work through in order. Stop and report immediately on any **fatal** fail — don't keep grading downstream items on a finding that's already dead.

| # | Check | How | A FAIL means |
|---|---|---|---|
| 1 | Asset actually in scope? | `mcp__bb__check_scope(host, path)`; also `mcp__bb__scope_status(handle)` for staleness | **Fatal.** Do not submit. Scope drifts between discovery and submission — a stale `scope_status` is reason enough to re-check before trusting an old scope call. |
| 2 | Vulnerability class in scope? | Check the program's excluded-classes notes via `mcp__bb__list_notes(handle, contains?)` | Programs routinely exclude self-XSS, missing security headers, rate limiting, clickjacking on non-sensitive pages, CSV injection, and version-disclosure-without-exploitation. A class on the excluded list is fatal even if the asset itself is in scope. |
| 3 | Is it a duplicate? | `mcp__bb__list_findings(handle, status?)` against the user's own history; encourage checking the program's disclosed-reports archive | Not fatal, but usually kills the payout. A duplicate isn't wasted — note what it reveals about what the program already tracks, and file that as context for next time. |
| 4 | Reproducible from a clean state? | Ask the user to re-run the steps in a fresh session, stated account/role, no leftover state from earlier testing | A finding that only reproduces in the researcher's dirty browser session (stale cookie, cached token, leftover test data) is the classic false positive. Re-test clean before trusting it. |
| 5 | Self-inflicted? | Check whether the user's own testing created the condition — an account they set up, a value they planted, a permission they granted themselves | Cross-user impact must be demonstrated between two genuinely separate accounts/roles, not "my own object, viewed by my own second tab." If the vulnerable condition only exists because the user built it, the finding is hollow until it's shown against a second, independent identity. |
| 6 | Impact demonstrated, not asserted? | Check `evidence_used` from `assemble_report`; pull the actual records with `mcp__bb__list_evidence` / `mcp__bb__get_evidence` | "Different response," "an error changed," or "the field looked odd" is not impact. There must be stored evidence showing the actual security consequence — data disclosed, action performed, boundary crossed. |
| 7 | Severity honest? | Compare `severity_proposed` from `assemble_report` against what's actually demonstrated in evidence, not the theoretical worst case | Overstated severity gets reports downgraded on the platform and damages the researcher's standing more than an accurate, modest claim would. Grade against what was proven, not what could theoretically happen if three more things went wrong. |
| 8 | Any unfilled `[YOU MUST FILL THIS IN: ...]` markers? | Scan `assemble_report`'s `markdown` output and its `gaps` field | **Fatal.** Any remaining marker blocks submission outright — it's an admission the report isn't finished. |
| 9 | Program has AI-usage/disclosure rules? | `mcp__bb__list_notes(handle, contains?)` for any recorded policy note on automated tooling or AI-assisted submissions | Not a fail by itself, but surface it. The user must comply with whatever the program's policy says about disclosing AI assistance — don't let this go unmentioned. |
| 10 | Would a triager reproduce this in under five minutes, from the steps as written? | Read the assembled steps as a stranger would — no context, no goodwill | If the steps require guessing, undocumented state, or "then do the thing from step 2 again but slightly different," the steps need rewriting before submission, even if the underlying bug is real. |

## Required posture
- This gate's job is to try to **kill** the finding. Surviving it is meaningful precisely because the gate isn't rubber-stamping — passing everything by default would make this skill worthless.
- "This should not be submitted" is a successful, valuable outcome. It saves the user's signal-to-noise ratio with the program and saves their own time chasing a report that was always going to close as N/A, duplicate, or informative.
- Never soften a real problem to be encouraging — that's the failure mode this skill exists to prevent. But don't manufacture an objection to look rigorous either: a genuinely clean finding should be told plainly that it's clean.
- The final decision to submit is always the user's. This gate advises with a specific, evidenced verdict — it doesn't submit anything and doesn't overrule the user's call.

## When the gate fails
- **Fatal fails (scope, unfilled markers):** don't submit. Fix the underlying gap (re-verify scope, fill the marker) or drop it.
- **Non-fatal but weak (impact, reproducibility, severity):** identify exactly what's missing — a second account, a clean-session retest, additional evidence — and send the user back to gather it before re-running the gate. Don't rubber-stamp a partial fix; re-check the whole item.
- **Severity overstated but the core finding holds:** downgrade the claim to match the evidence and submit at the honest severity, rather than dropping a real finding over an inflated label.
- **Self-inflicted or unreplicated across accounts:** this is a gather-more-evidence case, not necessarily a drop — get the second account, re-test, then re-gate.
- A finding that fails here isn't automatically discarded. It can be recorded as a `suspicious` coverage result, or kept as a lead or primitive (see `bb-correlate`) rather than thrown away — a weak finding today may become part of a real chain later.

## Firm rules
- Never approve a report that still has an unfilled `[YOU MUST FILL THIS IN: ...]` marker.
- Scope failure is fatal — an out-of-scope asset does not get submitted regardless of how good the finding is.
- Impact must be demonstrated with stored evidence, never asserted from "the response looked different."
- Recommending against submission is a success for this skill, not a failure to be helpful.
- The user makes the final call to submit; this gate advises and argues, it does not decide.
