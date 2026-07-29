---
name: bb-pick
description: Help choose which bug bounty program to target, or evaluate a program the user has already picked, using a scope/saturation/exclusions rubric — desk research on public pages only. Use before starting a new engagement or right after the user names a target.
---

# bb-pick

## When to use this
- The user wants help choosing a program to work.
- The user has already picked a program and wants it evaluated, recorded, and handed off.
- Before committing real hours to a target — picking well is a separate skill from testing well, and the wrong pick is the most common way a beginner burns out.

## Two modes — both are first-class

**Mode A — help me choose.** Walk the rubric below against 2-3 real candidates, found via `WebSearch`/`WebFetch` over public program directories, policy pages, and `arkadiyt/bounty-targets-data`. Shortlist honestly: state the drawbacks of each candidate, don't sell one. No single "winner" unless the signals genuinely point one way.

**Mode B — I've already picked one.** Accept the choice without argument. Don't relitigate it or push the user back toward the rubric. Run the rubric anyway, but as evaluation, not gatekeeping: what does this program's shape mean for how the next few weeks should go. If there's a genuine red flag — scope excludes most of what the user can currently test, or the program is famously picked clean — say it once, plainly, then proceed with whatever the user decides.

Never insist on re-choosing a target the user has already committed to.

## The rubric

Desk research only — every row below is answered from public pages, never from touching the target's own infrastructure.

| Signal | What to check | Why it matters |
|---|---|---|
| Scope breadth and shape | Wildcard vs. single host; mobile apps and APIs in scope vs. web-only; how many live hosts under a wildcard | A wildcard with many live hosts beats a single marketing site. A tiny scope means heavy competition per asset. |
| Age and saturation | How long the program has run; total resolved reports; whether assets were recently ADDED | Years of history and thousands of resolved reports means the easy findings are gone. Newly launched programs, or ones with recently-added scope, are the single best signal a beginner has a real chance. |
| Responsiveness | Published first-response time, time-to-triage, time-to-bounty (platform-shown metrics) | Slow triage is a real cost against a few fragmented hours a week — a report that sits for six weeks blocks learning from it. |
| Reward structure vs. reality | Advertised max vs. the actual distribution of paid reports where visible | A high ceiling with almost everything paying the floor tells you little. Don't let the headline number drive the choice. |
| Exclusions | The excluded-vulnerability-classes list, read in full, before choosing | A program excluding most of what the user is currently good at is the wrong program right now, regardless of how good it looks otherwise. |
| Safe harbour and policy clarity | Is there an explicit safe harbour clause; is scope language precise or vague/contradictory | A vague or hostile policy is itself a reason to walk away, independent of the technical scope. |
| Technology fit | What stack is actually in scope vs. what the user can read | A source-available product or a JS-heavy SPA suits someone who reads code. An opaque enterprise appliance with no visible surface does not. |

## Beginner-specific guidance
- Prefer VDPs or lower-competition programs to build reps first. A resolved report on a small program teaches more than a duplicate on a famous one.
- Depth beats breadth: a week on one target beats an hour each on seven. Recommend committing, not sampling.
- Brand recognition and headline bounty figures are the weakest signals here — those are exactly the programs everyone else already picked over.
- A duplicate on a busy, saturated program is not a personal failure. It's the structural consequence of choosing that program. Say this plainly if it comes up.

## After choosing
1. `mcp__bb__list_targets()` first — check the program isn't already tracked under an existing handle before creating a duplicate.
2. `mcp__bb__create_target(handle, platform, confidentiality)` — confidentiality can't be guessed; ask if it isn't already stated (public / private / nda).
3. `mcp__bb__add_note(handle, body)` recording *why* this program was chosen — the rubric signals that mattered, and any red flag that was raised and accepted anyway. A future session needs this; the reasoning won't survive in memory alone.
4. Hand off to `bb-scope` to turn the program's published scope into enforced rules before any testing starts.

`mcp__bb__set_scope_rules`, `mcp__bb__scope_status`, and `mcp__bb__coverage_summary` belong to `bb-scope` and `bb-next` respectively — this skill's job ends at create + note + handoff, not at running those.

## Honesty requirements
- Never call a program "easy." Nobody sizing it up from the outside knows that.
- Never estimate or imply an earnings figure, even a range.
- Program-quality signals are noisy and partly guesswork — a lightly-documented program, a platform with thin public metrics, or a policy page that doesn't say much leaves real gaps. Say so rather than presenting a thin read as a confident assessment.

## Firm rules
- Evaluation is desk research only: public policy pages, platform program directories, and public scope dumps. Never fetch, probe, or send any request to the target's own infrastructure while evaluating it — recon starts only after the program is chosen, scope is recorded via `bb-scope`, and the user runs the tools themselves.
- Never claim a program is "easy" or predict a payout or earnings figure.
- Accept the user's own choice of target without argument — evaluate and inform, don't gatekeep.
- Read the exclusions list before endorsing any program, and say plainly when it conflicts with what the user is currently good at.
- State each candidate's drawbacks honestly rather than selling one; a shortlist is not a pitch.
- Get confidentiality explicit before `create_target` — never default to `public`.
- This system is ingest-only. Every output here is desk research, notes, and a handoff for the human to act on — nothing is executed on the user's behalf.
