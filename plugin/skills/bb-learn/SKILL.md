---
name: bb-learn
description: Build the procedural skill of finding bugs systematically — disclosed-report study, recognition drills on the live target, hunt-along reasoning, and miss post-mortems. Use when the user knows vuln classes in theory but freezes on an unfamiliar app with no repeatable process.
---

# bb-learn

## When to use this
- The user says some version of "I know the vuln classes but don't know where to start on a real app."
- They want to study a disclosed report — theirs, a public one, or one they found via search.
- Before or during a `bb-next` session, when explaining the reasoning is worth more than just running the list.
- A duplicate came back, or a disclosed report turns out to cover their own target — something was missed and it's worth finding out why.

## Not what this skill does
Never explain what a vuln class is unless directly asked. This user has solid OWASP theory and few live findings — the gap is procedure: given an unfamiliar app, which of the 40 things they already know how to test comes first, how to enumerate objects and roles so a bug has somewhere to hide, and how to tell when a surface is exhausted. Teach that, not definitions.

## Mode 1 — disclosed-report study
The valuable framing is never "here's an IDOR report." It's: **what did the hunter notice FIRST, before they knew it was a bug?** Most write-ups skip straight to the conclusion — reconstructing the noticing moment is the actual lesson.

1. Use the report the user supplies, or find public disclosed reports via WebSearch/WebFetch (HackerOne Hactivity, Bugcrowd disclosures, PortSwigger research write-ups). If nothing solid turns up, say so — don't paraphrase a vague blog post as if it were a concrete case.
2. Reconstruct, in order: what was on screen; what looked ordinary but wasn't; what made them look twice; what they tried next and why; how they escalated it from odd to proven.
3. Explicitly separate **the observation** from **the conclusion** in what you give back to the user — label them. Beginners only ever absorb the conclusion ("this was an IDOR") and never see the noticing step, because most write-ups don't narrate it either.
4. Read `${CLAUDE_PLUGIN_ROOT}/reference/report-signals.json` for the report's vuln class and check its first-observable-signal entry against what the report actually describes. Point out whether this instance matches the general pattern or is a genuine outlier — both are useful, and say which it is rather than forcing a fit.
5. If the source material just doesn't say how they noticed it, say that plainly instead of inventing a plausible-sounding noticing moment.

## Mode 2 — recognition drills on the current target
Highest-value mode — it trains judgment on data the user actually cares about, not a toy example.

1. Call `mcp__bb__list_endpoints(handle, untested_only=true, limit=...)` and pick 3-5 endpoints with genuinely different shapes (different methods, param patterns, auth-looking vs. not).
2. Present them plainly — method, path, params — with no ranking and no hint about which one you think matters.
3. Ask the user which looks most promising and why, before revealing anything else.
4. Only then call `mcp__bb__next_actions(handle, limit?, per_endpoint?)` and compare its ranking and `why` against the user's answer.
5. Discuss the gap honestly. If the user spotted something the mechanical ranker doesn't weigh (a naming convention, a business-logic smell), say the user was right and the tool's ranking was incomplete — don't default to trusting the tool. If the user missed a signal the ranking caught, name the specific thing they walked past.
6. Keep it to one drill of 3-5 endpoints per session, not a 20-item quiz — this has to fit a few fragmented hours a week.

## Mode 3 — hunt-along explanation (default posture)
This is the default way `next_actions` gets used with this user, not an occasional add-on. Every time you work through a ranked action, explain *why this test on this endpoint* — the parameter shape, the naming convention, the auth boundary, the framework smell — before or while the user tries it. The explanation is the deliverable; clearing the checklist item is secondary.

Ground every explanation in this endpoint's actual data (`list_endpoints`, `list_notes`, `list_primitives` for it), not a generic restatement of the test case's title. If nothing endpoint-specific justifies the ranking beyond "the category is untested," say that plainly instead of manufacturing a reason.

## Mode 4 — post-mortem on a miss
Trigger: a duplicate report lands, a disclosed report turns out to cover the user's own target, or the user otherwise learns after the fact that something was there.

1. Get the specifics of what was actually found — the disclosed report, the duplicate notice, whatever surfaced it.
2. Check `mcp__bb__list_notes(handle, endpoint_id?, contains?)` and `mcp__bb__list_primitives(handle, contains?)` for that endpoint: had the user already observed the signal and filed it too weakly (a note that undersold what it meant), or never observed it at all? These are different lessons — say which one happened.
3. Cross-check `${CLAUDE_PLUGIN_ROOT}/reference/report-signals.json` for the vuln class's known first signal. If the miss matches a documented pattern, name it — that's the part that generalizes to other targets.
4. Record the lesson with `mcp__bb__add_note(handle, body, endpoint_id?)`, phrased as the pattern to recognize next time ("numeric ID + absent ownership check on the sibling GET is worth trying on the POST beside it"), not as "missed this one." If it's a reusable capability rather than an observation, `mcp__bb__add_primitive` instead.
5. Don't relitigate blame. The point is that the pattern is now written down somewhere it will resurface, not that the miss was properly mourned.

## Spaced practice
With only a few fragmented hours a week, a lesson that lives only in the conversation is gone by next session. Whenever a mode above produces a real insight, record it — `mcp__bb__add_note` for an observation, `mcp__bb__add_primitive` for a confirmed reusable capability — tagged to the endpoint or category it applies to, so `list_notes`/`list_primitives` resurface it later. Write the transferable version ("state-changing sibling of a tested GET is worth a pass even when the GET was clean"), not the vague one ("watch out for IDOR").

## Grounding rule
Every teaching claim needs a real anchor: a disclosed report, `reference/report-signals.json`, or the user's own `list_notes`/`list_primitives`/`list_leads` data. A model asked "how do I find IDORs" will happily produce a fluent, generic, mediocre methodology essay with nothing underneath it — that is exactly the output this skill exists to prevent. If none of the three anchors support a point, don't make the point; say the pattern is uncertain or program-specific instead of inventing a rule.

## What NOT to study
Depth on the common classes beats breadth across exotic ones. Chasing request smuggling, cache poisoning, or protocol-level edge cases before IDOR/BOLA-style access-control checks and auth-flow gaps are fast and automatic is a classic beginner time sink — and it dodges this user's actual gap, which is process on the common classes, not exposure to rare ones. Steer study time toward whatever `mcp__bb__coverage_summary(handle)` shows as high-density and still untested on the live target, not toward whatever bug class is trending that week.

## Firm rules
- Never explain what a vulnerability class is unless the user asks — assume OWASP-Top-10-level fluency; the gap this skill addresses is process, not definitions.
- Ground every teaching claim in something real: a disclosed report, `reference/report-signals.json`, or the user's own stored notes/primitives/leads — never a generic methodology essay.
- Drills use the live target's real endpoints from `list_endpoints`/`next_actions`, never invented example apps.
- Never assert a finding is real or that a recognized pattern definitely applies here — this skill builds recognition and records lessons, it doesn't validate bugs.
- Ingest-only: never sends traffic to any target. Every mode here is reading, discussing, and recording for the human — nothing is executed on the user's behalf.
