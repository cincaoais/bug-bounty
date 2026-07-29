---
name: pb-race-condition
description: Methodology playbook for finding TOCTOU race conditions (double-spend, limit bypass, idempotency gaps) on a real target. Load when testing a limited-resource action or when bb-next surfaces a race-condition test case.
---

# pb-race-condition

## When this applies
Any state-changing action that checks a condition and then acts on a limited or single-use resource: applying a coupon or promo code, redeeming a gift card, transferring or withdrawing balance, using a one-time voucher, accepting a capacity-limited invite, voting or rating once per user, claiming a limited-quantity item, or incrementing/decrementing a counter that should have a hard floor or ceiling. This is a narrower, timing-specific question than `pb-business-logic`'s broader field-trust and flow-order checks — that playbook establishes whether the *sequential* rule exists at all and hands off here specifically when the check-then-act pattern looks timing-sensitive rather than logic-broken. Covers WSTG-BUSL-04 (process-timing race conditions) and overlaps WSTG-BUSL-05 (missing limits on repeated use of a function).

## First signals
Notice these before you know whether a race actually exists:
- A business rule that reads like two conceptually separate steps: check coupon not-yet-used, then mark used; check balance sufficient, then debit; check seats-remaining greater than zero, then decrement and assign.
- A real-world limit that matters if bypassed — money, single-use codes, one-vote-per-user, limited inventory. Racing an inconsequential counter isn't worth the time even if it works.
- No idempotency key required or offered on the request — an endpoint that would have no way to recognize two identical concurrent submissions as "the same attempt twice."
- Measurable server-side processing time on the action (an external payment call, an email send, a slow join across services) — a wider window between check and act raises the odds a race is actually exploitable, so slower endpoints are worth prioritizing over fast ones.
- The same logical action reachable through more than one client path (web checkout and a mobile API, or a v1/v2 pair) that might not share the same lock or state.
- A "quantity" or "amount" field on the request itself, rather than the resource being consumed one unit at a time by default — a single request that can specify a large quantity against a small remaining stock is a related but distinct overdraw risk worth noting alongside the race.
- Any multi-step flow where the "reserve" step and the "confirm" step are separate requests — the gap between them is frequently a wider, more exploitable window than a single-request action's own internal check-then-act.

Common shapes worth prioritizing, by resource type:

| Resource | Check-then-act pattern | Notes |
|---|---|---|
| Coupon / voucher | valid & unused → mark used | Single-use flag race |
| Balance / wallet | sufficient funds → debit | Double-spend |
| Inventory / seats | quantity > 0 → decrement & assign | Oversell |
| Vote / like / rating | not yet voted → record vote | Duplicate-action race |
| Referral / signup bonus | not yet claimed → grant & mark claimed | One-time bonus race |

## Enumeration
1. List every endpoint that mutates a finite, valuable resource tied to the current user: wallet/balance changes, coupon or voucher redemption, referral-bonus claims, inventory decrement at checkout, like/vote/follow actions with a stated one-per-user rule, and any quota counter with real consequence.
2. For each, identify the exact resource being protected (a row, a counter, a balance) and the nominal rule the business states or implies ("max one redemption per code per account," "cannot go below zero").
3. Note whether the action is a single request or the final commit step of a multi-step flow — the exploitable window is often only at the last, committing request, not the earlier steps that merely prepare state.
4. Check for any stated idempotency mechanism (an `Idempotency-Key` header, a client-generated request ID) — its presence changes whether a bypass would also need to defeat that mechanism, and its absence is itself worth noting as a first signal.
5. Coverage is exhausted once every finite-resource action has a recorded sequential-control result and, for the ones where that control passed, a recorded concurrent-attempt result — a rule confirmed sequentially but never raced is still open surface, not a cleared item.

## Test procedure
1. Establish the sequential baseline first: attempt the action twice, one after the other, on your own test account or resource, and confirm the second attempt is currently rejected. This proves a check exists worth racing and gives you the control to compare against — skip this and a later "win" proves nothing.
2. Prepare a small number of otherwise-identical requests against your own resource — same coupon code, same transfer target, same limited item — differing in nothing meaningful, so any different outcome is attributable to timing alone, not to varying input.
3. Submit the requests concurrently, as close to simultaneously as whatever request tool you're already using allows. This is a timing concept — near-simultaneous submission — not a specific tool or script to name; use what's already in front of you.
4. Read back the actual resulting state, not just the HTTP responses: did the coupon apply twice, does the balance reflect two debits' worth of change, did inventory go negative, were two vote rows created for one identity. Both responses can look identical and "successful" even when only one should have logically won — the state is the evidence, not the status code.
5. If the first attempt shows no effect, narrow the timing window before concluding the rule is race-safe: reduce network variance between the two requests, and consider whether the vulnerable window sits at a slower sub-step (a payment-provider callback, an async worker) rather than the initial request — test at that step instead.
6. Where possible, target the cleanest boundary case: a resource with quantity exactly one, raced by exactly two concurrent claims, is the most reproducible demonstration and needs no more requests than that to show the limit was exceeded.
7. If the same logical resource is reachable through two different endpoints that might not share a lock (web checkout vs. mobile API checkout), test one request per endpoint fired concurrently, rather than two against the same endpoint.
8. Reserve-then-confirm variant: for a two-step flow, test concurrency at each step independently — race the reserve step against itself, then separately race the confirm step against itself, since a lock held during one step may not be held during the other.
9. Idempotency-key check, if one is offered: repeat the concurrent-request test while supplying the *same* idempotency key on both requests, to confirm the mechanism actually collapses them into one effective action rather than only appearing to be checked on the happy path.

## Evidence to capture
- The sequential control result showing the rule is normally enforced when attempts aren't concurrent — without this, a race "success" doesn't establish anything.
- Both requests sent concurrently, with timestamps close enough to demonstrate near-simultaneity, and both raw responses.
- The resulting server-side state read back afterward — final balance, redemption count, inventory count, row count — whatever concretely shows the limit was exceeded.
- How many attempts it took to reproduce and how consistently. Races are probabilistic: a single lucky hit is a lead, a handful of reproductions at a similar rate is a much stronger primitive.
- For a reserve-then-confirm flow, which of the two steps the race actually landed in, since that's what tells a developer where the lock is missing.
- The idempotency-key test result specifically: whether supplying the same key on both concurrent requests still produced two effects.

## Escalation
- A won race on money, balance, or inventory is direct, unambiguous business-logic impact — quantify it precisely ("coupon redeemed N times for the price of one across M concurrent attempts") rather than describing it qualitatively.
- A race that only duplicates something inconsequential (a log row with no downstream effect) isn't worth escalating further — verify actual downstream consequence before investing more attempts.
- A race-condition primitive combined with a mass-assignment or BOLA primitive on the same resource (you can also set which account a coupon applies to, and also double-redeem it) is a stronger, more reportable finding than either half alone — cross-reference `pb-mass-assignment` and `pb-idor-bola` when the same resource shows both.
- A low reproduction rate is still worth banking as a primitive via `add_primitive` rather than discarding as inconclusive — a real race at, say, 2-in-10 attempts is often still reportable once the mechanism is understood; let the human weigh whether the rate is sufficient to submit.
- An idempotency key that's accepted but not actually enforced is a distinct, often higher-value finding than the underlying race itself, since it means the one documented mitigation doesn't work — state that explicitly rather than folding it into the race writeup as a footnote.
- A won race at the reserve step that a later confirm-step re-validation quietly cancels isn't full impact — trace the flow to its actual point of consequence, the same discipline `pb-business-logic` applies to tampered fields.

## Out-of-scope traps
- Firing many concurrent requests "to make sure" a race triggers can shade into load or denial-of-service testing — keep the request count to the minimum needed to demonstrate the specific limit being exceeded (typically two, rarely more than a handful), and stop as soon as the state shows the bypass.
- A race demonstrated only in a sandbox or dev environment with unlimited test currency proves nothing about the production-enforced limit — confirm you're testing against the resource's real, enforced constraint.
- Some programs explicitly exclude load testing or require prior notification for concurrency testing, and payment-provider sandboxes often have their own abuse detection with its own terms — check the program's policy notes (captured via `bb-scope`) before running concurrent requests at all.
- A "win" claimed without ever running the sequential control test in step 1 is unverified — always establish that baseline before reporting a bypass.
- Rate-limiting or WAF-level blocking of near-simultaneous requests is a different control than the application-level check being fixed — if concurrent requests get blocked outright, that's evidence of a different (often accepted-by-design) defense, not proof the underlying TOCTOU is absent.
- A quantity/amount overdraw achieved with a single request (no concurrency involved) isn't a race condition — that's a plain validation gap, worth its own coverage entry under `pb-business-logic` rather than reported here.
- Confirm the resource actually reset or was distinguishable between the two concurrent attempts before crediting the race — if both requests targeted a resource that was already effectively unlimited (unlimited test currency, an uncapped dev-tier quota), no bypass has been demonstrated.

## Integration
Record the control test and the race attempt as separate coverage entries via `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, e.g. `race-toctou-control` and `race-toctou-concurrent` against the same endpoint — the control passing and the concurrent attempt succeeding are two different facts worth two different records. A confirmed race window with unclear impact or an inconsistent reproduction rate still goes in via `mcp__bb__add_primitive`, since "endpoint X has a demonstrated TOCTOU window, reproduced N/M attempts" is exactly the half-finding this system exists to keep instead of drop; file it as a lead via `mcp__bb__add_lead` instead if you haven't reproduced it at all yet. The assistant identifies the check-then-act boundary and proposes what to send and read back; it never claims the race is a confirmed finding — that requires the human's own reproduction and `mcp__bb__promote_to_finding(..., human_confirmed=True)`.
