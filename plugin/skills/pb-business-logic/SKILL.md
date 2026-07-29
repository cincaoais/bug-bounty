---
name: pb-business-logic
description: Methodology playbook for finding application-specific business logic flaws on a real target. Load when mapping a multi-step flow or when bb-next surfaces a business-logic test case.
---

# pb-business-logic

## When this applies
Any multi-step flow with state that persists between requests, and any point where the client reports a fact the server should be deriving itself:
- Checkout/cart/pricing flows, coupon or referral systems.
- Onboarding/KYC sequences, approval or review workflows.
- Quota/limit-gated actions (free-tier caps, rate-limited actions, one-per-account restrictions).
- Anything with a "step 1 of N" shape.
- Any field the client sends that looks like it states a price, quantity, discount, permission, or status rather than requesting one.

Covers WSTG-BUSL-01 through BUSL-07. No scanner finds these. Nothing here is a generic pattern like a payload string — every candidate requires understanding what specific abuse the business is trying to prevent, then testing exactly that.

## First signals
- A price, total, discount amount, tax, shipping cost, or quantity that appears anywhere in a client request — hidden field, JSON body, even a value that merely round-trips through a "review your order" step — rather than being looked up server-side from an authoritative source at the moment of the final action.
- A flow with distinct numbered or named steps where each step is its own request. The immediate question: does the server enforce that step 3 can only follow a completed step 2, or does it just trust whatever step-identifying parameter arrives?
- Any "apply once" restriction (one signup bonus, one coupon per account, one free trial) — these exist specifically because the business modeled abuse and built a counter. The counter is the thing to find and test, not the discount value itself.
- A status or state field in a response that the client is expected to echo back on the next request (order status, approval state, workflow stage). If the server trusts the echoed value instead of re-deriving it from stored state, the client can move the flow to a state it shouldn't reach.
- Two ways to reach the same end state — "buy now" vs. "add to cart then checkout," or a direct API call vs. the UI's guided flow — where one path visibly has more validation than the other.
- A quantity or amount field with no visible bound, or a bound only enforced by a UI widget (a dropdown, a slider) rather than anything you'd expect server-side.
- Anything involving money, points, credits, or inventory where a negative number, zero, or a value exceeding what's realistically available hasn't obviously been considered.

## Enumeration
1. For each multi-step flow, write out the intended sequence as the business defines it.
   - Read the help docs/FAQ if available — they often state the intended rule explicitly (e.g. "one discount per account"), which tells you exactly what to test against.
2. List every request in the flow and, for each, classify every field as **server-derived** (computed/looked-up, client never sends it) or **client-reported** (client sends a value the server is trusting).
   - This classification, done honestly, is most of the analysis. Anything client-reported that represents money, quantity, permission, or state is a candidate.
3. Identify the flow's real entry points, not just the UI's guided path.
   - Can any step be called directly via its own API endpoint without having completed the prior steps?
   - Can the flow be resumed, restarted, or abandoned-and-resumed in a way that skips validation tied to a specific attempt?
4. For quota/limit features, identify what the limit is actually keyed on — account ID, email, device fingerprint, cookie, phone number.
   - The key determines what the limit can be reset by rotating (a new email, a cleared cookie, a re-registration) versus what's actually enforced server-side per durable identity.
5. Map any place the same underlying action is reachable through more than one code path (web checkout vs. mobile app checkout vs. a partner/affiliate API). Validation is rarely duplicated identically, so each path is a separate test even for a nominally identical business rule.
6. Coverage here is judgment-based, not a checklist to exhaust mechanically: you've done enough enumeration once you can state, for every step of every meaningful flow, which fields are client-reported and what specific business rule protects the action from abuse of that field.

## Test procedure
1. Complete the flow once normally to get a legitimate baseline. Repeat with only one client-reported field altered (price/quantity/discount) to a value the business clearly wouldn't intend.
   - Confirm what the server actually charges/grants/records at the *end* of the flow, not just whether the intermediate request returns 200. A tampered value silently overwritten before the final step is not a bug.
2. For step-ordering, attempt to call a later step's endpoint directly without having completed the ones before it, using a fresh flow instance.
   - Separately, attempt to replay an earlier step's request after already completing a later one, to see if the flow re-validates or blindly re-applies stale state.
3. For "apply once" restrictions, identify the actual uniqueness key from enumeration and test whether the restriction survives varying only the parts of your identity you can legitimately vary between two genuine attempts (e.g., a second self-registered account with a different email you own).
   - Not by fabricating false identity documents or violating the program's account-creation rules.
4. For workflow-stage trust, submit a request with the flow's status/stage field set to a later value than the account's actual recorded progress, and check whether the server re-derives current stage from its own storage or accepts the claimed one.
5. For quantity/inventory logic, test boundary values deliberately and record the server's actual behavior at each:
   - Zero, a negative number, a value exceeding declared availability.
   - A value that would only make sense as a rounding or floating-point edge case (fractional quantities on an integer-only item, extremely small fractional prices).
   - Test one boundary at a time so the report can attribute the effect to a specific input.
6. For race-adjacent logic (a limit meant to trigger once, a balance that shouldn't go negative, a coupon meant to be single-use), a single-threaded test can only prove the *sequential* logic is present or absent — it cannot prove a race condition.
   - If sequential testing shows a check exists but you suspect a timing gap around it (the check-then-act pattern), that's a distinct hypothesis: file it as a lead and hand off to `pb-race-condition` for concurrent-request methodology if that skill is available, rather than improvising concurrency here.
7. Keep one control run per test: repeat the exact same flow with nothing tampered, to confirm the baseline still behaves normally and any observed effect is attributable to the specific change made, not to flakiness in the flow itself.

### Worked example
```
Flow: checkout
  1. POST /cart/items      {sku: "A1", qty: 2}          -> 201
  2. GET  /cart/summary                                 -> total: $40.00 (server-computed)
  3. POST /checkout        {cart_id: 91, applied_total: $40.00} -> confirm

Tampered step 3: {cart_id: 91, applied_total: $4.00}
  -> If the order confirmation and the actual charge both show $4.00: confirmed finding.
  -> If confirmation shows $4.00 but the payment-processor charge (visible in a later
     receipt/webhook) shows $40.00: the discrepancy is cosmetic, not exploitable — not a bug.
```
The distinction between those two outcomes is the entire finding. Trace to the point of actual consequence, not the first response that looked wrong.

## Evidence to capture
- The full sequence of requests and responses for the flow, in order, including the ones before the manipulated step — a triager needs the whole flow to understand the intended sequence, not just the one request that misbehaved.
- The exact field and value changed, and the value the server was expected to derive versus what it actually used — shown by the flow's own final state (order confirmation, balance, granted status), not by assertion.
- The business rule being violated, stated in the program's own terms where possible (quote the FAQ/help text describing the intended limit if one exists) — this turns "I changed a number" into a legible policy violation.
- For quota/once-only bypasses, both accounts/attempts used and exactly what was varied between them (which field made them "different enough" to both succeed).
- A clean control run showing the same flow completed normally without the tampered value, to preempt "this is just how the feature works" as a rebuttal.

## Escalation
- A single successful price/quantity manipulation escalates by demonstrating repeatability with a second, differently-shaped test (a different item, a different discount) rather than by pushing the same trick to an extreme value — extremity doesn't add credibility, a second independent confirmation does.
- A workflow-skip that reaches a "completed" or "approved" state without the intended prerequisite step is higher severity when that state unlocks a real-world action (funds release, shipment, credential issuance) than when it only skips a cosmetic UI step — state precisely what the reached state actually authorizes.
- A quota bypass escalates from "I got the bonus twice" to a material finding once you can state the actual key that failed to restrict it (e.g., "the limit is keyed on cookie, not verified identity, so it resets on every incognito session") — that explanation is what lets a triager assess blast radius without you demonstrating it at scale.
- If a business-logic flaw combines with a client-reported *role or ownership* field, cross-reference `pb-broken-access-control` or `pb-idor-bola` — the finding may really be an authorization gap wearing business-logic clothes, and should be framed under whichever primitive is actually broken.
- Chain candidates: does the manipulated end-state (a free/discounted order, an unlocked tier) grant access to a further feature that itself has its own untested surface? Bank the reached state as a primitive rather than stopping once the immediate manipulation is confirmed.

## Out-of-scope traps
- A client-side-only validation bypass (disabling JS, editing a disabled HTML attribute) that the server independently re-validates and rejects is not a finding — always confirm the server's actual final behavior, not just that a client-side gate could be defeated.
- Self-XSS-adjacent "I can see my own manipulated data" issues are not business-logic bugs — the flaw only exists if the manipulation affects data, funds, or state belonging to someone other than you, or breaks a rule the business explicitly stated it enforces.
- A price/quantity discrepancy that the platform corrects at a later step (e.g., a review page shows a tampered total, but the actual payment-processor call uses the server-recalculated amount) is not a bug — trace the flow to its actual point of consequence before reporting.
- Read the program's exclusions for "requires social engineering," "requires physical access," or "logic flaws requiring rate-limit abuse" — some programs explicitly exclude quota-bypass classes that rely on creating many accounts, which overlaps with common business-logic test technique.
- Discount/coupon stacking that the UI happens to allow but that the business may have deliberately permitted (some programs intentionally allow stacking as a feature) — check the FAQ or ask before assuming a violated rule; a rule you invented is not a bug.
- Don't build multi-account or multi-session tests that exceed what the program's account-creation policy allows (e.g., bulk-registering accounts) — that crosses from testing into the kind of abuse the finding is meant to describe, and can itself violate program terms.

## Integration
- Record each flow-and-field combination tested with `mcp__bb__record_coverage`, including clean results — "client-reported price, server re-validates" is exactly the kind of negative result worth keeping so the same flow doesn't get re-tested next session.
- Use `mcp__bb__add_lead` the moment you've formed a hypothesis about *why* a rule might be bypassable but haven't tested it, and `mcp__bb__add_primitive` the moment a manipulation is confirmed to work but doesn't yet look like a reportable bug on its own (an unlocked state, a bypassed check with no immediate payoff) — business-logic chains are built from exactly these accumulated pieces.
- The assistant maps flows, classifies fields, and proposes the manipulation to try; the human executes every request and is the sole judge of whether the resulting state is actually a violation of the business's intent, not merely unexpected.
