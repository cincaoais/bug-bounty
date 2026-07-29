---
name: pb-request-smuggling
description: Methodology playbook for finding HTTP request smuggling on a real target. Load when testing front-end/back-end parsing disagreement or when bb-next surfaces a smuggling test case.
---

# pb-request-smuggling

## When this applies
Any target sitting behind a chain of HTTP intermediaries that don't share one parsing implementation — a CDN in front of an origin, a load balancer in front of an app server, a reverse proxy in front of a legacy backend.
- The class exists because HTTP/1.1 allows both `Content-Length` and `Transfer-Encoding` to claim authority over where a request body ends.
- Not every server or proxy resolves that ambiguity, or handles an obfuscated `Transfer-Encoding` value, the same way.

Covers WSTG-INPV-15 (HTTP request smuggling/response splitting).
Testing typically starts from the same chain-mapping recon that feeds WSTG-INPV-17 (Host header handling), since both classes depend on how many distinct parsers sit in the request path and how they disagree.

**This is the highest-risk class in this playbook set.** If a disagreement is real, exploiting it can attach part of one request to a connection later reused by a different, unrelated user — careless testing can affect strangers, not just the tester's own session. Everything below is written for detection and observation on your own requests only.

## First signals
Notice these before forming any hypothesis:
- More than one distinct HTTP implementation visibly in the path.
  - Different `Server` headers or error-page behavior between a direct-to-origin response, if reachable, and one through the front-end.
  - A CDN/WAF vendor sitting in front of a distinctly different origin stack.
- Chain components publicly known to have had lax `Transfer-Encoding` handling in the past.
  - A legacy app server, an older load balancer version, a custom internal proxy.
- Persistent backend connections: does the front-end keep a keep-alive TCP connection to the backend across multiple client requests?
  - The primitive requires request-boundary confusion to affect a *subsequent* request on the same backend connection.
  - A chain that opens a fresh backend connection per client request removes the primitive entirely — worth confirming early since it can rule out the whole class for this target.
- Any indirect suggestion the front-end and back-end disagree about where a request ends.
  - This is inferred from timing and response pairing (see Test procedure), never from anything visibly different in a single request/response pair.

## Enumeration
1. Map every distinct proxy/CDN/load-balancer hop between client and origin.
   - Reuse whatever `bb-recon` already gathered — CDN detection, `Via`/`X-Forwarded-*`/`Server` fingerprints — rather than re-probing from scratch.
2. Classify each hop by which length-determination header(s) it's known or observed to honor.
   - A component that never parses `Transfer-Encoding` at all can't be one side of a CL.TE/TE.CL mismatch.
3. Prioritize endpoints that sit behind the full proxy chain and accept `POST` with a body.
   - Not a health-check path that bypasses the chain — the class requires a request whose body boundary is in dispute.
4. Separate endpoints by test safety.
   - Idempotent, side-effect-free, low-traffic paths versus ones on shared, high-traffic connections where any misfire has a higher chance of touching a real user's request.
   - This ordering matters more here than anywhere else in this set.
5. The surface is covered once the chain is mapped and classified by parser behavior, and a decision is made on which endpoints are safe to test at all.
   - Not once one endpoint that "looks smuggly" has been picked.

## Test procedure
Detection here is fundamentally **timing and response-pairing observation**, not crafting and firing a working smuggled request. Describe the concept to the human; the human executes every request by hand, one at a time, watching for the signal before ever considering a second request.

1. Establish which disagreement class is even plausible for this chain before testing anything:
   - **CL.TE** — the front-end trusts `Content-Length` to find the body's end; the back-end trusts `Transfer-Encoding` instead. The back-end treats what the front-end considered body as the start of a second, smuggled request.
   - **TE.CL** — the reverse: front-end honors `Transfer-Encoding`, back-end honors `Content-Length`, same class of consequence in the opposite direction.
   - **TE.TE** — both sides nominally honor `Transfer-Encoding`, but one can be tricked into ignoring it via an obfuscated or malformed header value the other still accepts — the disagreement is over whether `Transfer-Encoding` applies at all.
   - Which class is testable depends entirely on which headers each hop actually honors, per the enumeration pass — don't test all three blind.
2. The standard non-destructive detection concept is a **timing differential**.
   - A single, otherwise-ordinary request constructed so that, if the two parsers disagree about where the body ends, one of them is left waiting for body data that never arrives.
   - This produces a measurably longer response time than an identical request sent to a chain where the parsers agree.
   - A large, reproducible delay — seconds, not jitter — on a request that should return quickly is the signal; a clean, fast response rules the specific class out for that pair of hops.
3. Send exactly one such probe at a time, alone on its own connection, and wait for its own response before sending anything else on that connection or drawing any conclusion.
   - This is the entire reason the class differs from every other one in this set: a follow-up request sent too early, or sent on a connection that might be reused by someone else, is precisely the action that turns observation into impact on another user.
4. Treat a positive timing signal as **suspicious, not confirmed**.
   - Network jitter, backend load, and upstream retries can all produce a slow response with no parsing disagreement involved.
   - Repeat the same probe a small number of times in a quiet period to separate noise from a reproducible differential; don't treat one slow response as proof.
5. Do not proceed to any technique that deliberately smuggles a second request onto a connection to observe cross-request interference.
   - That step, by construction, risks landing on a connection a different real user's request will reuse next.
   - A reproducible differential, if the human and the program want to go further, is a decision for a controlled, low-traffic, program-coordinated test — not something this playbook walks toward, and not something to describe the mechanics of here.
6. If a differential is found, the immediate next question is impact scope.
   - Confirm from architecture, not from further testing, whether backend connections are per-client or shared/pooled across clients.
   - A per-client backend connection makes the finding self-contained; a shared/pooled one is where real risk to other users lives, and is the point to stop and consult the program rather than test further solo.

## Evidence to capture
- The chain topology as understood from recon.
  - Front-end vendor/version if known, hop count, connection-reuse behavior — this is what makes the timing result interpretable to a triager.
- The request sent, described structurally, and the measured response time.
  - E.g. "both Content-Length and Transfer-Encoding present with conflicting values" — not pasted as raw exploit bytes.
  - Alongside a same-request timing baseline from a clean, unambiguous request for comparison.
- Repro count and variance.
  - How many times the differential was observed against how many clean-baseline measurements in the same window, so the report shows signal against noise rather than one data point.
- An explicit statement of what was NOT done.
  - No second/smuggled request sent, no cross-request interference attempted, no other user's traffic touched — this affirmative statement is what makes the finding safe to have investigated at all.
- Store via `mcp__bb__store_evidence`.
  - Never store or paste raw request bytes structured to actually exploit the disagreement.

## Escalation
- Do not escalate this class by testing further yourself.
  - A reproducible timing differential is itself the reportable artifact.
  - The escalation path is disclosure to the program describing the suspected class (CL.TE/TE.CL/TE.TE) and the architecture reasoning for why it's plausible — the program's own security team decides whether and how to pursue confirmation on infrastructure they control end to end.
- If the report needs to characterize potential impact, describe it in terms of what the architecture *would* allow if the disagreement is real.
  - Request-queue poisoning, response cross-contamination between users' sessions, cache poisoning if a shared cache sits in the same chain (cross-reference `pb-cache-poisoning`) — without demonstrating any of it.
- The single biggest severity factor is the connection-sharing question from Test procedure step 6.
  - A finding on an architecture confirmed to pool backend connections across many users is categorically more severe than the same timing signal on a per-client-connection architecture, because the former is where smuggling actually reaches another person.

## Out-of-scope traps
- Many programs explicitly exclude or heavily restrict request-smuggling testing, or require prior coordination before any smuggling-adjacent test.
  - Check program scope/rules for this specific class before testing anything beyond passive recon, and stop immediately if notification is required and hasn't been given.
- A single slow response with no reproducibility is noise, not a finding.
  - Server load, GC pauses, and upstream retries all produce one-off delays indistinguishable from a genuine differential.
- Legitimate connection draining, health-check-triggered backend swaps, or WAF challenge pages can all produce a timing anomaly unrelated to request-length parsing.
  - Rule these out before treating a delay as a parsing signal.
- HTTP/2-only paths, with no HTTP/1.1 downgrade anywhere in the chain, are not vulnerable to the classic CL/TE disagreement.
  - Confirm the actual wire protocol reaching each hop rather than assuming HTTP/1.1 semantics apply.
- **Never send a second, differently-addressed request immediately after a probe "to see what it hits."**
  - That specific action is the one most likely to affect a real user and is out of scope for this playbook regardless of program rules — it belongs, if anywhere, in a program-coordinated test window, not solo research.
- Stop entirely at the first sign of any cross-request effect.
  - A response that doesn't match the request that should have produced it, on any connection, including your own repeated tests, is itself evidence the primitive is real — further probing only increases the risk of touching someone else's traffic.

## Integration
- Record coverage of the chain-mapping and timing-observation pass with `mcp__bb__record_coverage`, even when no differential was found.
  - "Tested, per-client connections confirmed, class not applicable here" is a real, useful result.
- A reproducible timing differential without further confirmation is exactly a primitive, not a finding.
  - Bank it with `mcp__bb__add_primitive` and stop there; don't let "half confirmed" turn into "let's just try one more thing."
- The assistant's role here is unusually narrow: identify the chain topology, name which disagreement class is plausible, and describe the timing-observation concept.
  - The human decides whether to test at all given program rules, sends every probe personally, and is the sole judge of whether a differential is reproducible.
- Never claim request smuggling confirmed from a timing signal alone.
  - `record_coverage(status="confirmed")` and any report language stronger than "suspected, timing-based" requires the human's own judgment plus, ideally, program coordination — this skill does not get to assert exploitation.
