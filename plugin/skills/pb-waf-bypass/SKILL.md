---
name: pb-waf-bypass
description: Methodology playbook for getting past defensive filters once a payload is blocked. Load when a WAF, filter, or 403 stands between a crafted input and the backend, or when bb-next surfaces a bypass-or-die test case for a known class.
---

# pb-waf-bypass

## When this applies
- A payload for a known class (XSS, SQLi, traversal, upload) was blocked, rewritten, or answered with 403 while the same request shape works unmodified.
- Consecutive payload variants keep failing and you need a structured escalation instead of guessing.
- A defense is visible in responses — WAF error pages, challenge pages, sanitized echoes, or different status codes for crafted vs benign inputs.
- The target's filtering is inconsistent across entry points (web UI vs mobile API vs older versions).

This playbook is the *delivery* layer: it assumes you already know the class you're trying to land (pb-xss, pb-sql-injection, pb-injection, pb-path-traversal, pb-file-upload). Bypass alone is not a finding — the class playbook still owns the vulnerability and its evidence bar.

## First signals
- A response that is clearly a block page (vendor WAF branding, challenge text, a generic "request denied") while nearby benign requests succeed.
- The *same* content in a different field or parameter position slipping through — the filter is position-specific, not content-specific.
- Sanitized echoes: your input comes back with the dangerous characters removed, encoded, or truncated — you can see exactly what rule fired.
- Behavior differences across content types, methods, or protocol versions for identical content — the defense sits on one parsing path only.
- A 403 on `/admin` that turns into a 200 with a trivial path variant — a rule matching a literal string, not a normalized path.

## Enumeration
The source skill's core discipline: **locate the layer before fighting the rule.** Answer six questions in order before mutating anything:

1. Which layer blocks? (WAF appliance / gateway / application filter / framework / database)
   - WAF/gateway blocks are typically generic pages on *any* content; application blocks are usually contextual (a validation message from the app itself); database/framework blocks surface as errors that quote the query or the engine.
2. What kind of rule? Blacklist (blocks listed patterns — bypass by finding unlisted equivalents), whitelist (blocks everything not listed — bypass by finding a listed shape that still reaches the sink), regex (bypass via match-boundary differences), semantic/parser-based (bypass via parser differentials between the filter and the backend).
3. Where is the rule's boundary? For a blacklist, probe which token is the trigger by bisecting your payload; for a whitelist, probe which shapes pass and whether any passing shape still reaches the sink.
4. Protocol differences: does the proxy and the backend parse the same request the same way? (Content-Length vs Transfer-Encoding divergence is the classic; request-smuggling methodology lives in pb-request-smuggling.)
5. Encoding differences: does each layer decode the same input the same number of times? A filter that decodes once and a backend that decodes twice is a bypass surface; so is one layer treating a charset differently.
6. Logic differences: is validation and execution the same code path? Anything that validates a transformed copy and executes the original (or vice versa) is a candidate.

Then inventory the alternate entry points — before spending an hour mutating one field, check whether the same capability exists behind weaker validation:
- Mobile/desktop APIs alongside the web UI; older API versions (`/api/v1` left online); internal/partner endpoints; different content-type handling on the same endpoint (JSON vs form vs multipart); headers/cookies as parameter transport.

## Test procedure
Work the escalation ladder in order; the source skill's rule is to try at least the first four levels before concluding "not bypassable." Each level describes what to try and what to observe — no copy-paste payloads here; every variant is derived from the class playbook's payload with one property changed at a time.

1. **Encoding** — re-encode the blocked characters or words: percent-encoding, double-encoding, Unicode escapes, numeric-entity forms. Observe whether the filter decodes before matching (blocked again), decodes after matching (passes the filter), or never decodes (the backend must decode it for you).
2. **Morphing** — change the shape without changing the meaning: case variation, doubling a blocked token so the filter strips one copy and leaves one, inserting comments or whitespace where the language tolerates it, swapping in an equivalent function/operator/tag. The key observation: does the response show the *stripped* or the *original* variant — stripping is itself a primitive.
3. **Logic** — change how the input travels rather than what it says: different HTTP method, different Content-Type, move the parameter from body to query to header to cookie to path. Observe which transport still reaches the sink — often the filter only watches one.
4. **Protocol** — exploit parse divergence: chunked transfer encoding, header folding, path normalization differences (`//`, `/.`, trailing dots), parameter duplication (does the backend take the first or the last value — and which one did the filter check?). This level overlaps pb-request-smuggling; load it when the divergence is between proxy and backend request boundaries.
5. **Alternate entry** — walk the Enumeration list of alternate endpoints; test the same content where no filter has been deployed. Finding an unfiltered mirror of a filtered endpoint is usually faster than any mutation.
6. **Combination** — chain what the levels taught you: the encoding the filter doesn't decode plus the position it doesn't watch plus the method it doesn't parse. A bypass is usually the *intersection* of several small gaps, not one magic string.
7. **Timing** — for stateful defenses (rate-limit WAF rules, challenge systems, IP reputation): spread attempts, vary session/IP rotation, or trigger the payload via a delayed/async path the filter doesn't sit on (a scheduled job, a webhook replay).

For path-based 403s specifically (admin panels, restricted files), the standard probe set is: case and trailing-slash variants, dot and percent-encoded path segments, semicolon/path-parameter suffixes, alternate methods, and the common forwarding headers the backend may trust (X-Forwarded-For / X-Real-IP / X-Original-URL / X-Rewrite-URL families) — test each *individually* and note which one changes the response, since a working header override is itself an access-control finding worth reporting separately.

**Confirmation discipline.** Every attempt is compared against the baseline blocked request. A bypass is only confirmed when the response returns to the *business-normal* response for the injected content (the class playbook's expected vulnerable behavior) — not merely when the block page disappears. Keep the baseline (blocked) request and the passing variant side by side as the evidence pair.

## Evidence to capture
- The baseline: the blocked payload and the exact block response (status, headers, page).
- The passing variant and its business-normal response — the side-by-side pair is the whole story.
- Which property changed between the two (encoding layer, position, method, content-type) — this is what proves the filter's gap, and it is reusable against every other payload on the target.
- Any header-override or alternate-entry discovery made along the way, as its own note — it is often a separate finding (auth bypass via trusted-header spoofing) independent of the payload.
- The layer conclusion: where the defense actually sits, so future sessions don't re-probe the same surface.

## Escalation
- A confirmed bypass is not a finding by itself — it is the transport for the class playbook's finding. Route back to pb-xss / pb-sql-injection / pb-injection / pb-path-traversal / pb-file-upload and complete *their* confirmation bar before claiming anything.
- A header override that changes authorization (X-Forwarded-For gaining admin access, X-Original-URL reaching a restricted path) escalates on its own as an access-control/auth finding — the payload you were carrying may be irrelevant to it.
- An unfiltered mirror endpoint escalates the reach of every other finding: bank it as a primitive even before a specific payload lands.
- A filter that strips or rewrites input and *shows* the result is itself a primitive (input transformation observable) — it combines later with stored-XSS or parser-differential work.
- Do not keep hammering one direction: after three failures at a level, move up the ladder. The source skill's discipline exists because time spent guessing is time not spent on the alternate entry that would have worked instantly.

## Out-of-scope traps
- Bypass success ≠ vulnerability: the class playbook's evidence bar (real impact, real confirmation) still applies, unchanged by how the payload arrived.
- WAF bypasses alone are generally not reportable — programs pay for the underlying bug, not for the fact their WAF has a gap. Report the bug; mention the WAF context only as it changes severity (e.g., a stored XSS that also defeats the WAF is still a stored XSS).
- Do not test WAF rules by brute force: rate-limited or challenge-based defenses exist to stop exactly that, and tripping them repeatedly reads as abuse, not testing.
- Trusted-header tricks are only meaningful when the backend actually trusts the header — a header you send that changes nothing is not a finding; one that changes authorization is, and it belongs in pb-broken-access-control's report shape.
- Timing-level evasion (rotating IPs, pacing) that exists only to hide probing is not part of a report; it is operational hygiene.
- Request-smuggling attempts cross into traffic-shaping territory quickly — stop at the point where pb-request-smuggling's methodology takes over, and never disturb other users' requests while testing.

## Integration
- Record every entry point tested with `mcp__bb__record_coverage`, including which levels of the ladder were tried and where the block sits, so next session starts at the right level instead of re-probing.
- Bank each confirmed *property* as a primitive with `mcp__bb__add_primitive`: "filter decodes once, backend twice" or "filter only watches the JSON body" are durable facts about the target, worth more than any single passing payload.
- Once a payload lands, immediately route to the owning class playbook and finish its confirmation; then bb-gate the result before reporting.
- The assistant proposes ladder levels and derived variants; the human sends every request and confirms which response is business-normal.
