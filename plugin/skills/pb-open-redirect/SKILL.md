---
name: pb-open-redirect
description: Methodology playbook for finding open redirect on a real target. Load when testing a url/next/return-style parameter, or when bb-next surfaces an open-redirect test case.
---

# pb-open-redirect

## When this applies
Any parameter whose value plausibly ends up in a `Location` header, a meta-refresh, or a client-side navigation call: `?url=`, `?next=`, `?return=`, `?redirect=`, `?continue=`, `?dest=`, post-login/post-logout redirect targets, an SSO/OAuth `redirect_uri`-adjacent parameter (distinct from the OAuth flow itself), unsubscribe/tracking-link redirectors, and any "continue to partner site" feature. Covers WSTG-CLNT-04.

## First signals
Notice these before knowing whether there's a bug:
- A parameter name that telegraphs its purpose (`url`, `next`, `redirect`, `return_to`, `continue`, `dest`, `target`) on any endpoint that visibly redirects (302/303, or a client-side `window.location` assignment) after some action.
- A redirect target you did NOT explicitly request appearing in a response you triggered incidentally — a login flow redirecting "back to where you were," a logout sending you to a page whose URL came from somewhere in session state.
- Client-side navigation reading a URL-shaped value from `location.search`/`hash` and assigning it to `window.location`, `location.href`, or a router's navigate call — a purely DOM-based variant with no server round-trip.
- A redirector used for tracking/analytics/unsubscribe links (click-through counting) — these are especially likely to accept an arbitrary external target since their whole job is "go somewhere else after logging a click."
- Inconsistent validation across similar redirect parameters on different endpoints (one correctly restricts to same-origin paths, a sibling doesn't) — same root cause as inconsistent CSRF-token coverage: shared intent, independently implemented.

## Enumeration
1. List every parameter, across every endpoint, that plausibly feeds a redirect: explicit `url`/`next`-style query params, hidden form fields carrying a return path, and client-side code assigning a URL-shaped value from the query string/hash to a navigation API.
2. Separate server-side redirects (visible as a 3xx with a `Location` header, testable directly) from client-side navigation (requires reading the JS or observing the browser actually navigate) — the two need different confirmation methods.
3. Note what validation shape is apparent before testing: does the app appear to require a same-origin path (`/dashboard`), a specific allowlisted domain, or accept anything URL-shaped?
4. Identify every flow that uses a redirect as part of a larger process — post-login, post-logout, post-payment, SSO callback, email-link click-through — since impact differs sharply by what state or token is attached at the point of redirect.
5. Coverage is exhausted once every redirect-carrying parameter across every flow has a recorded validation result (blocks external targets / allows them / partially validates) — a parameter correctly restricted to same-origin paths is a completed, valid "not vulnerable" test, not a skip.

## Test procedure
1. Baseline: trigger the redirect with its normal, in-app value and note the exact resulting `Location` header or navigation target.
2. Substitute a value pointing at a domain you control (or a well-known, harmless external domain if no listener is handy) and observe whether the resulting redirect target changes to that external destination — this single substitution is the entire detection probe.
3. If a bare external URL is blocked, test standard bypass-adjacent variants only far enough to characterize the validation, not to defeat it for its own sake: a protocol-relative URL (`//attacker-domain/...`), a value embedding the app's own expected domain as a substring or lookalike subdomain (`target.example.com.attacker.tld` or `attacker.tld/example.com`), and whitespace/backslash variants a URL parser might treat differently than a naive string-prefix check.
4. Test whether validation is applied consistently to both the path and the query/fragment portion — some implementations check the host correctly but still honor an embedded second redirect or an `@`-based userinfo trick to reach a different effective host.
5. For client-side navigation: confirm by observing the actual browser navigate (network tab, URL bar changing), not just that the JS *contains* a `location.href = ...` assignment — confirm the value genuinely flows from the URL-controlled input to the sink.
6. Check whether the redirect fires automatically (meta-refresh, immediate JS navigation) versus requiring a user-visible click-through with the destination shown — this materially changes how convincing the delivery story is, and should be recorded either way.
7. If the flow carries a token or session artifact at the point of redirect (an SSO `redirect_uri`, a password-reset completion redirect, an OAuth `state`/code exchange), note this explicitly and treat it as the higher-value chain described under Escalation — but don't test the OAuth flow itself here; that's `pb-oauth-flaws`'s remit.

### Worked example of tiering a result
```
Baseline:        ?next=/dashboard              -> Location: /dashboard
Bare external:   ?next=https://attacker.example -> Location: /dashboard   (blocked, tier: not vulnerable)
Protocol-relative: ?next=//attacker.example      -> Location: //attacker.example  (tier: bypass confirmed)
```
The bare-external test alone would have read as "not vulnerable." The protocol-relative variant is what actually reveals the validation only checks for a leading `http`/`https` scheme, not the resulting host — report the specific variant that worked, not just "open redirect found."

## Evidence to capture
- Baseline redirect target next to the substituted-value redirect target, full response headers (`Location`) or DOM/network evidence for client-side cases.
- The exact parameter, its value, and which bypass-adjacent variant (if any) was needed to pass validation, stated precisely.
- Whether the redirect is immediate/automatic or requires a visible click-through — central to the exploitability discussion.
- If chained to a token-carrying flow: the specific token/artifact observed traveling through the malicious redirect, captured via `mcp__bb__store_evidence` with appropriate redaction — only your own test account's token, never a real user's live one.
- Screenshots only where they clarify a client-side navigation that raw HTTP evidence doesn't capture on its own.

## Escalation
- A bare open redirect with no further chain is typically Low — describe it honestly at that level and check program policy before investing more time.
- The standard escalation path is chaining into a flow where a sensitive token travels with the redirect: an OAuth implicit-flow or authorization-code exchange whose `redirect_uri`/callback validation is loose enough to be steered off-origin (cross-reference `pb-oauth-flaws`) turns a bare redirect into token/code theft — name this as a distinct, higher chain, not the same finding restated.
- A redirect reachable from a server-side context (the server itself following a user-influenced redirect target, e.g., a webhook or import feature) rather than purely client-side/browser-side crosses into SSRF territory — cross-reference `pb-ssrf` and evaluate it under that playbook's evidence bar instead of double-counting it here.
- An open redirect usable as a phishing delivery vector (the URL shown to a victim looks like the real, trusted domain right up until the automatic redirect) is worth naming specifically when the flow is one a victim would plausibly click from an email or message — describe the realistic delivery context.
- If the redirect target is reflected into an intermediate "you are being redirected to X" page unescaped before navigating, check whether that reflection is itself an XSS surface (cross-reference `pb-xss`) — the two bugs commonly sit on the same endpoint.

## Out-of-scope traps
- A redirect that only ever stays on the same origin regardless of input (validated against a real allowlist of internal paths, or resolved through a lookup table rather than the raw parameter) is not an open redirect — confirm the actual final destination, not that a redirect happened at all.
- Many programs explicitly mark a bare open redirect (no token chain, no phishing-relevant context) as Low or Accepted/Informative — read the program's stated policy before assuming this is automatically reportable; some require the SSRF or OAuth chain before triaging above informational.
- A redirect requiring the victim to already be deep in a suspicious-looking multi-step flow, rather than one clean link, is weaker as a phishing vector — be honest about how convincing the delivery actually is.
- A `Location` pointing off-origin that exactly matches a documented, intentional "leaving this site" feature (a partner integration, an affiliate redirect) is working as designed — verify the feature's stated purpose before flagging its normal function as a bug.
- A same-window external link the user clicked deliberately, with no attacker-controlled redirect logic involved, is not an open-redirect finding — confirm the destination is genuinely attacker-influenceable, not just external.

## Integration
- Record each tested parameter with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, noting whether external targets were blocked, allowed outright, or allowed only via a specific bypass-adjacent variant.
- Bank a confirmed external-redirect capability that isn't yet chained into token theft or SSRF via `mcp__bb__add_primitive` — it's exactly the kind of half-result worth keeping for a later OAuth or SSRF finding to complete.
- The assistant proposes which parameters and bypass-adjacent variants to try; the human sends every request and confirms the actual navigation/`Location` result before anything counts as more than a candidate.
- Never state open redirect (or a chained OAuth/SSRF escalation) is confirmed from a described response alone — that's `record_coverage(status="confirmed")` or `promote_to_finding(..., human_confirmed=True)` after the human's own reproduction.
