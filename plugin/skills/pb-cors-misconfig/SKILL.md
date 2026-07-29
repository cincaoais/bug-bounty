---
name: pb-cors-misconfig
description: Methodology playbook for finding CORS misconfigurations (Origin reflection with credentials, null-origin trust, suffix-match bypass) on a real target. Load when testing cross-origin behavior or when bb-next surfaces a CORS test case.
---

# pb-cors-misconfig

## When this applies
Any authenticated (cookie- or credential-based) API endpoint that returns `Access-Control-Allow-Origin` at all — meaning the app has explicitly opted into being callable cross-origin via the browser's CORS mechanism. Covers WSTG-CLNT-07 (Testing Cross Origin Resource Sharing). The question is narrow: does the server's origin-matching logic ever let a page on a domain you don't control read a cross-origin response made *with the victim's credentials attached* — i.e. does `Access-Control-Allow-Origin` ever reflect an untrusted origin at the same time as `Access-Control-Allow-Credentials: true`. Every check below reads response headers from requests sent with an `Origin` header you control; none of it requires publishing an actual exploit page to prove the header behavior exists.

## First signals
Notice these before you've formed any hypothesis about a bug:
- Any response carrying `Access-Control-Allow-Origin` whose value isn't a single fixed string but appears to echo back whatever `Origin` header the request sent — the giveaway is the header's value changing when you change your request's `Origin`.
- `Access-Control-Allow-Credentials: true` present alongside a reflected (non-fixed) `Access-Control-Allow-Origin` — this combination is the entire vulnerability class; either alone is not enough.
- An allowlist that looks regex- or suffix-based (`*.example.com` intended) rather than an exact list — the most common source of an exploitable match on a domain the app never intended to trust.
- The value `null` accepted as an allowed origin — this specifically matters because `null` is what browsers send from sandboxed iframes, `data:` URLs, and some redirect chains, all producible by an attacker without owning any domain.
- A preflight (`OPTIONS`) response granting broader methods/headers than the app's own same-origin frontend appears to use — suggesting the policy was configured for a different, possibly removed, integration and never revisited.
- Endpoints that clearly return sensitive per-user data (profile, account, admin) also carrying permissive CORS headers, versus purely public/static endpoints where permissive CORS is far less consequential.
- A CORS policy inconsistent across endpoints on the same app — some strictly locked to one frontend origin, others wide open — often a sign of copy-pasted middleware configuration drift rather than a deliberate, reviewed policy.
- A `Vary: Origin` header missing on a response whose `Access-Control-Allow-Origin` does vary by request — a caching layer in front of the app could then serve one user's permissive, origin-specific response to a different user entirely, a distinct amplification worth noting alongside the base finding.
- An origin-matching implementation that looks custom (string concatenation, a regex built from a domain variable) rather than a well-known CORS middleware default — custom logic is where suffix/substring mistakes most often live.

Quick map of the pairing that actually matters, for triage when time is short:

| ACAO value | ACAC: true present | Exploitable for credentialed reads? |
|---|---|---|
| Fixed, single trusted origin | Either | No — working as intended |
| Reflects request `Origin` | Yes | Yes — the core finding |
| Reflects request `Origin` | No | Not for credentialed data; still worth noting |
| `*` (wildcard) | Yes (browser-invalid combination) | No — browsers reject this pairing outright |
| `null` accepted as valid | Yes | Yes — reachable without owning any domain |

## Enumeration
1. List every authenticated endpoint (cookie-based session or any credential the browser attaches automatically) that returns CORS headers at all — endpoints with no `Access-Control-Allow-Origin` header aren't reachable cross-origin via a browser and are out of scope here.
2. For each, note whether the response also carries sensitive, per-user data — this determines whether a finding here is worth pursuing at all (see Out-of-scope traps).
3. Send a small, varied set of `Origin` values against each candidate and record the exact `Access-Control-Allow-Origin`/`Access-Control-Allow-Credentials` pair returned for each — a controlled/arbitrary-looking domain, `null`, a subdomain of the real app, and a domain that merely contains the app's name as a substring or suffix.
4. Note whether the policy is applied globally (shared middleware, consistent everywhere) or per-route — per-route inconsistency means each sensitive endpoint needs its own independent check rather than extrapolating from one confirmed-safe endpoint.
5. Check both simple requests (GET, no preflight) and any endpoint requiring a preflight (custom headers, non-simple methods) — the preflight response can reveal a broader policy than actual simple-request behavior.
6. Note the presence or absence of `Vary: Origin` alongside a reflected value, since it determines whether a shared cache in front of the app could redistribute one origin-specific response to other requesters.
7. Coverage is exhausted once every credentialed, data-returning endpoint has a recorded observation of its actual `Access-Control-Allow-Origin`/`-Credentials` pairing under at least the standard probe set above — not once the login/profile endpoint alone has been checked.

## Test procedure
1. Baseline: send a normal same-origin-equivalent request (the app's own real frontend origin, if known) and record the CORS headers returned, if any.
2. Reflection probe: set the request's `Origin` header to a domain you control, or any clearly arbitrary value for a first pass, and observe whether `Access-Control-Allow-Origin` echoes that exact value back rather than a fixed, expected origin — informative but not yet the vulnerability on its own.
3. Credentials-pairing check: on the same request, check whether `Access-Control-Allow-Credentials: true` accompanies the reflected origin — log this explicitly as present or absent for every probe, since a reflected origin without credentials enabled is a materially weaker or often non-issue result.
4. Null-origin probe: send `Origin: null` and check whether it's accepted the same way a real domain would be — an attacker can trivially produce a `null` origin from a sandboxed iframe or `data:` URL without registering any domain.
5. Subdomain/suffix probe: if the app has subdomains outside your control you can reason about (a marketing site, a status page on the same parent domain), test whether the check trusts any origin that merely *ends with* or *contains* the expected domain — for example a domain that contains the app's name as a substring but is not a real subdomain, chosen based on the target's actual domain structure rather than a fixed example.
6. Preflight probe: for an endpoint using non-simple methods/headers, send an `OPTIONS` preflight with a controlled `Origin` and inspect `Access-Control-Allow-Methods`/`-Headers` for anything broader than the app's legitimate frontend appears to need.
7. Confirm sensitivity: with the reflected-origin-plus-credentials combination confirmed, note what specific sensitive fields the endpoint's response body contains — this is what turns a header misconfiguration into a data-disclosure claim.
8. Cache-amplification check: when a reflected value is confirmed, check whether `Vary: Origin` is present on that response — its absence in front of a shared cache means a single request from your controlled origin could poison a cached response served to other users, a distinct and worth-separately-noting amplification of the base issue.

### Worked example of the pairing check
```
Request:  GET /api/account  Origin: https://attacker-controlled.example
Response: Access-Control-Allow-Origin: https://attacker-controlled.example
          Access-Control-Allow-Credentials: true
          Body: {"email": "...", "billing_address": "...", ...}
```
Both headers reflecting/enabling together, on an endpoint returning real account data, is the finding. Either header alone, or the same reflection on an endpoint returning only public data, is a materially weaker or non-issue result — state which case was actually observed.

## Evidence to capture
- The exact `Origin` value sent and the exact `Access-Control-Allow-Origin`/`Access-Control-Allow-Credentials` pair returned, for every probe value tried — the full header set, not a paraphrase.
- Confirmation of what sensitive data the endpoint actually returns, sufficient to justify severity, without over-collecting more of a real account's data than needed to prove the point.
- The preflight response separately from the simple-request response when both were tested.
- For subdomain/suffix findings, the specific comparison origin used and why it sits outside the intended trust boundary.
- The presence or absence of `Vary: Origin` on any response where the origin-reflection or amplification concern is raised.
- Store via `mcp__bb__store_evidence`.

## Escalation
- A confirmed reflected-origin-plus-credentials pairing on a sensitive endpoint escalates by naming the specific data class exposed (PII, account settings, an API key or token visible in the response body) — name the field, don't just say "sensitive data."
- If the same endpoint also performs a state-changing action rather than only a read, the same misconfiguration can enable cross-origin *actions* on behalf of a victim, not just reads — treat this as a materially higher-severity variant and note it distinctly.
- A `null`-origin acceptance is a stronger, more directly weaponizable primitive than a reflect-anything policy in some ways, since it requires no domain registration at all to reach from a sandboxed context — call this out explicitly rather than treating all reflection findings as equivalent severity.
- If a subdomain-suffix bypass depends on a subdomain the program doesn't control (shared infrastructure, a third-party-hosted status page), check who actually owns that subdomain before claiming it as an escalation path — see Out-of-scope traps.
- Chain with any confirmed subdomain takeover (`pb-subdomain-takeover`) if a trusted-by-suffix subdomain turns out to be unclaimed — that combination turns a theoretical suffix-match concern into a concretely exploitable one.
- A missing `Vary: Origin` alongside reflection is worth escalating as a separate line item when the target sits behind a shared cache/CDN (confirmed via cache-related response headers) — the potential blast radius shifts from "one attacker-initiated request" to "any cached user's data served to any subsequent requester."
- If the same reflection-plus-credentials pairing is confirmed across every credentialed endpoint tested rather than just one, state that breadth explicitly — it points at shared middleware misconfiguration rather than a single route's mistake, which changes how the triager scopes the fix.

## Out-of-scope traps
- Permissive CORS (even full reflection) on an endpoint returning only public, non-sensitive data and requiring no credentials is usually not reportable — many programs explicitly note this; check the endpoint's actual data sensitivity before writing it up.
- `Access-Control-Allow-Origin: *` without `Access-Control-Allow-Credentials: true` is not exploitable for credentialed access at all — browsers refuse to combine a wildcard origin with credentialed requests, so this specific pairing is a dead end for this class regardless of how open the wildcard looks.
- A reflected origin is not itself proof credentials are honored cross-origin — always check for `Allow-Credentials: true` explicitly rather than assuming it from reflection alone.
- An allowlist including a broad-looking but genuinely program-owned and reviewed set of partner domains is a business decision, not a vulnerability, unless one of those domains is independently compromised or takeover-able.
- CORS headers on an endpoint that also requires a request-forgery-resistant token (a custom header the browser won't auto-attach cross-origin) may be substantially mitigated even with loose Origin handling — check what the endpoint actually requires beyond cookies before claiming full impact.
- Don't conflate CORS misconfiguration with a missing CSRF token — different mechanisms; a strict CORS policy doesn't replace CSRF protection and vice versa, and each is reported under its own class (`pb-csrf` for the latter).
- A reflected origin paired with `Vary: Origin` correctly present is not a cache-amplification concern even if the base reflection issue stands — verify the header is actually missing before adding the amplification claim to a report.
- An endpoint that requires a second factor beyond cookies to act on the response data (a per-request signed token the app itself checks, not just relying on the browser's same-origin policy) may be substantially mitigated even with loose CORS — read what the endpoint actually enforces before assuming CORS is the only control in play.

## Integration
- Record each endpoint's probe results with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, using test_case_ids like `cors-origin-reflection`, `cors-null-origin`, `cors-suffix-bypass`, `cors-preflight-scope` — a clean, correctly-restrictive result is worth recording so the endpoint isn't re-probed next session.
- Bank a confirmed reflection-plus-credentials pairing whose data sensitivity isn't yet fully characterized via `mcp__bb__add_primitive` rather than waiting until full impact is known.
- File an untested hypothesis (e.g. "a partner subdomain in the allowlist might be worth a takeover check") as a lead via `mcp__bb__add_lead`, cross-referencing `pb-subdomain-takeover`.
- Note the `Vary: Origin` observation on the same coverage record as the reflection test rather than as a separate pass — it's a modifier on the same finding, not an independent test case.
- The assistant proposes which `Origin` values to send and what header pairing to look for; the human sends every request and reads back the actual headers and body. Never claim a finding is real — that's `mcp__bb__promote_to_finding(..., human_confirmed=True)` after the human's own reproduction.
