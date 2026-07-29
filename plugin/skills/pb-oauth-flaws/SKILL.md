---
name: pb-oauth-flaws
description: Methodology playbook for finding OAuth/OIDC/SSO flow flaws (redirect_uri validation, missing/replayable state, token leakage, scope escalation) on a real target. Load when testing an SSO flow or when bb-next surfaces an OAuth test case.
---

# pb-oauth-flaws

## When this applies
Any login, account-linking, or "Sign in with X" flow built on OAuth 2.0 or OIDC: the authorization-code or implicit flow between the target app and an identity provider (Google, GitHub, a corporate IdP, or the target's own OAuth server), plus first-party integrations where the target app is itself the OAuth provider for third-party clients. The shape is a redirect-based handoff carrying `client_id`, `redirect_uri`, `state`, `response_type`, and eventually a `code` or token back to the app. This playbook covers flaws in the *protocol handling* — redirect-destination control, CSRF-on-the-flow, token exposure in transit — not the credential-proving step itself, which is `pb-authentication-flaws`'s territory once a session results. No dedicated WSTG ID covers OAuth directly; the redirect checks below extend WSTG-CLNT-04 (client-side URL redirect) and the state/CSRF checks extend WSTG-SESS-05 (CSRF) into this specific flow. Every check below is run through the real provider using accounts and clients you're authorized to use — none of it requires standing up a fake identity provider or forging a provider-issued assertion.

## First signals
Notice these before you've formed any hypothesis about a bug:
- A `redirect_uri` (or `redirect_url`, `callback_url`, `return_to`) parameter in the authorization request whose value you can influence at all, even slightly — an appended path segment, an appended query string.
- A `state` parameter that's absent, empty, fixed across multiple attempts, or clearly predictable (sequential, timestamp-derived) rather than a fresh random value per flow.
- The authorization response placing a token or code somewhere other than a backend-to-backend exchange — a URL fragment (implicit flow), or a query string that then loads a page which also pulls in third-party scripts.
- A "connect your account" or account-linking flow that ties a third-party identity to an existing target-app account based solely on an email claim, without the target app independently confirming ownership of that email.
- Scopes requested at authorization time broader than the app's own feature set appears to need, or a scope value editable directly in the authorization URL before consent.
- An OIDC flow where the app appears to trust the `id_token`'s claims without validating issuer, audience, or signature — overlaps `pb-jwt-flaws` directly, since the id_token is a JWT.
- Multiple OAuth client registrations for the same provider (web app, mobile app, a legacy integration), each with its own `redirect_uri` allowlist — allowlists drift and are rarely audited with equal care across all of them.
- Any place the authorization `code` or a token appears to leak via the `Referer` header when the callback page loads a third-party resource before completing the exchange.
- A `response_type` parameter you can change (e.g. from `code` to `token`) without the server rejecting the switch — an app that only intends to support the more-secure authorization-code flow but doesn't enforce that server-side may still honor an implicit-flow request.
- An authorization-code exchange with no `code_verifier`/PKCE check even though the client is a public client (a mobile app or SPA with no confidential secret) — PKCE's absence is most consequential exactly on client types that can't keep a secret.

Quick map of where flow flaws typically cluster, for triage when time is short:

| Flow stage | What a gap looks like | Detection probe |
|---|---|---|
| Authorization request | `redirect_uri` matched loosely (prefix/suffix/substring) | Incremental redirect_uri variants |
| Authorization request | `state` absent, fixed, or reused | Replay a captured `state` |
| Code exchange | No PKCE enforcement on a public client | Omit/mismatch `code_verifier` |
| Callback handling | Code/token exposed via `Referer` on page load | Inspect outbound third-party requests |
| Consent/scope | Requested scope wider than needed, not re-checked | Edit `scope`, test against a gated endpoint |

## Enumeration
1. List every OAuth/OIDC flow on the target: primary SSO login, account-linking/"connect" flows per supported provider, and any flow where the target app itself issues tokens to third-party clients (a developer/API-access feature, a Zapier-style integration).
2. For each, capture the full authorization request: `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, and any provider-specific extras.
3. Note the flow type — authorization code (with or without PKCE), implicit, or hybrid — since implicit and hybrid flows expose tokens in the browser in ways authorization-code flow does not.
4. For each `redirect_uri`, determine what the app appears to accept as a match: exact string, prefix match, or a check that inspects only the registered host and ignores path/query.
5. Identify whether the target app is only a *relying party* (consuming another IdP) or also an *authorization server* (issuing tokens to others) — the latter needs its own client-registration and allowlist review, a materially larger surface than a single login button.
6. Note whether PKCE is used at all, and if so whether it's actually required server-side or merely accepted when present — a public client with optional PKCE is a materially weaker posture than one where the authorization server rejects a code exchange missing a valid verifier.
7. Coverage is exhausted once every distinct flow (per provider, per client registration) has a recorded observation for redirect_uri validation strictness, state presence/uniqueness, and token-exposure path — not once the primary "Sign in with Google" button has been walked through once.

## Test procedure
1. Baseline: walk the full flow once legitimately and record every parameter in the authorization request and every value in the callback, including exactly where the code/token appears (query string vs. fragment) and how the token exchange looks.
2. Redirect_uri validation probe: resubmit the authorization request with `redirect_uri` modified in small, incremental ways — an appended path segment, an appended query parameter, a trailing slash added or removed, a sibling subdomain — and observe whether the provider still proceeds to the modified destination or rejects the request outright. A destination that's still the app's own domain, or one you don't need to actually control, is enough to observe the acceptance/rejection behavior.
3. From step 2's behavior, describe the match precisely — exact-string versus prefix, suffix, or substring leniency — since the mechanism, stated precisely, is the finding itself.
4. State-replay probe: capture a `state` value from one completed authorization flow, then start a fresh flow and see whether the same value is accepted a second time — this detects missing single-use enforcement, the precondition for CSRF-on-the-flow.
5. State-uniqueness probe: initiate the flow twice in a row and compare the two `state` values — identical or trivially related values indicate it isn't a fresh per-flow anti-CSRF token regardless of whether it's checked at all.
6. Token-leakage-via-referrer check: on the callback page, check whether it loads any third-party resource before the code/token is consumed, and whether `Referer` on that outbound request would carry the sensitive query string — a fragment-based token (`#access_token=...`) isn't sent in `Referer` at all, so this matters specifically for query-string-based flows.
7. Scope-escalation probe: edit `scope` in the authorization request to include an adjacent, plausible scope not normally requested, and check whether consent reflects it and whether the resulting token actually carries the expanded scope, tested against one low-consequence read-only endpoint.
8. Account-linking identity-confirmation check: if a "connect your account" flow exists, determine whether it links purely on a claimed email from the third-party provider or independently confirms that email is verified — test only by observing behavior with your own accounts across providers, never by fabricating an identity you don't control.
9. PKCE enforcement check: for a public client, attempt the code exchange with the `code_verifier` omitted or mismatched relative to the `code_challenge` sent earlier in the same flow, and confirm whether the exchange is rejected — a low-effort, high-value check once PKCE's presence is already noted.

### Worked example of a redirect_uri leniency finding
```
Registered redirect_uri: https://app.example.com/oauth/callback

Probe 1: redirect_uri=https://app.example.com/oauth/callback/extra
         -> provider redirects here without complaint (path-suffix leniency)

Probe 2: redirect_uri=https://app.example.com.attacker-controlled.example/cb
         -> provider rejects (host is actually checked, not just a prefix string-match)
```
Probe 1 alone is the finding, stated precisely as "path-suffix leniency on an otherwise host-locked redirect_uri" — a materially narrower and more specific claim than "redirect_uri is not validated," which probe 2 disproves.

## Evidence to capture
- The full baseline authorization request and callback for the flow under test.
- The exact `redirect_uri` variant sent and the provider's actual response (redirected as requested / rejected / redirected to the registered default) — this is the entire finding for that probe.
- The `state` value(s) captured across multiple flow attempts, side by side, showing reuse or predictability.
- For token-leakage checks, the actual outbound request to the third-party resource showing what did or didn't appear in its `Referer`/URL.
- For scope-escalation, the consent screen content if scopes are displayed, and the token's effective permissions as demonstrated against one low-consequence endpoint.
- For PKCE checks, the `code_challenge` sent at authorization time and the exact `code_verifier` (or lack thereof) used at exchange, alongside the exchange's actual accept/reject outcome.
- Store via `mcp__bb__store_evidence` — never store a real third-party access/refresh token beyond what's needed to demonstrate the point; redact after confirming the read.

## Escalation
- A loose `redirect_uri` match becomes an account-takeover primitive once a code or token would actually be delivered to a destination you control — describe it as "the provider redirects to any URI matching pattern P" and hand the attacker-hosted-destination step to the human's judgment and program rules, consistent with `pb-open-redirect`'s escalation boundary, since this is fundamentally an open-redirect-into-token-leak chain.
- Missing/replayable `state` is CSRF on the login or account-linking action — name the concrete consequence: login-CSRF forces a victim into an attacker-controlled session; account-linking CSRF binds a victim's account to an attacker's third-party identity, which can become takeover if that identity later authenticates as the victim.
- Scope escalation matters once the expanded scope actually grants access beyond what consent implied — demonstrate against the single lowest-consequence endpoint that proves the point.
- Chain a redirect_uri weakness with a confirmed token-leakage path (referrer, or an open redirect elsewhere) for the strongest writeup — each alone is a real but partial finding; together they describe a complete theft path.
- If the id_token's signature/issuer/audience isn't actually validated, hand off to `pb-jwt-flaws` for that specific check rather than re-deriving JWT validation methodology here, and note the cross-reference so triage sees the full picture.
- Missing PKCE enforcement on a public client escalates once combined with any plausible way an authorization code could be intercepted (a loose redirect_uri, a logged URL) — on its own it's a hardening gap, not yet a demonstrated theft path.
- If the target app is itself an authorization server for third-party clients, a redirect_uri or state weakness found in one registered client's flow doesn't automatically apply to every other registered client — check whether the allowlist and state handling are per-client or shared before generalizing the finding.

## Out-of-scope traps
- A `redirect_uri` validated by exact string match against a registered allowlist, with no path/query/subdomain leniency, is working as intended — don't report "the parameter exists and I could edit it" without a demonstrated acceptance of a modified value.
- A theoretical flow described from documentation or code reading with no token or code actually observed leaking is a lead, not a finding — this playbook's evidence bar requires a demonstrated leak or acceptance, not a plausible-sounding chain.
- `state` present, unique per flow, and correctly rejected on reuse is a clean result — don't report its mere presence as insufficient without a specific demonstrated bypass.
- Many providers additionally validate via PKCE (`code_verifier`/`code_challenge`) — a loose `redirect_uri` match may be substantially mitigated by PKCE; check for and note PKCE presence before claiming full impact from a redirect_uri finding alone.
- Some programs explicitly exclude findings against a third-party IdP's own infrastructure (Google's, GitHub's) that isn't a program asset — confirm which side of the flow (relying party vs. provider) the weakness actually lives on before reporting.
- A scope that's requested but never actually checked/enforced server-side in a way that changes access is a code-quality observation, not an escalation — confirm the expanded scope actually unlocks something before calling it scope escalation.
- PKCE enforced and verified server-side (a mismatched or missing verifier is rejected) closes this specific gap even if the client is public — don't report PKCE's mere theoretical relevance once the enforcement check has actually passed.
- A confidential client (server-side app holding a real client secret) using the implicit or hybrid flow's fragment-based token delivery only where the browser context is fully trusted (no injected third-party scripts) is a design choice, not automatically a finding — assess the actual exposure before treating implicit flow as inherently reportable.

## Integration
- Record each flow tested with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, using test_case_ids like `oauth-redirect-uri-match`, `oauth-state-reuse`, `oauth-state-uniqueness`, `oauth-token-referrer-leak`, `oauth-scope-escalation` per provider/flow.
- Bank a confirmed loose redirect_uri match or missing state check via `mcp__bb__add_primitive` even before a full token-theft chain is demonstrated — it's a reusable capability worth keeping regardless.
- File an untested hypothesis (e.g. "this account-linking flow might trust the email claim without verification") as a lead via `mcp__bb__add_lead`.
- The assistant proposes which parameter variants to try and what to check in the response; the human runs every request through the real provider and confirms what actually happened. Never claim a finding is real — that's `mcp__bb__promote_to_finding(..., human_confirmed=True)` after the human's own reproduction.
