---
name: pb-csrf
description: Methodology playbook for finding CSRF on a real target. Load when testing state-changing requests for token presence/validation, or when bb-next surfaces a CSRF test case.
---

# pb-csrf

## When this applies
Any state-changing request (POST/PUT/PATCH/DELETE, or a GET that changes state against REST convention) performed by an authenticated, cookie-based session — CSRF's mechanism depends entirely on the browser auto-attaching credentials to a cross-site request. Sensitive actions: password/email change, funds transfer, privilege grant, account deletion, adding a payment method, changing security settings (MFA, recovery email). Covers WSTG-SESS-05.

## First signals
Notice these before knowing whether there's a bug:
- A state-changing POST/PUT/DELETE with no anti-CSRF token anywhere in the body or headers — no hidden token field, no custom header a cross-site request wouldn't carry.
- A token IS present, but it's unclear whether it's actually validated server-side versus merely expected by convention — this is the more common and more interesting case; presence is not enforcement.
- A state-changing action reachable via GET (a "one-click" unsubscribe/delete/approve link) — GET is the easiest CSRF delivery vector, since a plain `<img src>` or link click triggers it.
- The session cookie's `SameSite` attribute value — `Strict` or `Lax` (today's browser default when unset) already blocks a large share of classic CSRF; note the actual value before assuming an unprotected-looking form is exploitable.
- A JSON-body API requiring no custom header and accepting a simple content-type (`text/plain`, form-urlencoded) that a plain HTML form can send — some JSON APIs are "safe by accident" only via `Content-Type` enforcement forcing a preflight; check whether that enforcement is actually present.
- Multiple routes triggering the same state change (a web form and a "simplified"/legacy/mobile-API endpoint) where only one carries a token — inconsistent token coverage across equivalent endpoints is a common gap.

## Enumeration
1. List every state-changing action across the app: account settings, financial actions, admin actions, anything that writes, deletes, or changes a permission.
2. For each, note the HTTP method, whether a token/nonce is present, where it's carried (hidden form field, custom header, cookie-duplicated-as-header/double-submit), and the session cookie's `SameSite` value.
3. Group actions by which framework/route layer handles them — a global CSRF middleware, if present, likely covers most routes uniformly; look specifically for routes that opt out or bypass it (an API-only blueprint, a webhook receiver misclassified as not needing protection, a legacy route predating the middleware).
4. Note the authentication mechanism per endpoint — pure `Authorization: Bearer` auth with no cookie in the credential path is not CSRF-susceptible by the classic mechanism; only cookie-authenticated actions belong in this enumeration.
5. Coverage is exhausted once every state-changing, cookie-authenticated action has a recorded token-presence AND token-validation result — presence alone doesn't answer the question that matters.

## Test procedure
1. Baseline: perform the sensitive action normally, capturing the complete request including the token value and the session cookie's `SameSite` attribute.
2. Token-removal test: resend the exact request with the token field/header removed entirely (not blanked) and see whether the server still performs the action. If it does, the token isn't actually being checked — a more common and more important finding than the token being absent from the UI.
3. Token-alteration test: resend with the token changed to a different-but-plausible value (e.g., one obtained from a separate legitimate session, for double-submit or session-bound schemes) and confirm the server rejects it — a token that's present and required but not actually tied to the acting session's identity is a weaker but still real gap.
4. Method/verb test: if a token is enforced on POST, check whether the same action is also reachable via GET or another verb where the same enforcement wasn't applied.
5. Cross-origin simulated-request test: construct the equivalent of a foreign-origin auto-submitting request — a form or fetch hosted on a domain you control that a victim's browser would submit with cookies attached — and confirm, using your own two accounts/sessions, whether the action succeeds with no visible interaction beyond a page load. Test this only against your own second account, never a real third party.
6. `SameSite` interaction check: note the cookie's actual value and browser behavior — if `Strict`/`Lax` is set and no token exists, weigh whether cross-site delivery is realistically still possible (e.g., a top-level navigation still permitted under `Lax` for GET-based state changes) before concluding a missing token is exploitable.
7. Content-type/preflight check for JSON APIs: confirm whether the endpoint accepts a simple content-type (`text/plain`, `application/x-www-form-urlencoded`) a plain HTML form can send without triggering a CORS preflight, rather than requiring `application/json` — this determines whether "it's a JSON API" is actually a real mitigation here.

### Worked example of a token-removal test
```
Baseline:      POST /api/account/email  {email: "new@example.com", csrf_token: "a1b2..."}
               -> 200, email updated

Removal test:  POST /api/account/email  {email: "new@example.com"}   (csrf_token field omitted)
               -> 200, email updated AGAIN

Negative control: POST /api/account/email with an unrelated required field also omitted
               -> 400, "missing field" — confirms the endpoint does validate the body shape
               in general, so the token's absence specifically is what's being skipped, not
               validation as a whole.
```
The removal test succeeding is the finding: the token is decorative, not enforced. The negative control is what rules out "the endpoint just doesn't validate anything."

## Evidence to capture
- The baseline request/response with the token present, next to the token-removed request/response showing the action still succeeded.
- The session's `SameSite` cookie attribute exactly as set, and the authentication mechanism (cookie vs. bearer-only) for the tested endpoint.
- For the cross-origin test: the minimal harmless HTML/JS used to construct the simulated foreign-origin submission, and proof the state change landed (a re-fetch of the affected resource from the legitimate account) — not just that the malicious page "sent" something.
- The specific sensitive action affected, framed as real-world impact (what changed, for whom), not "CSRF is possible."
- Confirmation of whether the action requires re-authentication/step-up (a password re-entry prompt materially changes exploitability) — note if step-up auth exists and whether it was actually enforced.

## Escalation
- A token-removal bypass on a low-sensitivity action (a display preference) is weak; the same bypass on an account-security action (email/password change, MFA disable, payment method) is materially higher severity — always state which specific action was tested, not "CSRF exists on the site."
- Chaining a forced email or password change into full account takeover (attacker forces their own recovery email, then initiates a password reset) is the standard way to raise CSRF severity — describe the chain concretely, using only your own two test accounts.
- A CSRF-able action that itself grants a further primitive (adding an API key, adding an OAuth-connected app, elevating a role) should be named as that primitive's compromise, not left at "an action was forced."
- If the same missing-token pattern repeats across many endpoints sharing one route layer, name it as a systemic gap in that middleware/blueprint rather than filing many near-duplicate reports.

## Out-of-scope traps
- A non-sensitive, non-destructive action (a UI theme change, dismissing a notification) forced via CSRF is typically Low/Informative — many programs won't reward it; check policy before investing further effort.
- An unauthenticated action cannot be CSRF by definition — there's no session/credential being forged. Re-classify as something else if you find a bug there.
- If the session cookie is `SameSite=Strict` (or `Lax` and the action is only reachable via a verb `Lax` blocks cross-site) with no realistic top-level-navigation-GET path, treat the missing token as defense-in-depth absence, not a live exploit path — say so plainly rather than claiming impact the browser default already prevents.
- A CORS misconfiguration is a different bug class (CORS is about reading a cross-origin response; CSRF is about triggering a cross-origin write with no need to read it) — don't conflate the two even though they sometimes chain together.
- A token that's present but only "weak" in some subjective sense (looks short, looks guessable) is not a bypass by itself — the report needs to show the token isn't actually validated (step 2 above), not just that it looks unconvincing.
- Re-verify token enforcement close to submission time — frameworks patch or add CSRF protection incrementally across routes, so a gap found weeks ago may already be fixed.

## Integration
- Record each tested action with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, noting explicitly whether the result was "no token," "token present but unvalidated," or "token enforced correctly" — these are different findings, not the same coverage record.
- Bank a confirmed token-not-validated result that isn't yet chained into real impact via `mcp__bb__add_primitive` — it may combine with an account-takeover chain found later.
- The assistant proposes which actions and token variants to test; the human sends every request (including the cross-origin simulation) and confirms from the legitimate account's own view that the state actually changed.
- Never state CSRF is confirmed from a described request/response alone — that's `record_coverage(status="confirmed")` or `promote_to_finding(..., human_confirmed=True)` after the human's own reproduction.
