---
name: pb-jwt-flaws
description: Methodology playbook for finding JWT validation flaws (alg=none, alg confusion, missing signature/expiry checks, kid/jku abuse) on a real target. Load when a JWT is in use or when bb-next surfaces a JWT test case.
---

# pb-jwt-flaws

## When this applies
Any point where a JSON Web Token carries authentication or authorization state: an `Authorization: Bearer` header, a session cookie that's actually a JWT, an API key that decodes as one, an SSO/OIDC id_token, or an internal service-to-service token visible from the client side. This overlaps `pb-session-management` (token lifecycle: rotation, expiry, logout) and `pb-broken-access-control` (a role claim read from the token without verification) — this playbook is specifically about whether the *validation* of the token itself is sound, not what the token is used for afterward. Covers WSTG-SESS-10 (Testing JSON Web Tokens). Every check in this playbook operates on a token you already legitimately hold — decoding, tampering, and resubmitting your own credential — since the goal is characterizing what the *verifier* accepts, not obtaining anyone else's token.

## First signals
Notice these before you've formed any hypothesis about a bug:
- A base64url-looking three-part dot-separated string in an `Authorization` header, cookie, or local storage value — decode the header and payload (no signature verification needed to read them) and note `alg`, `typ`, `kid`, `jku`/`jwk`, `iss`, `exp`, `aud`.
- An `alg` of `none`, or `HS256` on a token that otherwise looks like it should be asymmetrically signed (issued by an OIDC provider, references a `kid` pointing at a public-key set) — anything unusual for the stack in use.
- A `kid` header that looks like a file path, a URL, or a raw parameter value passed into a lookup, rather than an opaque identifier from a fixed, small set.
- A `jku` or `x5u` header present at all — these tell the verifier *where to fetch the verification key from*, which is only safe if fetching is restricted to a trusted, fixed set of locations.
- Two services/endpoints accepting what looks like the same token format but with visibly different validation strictness — validation is frequently reimplemented per-service.
- A token whose `exp` is far in the future, absent entirely, or whose expiry doesn't visibly change behavior once passed — expiry enforcement is easy to skip in custom middleware.
- Any place the app appears to trust a claim's value (a role, a user ID, a tenant ID) without the request also being tied to a working signature check.
- A logout or password-change flow that doesn't visibly invalidate the previously-issued token server-side (stateless JWTs commonly can't be revoked without an explicit denylist) — a lifecycle question that overlaps `pb-session-management` directly.
- A JWT accepted in more than one place it could be presented — header, cookie, and query-string parameter all honored for the "same" token — since each transport is a separate opportunity for a verifier to diverge.

Reading a JWT's contents is not itself a vulnerability — the payload is encoded, not encrypted, and meant to be inspectable. The flaw, if any, is entirely in how the server *validates* the token before trusting it.

Quick map of where validation gaps typically cluster, for triage when time is short:

| Validation step | What a gap looks like | Detection probe |
|---|---|---|
| Signature check | Present but not actually enforced | `alg=none`, signature stripped |
| Algorithm pinning | Header-supplied `alg` honored as-is | Change `alg`, expect rejection |
| Expiry | `exp` absent or not checked at use-time | Resubmit an expired token |
| Claim integrity | Payload edited without resignature accepted | Tamper one claim, expect rejection |
| Key resolution | `kid`/`jku` fetched from an unrestricted source | Vary `kid`, note which key is used |

## Enumeration
1. Collect every distinct token the app issues or accepts: primary session token, refresh token, password-reset token if JWT-shaped, SSO id_token, third-party/partner API tokens, internal microservice tokens visible from client-side traffic.
2. For each, decode header and payload and log: `alg`, `kid`/`jku` presence, the claim set (especially any authorization-relevant claim: role, scope, tenant, permissions), and `exp`/`iat`/`nbf` presence.
3. Identify every distinct verifier — every service/endpoint accepting the token — since validation logic commonly drifts between a gateway, a backend service, and a legacy endpoint.
4. Note whether the app exposes a JWKS endpoint (`/.well-known/jwks.json` or similar) — its presence means asymmetric verification is expected somewhere, the precondition for the algorithm-confusion check below.
5. Coverage is exhausted once every distinct token type has a recorded observation for algorithm handling, expiry enforcement, and signature enforcement, across every verifier that accepts it — not once the primary session token has been glanced at.

## Test procedure
Every probe below modifies only the header/claims of a token you already legitimately hold, then resubmits it in your own already-authenticated context — never attempt to derive another user's token or a real signing secret as part of these steps.

1. `alg=none` acceptance: take your own valid token, change the header's `alg` to `none`, strip the signature segment, and submit it. Note only whether the server accepts an unsigned assertion of your own identity — this proves signature validation is absent, without needing any other user's identity.
2. Algorithm-confusion signal (RS→HS concept): if the app uses `RS256`/asymmetric signing and a public key or JWKS is discoverable, check whether the server enforces an expected algorithm server-side regardless of what the `alg` header claims, or honors whatever algorithm the header names — confirm this by resubmitting your own token with the algorithm header changed and confirming it's rejected. That server-side pinning check is the whole point; don't go further into constructing an actual cross-algorithm forgery here.
3. Expiry enforcement: decode `exp`; once the token is expired, resubmit the identical expired token and confirm whether it's still accepted. If no `exp` claim exists at all, record that as a first-class observation on its own.
4. Signature-tampering baseline: flip a single character in the signature segment of an otherwise-valid token and confirm rejection — the negative control every other probe here depends on for meaning.
5. Claim-tampering-without-resigning: modify a claim (role, user ID, tenant) in your own token's payload without adjusting the signature, and confirm rejection due to signature mismatch — if it isn't rejected, that's a stronger, more direct finding than any algorithm concept above, and worth checking first.
6. `kid` header abuse (conceptually): if `kid` looks like a path, filename, or raw lookup value, note the shape only — check whether varying it (to another *legitimate* key ID your own tokens are issued under, if more than one exists) changes which key the server verifies against. Don't send path-traversal or injection-style values here; flag that as a lead for `pb-path-traversal`/`pb-sql-injection` instead if the shape suggests it.
7. `jku`/`x5u` trust boundary: if present, note whether the value is a fixed, expected host or something that looks steerable — thoroughly testing this (standing up an alternate key server) is a heavier test the human should scope deliberately, not a default first probe.
8. Cross-service replay: submit a token issued for one purpose/audience (e.g. a password-reset-flow token, a partial-MFA token) to an unrelated, fully-authenticated endpoint, checking whether `aud`/`iss`/scope are actually enforced per-endpoint — cross-reference `pb-session-management`'s session-puzzling coverage if this looks promising.
9. Post-logout/post-password-change reuse: after triggering logout or a password change, resubmit the token that was valid immediately beforehand and confirm whether it's actually rejected — a stateless JWT with no server-side denylist frequently remains valid until its natural `exp`, regardless of what the UI implies about "you've been logged out."

### Worked example of the alg=none check
```
Original header: {"alg":"RS256","typ":"JWT"}
Modified header: {"alg":"none","typ":"JWT"}
Submitted as:     <base64(header)>.<base64(payload)>.
                  (empty signature segment)

Result: 200, authenticated response for your own account
        -> signature validation is not enforced at all
```
This proves the gap using only your own already-valid identity — no other user's token, secret, or credential was needed to demonstrate it.

## Evidence to capture
- The decoded header and payload of the token type under test — only the values relevant to the check; redact anything sensitive not needed to make the point.
- The exact modification made (e.g. "`alg` changed from `RS256` to `none`, signature segment removed") and the exact request it was submitted in.
- The server's response proving acceptance or rejection — status code and, critically, whether an authenticated action actually succeeded, not just a 200 on the token-bearing request itself.
- The negative control result (a tampered-signature token correctly rejected) alongside any positive finding, so the report shows the gap is specific, not "nothing is checked."
- For expiry findings, both the `exp` value and the actual wall-clock time the resubmission was attempted.
- Store via `mcp__bb__store_evidence` — never paste a token containing another real user's data; use your own test token throughout.

## Escalation
- `alg=none` or a signature-check bypass confirmed against your own token becomes account-takeover-class impact once it lets you assert an *arbitrary* identity claim (a second, still-your-own-test-infrastructure account) rather than just replaying your own already-valid identity unsigned.
- A successful claim-tampering result (role/tenant changed, accepted without resignature) is usually the single highest-value finding here — bank it via `add_primitive` immediately and check how many privileged actions it reaches, per `pb-broken-access-control`'s method, rather than re-deriving that here.
- Missing expiry enforcement escalates once paired with a realistic leakage path for the token (a Referer header, logs, a prior finding) — the missing check alone is a weaker, defense-in-depth observation until leakage is also plausible.
- Cross-service replay across different verifiers is a systemic finding — name every verifier reached in the writeup, not just the first one confirmed.
- Never attempt to actually recover or crack a real HMAC signing secret as escalation — a weak-secret concern is reported only as a methodology note the human pursues under their own authorized process; this playbook does not include or imply a cracking recipe.
- A token that survives logout or password-change escalates once you show a plausible way it could have leaked (a shared device, a proxy log, a prior finding) — the missing revocation alone is a weaker, defense-in-depth-style observation until paired with a leakage path.
- If the same weak validation is confirmed across every verifier that accepts the token (per the enumeration pass), state that breadth explicitly — a fix applied to only one service leaves the others silently exposed, which is exactly the kind of systemic detail a triager needs to scope the real fix.

## Out-of-scope traps
- Decoding and reading a JWT's claims is not a finding by itself — payloads are base64, not encrypted, and meant to be inspectable client-side. Only the validation gap is reportable.
- A token that rejects every tampering attempt in this procedure (bad signature, `alg=none`, expired reuse) is a clean result — record it and move on rather than continuing to hunt for a bypass that isn't there.
- Short-lived access tokens paired with a separately-secured refresh flow are working as intended; don't report fast expiry as a weakness on its own.
- A `kid`/`jku` value that resolves only within a fixed, server-side-controlled allowlist (confirmed by testing a value outside that set and seeing it rejected) is not a finding — the risk is specifically an *unrestricted* key source, not the header's mere presence.
- Some programs explicitly scope out "algorithm confusion without a demonstrated forged token" as theoretical — check program notes before writing up the RS→HS concept without a working demonstration on your own test tokens.
- A library that technically supports `alg=none` but whose application wrapper always supplies an expected-algorithm allowlist server-side is not vulnerable — step 4's probe is what actually distinguishes this; don't infer vulnerability from library capability alone.
- A JWT that survives logout because the app deliberately relies on short expiry plus a documented accepted-risk window (not a revocation promise) is working as designed — check what the app actually claims about logout behavior before reporting reuse as a bug.
- A `kid` value that looks path-like but is actually matched against a fixed allowlist before ever touching a filesystem or URL fetch is not vulnerable — confirm the value is actually used unvalidated, not merely shaped like it could be.

## Integration
- Record each check with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, using test_case_ids like `jwt-alg-none`, `jwt-alg-confusion-signal`, `jwt-expiry-enforcement`, `jwt-signature-tamper`, `jwt-kid-abuse`, `jwt-cross-service-replay` — a clean rejection on any of these is worth recording so the token type isn't re-tested from scratch next session.
- Bank a confirmed validation gap with unclear downstream impact via `mcp__bb__add_primitive` — "verifier X accepts `alg=none` on my own token" is a reusable capability worth keeping before every reachable endpoint is checked.
- File an untested hypothesis (e.g. "the JWKS host might be attacker-influenceable via the `jku` header") as a lead via `mcp__bb__add_lead` rather than standing up test infrastructure without the human's go-ahead.
- The assistant proposes which header/claim to modify and what to check in the response; the human decodes, edits, and resubmits every token and confirms what the server actually did. Never claim a finding is real — that's `mcp__bb__promote_to_finding(..., human_confirmed=True)` after the human's own reproduction.
