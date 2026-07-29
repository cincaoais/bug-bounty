---
name: pb-session-management
description: Methodology playbook for finding session-management flaws (token lifecycle, fixation, logout, expiry) on a real target. Load when testing session handling or when bb-next surfaces a session test case.
---

# pb-session-management

## When this applies
Any point after identity is established where the app issues, carries, or retires a session identifier: a cookie-based session, a bearer/JWT token, a refresh token, a "remember me" long-lived token, or SSO session state propagated across subdomains or services. This picks up exactly where `pb-authentication-flaws` leaves off — that playbook covers proving who you are, this one covers what happens to the credential the app hands you afterward: does it rotate, does it die on logout, does it expire, can it be fixed in advance by an attacker. Covers WSTG-SESS-01 through SESS-09.

## First signals
Notice these before you know whether the app is vulnerable:
- The session cookie/token value **before** authentication compared to the value **after** — a value that survives login unchanged, rather than being replaced, is a fixation smell.
- Token structure: opaque random-looking string vs. a decodable JWT vs. something that looks sequential or incrementing vs. base64 of readable content (decode only, never modify — WSTG-SESS-09).
- Set-Cookie attributes on any session-bearing cookie — presence or absence of `Secure`, `HttpOnly`, `SameSite` (WSTG-SESS-02), visible directly in response headers.
- The session value appearing somewhere it shouldn't: a URL query string, a Referer header leaking it to a third party, or a place the app's own documentation says it logs requests (WSTG-SESS-04).
- Logout that only changes what the client does (redirect, clear local state) with no visible server round-trip that would actually invalidate anything — the tell is whether logout is a trivial client-side action or a real state-changing request.
- A "log out other devices" or active-sessions list feature — worth checking early, since it's a strong hint the app tracks sessions server-side and therefore *can* revoke them, which raises the bar for every other lifecycle check.
- A session token that's identical in shape and length across every account you test with — no per-account entropy source is itself worth noting even before you've tried to predict one.
- More than one cookie or token doing session-like work at once (a legacy `sessionid` alongside a newer JWT) — dual mechanisms are a common source of one being rotated/invalidated while the other is forgotten.

Quick map of lifecycle events to the behavior expected at each:

| Event | Expected behavior | WSTG |
|---|---|---|
| Login | Pre-auth value replaced, not reused | WSTG-SESS-03 |
| Password/email/MFA change | Prior tokens stop working | WSTG-SESS-01 |
| Logout | Server-side invalidation, not just a client redirect | WSTG-SESS-06 |
| Idle/absolute timeout elapses | Server rejects the expired token | WSTG-SESS-07 |
| Token used outside its original purpose | Rejected by unrelated endpoints | WSTG-SESS-08 |

## Enumeration
1. List every place a session or token is issued or renewed: login, a token-refresh endpoint, SSO callback, "switch account/organization," step-up auth for a sensitive action, password-reset completion, email-verification completion.
2. List every place a session should logically end or rotate: logout, password change, email change, MFA method change, admin-forced revocation, account deactivation.
3. Identify how the token actually travels on the wire: `Cookie` header, `Authorization: Bearer`, a custom header, a hidden form field, or — the worst case — a query string parameter.
4. Note every lifetime signal available without guessing: cookie `Expires`/`Max-Age`, a JWT's `exp`/`iat` claims (decode only), and any documented idle-timeout behavior.
5. If the token is a JWT, note what it's used for versus what claims it carries — a token minted for one purpose (password-reset, partial-MFA-auth) accepted by unrelated endpoints is a session-puzzling candidate (WSTG-SESS-08), not a fixation or expiry issue.
6. Coverage is exhausted once every issuance point has a recorded rotation check and every termination point has a recorded invalidation check — an "it's probably fine" skipped on a secondary path (a refresh-token endpoint, an SSO callback) is exactly the kind of gap that survives a superficial pass.

## Test procedure
1. Fixation check (WSTG-SESS-03): capture the session identifier issued before authentication (if one exists pre-login), authenticate, then compare it to the post-login value. If it's unchanged, confirm impact by setting that pre-auth value yourself on a second session you control and checking whether it becomes authenticated once you log in through it — test this only across your own two sessions/identities, never against a real third party.
2. Rotation on privilege change (WSTG-SESS-01): change password, change email, or upgrade a role on a test account from a second, still-open session, then check whether the *original* token/cookie from before the change still authenticates.
3. Logout invalidation (WSTG-SESS-06): log out in one session, then replay the captured token/cookie value directly against an authenticated endpoint. A 200 with real data is confirmed non-invalidation. Watch for the sneakier variant where the client redirects to a login page but the underlying API call, replayed directly, still succeeds — check the raw response, not the rendered page.
4. Expiry enforcement (WSTG-SESS-07): note the claimed or observed timeout, then use a token whose lifetime has clearly elapsed (a `exp` claim in the past, or waiting past a stated idle timeout) and confirm the server rejects it rather than the client merely choosing to redirect.
5. Active-session revocation: if the app exposes a "log out other devices" or session list, trigger it from one session and confirm from a second, previously-authenticated session that access is actually cut server-side, not just removed from a UI list.
6. Session puzzling (WSTG-SESS-08): check whether a token minted for a narrow purpose — a partial-auth token issued mid-MFA, a password-reset session — is accepted by an endpoint outside that purpose, by presenting it where a full session would normally be expected.
7. Token exposure sweep: check whether the token appears in a URL that later gets linked out to a third-party resource (Referer leakage), and whether anything client-side-readable is also reachable by third-party embedded scripts on the same page.
8. CSRF adjacency (WSTG-SESS-05): for a cookie-based session, check for a CSRF token on state-changing requests, and note explicitly if `SameSite` alone is the only defense present — record this as its own test case rather than folding it into the session-lifecycle findings above.
9. Dual-mechanism drift: where two session-like tokens coexist, run the rotation and invalidation checks (steps 2 and 3) against each independently — a fix applied to one is not evidence the other received the same fix.
10. Entropy sanity check: for an opaque token, request several fresh sessions across logins and eyeball length and character-set consistency; a token that's short, fixed-length in an unusual way, or reused a visible substring across sessions is worth flagging even without fully modeling its generation.

## Evidence to capture
- The pre-login and post-login session value side by side, with timestamps, showing whether it changed.
- The full raw request and response of any successful post-logout or post-rotation replay — the actual returned data, not a description of "it still worked."
- The Set-Cookie header exactly as received, for every session-bearing cookie, showing the attribute set.
- The decoded (not modified) JWT payload relevant to an expiry or puzzling test, with the specific claim that mattered.
- For puzzling, the narrow-purpose token used and the unrelated endpoint's full response showing it was accepted.
- For dual-mechanism apps, both tokens' rotation/invalidation results side by side, showing which one lagged.
- Several fresh token samples together, if entropy is in question, with enough of each preserved to demonstrate the pattern without needing to paste every character of a live, still-valid value.

## Escalation
- Fixation combined with any feature that lets a session identifier be handed to someone else (a shareable login link, an embeddable auth flow) escalates toward account takeover — demonstrate this only across your own two identities, and describe the realistic delivery mechanism rather than asserting it against a real victim.
- Non-invalidation after logout is most consequential when paired with a believable way an old token becomes accessible later (a shared or public machine, browser history, a cached request) — walk the report through that path instead of stopping at "logout doesn't invalidate."
- Session puzzling that lets a narrow-purpose token reach a sensitive endpoint is a BFLA-flavored finding — cross-reference `pb-broken-access-control` and, if the endpoint is a JSON API accepting extra fields once reached, `pb-mass-assignment`.
- Bank a confirmed "old token still works after X" result as a primitive via `add_primitive` even before you've found a realistic way an attacker would obtain that old token — the capability is worth keeping on its own.
- Dual-mechanism drift where the legacy token never rotates is worth more once you show the legacy token alone is still sufficient to authenticate — a lagging mechanism that's no longer actually accepted anywhere is a design leftover, not a live gap.
- A confirmed low-entropy or patterned token escalates once a second sample from a different account shows the same pattern — one sample is an observation, two independent confirmations make it a primitive worth banking.

## Out-of-scope traps
- `SameSite=Lax` without `HttpOnly`/`Secure` is common and frequently not independently rewarded — check whether the program treats missing cookie flags as informative before reporting flags alone as the finding.
- A long "remember me" expiry (e.g. 30 days) is often an explicit design choice — verify against program policy before framing long-but-intentional expiry as a bug by itself.
- "Logout doesn't instantly clear client-side storage" is a UI/cosmetic observation, not server-side non-invalidation — always confirm with a replayed server request before claiming the token is still live.
- Fixation and hijack testing must stay within your own two test identities; never attempt to predict, intercept, or guess a real user's session token.
- A JWT with no `exp` claim isn't automatically a bug if the server maintains a separate server-side revocation/allow-list — check for that mechanism before assuming the token is the sole source of truth on validity.
- A legacy token mechanism that's issued but never actually checked by any live endpoint (dead code path) isn't a session-management bug — confirm the token is genuinely still accepted somewhere before reporting drift between two mechanisms.
- Two tokens with different formats isn't automatically "dual mechanism drift" — confirm both are actually independently sufficient to authenticate before treating the difference as a gap rather than intentional layering (e.g., a short-lived access token plus a separate, more tightly controlled refresh token).

## Integration
Record each lifecycle check with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, using test_case_ids like `session-fixation`, `logout-invalidation`, `token-rotation-on-pwchange`, or `session-puzzling` — mark a clean rotation/invalidation check `not-vulnerable` so `bb-next` stops re-suggesting it. A confirmed-but-not-yet-impactful capability (a token that survives logout, a puzzling acceptance) goes in via `mcp__bb__add_primitive`; a hypothesis you haven't tested yet (this fixation could combine with the referral-link feature) goes in via `mcp__bb__add_lead`, referencing the supporting notes. The assistant proposes what to capture and compare; it never asserts a finding is confirmed — only the human, after independent reproduction, calls `mcp__bb__promote_to_finding(..., human_confirmed=True)`.
