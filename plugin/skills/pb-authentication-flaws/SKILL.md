---
name: pb-authentication-flaws
description: Methodology playbook for finding authentication flaws (login, registration, password reset, MFA) on a real target. Load when testing auth flows or when bb-next surfaces an authentication test case.
---

# pb-authentication-flaws

## When this applies
Any flow that establishes or re-establishes who the caller is: login, registration/signup, password reset ("forgot password"), password change, MFA enrollment and verification, "remember me"/persistent login, account-recovery via security questions, SSO/social-login fallback, and any alternate channel that authenticates the same identity differently (mobile app API, legacy endpoint, partner integration). This is about proving *who you are*, not what a given session token is worth afterward — token lifecycle, fixation, and logout belong to `pb-session-management`, which usually starts exactly where this playbook ends. Covers WSTG-ATHN-01 through ATHN-10, plus WSTG-IDNT-02 (registration abuse) and WSTG-IDNT-04 (account enumeration).

## First signals
Notice these before you've formed any hypothesis about a bug:
- A password-reset link or code whose structure looks short, sequential, timestamp-derived, or otherwise patterned rather than a long opaque random value.
- The reset token appearing somewhere beyond the single email/SMS it should live in — a URL you can see in a Referer header, an analytics/tracking pixel request, or an API response body that echoes it back.
- Any measurable difference between "this identifier exists" and "this identifier doesn't" across login, registration, and password-reset endpoints — a different status code, a different error string, a different response time class, an extra field in the body.
- A login form with no visible lockout, CAPTCHA, or backoff after several wrong attempts on your own test account — an *observation* about exposure, not an invitation to run a credential list against it.
- MFA state expressed as something the client reads and acts on (`"mfa_required": true` in a JSON body, a query parameter, a client-side redirect) rather than the server simply refusing to issue a usable session until the second factor is verified.
- A "trust this device" or "remember me for N days" cookie set at a point in the flow that precedes MFA verification.
- A mobile-app or legacy API version of login/registration that appears to enforce a visibly weaker policy (no MFA prompt, no lockout, different password rules) than the primary web flow — WSTG-ATHN-10.
- An "email verification pending" account state that still lets you call authenticated endpoints directly, before the verification link is ever clicked.
- A password-change form that doesn't ask for the current password — it widens the blast radius of any adjacent session-fixation or CSRF gap on that same action.

Quick map of where flaws cluster by flow, for triage when time is short:

| Flow | Where flaws typically cluster | WSTG |
|---|---|---|
| Login | Missing/weak lockout, alternate-channel weaker policy | WSTG-ATHN-03, ATHN-10 |
| Password reset | Predictable/reused/leaked token | WSTG-ATHN-09 |
| Registration | Enumeration oracle, unexpected bound fields | WSTG-IDNT-02, IDNT-04 |
| MFA | Flow-order skip, client-asserted state | WSTG-ATHN-04 |
| Recovery Q&A | Small answer space, no rate limit | WSTG-ATHN-08 |
| Remember-me / trust-device | Issued before second factor completes | WSTG-ATHN-05 |

## Enumeration
1. List every credential-related endpoint on the target: login, logout, register, request-reset, confirm-reset, change-password, MFA-enroll, MFA-verify, MFA-recovery-code redemption, "resend code," "resend verification email," SSO callback.
2. For each, record what identifier it accepts (email, username, phone), what it returns, and whether a rate-limit or lockout behavior is visible at all.
3. Enumerate every MFA method the app offers (TOTP, SMS, email code, push, backup/recovery codes) — each is a separately implemented surface and rarely shares identical protections with the others.
4. Pull auth-adjacent routes out of client-side artifacts: JS bundle route tables, mobile app strings, or an older API version (`/v1/login` beside `/v2/login`) that may still be live and less carefully maintained.
5. Note where password-reset and MFA-recovery intersect account-recovery as a whole — a "lost your MFA device" path is often a second, less-scrutinized authentication bypass built to handle the first one failing.
6. Coverage is exhausted once every credential endpoint and every MFA method has at least one recorded observation for token structure/leakage, enumeration differencing, lockout behavior, and flow-order enforcement — an untouched MFA method or a never-tried alternate channel is still open surface, even if the primary web login looks solid.

## Test procedure
1. Reset-token analysis (WSTG-ATHN-09): request two reset tokens for your own test account a short time apart and compare structure — length, character set, whether it decodes as a JWT (inspect the header/payload only, never forge a signature), and whether it resembles a timestamp or counter. Then confirm single-use: complete a reset with the link, and try reusing the identical link a second time.
2. Reset-token leakage sweep: check the reset-confirmation page for outbound requests (analytics, third-party embeds) that could carry the token in a Referer header, and check whether the token shows up anywhere in a response body beyond the one flow that's supposed to consume it.
3. Account-enumeration differencing (WSTG-IDNT-04): submit one known-valid identifier and one clearly-invalid one to registration, login, and password-reset, and diff status code, body wording, header set, and rough response-time class. A handful of paired comparisons is enough to characterize the behavior — this isn't a list-based sweep.
4. Lockout/backoff observation (WSTG-ATHN-03): on your own test account only, submit a small number of deliberately wrong credentials and note whether/when a lockout, delay, or CAPTCHA appears. This characterizes credential-stuffing exposure as an observation about the defense's presence — it stops there, it is not a spray against real accounts, and it never targets an identifier you don't control.
5. MFA short-circuit: after correctly authenticating the password step on a test account with MFA enabled, attempt to call a downstream authenticated endpoint directly, before completing MFA, using whatever session/token was issued at that intermediate stage — check whether it's already accepted.
6. MFA state-trust check: inspect whether the "MFA still required" state is something the client asserts (a boolean the frontend chooses to honor) versus something the server itself blocks on every subsequent request regardless of what the client claims.
7. Persistent-login/device-trust replay: if a "remember me" or "trust this device" cookie is issued, check when in the flow it's set (before or after MFA) and whether it authenticates a session on its own without re-prompting for the second factor.
8. Registration abuse (WSTG-IDNT-02): check whether the registration endpoint accepts fields beyond the ones the form exposes — a role, verification-status, or plan field submitted alongside the legitimate ones is a mass-assignment question; hand it to `pb-mass-assignment` if the field appears to bind.
9. Recovery-question weakness (WSTG-ATHN-08): if security questions exist, note the answer space size and whether attempts against them are rate-limited the same way the main login is.
10. Pre-verification access check: on a freshly registered, not-yet-email-verified account, attempt an authenticated action that should logically require verification first — note exactly what is and isn't gated on that status.
11. Alternate-channel parity check: replay the lockout/backoff and password-policy observations from step 4 against any mobile or legacy endpoint found in enumeration, since a weaker policy there (WSTG-ATHN-10) is a separate, independently reportable gap even if the primary web flow is solid.

## Evidence to capture
- Both branches of every enumeration diff (valid vs. invalid identifier), with full request/response pairs, not a paraphrase of the difference.
- Multiple reset tokens for your own account, with timestamps, showing the pattern across requests — redact the live value before it leaves your own notes, but keep the raw evidence to demonstrate structure.
- The exact response, header, or timing behavior that shows lockout is present or absent after a small, bounded number of attempts on your own account.
- The specific field or response that proves MFA state is client-asserted rather than server-enforced, and the actual authenticated response reached when MFA was skipped.
- The full request/response for any accepted-but-unexpected registration field, plus a read-back proving it actually bound server-side.
- The exact endpoint and response reached from a not-yet-verified account, showing whether verification status actually gated anything.
- For alternate-channel parity findings, the two responses (primary flow vs. alternate) side by side under otherwise identical inputs.

## Escalation
- A predictable or reused reset token only becomes account takeover once you show it actually yields a usable authenticated session — confirm the full chain rather than stopping at "the token looks weak."
- An enumeration oracle on password-reset is more consequential than the same oracle on login or registration alone, since it directly supports targeted account-recovery abuse; note this distinction in how you frame severity.
- An MFA short-circuit that reaches a genuinely authenticated endpoint is the strongest primitive here — bank it via `add_primitive` immediately, even before you've mapped everything it unlocks.
- A weak reset flow paired with a mass-assignment gap on the same registration/profile endpoint (`pb-mass-assignment`) is a realistic, higher-severity chain: recover access cheaply, then escalate role on arrival.
- Once any auth flow issues a session, hand off session-lifecycle questions (does it rotate, does logout kill it) to `pb-session-management` rather than re-deriving that methodology here.
- Pre-verification access to authenticated functionality escalates fastest when the reachable action itself has real consequence (placing an order, sending a message as that identity) rather than a harmless read.
- A weaker alternate-channel policy is worth more once you show it reaches the same underlying account and data as the primary channel — confirm both channels operate on the same backend identity before framing it as a bypass rather than a separate, lower-stakes surface.

## Out-of-scope traps
- Username/email enumeration alone is frequently accepted risk on bug bounty programs — check the program's policy and disclosed-report history before writing it up standalone; it's stronger paired with reset-flow leakage or a missing lockout than reported alone.
- Missing CAPTCHA or no visible rate limit is commonly excluded by programs as a design tradeoff — check `bb-scope`-captured exclusion notes before treating it as the finding itself rather than supporting context.
- Weak password-complexity policy alone (no digit required, short minimum length) is usually informative-only; don't lead a report with it.
- Any lockout/backoff observation must stay confined to your own test account — never run repeated auth attempts against an identifier that isn't yours, even to "confirm" the same behavior.
- Testing reset-link expiry needs enough real elapsed time to be conclusive; a token that still works after five minutes says nothing about a policy that claims 24-hour expiry.
- MFA bypass and reset-token attacks need to actually reach another identity's session or data to count as cross-user impact — reaching your own account through an unintended path is a weaker, self-inflicted result.
- A "verification pending" gap that only exposes the new account's own, still-empty data isn't impactful by itself — it matters once it reaches something with real consequence, or lets an unverified identity act on someone else's data.
- Some programs provide pre-verified or pre-provisioned test accounts specifically so testers don't have to exercise the registration flow — check whether that's the case here before treating registration-stage behavior as representative of the real onboarding flow.

## Integration
Record every attempted check with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, using test_case_ids like `reset-token-predictability`, `mfa-flow-skip`, or `enum-password-reset` — a clean result matters as much as a hit, since it stops the same flow being re-suggested by `bb-next`. Bank any confirmed-but-not-yet-impactful capability (MFA state read from a client-visible field, an accepted extra registration field) with `mcp__bb__add_primitive` before you know what it chains into, and file a hypothesis you haven't tested yet as a lead via `mcp__bb__add_lead`. The assistant proposes what to try and reads the evidence back; it never claims a finding is real — only the human, after independently reproducing the chain, calls `mcp__bb__promote_to_finding(..., human_confirmed=True)`.
