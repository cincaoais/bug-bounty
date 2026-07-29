---
name: pb-broken-access-control
description: Methodology playbook for finding function-level and vertical broken access control on a real target. Load when testing role boundaries or when bb-next surfaces a privilege test case.
---

# pb-broken-access-control

## When this applies
Any point where the application distinguishes what a user is *allowed to do* by role, plan tier, or feature flag — rather than which specific object they own, which is what separates this from `pb-idor-bola`. Candidates:
- Admin panels, staff-only routes, moderation actions.
- Billing/plan-gated features (a paid capability behind a free account).
- Internal-only APIs that happen to share infrastructure with the public API surface.
- Multi-role apps: owner/editor/viewer, tenant-admin/tenant-user.
- Any UI where a menu item or button is hidden for your role but the underlying route might still exist.
- Support/back-office tooling that shares the same API gateway as the customer-facing product, since it's easy for a shared gateway to apply one broad authentication check without a matching per-audience authorization check.

Covers WSTG-ATHZ-02 (authorization schema bypass) and WSTG-ATHZ-03 (privilege escalation).

## First signals
- A UI element (button, nav link, settings page) that's absent or disabled for your current role — the absence of a *link* tells you nothing about whether the *route* is absent.
- Route or API paths with role-suggestive naming even if you never saw them linked: `/admin/*`, `/internal/*`, `/staff/*`, `/_internal/api/*`, `/manage/*`, versioned-but-undocumented API prefixes.
- JS bundles or mobile app binaries referencing route strings, feature flags, or role names your account doesn't currently have — client-side router configs and feature-flag tables often ship the full map regardless of who's logged in.
- A multi-step admin action where only the *first* step (loading the admin dashboard shell) is protected, and subsequent AJAX calls it fires are separately-routed endpoints that might not re-check the role.
- Inconsistent enforcement across HTTP methods on the same path — GET is checked but PUT/PATCH/DELETE on the identical resource path isn't, or vice versa.
- A "downgrade" flow (cancel subscription, remove a team member's role) that's checked carefully, while the matching "upgrade"/"grant" flow in the same feature area isn't — developers reason hard about the dangerous direction and forget the other.
- A recently-shipped feature (visible in a changelog, release notes, or a JS chunk with a fresh hash) sitting next to a much older, well-tested part of the app — new code is where access-control regressions concentrate, since the older surface has already absorbed a round of scrutiny.
- Any place a role or permission is read from a client-controlled source: a JWT claim the app merely decodes without verifying signature/audience, a hidden form field, a cookie value, a query parameter (`?role=admin`, `?debug=true`).
- A feature-flag or A/B-test header/cookie (`X-Feature-Flag`, `beta=true`) that toggles visible UI — these are frequently wired straight through to gate backend functionality too, on the assumption that only the flagging system would ever set them.
- An API version difference: a newer `/v2/` endpoint enforcing a check that an older, still-live `/v1/` equivalent never got updated to include.

## Enumeration
1. Build a role matrix first. List every distinct role/tier the app defines — check the signup flow, billing plans, and team-invite dialogs, not just what your test accounts happen to have.
   - Ask the user to provision at least two roles if the program allows it; the enumeration is weak with only one.
2. For each role, walk the UI once and record every route, button, and API call it triggers.
   - Diff the route lists across roles: anything present for a higher role becomes a candidate to forced-browse as a lower role.
3. Extract routes from client-side artifacts:
   - JS bundle route tables and source maps, if present.
   - Mobile app strings or decompiled resources.
   - OpenAPI/Swagger docs even if not linked from the UI.
   - GraphQL introspection if enabled.
   - This surfaces routes never rendered for any role you were actually given.
4. For every privileged action found, enumerate its full verb set (GET/POST/PUT/PATCH/DELETE) against the same path — don't assume the verb you observed is the only one implemented.
5. List every place a role/permission claim could be client-supplied (JWT payload, cookie, hidden field, header) versus server-derived (looked up from session/DB). The client-supplied ones are the highest-value candidates.
6. Coverage is exhausted when every distinct privileged action has been attempted from every lower role you have access to, across every verb it implements, and every client-controlled role signal has been identified and tried at least once in its tampered form.
7. Note which checks are enforced by a shared middleware/decorator versus implemented ad hoc per handler, where the code or docs make this visible — an app that centralizes authorization is a different risk profile from one that re-implements the check per route, and it tells you whether one confirmed gap likely generalizes or is a one-off.

## Test procedure
1. As the lower-privilege account, forced-browse directly to the higher-privilege route or API path using the exact path found in enumeration — don't rely on the UI ever linking there.
2. If direct access is denied, retry with the HTTP method varied.
   - If you found the action as POST, also try GET/PUT/PATCH/DELETE on the identical path.
   - Trailing-slash, case, and path-alias variants are worth one pass as a check on the routing layer's consistency, not as an evasion technique.
3. For a client-supplied role/permission signal, change your own account's value to the higher role's value and resend, watching for a difference in the *response content*, not just the absence of an error page.
4. For a multi-step admin flow, isolate whether each individual backend call is checked, not just the entry page.
   - Load the entry page as the low-privilege account if it happens to render, then replay each subsequent action call directly.
5. Confirm the negative control: verify the lower-privilege account is properly denied on at least one *other* known-restricted action, so the report shows this endpoint is the exception, not evidence the whole app has no access control.
6. For vertical checks, test both directions once you've confirmed one: if a viewer can reach an editor action, also check whether an editor can reach an owner-only action. Role boundaries are rarely implemented with uniform rigor across every tier.
7. Where a feature is plan/tier-gated rather than role-gated, the same procedure applies: forced-browse the paid route/API on the free account and check whether the response contains the gated functionality or data, not just whether the UI hides the upsell.
8. If the app exposes a "switch workspace/organization" mechanism, test whether the current role is re-evaluated per workspace or cached from the first one selected in the session — a role check that only runs once at login can be stale for the rest of the session.

### Worked example
```
UI as viewer role: no "Delete Project" button rendered.
Forced browse:  DELETE /api/v2/projects/881  (as viewer's session)
Result:         204 No Content
Confirm:        GET /api/v2/projects/881 (as owner) -> 404, project is gone
```
The 204 alone is suggestive; the follow-up GET as the owner proving the project is actually gone is what turns "I got a success status" into "the privileged action executed."

## Evidence to capture
- The exact role/plan of the account used, and how it was provisioned (signup, invite, downgrade) so the triager can reproduce the starting state.
- The full request that reached the privileged action, and the response proving the action executed or the data returned — a 200 status alone is not proof; show the effect (record created/modified, privileged data present in body).
- The client-supplied value that was changed, if applicable: which claim/field/cookie, the old value, and the new value. Never paste a real admin's token if one was ever observed; show only your own tampered value.
- The negative control result: a comparable restricted action from the same account correctly denied, to preempt "your test account might just be misconfigured."
- If found via a client-side artifact, the specific file/route reference and how it was located — that alone tells the triager where to look for the missing check.
- Which verbs/paths were tried and correctly denied alongside the one that wasn't — this scopes the fix for the program and shows the testing was systematic rather than a single lucky guess.

## Escalation
- A read-only broken function-level check (viewing admin data) escalates when paired with a mutating sibling on the same route family (editing/deleting) — check whether the write side has the identical gap.
- Privilege escalation from the lowest tier straight to full admin is higher severity than viewer-to-editor. State which boundary was actually crossed rather than calling everything "privilege escalation" generically.
- If the client-supplied role signal is a JWT or signed token whose signature isn't actually verified, that's a broader primitive than one endpoint. Bank it (`add_primitive`), then probe a second, unrelated privileged route with the same tampered token before concluding scope.
- Combine with `pb-idor-bola` when the privileged function also takes an object ID: an admin "edit any user" function reachable by a normal user is both a vertical and object-level break — describe the actual blast radius (which users, which fields), not just "I reached the endpoint."
- A single reachable admin action that also exposes a way to grant further roles (promote another account to admin) escalates from a one-off bypass to a durable foothold — note explicitly whether the reached function can create persistence, since that changes remediation urgency.
- If the reachable function operates across tenants/organizations in a multi-tenant app, state that explicitly and separately from a same-tenant privilege jump — cross-tenant impact is usually the largest severity multiplier available in this class.

## Out-of-scope traps
- A hidden UI element with no corresponding server-side gap is a UX/design nit, not broken access control — it's only a finding once forced browsing shows the *server* doesn't check either.
- A staff-only route that returns generic, non-sensitive content (a static shell with no live data or actions) when forced-browsed is a low-value or Informative finding. Separate "I reached a URL" from "I reached functionality or data."
- Read the program's policy for excluded classes before reporting: many programs explicitly exclude missing security headers, clickjacking on non-sensitive pages, and sometimes self-XSS — check these don't overlap with what looks like an access-control finding.
- Accounts you were issued *specifically* to test staff features (a program-provided admin test account) are working as intended when they reach admin routes — verify your account's intended tier before reporting cross-tier access as a bug.
- A CORS misconfiguration or missing rate limit is a different class. Don't fold it into a broken-access-control report just because it was noticed along the way — note it separately.
- An error message that differs between "route doesn't exist" and "route exists but denied" (404 vs. 403) is reconnaissance, not itself an access-control finding — it earns a note, not a report.
- A route reachable only through a deliberately-shared, time-boxed internal tool (a support-issued temporary access link, a staging environment with different auth) may be intended internal tooling rather than a public-facing gap — confirm which environment/host you're actually on before reporting.
- Don't conflate "the button was easy to unhide with dev tools" with "access control is broken" in the write-up's framing — lead with what the server allowed, not with how trivial the client-side step was.

## Integration
- Log every attempted route/verb/role combination with `mcp__bb__record_coverage`, including the ones correctly denied — a clean result on a privileged route matters just as much for future sessions, since it stops the route being re-suggested.
- A tampered token or unverified-signature capability that isn't yet tied to a specific bug goes in as a primitive via `mcp__bb__add_primitive` so it can be tried against other routes later without re-discovering it.
- The assistant enumerates roles and routes and proposes what to forced-browse; the human sends every request and confirms whether the response actually contains privileged functionality or data before anything is called a finding.
