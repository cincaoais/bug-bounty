---
name: pb-mass-assignment
description: Methodology playbook for finding mass assignment / object-property injection on a real target. Load when testing a JSON API that binds request bodies to objects, or when bb-next surfaces a mass-assignment test case.
---

# pb-mass-assignment

## When this applies
Any endpoint that creates or updates an object by binding a request body more or less directly to a server-side model rather than to an explicit, narrow field list: profile updates, cart/order updates, resource creation (comment, post, listing), account settings, org/team membership changes, and admin-adjacent object edits reachable from a normal-user context. The tell isn't the endpoint's name, it's the binding style — this is about whether the server accepts fields the form never shows, which is a different question from whether the server checks *who owns* the object. When the field in question is an ownership/role field and binding it changes access, the finding sits on the boundary with `pb-broken-access-control` and `pb-idor-bola`; that overlap is expected, not a sign you've picked the wrong playbook. Closest anchors: WSTG-BUSL-01 (business logic data validation) and WSTG-BUSL-03 (integrity checks on business-critical data); the class itself is best known outside WSTG as OWASP API Security's Broken Object Property Level Authorization (mass assignment).

## First signals
Notice these before you know whether binding is happening:
- A JSON API that echoes a full object (a GET, or the body of a create/update response) containing fields the UI never exposes for editing — `role`, `is_admin`, `verified`, `status`, `price`, `owner_id`, `balance`, `plan`, `permissions`, `org_id`.
- An update endpoint that accepts what looks like a full object body rather than a small, named set of fields — the extra keys you can see in a GET are syntactically valid siblings in the same shape the PATCH/PUT already accepts.
- A nested payload (`{"user": {...}, "address": {...}}`) — nested binding is where a privileged sibling field most often hides, because it's easy for a developer to whitelist top-level keys and forget the nested object is bound wholesale.
- A framework or stack known for this pattern by default: naive `.update(req.body)`-style calls in Node ORMs, a Django REST Framework serializer with a broad field set, older Rails models without an explicit permitted-params list, a Spring `@RequestBody` bound straight onto a JPA entity. Recognizing the stack narrows where to look; it isn't proof of anything by itself.
- An admin-only endpoint for the same object type as a general-user one — the admin view's field set is a strong hint at what fields exist on the model even when the general-user endpoint's response hides them.
- A GraphQL mutation whose `input` type (visible via introspection or schema mining) carries more fields than the client's own form ever populates — the same class, reached through `pb-graphql-abuse`'s enumeration instead of a REST body.
- An OpenAPI/Swagger schema, changelog, or SDK type definition that documents a field the current UI has since removed or never shipped — deprecated-looking fields are frequently still bound server-side.

Common field categories worth prioritizing, roughly in order of impact if bound:

| Field category | Example names | Impact if bound |
|---|---|---|
| Role / permission | `role`, `is_admin`, `permissions`, `scopes` | Privilege escalation |
| Ownership | `owner_id`, `user_id`, `org_id`, `created_by` | Write-side IDOR/BOLA |
| Financial | `price`, `balance`, `quantity`, `discount` | Financial/business-logic impact |
| Status / workflow | `verified`, `status`, `is_active`, `approved` | Workflow bypass |

## Enumeration
1. List every state-changing JSON/form endpoint on the target: signup, profile update, checkout/cart update, resource create (post, comment, listing), invite/membership update, integration/webhook settings.
2. For each, capture the full field set visible from a read (a GET, or the body of a create response) — this is the candidate list of fields to try as additions on write.
3. Note the auth context per endpoint: is it operating on "my own" object, and does that object also carry fields that aren't really "mine" to set (a role or balance column sitting on the same row as my profile)?
4. Identify sibling admin routes for the same object type (`/admin/users/{id}` next to `/users/me`) — even without access to call the admin route, its documented or observed field set tells you what to test for on the general-user route.
5. Coverage is exhausted once every state-changing endpoint has a recorded field-by-field result for every privileged-looking field visible anywhere for that object type — a single "tried role, got rejected" test does not clear an endpoint that also exposes `owner_id`, `verified`, or a nested sub-object with its own fields.

## Test procedure
1. Capture a baseline: perform the normal update through the UI/form once and record the exact request body sent.
2. Build the candidate field list from enumeration — every field seen on a GET, an admin view, API docs, or a JS bundle's generated types that isn't in the baseline body.
3. Additive-field test: resend the baseline request with exactly one candidate field appended, using a value that would be observably different from the current state if it actually bound (e.g., toggling a boolean-shaped field, or setting an enum field to a different valid value already used elsewhere in the app) — one field per request, so causality is unambiguous.
4. Read-back confirmation: after each attempt, re-fetch the object (or check the update response if it echoes the full object) and confirm whether the field's value actually changed server-side. A 200 response proves nothing on its own — the state has to be shown to have moved.
5. Nested-object variant: for a nested payload shape, try the candidate field at each plausible nesting level, since frameworks commonly whitelist top-level keys but deep-merge nested ones without the same check (or the reverse).
6. Ownership-field test: specifically try `user_id`, `owner_id`, `org_id`, or `created_by` on any create endpoint — binding one of these lets an object be attributed to someone else, which turns mass assignment directly into an access-control primitive.
7. Casing/shape variant, used sparingly: if a direct field name is ignored, try the same field with different casing or as an array/object wrapper only where a known framework binding quirk (not a guess) makes that a realistic developer oversight — this is still testing the binding mechanism, not broad fuzzing.
8. Revert cleanly: once a field is confirmed to bind, restore its original value immediately through the same mechanism, and only ever on an object you own.
9. Status/workflow-field test: try transition-only fields (`verified`, `approved`, `status`) directly on the update body rather than through whatever workflow action is supposed to set them — a bound status field lets you skip an approval or verification step entirely.
10. Cross-check via the create path: if the object type also has a create endpoint, retry the same candidate fields there — creation code paths are frequently newer or less reviewed than the update path for the same object, and a field ignored on update sometimes still binds on create.

## Evidence to capture
- The baseline request (legitimate fields only) and the modified request (baseline plus one added field), shown side by side.
- The read-back response proving the field's value before and after — this, not the write response's status code, is what proves binding occurred.
- Where the field name was learned (a GET response, an admin view, API docs, a JS bundle's type definitions) — this supports the argument that the field was never meant to be user-writable.
- Any server error that leaks the underlying binding mechanism (an ORM/ODM validation message naming the field) even on an attempt that failed — it confirms direct-binding architecture regardless of that one field's outcome.
- For a status/workflow field, the request/response pair that shows the object reaching the target state, plus what the legitimate workflow action normally requires to get there (an approval click, a second party's confirmation) that was skipped.
- For a create-vs-update discrepancy, both endpoints' results for the identical field side by side.

## Escalation
- A bound `role`, `is_admin`, or `permissions` field is direct privilege escalation — confirm it by reaching something the elevated role now unlocks, not by stopping at "the field changed." Cross-reference `pb-broken-access-control` for how to demonstrate the unlocked functionality concretely.
- A bound `price`, `balance`, or `quantity` field on an order or payment object needs the actual transaction outcome checked (amount charged, credited balance), not just a display value, before it counts as financial impact.
- A bound `owner_id` or `org_id` field is a write-side IDOR/BOLA primitive — reassigning ownership of an object you shouldn't control is the same class as `pb-idor-bola`, viewed from the write direction; describe it under whichever primitive is actually broken.
- Even a field that binds with no visible effect yet is worth banking as a primitive via `add_primitive` — "this endpoint persists `internal_notes` even though the form never sends it" may combine with something found later on a different endpoint of the same object type.
- A bound `verified`/`approved` status field escalates once you show what it actually unlocks downstream (a listing goes live, a payout is released) rather than stopping at "the flag flipped."
- The same field bindable through both REST and GraphQL surfaces for one object type is a stronger, more portable finding than either alone — worth explicitly noting that both paths share the same underlying gap.

## Out-of-scope traps
- A field accepted in the request but silently dropped or overwritten server-side (many frameworks re-set canonical fields after save) is not a finding — always do the read-back check before claiming a bind succeeded.
- Testing must stay on an object you own end to end; touching a shared or another real user's object to "prove" binding is out of scope regardless of the technique.
- A field that binds but only through an endpoint that already requires admin-level auth to reach isn't privilege escalation — confirm the auth context is genuinely lower-privileged before framing it that way.
- Some public/versioned APIs explicitly document "unrecognized fields are ignored" — check documented behavior before assuming an accepted extra field is unintended.
- Changing your own non-privileged fields (display name, bio, avatar) isn't a finding by itself — the interesting field set is specifically privilege, ownership, and financial attributes.
- A status field that binds but is re-validated at the point of actual consequence (e.g., a `verified` flag flips, but the payout process independently re-checks verification from its own source) doesn't carry the impact the flipped flag suggests — trace to the point of real consequence before claiming it.
- A field visible in old API documentation or a deprecated SDK version that the current live schema no longer defines isn't evidence of anything — confirm the field is present in the schema actually served today before testing it.

## Integration
Record each field tested as its own coverage entry via `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, using test_case_ids like `mass-assign-role`, `mass-assign-owner-id`, or `mass-assign-price` per endpoint, so a clean result on one field doesn't hide an untested one on the same route. A field confirmed to bind with unclear impact still goes in via `mcp__bb__add_primitive` — "endpoint X binds arbitrary top-level fields on the user object" is the reusable capability this system is built to keep, since it applies to every field discovered on that endpoint later. Note the overlap with `pb-broken-access-control` explicitly whenever a bound field is ownership- or permission-related, rather than letting the correlation go unrecorded. The assistant reports what bound and what the read-back showed; only the human, after independent reproduction, calls `mcp__bb__promote_to_finding(..., human_confirmed=True)`.
