---
name: pb-idor-bola
description: Methodology playbook for finding IDOR/BOLA on a real target. Load when testing object-level authorization or when bb-next surfaces an IDOR test case.
---

# pb-idor-bola

## When this applies
Any endpoint that takes an object reference and returns or mutates data scoped to a specific owner:
- `/orders/{id}`, `/api/users/{id}/profile`, `?invoice=1042`, `/messages/{uuid}/attachment`.
- GraphQL fields resolved by a node ID.
- A WebSocket message carrying a resource ID in its payload.

The shape is "the client names which object it wants." The question is whether the server checks that the caller is allowed to have *that specific object*, not just that the caller is authenticated at all.

Covers WSTG-ATHZ-04 (IDOR) and overlaps WSTG-ATHZ-02 (authorization schema bypass) whenever the object is scoped by role rather than pure ownership.

## First signals
Notice these before you've formed any hypothesis about a bug:
- An ID in the URL, query string, request body, or a hidden form field that looks sequential, incremental, or otherwise guessable (`1042`, `ORD-00981`) rather than opaque.
- Even a UUID isn't automatically safe. Check whether it was *disclosed* somewhere you can read: another list endpoint, a "shared with" feature, an export, a webhook payload, a PDF's metadata, a support-ticket reference visible cross-account.
- Two near-identical endpoints where one is GET (read) and a sibling is POST/PUT/DELETE (mutate) on the same object shape. Access-control code often gets duplicated per-route instead of centralized, so the two rarely get equal attention.
- A response that includes an object reference you didn't ask for — a nested `owner_id`, a `related_invoice_id`, a `next`/`prev` pagination link pointing at a neighboring record.
- Multi-tenant apps: any endpoint that doesn't visibly scope by tenant/org/workspace ID in addition to the object ID.
- A mobile app or SPA that fetches by ID client-side after an initial list call — the list call might be properly scoped while the by-ID fetch is not.
- File and media endpoints (`/download/{id}`, `/attachments/{id}.pdf`, S3-style presigned-looking paths that aren't actually signed) — these get overlooked because they don't look like "API" traffic, but they're object references like any other.
- A "duplicate" or "clone" action that takes a source object ID as input — cloning frequently reuses the same fetch code path as viewing, so a missing check here mirrors a missing check on the view endpoint, but the two are rarely tested together.

## Enumeration
Map every place an object reference appears before testing any single one. This is a mapping pass, not a testing pass — resist the urge to fire a swap the moment you spot the first candidate ID; a partial map means you'll re-discover the same object type from a different route next week and re-test it from scratch.

1. Walk the whole authenticated app once as your own account and log every URL/param/body-field carrying an ID — spreadsheet or notes, not memory.
   - Include IDs in headers (`X-Resource-Id`) and JSON bodies, not just path segments.
2. Group by object *type* (order, invoice, message, user, document), not by endpoint.
   - The same object type reachable through five routes (web UI, mobile API, export, webhook config, admin-lite panel) needs the ownership check verified on each route independently — a fix on one route rarely propagates to the others.
3. For each object type, note the ID format:
   - Sequential integer or ULID → enumerable by adjacency.
   - Opaque but disclosed elsewhere → enumerable by harvesting IDs from other pages.
   - Opaque and never disclosed → still worth one confirmed test, since front-end code sometimes leaks IDs a UI never displays.
4. Check both directions of every relationship: if a user can list *their* orders, is there a corresponding "list all" or internal-scope route that takes the same ID shape with a weaker check?
5. Note pagination and search/filter endpoints separately — a filter parameter like `?user_id=` or `?account=` on a list endpoint is an object reference too, even though it doesn't look like the usual `/resource/{id}` shape.
6. You've covered the surface when every distinct object type has at least one tested read endpoint and one tested mutating endpoint, across every route that exposes it — not when you've tried a handful of URLs that looked interesting.

## Test procedure
1. Get two authenticated sessions for two different, unrelated accounts (not admin vs. user — two ordinary peers, unless you're specifically testing vertical boundaries, which belongs in `pb-broken-access-control`).
2. As account A, create or locate an object you own and note its ID and the full baseline response (status, body, headers).
3. As account B, request that same object ID on the same endpoint and method, using auth B legitimately holds.
   - Compare status code, body shape, and body content against the baseline — not status code alone.
4. Repeat step 3 for every sibling route carrying that object type: list, detail, export, print/PDF, webhook-replay, "share"/"duplicate" actions.
   - A fix on the primary detail page is frequently absent on export/print variants.
5. For mutating endpoints, don't stop at a successful write — re-fetch the target object (or check account A's view) to confirm the write actually landed, rather than trusting a 200 status alone.
6. If the ID is sequential, test one adjacent ID (yours ±1) and one far-off ID, to rule out a coincidence where ±1 happens to belong to a seed/test account you also control.
7. Test object-reference-in-body separately from object-reference-in-path. Some frameworks enforce path-based authorization via middleware but leave a body-based reference (`{"invoice_id": 1042}` in a POST) unchecked.
   - The same distinction applies to query-string references and to references buried in a multipart form field — each is a separate code path in most frameworks, and each deserves its own test rather than assuming a pass on one implies a pass on the others.
8. If a plain object-ID swap is blocked, don't stop there:
   - Try wrapping the same ID in an array.
   - Try nesting it one level deeper in JSON.
   - Try the batch/bulk variant of the same endpoint — the per-item ownership check is a common place to be missing even when the single-item version has one.

### Worked example of the comparison
```
Baseline (account A, own object):
  GET /api/v1/invoices/4471  -> 200, body contains amount, line_items, billing_address

Test (account B, A's object ID):
  GET /api/v1/invoices/4471  -> 200, body contains the SAME amount/line_items/billing_address

Negative control (account B, an object that is genuinely not theirs by design,
e.g. a deleted or never-existing ID):
  GET /api/v1/invoices/999999 -> 404, body: {"error": "not found"}
```
The middle result is the finding — same status, same data, wrong account. The negative control is what proves the endpoint *can* deny access and simply isn't doing so for this object, which preempts "maybe it always returns 200" as a rebuttal.

## Evidence to capture
- Both accounts' identifiers (username/email or account ID — never real personal data if these are program-provided test accounts that happen to mix in real user data).
- The exact request (method, full URL, relevant headers, body) made as account B against account A's object.
- The full response: status code, headers, and enough body to prove which object's data came back — a field only account A's object would contain, not a guess.
- The baseline: what account B gets when correctly denied on a *different*, clearly-not-theirs object, so the report shows this endpoint behaves correctly except for this one case.
- Screenshots only if they add proof beyond the raw HTTP; the request/response pair is the actual evidence, not a screenshot of a browser tab.
- Store via `mcp__bb__store_evidence` — never paste account B's session token, or more of account A's real data than needed to demonstrate access.
- If the object type was tested across multiple sibling routes, capture at least one clear pass/fail pair per route rather than only the first route that confirmed the bug — the report is stronger for showing the pattern holds, and it tells the triager exactly which routes still need fixing.
- Timestamp of the test, and the tool used to send it (proxy, curl, raw HTTP client) — useful if the program's own logs need correlating during triage.

## Escalation
A single confirmed horizontal IDOR is often Low/Medium on its own. Turn it into higher impact by naming the primitive it grants, not by trying harder payloads on the same endpoint.
- Does the exposed object contain data that unlocks something else — an API key, a password-reset token, a recovery code, an internal email reused as a username elsewhere?
- Is the ID sequential, meaning the finding is "read any user's X," not "read one specific user's X"? That's the gap between Medium and mass-disclosure Critical, and demonstrating it only needs a *second* independent ID pair, not a full harvest.
- Does the same gap exist on the mutating sibling (delete/cancel/reassign), turning read-only disclosure into takeover or data destruction?
- Does the object contain enough personally identifying data (full name plus address plus partial payment info, for example) that the *class* of data itself changes the severity conversation, independent of how the access was gained?
- Chain with an admin/support panel: can you feed another user's ID into an admin-facing route whose check is weaker because it assumes only staff would ever reach it?
- Does the disclosed object let you pivot to a different object type — an order revealing a customer ID that's itself an unauthenticated-check-free reference on a separate `/customers/{id}` endpoint?
- If the target is multi-tenant, does the same access-control gap cross tenant boundaries as well as user boundaries within a tenant? Crossing a tenant boundary is usually the single biggest severity jump available in a SaaS program, since it implies exposure of an entire customer's data, not one user's.
- Bank each capability you find along the way as a primitive even before you know it chains — see Integration below.

## Out-of-scope traps
- A 403 whose body text differs from a normal-user 403 (custom message, different JSON key) but whose status and access behavior are identical is not a finding. Confirm the *data itself* is or isn't returned, not just the prose.
- Predictable IDs alone are not a vulnerability — the program cares whether authorization is missing, not that the ID is guessable. Don't report "IDs are sequential" as its own issue.
- Publicly-intended references (a public share link, a public listing, a support-article ID) are working as designed — check the feature's stated purpose before assuming any access is unauthorized.
- Objects you can access because you were legitimately granted them (shared/collaborated resources, org-wide visibility by design) are not IDOR — verify the app's actual sharing model first.
- Read the program's exclusions for "requires a second account we did not provide" — some programs require testing only with the accounts they issued.
- A soft-404 or generic error on someone else's object that leaks no data is not the same as a confirmed IDOR — don't round an ambiguous response up to "vulnerable."
- Rate-limiting or CAPTCHA appearing after many rapid ID guesses is not a mitigation that excuses the underlying missing check — it may slow mass harvesting but doesn't change whether a single unauthorized access is possible, which is what the report is about.
- An endpoint that requires knowledge of a second, unguessable, out-of-band value (a signed link token, a per-object secret sent by email) alongside the ID is not a bare IDOR — verify whether that second value is actually enforced server-side before assuming the ID alone should have been sufficient protection.

## Integration
- Record every test — including clean ones — with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)` so the object type isn't re-suggested next session.
- Bank a confirmed capability that isn't yet a reportable bug (e.g. "I can read other users' invoice IDs via the export list, but the export endpoint itself is still ownership-checked") with `mcp__bb__add_primitive` rather than dropping it — it may combine with something found later.
- The assistant proposes which objects and routes to test and how to compare responses; the human sends every request and is the one who judges whether the returned data is genuinely another user's.
- Never state a finding is confirmed. That's `record_coverage(status="confirmed")` after the human says so, not an assistant assertion.
