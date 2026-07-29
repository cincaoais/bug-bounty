---
name: pb-graphql-abuse
description: Methodology playbook for finding GraphQL-specific flaws (introspection, field-level authz, batching, BOLA/BFLA) on a real target. Load when testing a /graphql endpoint or when bb-next surfaces a GraphQL test case.
---

# pb-graphql-abuse

## When this applies
Any discovered GraphQL endpoint — commonly `/graphql`, `/api/graphql`, `/v1/graphql`, or a path pulled from a JS bundle's Apollo/Relay client config — and any API gateway that fronts a GraphQL layer for multiple underlying services. GraphQL puts one endpoint in front of many independently-resolved types and fields, so most of what matters here is authorization *per field and per object*, not per route — REST-style "is this endpoint protected" thinking under-tests it badly. Covers WSTG-APIT-01. Object- and field-level authorization gaps found here are the GraphQL expression of `pb-idor-bola` and `pb-broken-access-control`; extra-field acceptance on a mutation input is the GraphQL expression of `pb-mass-assignment`.

## First signals
Notice these before you know how much of the schema you can see:
- A POST endpoint accepting a `query`/`variables`/`operationName` JSON body and returning a `data`/`errors` envelope — that shape alone confirms GraphQL and is worth testing further even before introspection.
- Whether an introspection query answers at all — this changes how much of the rest of this playbook you can do directly versus by inference, but isn't itself the finding.
- A GraphQL error message that leaks field or type names even with introspection disabled (a "did you mean X" suggestion on a near-miss field name is itself a schema leak).
- The client app only ever sending a small, fixed set of queries (visible in a JS bundle or proxy history) — a wide gap between what the client asks for and what the schema actually exposes is where field-level authorization gaps concentrate.
- A query accepting a list variable, or the endpoint accepting an array of operations in a single POST body — early signal that batching or aliasing is possible.
- A mutation's input type, once visible, containing more fields than the client's own forms ever populate.
- A single GraphQL endpoint fronting what used to be (or still partially is) several separate REST services — the older service's authorization model doesn't always survive the migration into a unified schema.
- A field resolver that's visibly slower than its siblings — often a sign it's doing a real database join per item rather than reading from a cache, which matters directly for the amplification check below.

Mapping the authorization classes to their GraphQL shape and closest sibling playbook:

| Class | GraphQL shape | Related playbook |
|---|---|---|
| BOLA | Object resolved by an ID variable with no ownership check | `pb-idor-bola` |
| BFLA | Field or type reachable regardless of role | `pb-broken-access-control` |
| Mass assignment | Mutation input accepts fields the client never sends | `pb-mass-assignment` |
| Amplification | No per-request cost/alias/batch limit | this playbook |
| Depth/complexity | No nesting-depth limit | this playbook |

## Enumeration
1. Attempt standard introspection (WSTG-APIT-01) first. If it answers, extract the full type graph — every query, mutation, and field per type, including ones the client app never calls.
2. If introspection is disabled, reconstruct a partial schema from other sources: field-suggestion errors on near-miss names, the client bundle's persisted queries or generated TypeScript types, and any schema/docs page (GraphQL Voyager, GraphiQL) left reachable.
3. From the schema (or the client-observed query set as a fallback), list mutations that change state, fields returning data classes not shown in the UI (internal notes, other users' PII, cost/margin figures), and any suggestively named type or field (`AdminX`, `InternalY`, `debug`, a leading underscore).
4. Enumerate authorization boundaries per field, not per endpoint — note, for each sensitive field and mutation, which role/identity is *supposed* to reach it, independent of whether the single `/graphql` endpoint itself requires authentication.
5. Note the input type's full field list for every mutation you plan to test — this is what step 6 of the test procedure below tests against.
6. Coverage is exhausted once every mutation and every field on a sensitive type has a recorded object-level and field-level authorization result, and the schema's amplification/depth behavior has been observed at least once — a schema with dozens of types rarely gets fully covered in one pass, so track what's untested explicitly rather than treating "I ran introspection" as done.

## Test procedure
1. Field-level authorization gap (BFLA over GraphQL): as an authenticated low-privilege identity, query a field the UI never requests but the schema exposes on a type you can otherwise reach — check whether the resolver enforces access on its own, independent of what the official client happens to send.
2. Object-level authorization gap (BOLA over GraphQL): pass another object's ID as a query variable (e.g., an order or user ID that isn't yours) the same way you would test IDOR over REST — the resolver has to check ownership itself; a schema that accepts any ID with no per-object check returns another identity's data.
3. Mutation authorization: for every state-changing mutation found, pass an ID belonging to another owned object into its input the same way as step 2 — a missing ownership check on a write is more severe than the equivalent read-only gap, and both should be tested for the same object type.
4. Input coercion: check whether a mutation's input type accepts fields beyond what the client form populates. This is the GraphQL expression of mass assignment — hand a confirmed extra-field bind to `pb-mass-assignment`'s escalation guidance for how to grade impact.
5. Aliasing/batching observation: submit one request containing a few aliased copies of the same query, or an array-batched set of operations in a single call, and note whether the server applies any per-request query-count or complexity limit. This characterizes whether amplification protection exists — a handful of aliases is enough to observe the limit or its absence; it is not a flood.
6. Depth/complexity observation: construct one query that follows real relations in the schema a few levels deep (e.g., user → posts → comments → author → posts) and note whether the server rejects it, times out gracefully, or executes it in full. This is an observation about a missing depth/complexity limit, not a denial-of-service test — never push the depth or repetition further than needed to make the one observation.
7. Error-based schema mining, only if introspection is off: send deliberately near-miss field and type names in queries and mutations, and use the suggestion errors to reconstruct schema shape incrementally.
8. Cross-service authorization check: for a schema you suspect fronts multiple formerly-separate services, test the same field/object pair under two different, unrelated identities to see whether the newer unified layer applies one consistent rule or inherits whichever service's rule happened to migrate over.
9. Subscription/real-time check, if the schema exposes GraphQL subscriptions: confirm a subscription to another user's data stream requires the same ownership check as the equivalent query — subscriptions are newer and frequently under-reviewed relative to queries and mutations on the same type.

## Evidence to capture
- The introspection query and raw schema response, or the sequence of near-miss queries used to reconstruct a partial schema when introspection was disabled.
- Full query, variables, and response for each object- or field-level authorization test, showing clearly whose data (or which field) came back to which authenticated identity.
- The aliasing/batch request sent and the response or timing that shows whether a limit existed, noting the exact count used — "no limit observed at N" is not the same claim as "no limit exists."
- The depth/complexity query used, verbatim, and the server's behavior (timeout, graceful rejection, or full execution) with response time.
- The mutation's full input type from the schema next to the fields the legitimate client actually sends, for any extra-field acceptance finding.
- For a cross-service authorization inconsistency, both identities' queries and responses against the same field, showing which one was inconsistently allowed.
- For a subscription-level gap, the subscription request and at least one streamed message showing another identity's data arriving.

## Escalation
- A BOLA/BFLA field returning another identity's data is a direct, confirmable finding once shown against two independently-owned accounts — hold it to the same evidentiary standard as `pb-idor-bola`.
- A mutation-level ownership gap outranks the equivalent read-only gap on the same type — always check whether a confirmed BOLA read also has a corresponding writable mutation with the same missing check.
- An amplification gap (no per-request cost limit) paired with a resolver that fans out to many downstream calls per aliased field is worth describing as a resource-exhaustion risk — describe the mechanism and the missing limit in the report; never demonstrate it by actually degrading the service.
- Extra input fields accepted on a mutation chain directly into `pb-mass-assignment`'s escalation guidance — a privileged field on a GraphQL input type deserves the same seriousness as one on a REST body.
- A subscription-level data leak escalates a query-level BOLA finding once you show it's persistent (an attacker doesn't need to keep re-querying, the data streams to them continuously) — note that distinction explicitly since it changes the practical exposure.
- A cross-service inconsistency is worth more once you can name which legacy service's weaker rule is actually winning — that's the fact a triager needs to fix the right code path.

## Out-of-scope traps
- Introspection being enabled is rarely a standalone finding — it's recon value, not impact. Check the program's stated stance (many explicitly won't reward "introspection enabled" alone) before writing it up on its own.
- A deeply nested query that runs slowly with no actual data exposure or missing authorization behind it is informative at best — don't frame a depth observation as a vulnerability without a concrete resource-exhaustion argument, and never escalate depth or repetition to the point of causing real denial of service.
- A field name that merely sounds sensitive (`isAdmin` on a type with no real admin distinction in this app) isn't automatically a bug — confirm the field actually gates something before reporting it.
- Batching/aliasing limits are frequently enforced at a gateway layer in front of the resolver rather than inside it — a single test showing "no limit at N=5" doesn't establish there's no limit anywhere; report what you actually observed, not what you didn't test.
- A schema leak that requires an already-authenticated, already-privileged session to reach is a materially weaker finding than the same leak pre-auth — grade severity against the access level actually required to trigger it.
- A slow resolver by itself isn't a resource-exhaustion finding — it needs to be paired with an actual missing amplification limit before it's more than an observation about performance.
- Subscriptions that simply mirror an already-public data feed (a public activity stream, a status page) aren't an authorization gap even if any authenticated user can subscribe — confirm the streamed data is genuinely scoped to be private before treating access to it as a finding.

## Integration
Record schema-discovery state and each field/object test via `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, using endpoint-scoped test_case_ids like `graphql-introspection`, `graphql-bola-field`, `graphql-bfla-field`, `graphql-batch-limit`, or `graphql-depth-limit` — a single `/graphql` endpoint typically needs many separate coverage records, one per field or mutation tested, not one blanket result. Bank the reconstructed schema and any field confirmed reachable without proper ownership checks as a primitive via `mcp__bb__add_primitive` even before deciding its full impact, and file a schema-driven hypothesis you haven't tested yet (an `AdminSettings` type worth checking) as a lead via `mcp__bb__add_lead`. The assistant proposes which fields, mutations, and limits to probe and reads the responses back; it never asserts a BOLA, BFLA, or amplification issue is confirmed — that requires the human's own reproduction and `mcp__bb__promote_to_finding(..., human_confirmed=True)`.
