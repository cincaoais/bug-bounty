---
name: pb-api-security
description: Methodology playbook for the REST/protocol API surface of a target. Load when endpoints, API docs, debug endpoints, legacy versions, or WebSocket/gRPC channels are in scope, or when bb-next surfaces an API test case that isn't GraphQL- or auth-specific.
---

# pb-api-security

## When this applies
- REST/JSON endpoints that need method-level and parameter-level testing beyond a single class.
- Exposed API documentation: Swagger/OpenAPI, /api-docs, GraphQL playgrounds.
- Debug/management endpoints: /actuator, /debug, /console, /metrics, health and info paths.
- Legacy API versions still online (`/api/v1` beside `/api/v2`), internal RPC or service endpoints reachable from the internet.
- WebSocket channels, gRPC services, microservice gateways and reverse proxies.
- Resource-consumption questions: deep queries, giant payloads, missing rate limits.

Division of labor: GraphQL-specific testing is `pb-graphql-abuse`; object-level authz is `pb-idor-bola`; function-level authz is `pb-broken-access-control`; request-boundary divergence is `pb-request-smuggling`. This playbook owns the REST-surface panorama — docs, versions, methods, debug endpoints, and the protocol channels that don't have their own playbook.

## First signals
- A Swagger/OpenAPI UI or JSON document linkable from the app, or discoverable at the usual doc paths — the whole route table, including routes the UI never calls.
- A version prefix in URLs (`/api/v1/...`) with a newer version elsewhere — the old version is where auth fixes lag.
- An endpoint answering differently per HTTP method (405 vs 200 vs a different handler) — method handling is inconsistent and worth mapping fully.
- A debug or actuator path returning environment, bean, or mapping details — the deployment internals are one hop from the app's secrets.
- A WebSocket endpoint whose handshake never checks a token, or a gRPC service with no visible auth.
- A header like `X-Version`, `X-Backend`, `X-Server` revealing internal routing or versions.

## Enumeration
1. Collect the authoritative endpoint list: API docs (Swagger/OpenAPI JSON), client JS route tables (bb-code), mobile-app endpoints (pb-android/pb-miniprogram), and Burp history (bb-burp). Merge them into the coverage ledger — the union is the real surface.
2. For every endpoint, note: methods accepted, parameters (documented and observed), auth requirement as stated, and which UI feature calls it.
3. Inventory documentation and debug exposure separately: which doc paths answer without auth, which actuator/env/heapdump endpoints are reachable, which internal service paths leak through the gateway.
4. Inventory legacy and internal surfaces: old version prefixes, `/internal` `/admin` `/ops` path families, endpoints with internal names in the docs that aren't linked anywhere in the UI.
5. Inventory protocol channels: WebSocket endpoints and message schemas, gRPC reflection availability, any SOAP/XML-RPC leftovers.
6. You've covered the surface when the union of docs + JS + mobile + proxy history is in the ledger, not when you've tested the three endpoints you use as a user.

## Test procedure
1. Method-level testing per endpoint — the cheapest differential: send GET/POST/PUT/PATCH/DELETE/OPTIONS (plus HEAD) to the same path and record the status and behavior of each. Findings hide in the gaps: a GET that requires auth while OPTIONS leaks headers, a POST that skips a check the PUT performs, a PATCH accepting fields the docs don't list.
2. Parameter-level testing per endpoint, one dimension at a time: missing value, empty value, type confusion (string where int expected), array where scalar expected (`id[]=1`), oversized values, and special characters. Record which dimension the handler mishandles — each is a lead, only a few become findings.
3. Auth-state differential: same request with valid token, no token, expired/other-user token (the other-user case is pb-idor-bola territory — hand it off rather than half-doing it here).
4. Hidden/debug parameters on state-changing endpoints: debug/test flags, `_method`-style overrides, and undocumented fields the handler reads anyway. Confirmation is a *visible* behavior change (debug output appears, validation skipped) — not the parameter merely being accepted.
5. Documentation exposure: doc paths unauthenticated is a finding when the docs reveal privileged/internal routes beyond the public surface — severity scales with what the docs unlock. Record exactly which undocumented route became testable.
6. Debug endpoint checks: actuator/env/beans/mappings/heapdump-class endpoints — an unauthenticated env or heapdump is typically directly reportable; a health endpoint is usually not. Distinguish by what data actually returns.
7. Legacy-version differential: run the *same* check against `/api/v1` and `/api/v2` — a fix present in v2 and absent in v1 is the classic high-yield finding; report the v1 gap with the v2 fix as proof it's a regression, not a design choice.
8. WebSocket channel: does the handshake authenticate? Can a message carry a foreign user/room ID and be processed (authz at message level, not connection level)? Can message content reach an injection sink (route to the matching playbook)?
9. gRPC: reflection enabled? auth on the service? the protobuf message fields enumerable? Route injection-shaped fields to their playbooks; the gRPC-specific deliverable here is the reflection/auth state.
10. Resource-consumption probes stay minimal: one deep-nested or giant-payload request to establish that no limit exists, never a sustained load (the legal gate classifies floods as DoS).
11. Internal-interface leakage through the gateway: paths that respond differently with header variations (X-Forwarded-For / Host / X-Original-URL families) — a header that changes routing or auth is a pb-broken-access-control finding; this playbook just maps which paths answer.

### Worked example of tiering a result
```
Probe:  GET /api/v1/orders/1007 with user A token → 200, order data
Probe:  GET /api/v2/orders/1007 with user A token → 403 (ownership check present)
Probe:  GET /api/v1/orders/1008 with user A token → 200, user B's order
        -> v1 lacks the v2 ownership check; confirmed IDOR on legacy version
        -> report shape: pb-idor-bola, with the v1/v2 differential as the proof
```
Report exactly what was shown: "v1 doesn't check ownership" is proven by the differential, not by the absence of a check in code you can't see.

## Evidence to capture
- The endpoint union and where each entry came from (docs/JS/mobile/proxy) — provenance matters when the program asks how you found it.
- For method findings: the method-by-method response table for the affected endpoint.
- For docs/debug findings: the unauth request and the sensitive content actually returned (redacted before storing).
- For version-differential findings: the same request against both versions, side by side.
- For WebSocket/gRPC: the handshake request/response, and the message that crossed a boundary.
- For every auth-state differential: which token state was used and what changed.

## Escalation
- Docs exposure escalates by what they unlock: public-route docs < internal/privileged routes < credentials or env in debug output.
- A method gap escalates when the missing check sits on a state-changing method — a GET leak is usually lower than a POST/PUT that mutates without auth.
- Legacy-version gaps escalate by the sensitivity of the operation the old version still allows — the v2 fix is the severity evidence.
- An unauthenticated actuator/env/heapdump escalates to high when it contains secrets (DB credentials, tokens, signing keys) — capture the fact, redact the values.
- WebSocket authz gaps escalate when the message-level boundary crossed reaches other users' data or privileged operations.
- Debug-parameter acceptance escalates only with a visible effect — "the parameter exists" is a note; "debug=1 returns the SQL" is a finding.
- Resource-limit gaps are low on their own (a missing limit is a design observation) — they escalate as the enabling condition of an abuse story (enumeration, credential stuffing) that another playbook confirms.

## Out-of-scope traps
- A health/status endpoint returning 200 is not a finding; know the difference between liveness data and sensitive internals before filing.
- OPTIONS returning allowed methods is normal HTTP, not a vulnerability — it becomes one only when combined with something it shouldn't reveal or enable.
- "No rate limit" is generally not reportable alone — attach it to a demonstrated abuse, or file it under the program's specific rules if they name it.
- Do not exhaust resources to prove missing limits — one demonstration request is enough; sustained load is a DoS-class action in this system's legal gate.
- Endpoints on third-party infrastructure (the API gateway vendor's console, a SaaS behind the API) are not the program's — attribute before testing.
- Docs found via aggressive path brute-forcing can be out of policy — prefer linked/referenced discovery and note how you found each one.
- Internal-interface tests via header spoofing blur into auth-bypass territory — stop and hand off to pb-broken-access-control the moment a header changes authorization, and keep the test count minimal.

## Integration
- Record every endpoint × method × auth-state tested with `mcp__bb__record_coverage` — the ledger's per-endpoint granularity is exactly this playbook's output format.
- Bank primitives with `mcp__bb__add_primitive`: doc paths that answer, hidden parameters accepted, legacy versions online, header-sensitive paths — durable facts that future sessions chain on.
- Hand off confirmed class findings to their owners (pb-idor-bola, pb-broken-access-control, pb-graphql-abuse, pb-request-smuggling) instead of re-writing their methodology here.
- The assistant merges the endpoint union and proposes the differential table to run next; the human sends every request and confirms each behavior change.
