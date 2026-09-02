---
name: pb-unauth-surface
description: Methodology playbook for reconstructing an unauthenticated attack surface from public sources only — recovering API paths and keys that aren't in the main-site JS, and disproving front-end crypto used as authentication. Load when testing a zero-identity surface (standalone H5, migrated/retired domain, sibling or same-IP host, gateway 405 / empty-array responses, getRsaKey-style front-end encryption), or when bb-next surfaces an unauthenticated-surface test case.
---

# pb-unauth-surface

## When this applies
Zero-identity testing: you have no account for the business, and the interesting path is **not** reachable from the current front-end. Specifically — a standalone H5/activity site, a retired or migrated brand domain (old host NXDOMAIN or 301), a sibling domain or same-IP virtual host that leaks a path the main site hides, an API gateway answering `405` or `200 {data:[]}`, or front-end encryption (`getRsaKey`, JSEncrypt, SM2, front-end AES) that looks like it might be standing in for authentication. This playbook owns one job: **reconstruct the interface from public surface only, and decide whether client-side cryptography is actually replacing auth.**

Division of labor: raw JS/webpack unpacking and secret extraction is `bb-code`; once a path is reachable and you're testing role/ownership, that's `pb-broken-access-control` / `pb-idor-bola`; once the path is known and you're doing full-method/BOLA/version work, that's `pb-api-security`; unauthenticated ops panels / object storage / middleware is `pb-cloud-infra`; a path that only lives inside an APK or miniprogram package is `pb-android` / `pb-miniprogram`. This skill is the front of that chain — finding the host, path, and key when they aren't in front of you.

## First signals
Notice these before forming a hypothesis:
- A generic SPA 404 (a tens-of-KB `index.html`, `X-Powered-By: Next`) returned for an API-looking path — that's front-end routing swallowing the path, **not** the backend saying the endpoint is absent.
- A gateway JSON body like `Route Not Found` / `no api` / `divide: selector` — the gateway is alive, this route just isn't mounted here; a different host/prefix may mount it.
- `405 Request method 'GET' not supported` — the controller **exists**, the method is wrong. This is more valuable than a uniform 404.
- `200` with `data:[]` or an empty object — you're already inside the controller; only a parameter, field name, or crypto binding is missing.
- A `getRsaKey` / `getPublicKey` / ticket endpoint plus JSEncrypt-style client code — front-end encryption that may be transport obfuscation mistaken for authentication.
- An old host that is `NXDOMAIN` versus one that `301`s — the 301 `Location` is the new battleground; the backend methods may have moved with it, or been left behind.
- A path string appearing in a sibling domain, a `urlscan`/Wayback record, or a same-IP virtual host that the primary site never references.

## Enumeration
1. Build a host map, not a single domain. Classify every host into four types and tag each with its DNS/IP so same-IP relationships are visible:

| Class | Typical | What it's good for |
|---|---|---|
| C-end shell | main site / `m.` / new brand domain (Next/Vue) | rarely holds the path directly — record and move on |
| API gateway | `appgw` / `apigw` / `qr` / `gateway` | fingerprint it (below); don't scan it like a SPA |
| Standalone business H5 | invoice / vat / activity CDN | highest yield — unpack its JS, probe its prefixes |
| Backend / SSO | `passport` / `admin` / vendor domain | zero-identity only proves "where the wall is" |

2. Record the allowed discovery sources you actually have: unauthenticated HTML/JS/source-maps, certificate-transparency / `urlscan` / Wayback / public GitHub, sibling domains and same-IP hosts, `301` Locations, public docs, and any package downloadable without login.
3. Note migrated/retired domains and their `301` targets explicitly — they belong on the map even when they look dead.
4. Coverage here is exhausted once the map distinguishes at least the C-end shell, the suspected gateway, and the suspected business H5 — and every candidate path has a recorded public-surface provenance, not a screenshot.

## Test procedure
The assistant proposes the request and reads the response; the human runs every `curl`. Keep requests single and low-volume — this is reconstruction, not a sweep.

1. **Response fingerprint (never follow redirects blindly).** For each candidate path record the four-tuple `status / Content-Type / Server / body-shape` and route on it: SPA-HTML-404 → wrong host, switch host; gateway-JSON-"route not found" → switch host or prefix; business JSON with the path echoed in the body → real app, proceed; short business text ("link does not exist") vs a uniform 404 page → path exists, resource doesn't, keep the prefix and vary module/method; `302 → SSO` → an auth wall exists (record the `Location`'s sid/app name), it is not "no service"; `405` → POST it immediately; `200 {data:[]}` → inside the controller, vary params/fields.
2. **Path discovery — five parallel sources**, ordered most-attacker-like to dirtiest (raw unpacking itself is `bb-code`): (a) live JS — homepage, build manifest, async chunks, `baseURL`; (b) historical/side channels — `urlscan`, Wayback, CT, third-party script hosts; (c) sibling domains + same-IP — resolve an unresolved old host to the gateway IP with `--resolve` and compare responses; (d) naming conventions — given one segment, the shape `/{svc}/{module}/{method}/{id}`, `/gp/{ctx}/{action}`, or `open`/`anon`/`ForFree` variants; (e) packages — method names present in an app/miniprogram but absent from the C-end web (hand extraction to `pb-android`/`pb-miniprogram`, bring the path back here). A empty result from source (a) is normal — move to (b)/(c), do not close the case.
3. **Key recovery and auth disproof.** The goal is not to decrypt — it's to decide whether cryptography is standing in for authentication. From the client code, align six things (extraction via `bb-code`): the key-fetch endpoint, the algorithm/padding, the **exact POST field name** (a response `uuid` may need to be sent as `rsaUuid`), the key lifetime (repeated GETs returning the same uuid/public key = a static key id), the encryption scope, and whether the key is fetchable with no cookie. Then walk the tiers on your own probe:

| Tier | Condition | If the business call still succeeds |
|---|---|---|
| T0 | no cookie, no Authorization | unauthenticated exposure |
| T1 | wrong / expired token | auth isn't being checked |
| T2 | logged in, but without the business role | SSO and ACL are separated — "through the door, can't act" |
| T3 | encryption removed, or the bound field wrong | crypto is protocol, not identity |

T0 success returning sensitive fields is an unauth-exposure finding. T0 that only yields a `302`/ACL while the business method is retired is a path that exists with a broken exploit chain — write the two apart.
4. **Field alignment (empty results mislead most).** GET a method that expects POST → catch the `405`, switch to POST; POST `{}` → `data:[]` means you reached the controller; then compare three bodies — plaintext keyword, wrong field name, and correct-field+ciphertext — copying field names from a sibling encrypted endpoint (a change-password call often reuses the same `rsaUuid` a query uses). A wrong field name reads exactly like "no vulnerability."
5. **Migration recheck.** For a retired site ask four things: is the old host `NXDOMAIN` or `301` (the `301` `Location` is the new target)? Did the new brand domain move the API too, or only the C-end shell? Which same-IP ServerName still reverse-proxies the old prefix (`/gp`, `/mag`)? Did the front-end chunk drop a method name the gateway still serves (`405`/`200` is more honest than JS)?
6. **Failure escalation.** Do not conclude "no such endpoint" before L4: L1 main-site JS full-text search → L2 async chunks / standalone-H5 JS → L3 sibling domains, CDN, urlscan, CT → L4 gateway host probe + `405`/business-JSON → L5 change entry (app, miniprogram, open docs) → L6 old method name + new host → L7 replay a Wayback old-JS `baseURL` against the live gateway.

## Evidence to capture
- For every candidate path, its public-surface **provenance** — the JS line, `urlscan` record, or sibling-domain fingerprint that proves it exists without a login. A path seen only in a logged-in DevTools screenshot is a hypothesis, not evidence.
- The recorded four-tuple fingerprint (`status / Content-Type / Server / body-shape`) for each host/path decision.
- The key-fetch exchange: endpoint, algorithm/padding, the exact bound field name, and whether the key is static across requests.
- For a T0 result: the full unauthenticated request/response, the sensitive fields returned, and a `curl` that visibly carries **no** session cookie.
- For migration findings: the old-host `301`/`NXDOMAIN` response and the `Location`, side by side with the live method's response on the new/gateway host.

## Escalation
- T0 success returning real, sensitive fields (accounts, tax/company IDs) is the headline — bank it via `add_primitive` immediately, then hand bulk enumeration of it to `pb-api-security` rather than mass-pulling records here.
- A path that only exists behind a role wall once recovered belongs to `pb-broken-access-control`; hand it off with the recovered host/path instead of re-deriving authz here.
- A confirmed "client-side RSA/AES/uuid is not authentication" (T3) turns a "just encrypted traffic" endpoint into an unauth-access story — that reframing is the escalation.
- A list endpoint reachable unauthenticated escalates by the count and the field sensitivity: characterize how many records and which fields (account, phone, tax id), and put only a redacted sample in evidence.
- For an ID-driven endpoint, escalation depends on where the ID comes from — a public format, the attacker's own C-end order, or enumeration. Without a lawful source of IDs you cannot claim "any user."

## Out-of-scope traps
- A path from a logged-in Network tab or a report screenshot is a **hypothesis**, not a discovery source — it only counts once reconstructed from public surface. Screenshots prove *exploitation*; public surface proves *discovery*.
- A SPA's `404` is not the endpoint's `404`. Never write "no such interface" off a main-site 404 before the L4 gateway probe.
- Client-obtainable RSA/AES/uuid is not authentication — don't report "encryption present" as security, and don't report its absence as a bug on its own.
- Path follows the **host**, not the brand's marketing site — a method living on a gateway or sibling host is in play only if that host is in scope; attribute the host to the program before testing.
- Sibling-domain / same-IP hosts and vendor gateway consoles are frequently a different owner — confirm scope for the exact host with `bb-scope` before probing it, even when the IP matches.
- Reconstruction stays low-volume. Do not brute-force prefixes or fields aggressively — high request rates cross into the DoS shape the scope hook's legal gate blocks, and add nothing that a handful of fingerprinted probes don't.
- A retired H5 that is genuinely gone (NXDOMAIN, no 301, method 404 on every host) is a dead end — record it excluded so it isn't re-walked, and don't inflate "the old site had it" into a current finding.

## Integration
Record every probe with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, using test_case_ids like `unauth-path-recovery`, `crypto-as-auth-disproof`, or `migration-recheck` — a fingerprinted dead end (SPA-404, NXDOMAIN, wrong-field `[]`) is a *clean* result worth recording so `bb-next` stops re-suggesting it. Bank recovered hosts, live-but-hidden paths, and static key ids as primitives with `mcp__bb__add_primitive` before you know what they chain into; file an untested path hypothesis as a lead via `mcp__bb__add_lead`. The assistant proposes the reconstruction and reads the fingerprints back; the human runs each `curl` and, after independently reproducing an unauthenticated reach, calls `mcp__bb__promote_to_finding(..., human_confirmed=True)`.
