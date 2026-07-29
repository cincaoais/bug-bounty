---
name: pb-cache-poisoning
description: Methodology playbook for finding web cache poisoning/deception on a real target. Load when testing CDN/cache behavior or when bb-next surfaces a cache-poisoning test case.
---

# pb-cache-poisoning

## When this applies
Any target sitting behind a shared HTTP cache — a CDN, a reverse-proxy cache (Varnish, nginx `proxy_cache`), or an application-layer cache — where responses are stored and replayed to users other than the one who generated them.
- The bug exists when the cache **key** (what the cache uses to decide "is this the same request as one already stored") includes less than what actually varies the **response** the origin generates.
- An "unkeyed" header, query param, or cookie can then change a cached response without changing which entry future requests hit.

Covers the overlap of WSTG-INPV-17 (Host header handling — a classic unkeyed input) and WSTG-INPV-04 (parameter pollution — unkeyed/duplicate query params).
Also touches WSTG-CONF-07/12 (cache-control and CSP header correctness), since correct cache-control directives are what should prevent this class entirely.

A related variant is **cache deception**: the cache key is misled by the *path* rather than a header/param — a request for a static-looking path that doesn't exist gets a dynamic, user-specific response cached under a static-looking key that other users then hit.

## First signals
- A CDN or cache clearly in front of the app.
  - `X-Cache`, `CF-Cache-Status`, `Age`, `Via`, or similar headers present — no cache in the path means this class doesn't apply at all; confirm this first.
- A response that visibly changes based on a header or query parameter the app clearly reads.
  - A personalization header, a locale/currency param, an `X-Forwarded-Host`-influenced canonical link or asset URL — on an endpoint that also shows cache-hit behavior (`Age > 0`, a `HIT` status) on repeat requests.
- Cache-hit status persisting across requests that vary only in a header/param you'd expect to be part of the key.
  - The mismatch between "what changes the response" and "what changes the cache status" is the entire signal.
- Reflected input appearing in a response body or a response header on a path that is itself cacheable.
  - A header value or param showing up in a redirect `Location`, a canonical link, an asset URL — reflection alone is common and mostly harmless; reflection *plus* cacheability is the combination worth testing.
- A static-asset-style path that actually maps to a dynamic origin route.
  - An extension the CDN treats as always-cacheable, common in SPA routing or extension-based cache rules — a candidate for cache deception rather than classic poisoning.

## Enumeration
1. Confirm cache presence and behavior per host before testing any single endpoint.
   - Send two identical requests a few seconds apart and check for `HIT`/`MISS`/`Age` movement.
   - Note which hosts/paths are cached at all — most authenticated, per-user pages are usually, and correctly, never cached.
2. For each cached endpoint, enumerate every input the origin visibly reacts to.
   - Standard headers (`Host`, `X-Forwarded-Host`, `X-Forwarded-Scheme`, `Accept-Language`, `User-Agent`), custom headers already surfaced in `bb-recon`/`bb-code`, and query parameters.
   - Cross-reference what's already mapped rather than guessing blind.
3. For each such input, determine from repeated cache-status observation, not assumption, whether it's part of the key.
   - Does varying it produce a `MISS` every time (keyed), or does a `HIT` persist across different values (unkeyed, and therefore a candidate)?
4. Enumerate path-based cache-deception candidates separately.
   - Routes where appending a static-looking suffix or trailing segment still resolves to the same dynamic origin handler while the CDN's own path-based rules treat it as a static, long-lived entry.
5. The surface is covered once every cached endpoint has its reactive-input set classified keyed vs. unkeyed, and every static-suffix caching rule has been checked against at least one dynamic route it might inadvertently cover.
   - Not once one interesting header has been tried on one page.

## Test procedure
The entire test is scoped to **your own cache key**: every step below uses a unique cache-buster (a throwaway query param or path segment no one else would ever send) so any poisoned entry this testing creates is only ever served back to you, never to another real visitor.

1. Pick a cacheable endpoint and a candidate unkeyed input.
   - Attach a unique, single-use cache-buster to isolate a private cache entry, and reuse that same value across every request in this test so you're always reading and writing the one entry you created.
2. Send a request to that cache-busted URL with a distinctive, benign marker value in the candidate input.
   - An identifiable nonce string, not a script tag or exploit string.
   - Confirm the response is a cache `MISS` — the first write.
3. Send a second, plain request to the *same* cache-busted URL without the candidate input, or with a different, equally benign value.
   - If the response comes back a `HIT` and still contains your marker from step 2, the input is confirmed unkeyed, and the marker-influenced output got cached and served back without the input being resent — that's the core finding.
4. Confirm a negative control.
   - Repeat with an endpoint or input already known to be correctly keyed, or with cache-control set to no-store, and verify the marker does *not* persist.
   - This rules out "the app just always echoes this" as an alternate explanation and shows the caching behavior specifically carried it.
5. Only once unkeyed-input-into-cached-response is confirmed on your own isolated key, name what the reflected content actually is.
   - A value in a page body, a redirect target, an asset URL, or a canonical link.
   - Naming the mechanism is the job here — crafting a payload around it belongs to the injection playbook the reflection point implicates, not this skill.
6. For cache-deception candidates, request the dynamic/authenticated page via the static-suffixed path using your own authenticated session and a cache-buster.
   - Then check from an unauthenticated or second-session request to the *exact same* static-suffixed URL whether your own personal content comes back — this is the deception-specific proof, distinct from the header/param case above.
7. Stop at proving the mechanism on your own key.
   - Do not attempt to poison a shared, non-cache-busted, real endpoint URL that other visitors actually request — that is the line between "I proved the cache can be poisoned" and "I poisoned something a real visitor might load."

## Evidence to capture
- The exact request pair — cache-busted URL, the input tested, the marker value used — and both full responses, with cache-status headers (`X-Cache`, `Age`, `CF-Cache-Status`, or equivalent) visible in each.
- The negative-control result alongside the positive result.
  - A correctly-keyed input, or a no-store endpoint not carrying the marker — so the report shows the caching behavior specifically caused it.
- For cache deception: the authenticated response containing personal content, and the follow-up unauthenticated/second-session response to the identical static-suffixed URL showing the same content came back.
- Confirmation the cache-buster was unique to this test and that no request was sent to a non-cache-busted, real endpoint URL during testing.
- Store via `mcp__bb__store_evidence`.
  - Keep the marker benign — an identifiable string, never live script or exploit content — throughout everything stored.

## Escalation
- Unkeyed input reflected into a cached response is Low/Informational on its own until paired with content that matters.
  - A redirect/canonical-URL takeover, a cached error page replacing the real page (denial of service for other users), or reflected content landing somewhere the target app doesn't escape it — turning cache poisoning into stored XSS served to everyone who hits that entry, the highest-severity outcome in this class since it converts a per-request bug into a persistent one.
- Severity scales sharply with cache scope and TTL.
  - A poisoned entry on a low-traffic path with a 30-second TTL is very different from one on the homepage with a multi-hour TTL — name the actual scope and duration rather than assuming worst case.
- Cache deception escalates specifically by what personal data appears in the leaked static-suffixed response.
  - Session tokens, PII, or account details are materially bigger than a mostly-empty personalized shell page.
- If the same host also showed a dangling-CNAME signal (`pb-subdomain-takeover`) or a request-smuggling signal (`pb-request-smuggling`), name the chain explicitly rather than reporting cache poisoning in isolation.
  - A shared front-end/cache layer is often the same infrastructure implicated in those classes.

## Out-of-scope traps
- Reflected input with no caching in the path — confirmed `MISS`/`no-store` on every request — is not cache poisoning regardless of how dangerous the reflection would be if cached.
  - Verify cache-hit persistence before calling anything in this class a finding.
- A "poisoned" response that only ever comes back to the same session/cookie/IP that created it has no other-user impact.
  - Confirm the cache is actually shared across different clients before treating self-only persistence as a finding.
- Any test that can't use a unique cache-buster, because some frameworks reject unknown params, and might land on a real, shared cache key needs program coordination before testing, not a workaround.
- Rate-limiting or WAF blocking rapid repeated requests to the same URL is not a mitigation for the underlying keying bug.
  - It may slow discovery without changing whether the miskeying exists.
- A CDN correctly stripping or normalizing the candidate header/param before it reaches the origin, confirmed by the marker never appearing in the origin's own response, means the input isn't reaching the app at all.
  - A clean result, not an inconclusive one.
- Check program scope for explicit cache-poisoning testing rules.
  - Some programs restrict it to specific pre-approved paths or require a cache-buster convention of their own; follow theirs if one is documented.

## Integration
- Record every cached endpoint and candidate input tested with `mcp__bb__record_coverage`, including keyed inputs that came back clean.
  - That rules them out for next session.
- Bank a confirmed unkeyed-input-on-your-own-key result as a primitive via `mcp__bb__add_primitive` even before its downstream impact (XSS, redirect takeover) is demonstrated.
  - The miskeying itself is a reusable capability worth keeping.
- The assistant identifies candidate endpoints/inputs and the cache-buster methodology.
  - The human sends every request, reads every cache-status header, and confirms whether the marker persisted.
- Never claim cache poisoning confirmed from a single HIT/marker match without the negative control also having been run and reported by the human.
  - `record_coverage(status="confirmed")` follows the human's judgment on the full pair, not an assistant inference from one response.
