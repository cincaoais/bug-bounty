---
name: pb-subdomain-takeover
description: Methodology playbook for finding subdomain takeover via dangling DNS on a real target. Load when testing DNS/CNAME exposure or when bb-next surfaces a subdomain-takeover test case.
---

# pb-subdomain-takeover

## When this applies
Any in-scope hostname whose DNS record points at infrastructure the program no longer controls:
- A CNAME to a third-party PaaS/CDN/SaaS host name — cloud storage, an app-hosting platform, a help-desk vanity domain, a CDN edge, a marketing tool — that has since been deprovisioned.
- NS delegation of an entire subdomain zone to a DNS provider account that was closed.
- Rarer and lower-confidence: an A record pointing at a reusable/ephemeral IP from a cloud provider's pool.

Covers WSTG-CONF-10 (subdomain takeover).
Overlaps WSTG-CONF-02 when the dangling record is leftover config from decommissioned infrastructure.

## First signals
Notice these before you've formed any hypothesis:
- A CNAME resolves to a well-known SaaS/PaaS/CDN suffix, and requesting the hostname returns that provider's own "no such app / bucket / repository / site" fingerprint page.
  - Or a TLS handshake that fails outright, or serves a certificate that doesn't cover the requested name.
- NXDOMAIN on the CNAME *target* itself.
  - A stronger signal than a live fingerprint page — nothing at all answers for that name anymore.
- A hostname that appears in recon (subfinder/amass/certificate-transparency) but returns nothing meaningful on direct HTTP/HTTPS probe.
  - Even though DNS resolution for it still succeeds — the host exists in DNS, nothing serves there.
- Old campaign or integration subdomains: `promo.`, `go.`, `shop.`, `cdn-old.`, a former vendor's name.
  - Disproportionately likely candidates — pointed at a third-party tool once, abandoned in DNS after the contract or campaign ended.
- A subdomain referenced in stale documentation, an old sitemap entry, a certificate SAN list, or a JS bundle string, that no longer appears in the live site's navigation.

## Enumeration
1. Pull every subdomain already ingested from recon (subfinder/amass/certificate-transparency plus httpx status).
   - Cross-reference `bb-recon` output before running anything new — this is a mapping pass over existing data first.
2. For each subdomain carrying a CNAME, resolve the target and classify the service by suffix.
   - Match against known provider suffixes: `.s3.amazonaws.com`, `.blob.core.windows.net`, `.github.io`, `.herokuapp.com`, `.zendesk.com`, `.fastly.net`, `.netlify.app`, `.wpengine.com`, and similar.
3. Separate three DNS shapes, since each needs its own check:
   - CNAME to a third-party host — the common case.
   - NS delegation of a whole subzone — takes over every future record in it, not one hostname.
   - A-record-to-cloud-IP — treat as lower-confidence unless the IP range is clearly attributable to one provider.
4. Resolution alone is not the signal.
   - A CNAME that resolves fine but points at a still-claimed, functioning service is not a candidate — only carry forward targets that look unclaimed or unreachable.
5. The surface is covered once every subdomain in scope with an off-apex CNAME/NS pointer has been resolved and classified claimed / unclaimed-candidate / inconclusive.
   - Not once the handful that "look interesting" have been spot-checked.

## Test procedure
1. Request each unclaimed-candidate directly over HTTP and HTTPS.
   - Record the exact status code, response body, and TLS behavior (certificate coverage, handshake failure).
2. Compare the body against the specific third-party platform's documented "unclaimed" fingerprint.
   - A generic 404 from an unrelated app is not the same as that platform's own not-found page.
3. Re-resolve at test time before treating anything as current.
   - DNS entries used as evidence can change between recon and test — a stale reading produces a false positive.
4. Determine, as a factual question about the third-party platform's own product, whether it lets an arbitrary stranger register that exact custom name during its own onboarding.
   - That's what makes a dangling pointer *claimable* rather than merely dead.
5. Stop before registering or claiming anything.
   - Describe to the human what a minimal, non-destructive proof-of-control would look like: register the exact name on the provider, serve a static page identifying it as a temporary security-research PoC, nothing user-facing.
   - Only the human decides whether the program's rules permit this step, and only the human performs it.
6. If the human proceeds under explicit program authorization, the goal is control, not effect.
   - No redirecting the parent domain's real visitors, no login-lookalike content, minimal live window, prompt teardown once evidence is captured.

## Evidence to capture
- The DNS chain: in-scope hostname, its CNAME/NS target, and the resolution timestamp.
  - DNS state has a shelf life as evidence — the timestamp matters.
- The exact unclaimed-service response: status, full body of the fingerprint page, TLS certificate detail or handshake failure.
- A saved copy of the provider's own not-found/unclaimed page.
  - Triagers need to recognize the specific platform's fingerprint, not take your word for it.
- If a benign proof-of-control was authorized and performed: the artifact served, the exact live window, and confirmation it was torn down.
- Store via `mcp__bb__store_evidence` — nothing beyond what proves the dangling pointer and the platform's own response.

## Escalation
- A dangling CNAME on a subdomain never referenced in trust decisions is usually Low/Medium — mostly phishing-infrastructure risk.
  - It escalates sharply when the subdomain is *trusted* somewhere: a CSP `connect-src`/`script-src` entry, an allowed CORS origin, an iframe/postMessage target, or covered by a broadly-scoped session cookie (`Domain=.example.com`, readable from any subdomain, claimed or not).
- NS-delegation takeover of a whole zone is categorically worse than a single dangling CNAME.
  - It grants every future record in that subzone, not one hostname — report the two at different severities, don't collapse them.
- If the dangling host shares a parent domain with broadly-scoped session cookies, name the specific chain as the impact.
  - Takeover leads to cookie read on the subdomain leads to session hijack on the main app — not just "attacker-controlled content."
- Only chain with `pb-cache-poisoning` if the dangling host actually sits behind the program's shared CDN/cache layer.
  - Otherwise keep the findings distinct.

## Out-of-scope traps
- A subdomain parked because the *apex domain itself* expired is a different, often out-of-program finding from a dangling pointer on a still-registered, in-scope domain.
  - Confirm which case you're in before reporting.
- A fingerprint page that looks like "not found" on a provider that does not actually allow public registration of arbitrary custom names is not exploitable.
  - Verify the provider's onboarding model before claiming impact.
- A CNAME target already claimed by some other, non-program party is not a takeover.
  - There's no available claim to make, and it may already be legitimately in use.
- Never claim, register, or take control of third-party infrastructure without both explicit program authorization and the human's decision to proceed.
  - Doing so on your own initiative is out of scope regardless of technical feasibility.
- A record intentionally left pointing at a decommissioned-but-still-owned internal service, confirmed by the program, is informational, not a takeover.
- Internal-only or split-horizon DNS names resolving only inside a VPN are frequently outside external testing scope.
  - Check program rules before treating internal resolution as reachable.

## Integration
- Record every subdomain checked with `mcp__bb__record_coverage`, including the ones that resolved cleanly to a claimed service.
  - That's real coverage, not a non-result.
- Bank a confirmed dangling-CNAME-with-matching-fingerprint as a primitive via `mcp__bb__add_primitive` even before any proof-of-control is authorized.
  - "Dangling pointer plus claimable service, unclaimed" is worth keeping even if claiming never gets approved.
- The assistant identifies candidate subdomains and describes what a proof-of-control step would involve.
  - The human decides whether program rules allow it and is the only one who ever registers anything on third-party infrastructure.
- Never claim a takeover is real before the human has confirmed both the technical step, if performed, and program-rule compliance.
  - `record_coverage(status="confirmed")` reflects the human's call, not an inference from a fingerprint match alone.
