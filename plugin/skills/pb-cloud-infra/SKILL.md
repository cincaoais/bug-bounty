---
name: pb-cloud-infra
description: Methodology playbook for cloud, infrastructure, and supply-chain surfaces on a real target. Load when the attack surface includes object storage, cloud metadata, containers/K8s, ops panels and middleware, CI/CD, or third-party integrations, or when bb-next surfaces a cloud/config test case.
---

# pb-cloud-infra

## When this applies
- Cloud assets: object storage buckets, cloud metadata endpoints, serverless functions.
- Containers/K8s: Docker APIs, K8s dashboards, service-account tokens, etcd.
- Ops panels & middleware: Grafana, Zabbix, ELK/Kibana, Jenkins, GitLab, Nacos, Apollo, Redis, Kafka, RabbitMQ, database admin consoles.
- CI/CD pipelines and dependency manifests (SBOM): package.json, requirements.txt, pom.xml, composer.lock.
- Third-party integrations: payment callbacks, SMS/email gateways, CDN, map/geo APIs.
- Information disclosure: error stacks, debug endpoints, backup files, `.map` files, exposed logs, `.git` leftovers.

Covers the configuration and supply-chain territory that bb's endpoint-focused playbooks don't.

## First signals
- An unauthenticated 200 on a management or console path (`/actuator`, dashboards, admin consoles) where the main app requires login — the ops surface often ships without the app's auth.
- A login page for a well-known panel or middleware with its default port, path, or branding — default credentials and known CVEs are the first two things to check, in that order.
- A bucket or storage hostname in the page source, a CDN URL, or a signed URL with credentials in the query string — where the object lives, its ACLs become testable.
- Build or deploy artifacts in the response: version banners, PDB/SBOM fingerprints, `X-Powered-By`, generator meta tags — version identification is the gate to CVE matching.
- Error pages quoting stack traces, framework internals, or cloud provider resource names — disclosure that also fingerprints the deployment.
- A callback/webhook configuration field (payment notify, SMS status, email bounce) — the integration's validation is usually weaker than the main app's.

## Enumeration
Walk the surface in four families; this is an inventory pass, not a testing pass.

1. Ops/management surface:
   - Panels: server control panels, database consoles, monitoring (Zabbix/Grafana), log search (ELK/Kibana/Splunk), CI/CD (Jenkins/GitLab), config centers (Nacos/Apollo).
   - For each: is it reachable unauthenticated? Does it accept default credentials? Which API sub-paths answer without a session?
2. Cloud surface:
   - Object storage: bucket names (guessed from hostname/subdomains), public read/write ACLs, presigned-URL leakage, listing/ACL endpoints.
   - Metadata: whether any SSRF-style path from the app can reach the cloud metadata address (that exploit path is pb-ssrf's job; this playbook identifies *what* metadata would mean).
   - Serverless: exposed function endpoints, environment-variable leakage, temp-credential exposure.
3. Middleware surface: message queues (Kafka/RabbitMQ management ports), caches (Redis/Memcached on default ports), search engines — reachable without auth, data enumerable, or messages injectable?
4. Supply-chain surface: dependency manifests and lockfiles (client-visible or in exposed repos), CI/CD logs and artifacts, public repositories, hardcoded vendor credentials. Fingerprint → version → CVE lookup is the standard path here.

For every discovered asset, record whether it answers unauthenticated, what version/banner it shows, and which program asset it belongs to — infrastructure findings live or die on attribution.

## Test procedure
Test each family in priority order: unauthenticated access, then default credentials, then CVE applicability, then data exposure.

1. Unauthenticated access checks — the highest-yield first step for every panel/console found:
   - Request the root and known API sub-paths without any session; note which answer with real data rather than a login redirect.
   - For CI/CD: anonymous build/view access, public job logs, workspace browsing.
   - For config centers: unauthenticated config export, default account acceptance.
   - Confirmation is always "real data returned unauthenticated" — a login redirect is not a finding, a 200 with data is.
2. Default/weak credential checks — only where the program allows credential testing (check the policy; many forbid brute force). Try the documented default for the identified product version; never run lists against it.
3. Cloud storage ACL checks:
   - Is the bucket enumerable (listing) or readable (known object paths) without credentials?
   - Is it writable (a test upload of a marker object you own)?
   - Do signed URLs expose credentials or stay valid beyond their apparent window?
   - Record exactly which operation succeeded — read vs list vs write are different severities.
4. Version → CVE matching: from every banner/fingerprint collected, compare against known CVEs for that product/version, then verify applicability with the simplest non-destructive probe the CVE implies. An unverified version match is not a finding.
5. Integration/callback checks: for payment/SMS/email callbacks — is the callback signature actually verified, or is the notify URL plus parameters enough to forge an event? Is the recipient/content of outbound messages partially user-controlled (header injection, template injection)?
6. Information-disclosure sweep: backup/archive patterns, `.map` sources, `.git` exposure, log files — each is a data point; escalate only what is usable for a next step (credentials, internal hostnames, source code).

### Worked example of tiering a result
```
Probe:  GET https://target/graph (no session)
Result: 200, JSON time-series of internal host metrics, no auth challenge
        -> unauthenticated data exposure confirmed (not just "login page found")

Probe:  bucket "target-assets" — list objects
Result: 403 on listing, but GET of a guessed object path returns the file
        -> read access without listing confirmed; tier: readable, not enumerable
```
Report exactly the tier reached — "the panel is reachable" is not "its data is readable without auth".

## Evidence to capture
- For unauthenticated access: the request without credentials and the response showing real data (redact anything PII-shaped before storing).
- For default credentials: the product/version and the documented default used — plus the program's authorization to test credentials at all.
- For cloud storage: the exact operation proven (list/read/write), the marker object if you wrote one, and the ACL or signed-URL detail that made it possible.
- For CVE claims: the fingerprint, the advisory reference, and the non-destructive confirmation result.
- For integrations: the forged callback/event and the state change it caused.
- Attribution evidence for every asset: which program system it belongs to, since third-party-hosted panels (vendor SaaS) are usually out of scope.

## Escalation
- Unauthenticated panel access escalates by what the panel can do: read-only metrics < queryable logs < config export with credentials < remote command/exec capability. Name the highest capability you actually demonstrated.
- Default credentials escalate only when the account is beyond the demo/default role — a default credential that only reaches a demo dataset is low; one that reaches production config or pipelines is high.
- A writable bucket escalates when its content is *served* (stored-XSS or content-poisoning against visitors) or when the bucket is a deploy source (supply chain).
- Leaked CI/CD credentials escalate by blast radius: what the pipeline can reach (source repos, artifact registries, production deploy keys). The credential is the finding; the reach is the impact.
- Signed-URL or AK/SK leakage escalates by what the key is authorized for — check the key's permissions before claiming impact, and never enumerate beyond what the program permits.
- Cross-link: metadata reachability belongs to pb-ssrf; exposed `.env`/`.git` findings belong to pb-secrets-exposure; a dangling CNAME belongs to pb-subdomain-takeover. Chain them in bb-correlate rather than duplicating.

## Out-of-scope traps
- Attribution first: panels or buckets belonging to third-party vendors (the panel vendor's SaaS, a CDN's infrastructure) are not the program's assets — verify ownership before spending effort or filing.
- Default-credential testing is frequently *explicitly forbidden* in program policy; a finding obtained by breaking that rule is worse than no finding. Check the rules before the attempt.
- Version fingerprint ≠ vulnerable: an unverified CVE match is not a finding; a "the version is old" claim is not impact.
- A login page or reachable port is not unauthorized access — only demonstrated access to data or function counts.
- Do not enumerate buckets/keys by brute force; guessing a few predictable names is reconnaissance, mass enumeration is abuse.
- On cloud platforms shared with the vendor (PaaS/serverless), metadata may belong to the platform vendor, not the program — the reach must be attributable to the target's own infrastructure.
- Redact aggressively: config exports and logs are full of credentials and PII; the ledger's redaction runs on ingest, but prefer capturing structure over secrets in the first place.

## Integration
- Record each discovered asset and each check run with `mcp__bb__record_coverage` — including clean results — so the ops surface doesn't get re-walked next session.
- Bank every credential, internal hostname, version fingerprint, and unauthenticated-but-harmless endpoint with `mcp__bb__add_primitive`; these are the chaining fuel bb-correlate exists for.
- Newly discovered hosts/buckets go through bb-recon into the ledger as scope-visible assets.
- The assistant proposes which asset family to test next and what a clean vs confirming response looks like; the human runs every request and confirms what actually came back.
