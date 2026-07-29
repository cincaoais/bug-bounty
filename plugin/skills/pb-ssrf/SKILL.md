---
name: pb-ssrf
description: Methodology playbook for finding server-side request forgery on a real target. Load when a feature makes the server fetch something you named, or when bb-next surfaces an SSRF test case.
---

# pb-ssrf

## When this applies
Any feature where the server, not your browser, fetches or connects to a resource whose location you influence:
- Webhook/callback URL fields, "import from URL," URL preview/unfurl (chat apps, link cards).
- PDF or screenshot generators fed a URL or HTML.
- Avatar/logo "fetch from URL," XML/SOAP/RSS ingestion.
- SSO/OAuth metadata or JWKS URLs, image proxies.
- Integrations that ping a user-supplied host to "test the connection."
- File-import features accepting a path or URL instead of an upload.

Covers WSTG-INPV-19.

## First signals
Notice these before you know whether the app is vulnerable:
- A field literally labeled URL, endpoint, callback, webhook, feed, or host, on a feature whose whole job is server-side fetching.
- A response time or behavior that visibly depends on what host you put in the field — a fast failure for a clearly-dead host versus a slow timeout for a live-but-unresponsive one tells you the server actually attempted the connection rather than validating the string client-side.
- A feature that accepts a URL and shows you *something derived from fetching it* — a title, a thumbnail, a file size, a content-type, an error message quoting the response. Any of that is the server relaying information back from a request it made on your behalf.
- File-upload alternatives that accept "import from URL" instead of, or alongside, a real upload.
- Redirect-following behavior: does the feature follow a 3xx it receives? A feature that fetches your URL and visibly follows a redirect (different final content, different displayed host) is a distinct and often more exploitable primitive than direct-URL fetching, since target-side allowlists frequently check only the initial URL.
- Any parameter accepting a hostname, IP, or internal-scheme-shaped path even where the feature isn't obviously "fetch a URL" — image processing libraries, XML parsers, and PDF renderers often accept URLs in places that don't look like it from the UI.

## Enumeration
1. Inventory every feature where server-driven fetch is even plausible, not just the obvious "webhook URL" field.
   - Walk settings, integrations, import/export, notifications, and any "preview" or "unfurl" behavior.
2. For each candidate, identify exactly what the server does with the result:
   - Does it just check reachability (200/non-200)?
   - Does it parse and display content?
   - Does it fetch and store a copy (image/file import)?
   - Does it render fetched HTML (PDF/screenshot generator)?
   - The end use determines both the test and the achievable impact — a reachability-only check limits you to blind/timing signals, while a content-returning fetch can leak response bodies directly.
3. For each candidate, note the accepted input shape: full URL, hostname only, path appended to a fixed base, or IP address. This determines which bypass surface (scheme, redirect, DNS) is even relevant.
4. Check whether the same fetch capability is reachable through more than one entry point.
   - A webhook URL settable in one integration is frequently reusable via a "test this webhook" button, a retry mechanism, or an API-only equivalent of a UI feature — each is a separate test, since validation is commonly duplicated inconsistently across them.
5. You've covered the surface once every field that plausibly triggers a server-side fetch has been identified and classified by end-use (blind / content-echoing / rendering), even for the ones you haven't yet tested for a bypass.

## Test procedure
1. Start with a URL pointing at infrastructure you control (a request-bin style listener or a host you own) to establish baseline behavior.
   - Does the request arrive at all? What request line and headers does it carry? Does it follow redirects? Does the response content or headers come back to you in the app?
2. From that baseline, determine which of the three SSRF outcomes is achievable here, in order of how much it proves:
   - **Full response disclosure** — the app shows or stores content from the fetched URL. Strongest evidence; capture the exact returned content.
   - **Distinguishable blind behavior** — no content comes back, but you can tell open-vs-closed-vs-filtered on a target host by response time or error-message variation (connection refused vs. timeout vs. explicit "blocked" message).
   - **DNS interaction only** — your controlled domain resolves and you observe a lookup with no further evidence of a request being made. Weakest signal; treat as a lead, not a confirmed capability, until something above it is also demonstrated.
3. Test scheme handling: does the field accept non-`http(s)` schemes at all (`file://`, `gopher://`, `dict://`) where the underlying library might support them even though the feature is nominally "URL"?
   - Only note what the library returns for a scheme it accepts. Don't chain into a full internal-file-read attempt beyond confirming the scheme is honored — that's a distinct escalation with its own evidence bar.
4. Test redirect-based routing: point the URL at your own listener configured to redirect to a second, different destination you also control, and confirm whether the final request lands on the redirect target.
   - This reveals whether an allowlist is checked only against the input URL or against every hop.
5. Test DNS-based indirection only as far as confirming resolution behavior: a hostname you control that you can point at different IPs shows whether validation happens at parse-time (checks the literal string) or connect-time (checks the resolved address). This is a methodology observation about *when* validation runs, not a technique for evading a specific filter.
6. Once basic outbound fetch is confirmed, test the classic high-value internal targets deliberately and note results factually:
   - Cloud metadata endpoints (AWS/GCP/Azure's well-known metadata service address).
   - Common internal service ports on `localhost`/`127.0.0.1`.
   - Any internal hostname previously disclosed (error pages, DNS, JS bundles — cross-reference notes from `bb-recon`/`bb-correlate`).
   - Record exactly what came back; a connection-refused is a different result from a 200 with content.
7. If the target sits behind a cloud load balancer or CDN, remember server-side fetches from application infrastructure often originate from a different network position than the internet-facing host — a metadata-endpoint hit from the app backend is a materially different finding than one that would come from the edge.

### Worked example of tiering a result
```
Input:  webhook_url = http://<your-listener>/probe
Result: listener receives the request within ~400ms, User-Agent: internal-webhook-svc/1.2
        -> confirms server-side fetch, tier: reachable

Input:  webhook_url = http://169.254.169.254/latest/meta-data/
Result: app shows "Webhook test failed: 200 OK" but does not display body
        -> tier: distinguishable blind (status differs from a dead-host 000/timeout case)
        -> NOT full disclosure; the metadata content itself was never observed through the app
```
Report exactly the tier reached — calling the second case "SSRF to cloud metadata" without ever seeing the body overstates what was actually shown.

## Evidence to capture
- The exact field/feature used and the literal input submitted.
- Proof of server-side origination: the request as received on your listener (source IP if visible, headers, timing) — this is what separates SSRF from a client-side fetch triggered by accident.
- The full content or behavior returned to you through the app for each outcome tier reached (response body if content came back, exact error/timing differential if blind).
- For redirect-based findings, both the initial URL and the redirect target, and evidence the final request reached the second host.
- For internal-target tests, the full raw response the app surfaced — a metadata-service hit is only as strong as what data it actually returned through the app, not the fact you got any response at all.
- Any internal hostnames or IPs newly discovered this way, filed as notes even if the specific request wasn't itself sensitive — they inform future SSRF and access-control testing on the same target.

## Escalation
- DNS interaction alone escalates to a real finding only once paired with content disclosure, a distinguishable port-scan-style signal, or a demonstrated internal-target hit — treat the gap between them as the actual work, not a formality.
- A confirmed fetch of external `http(s)` URLs escalates when the same primitive reaches metadata endpoints or internal-only hosts and returns their content — that's the step from "the server made a request I asked for" to "I can read data I'm not authorized to see."
- Cloud metadata content that includes temporary credentials is a distinct, higher escalation step from merely reaching the metadata IP. Reaching the IP and getting a 200 with a role name is not the same as retrieving usable credential material — be precise in the report about which you actually obtained.
- If scheme handling accepted something beyond `http(s)`, that's a primitive worth banking even without full impact yet — it may combine with a file-handling bug found elsewhere.
- A blind SSRF into an internal service that also accepts the redirect technique is a stronger, more portable primitive than one that only works via direct-URL fetch, since it survives simple hostname-allowlist defenses.
- If the reached internal host turns out to itself expose an unauthenticated admin interface or a further object-reference surface, cross-reference `pb-idor-bola`/`pb-broken-access-control` — the chain's endpoint is a different bug class from the SSRF that got you there, and the report should credit both steps distinctly.

## Out-of-scope traps
- A DNS lookup you caused is not proof of SSRF impact by itself — many programs explicitly downgrade "I made your server resolve a domain I own" to Informative unless paired with a demonstrated connection or data return. State clearly which tier you actually reached.
- Client-side fetches (browser-triggered, via JS/CSS/image tags rendered in *your own* browser) are not SSRF — confirm the request truly originates server-side (check source IP on your listener, or that the behavior persists with JS disabled or when the "preview" happens without your browser loading anything).
- A feature that fetches a URL you supply but only ever returns generic success/failure with no distinguishable timing or content difference across targets may still be worth noting as a primitive, but isn't reportable as SSRF until a distinguishing signal is found — don't round "the field exists" up to a finding.
- Read the program's scope and exclusions for "third-party service abuse" or "blind SSRF without further impact" — several programs explicitly state a policy on how much impact is required before an SSRF report is accepted.
- Metadata-endpoint reachability on infrastructure that isn't actually the target's own (a shared PaaS, a serverless platform where the metadata belongs to the platform vendor, not the program) is out of scope for that program even if technically reachable — verify whose infrastructure you actually reached before treating it as impact.
- Don't escalate into denial-of-service territory (repeated large fetches, fetch loops, resource exhaustion) to "prove" the primitive further than a single clean demonstration requires.

## Integration
- Record each tested field with `mcp__bb__record_coverage`, noting which outcome tier (blind/DNS/content/internal-target) was reached even when the result is clean, so the surface doesn't get re-walked next session.
- A DNS-only or blind signal that isn't yet a reportable finding belongs in `mcp__bb__add_primitive` — it's exactly the kind of half-result this system exists to keep instead of losing to memory.
- The assistant identifies candidate fields and proposes the test sequence and what to send to a listener you control; the human owns the listener, sends every request, and confirms what actually came back before any tier above "candidate" is claimed.
