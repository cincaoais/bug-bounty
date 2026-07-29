---
name: pb-secrets-exposure
description: Methodology playbook for finding exposed secrets and artifacts on a real target. Load when testing for leaked credentials/config or when bb-next surfaces a secrets-exposure test case.
---

# pb-secrets-exposure

## When this applies
Any surface that might serve a file or value never meant to be public:
- A `.git`/`.svn` directory left under webroot.
- A `.env`/config file, or a backup artifact (`.bak`, `.old`, `~`, `.zip`, `.tar.gz`, `.sql`).
- A verbose debug/error endpoint that echoes internal state.
- An open cloud storage bucket.
- A hardcoded key or token shipped inside a JS bundle or mobile binary.

Covers WSTG-CONF-04 (backup/unreferenced files), WSTG-CONF-03 (file extension handling), WSTG-CONF-11 (cloud storage), and WSTG-ERRH-01/02 (verbose error/stack-trace disclosure).
Overlaps `bb-code` for anything embedded in shipped source. The question throughout is whether the artifact is reachable unauthenticated and contains something the program didn't intend to publish — not whether a secret-looking string exists somewhere.

## First signals
- `.git/HEAD` or `.git/config` returning 200 with real git content.
  - Check the body, not just the status — a custom 404 page can still return 200.
- `.env`, `.env.production`, `web.config`, `appsettings.json`, `config.php.bak` reachable directly.
  - Especially on subdomains built by quick static-site/CI pipelines that sometimes upload the whole working tree instead of only the build output.
- A backup-style or editor-artifact suffix sitting next to a live file of the same base name.
  - `app.js` alongside `app.js.bak`, `index.php~`, a stray `.swp`.
- Directory listing enabled on a path that would otherwise be invisible.
  - `/backup/`, `/uploads/`, `/old/` — the listing itself hands you the enumeration.
- A cloud storage bucket responding with a listable-objects response instead of access-denied.
  - Guessed from a naming convention, discovered in a JS bundle, or surfaced as a CNAME target while working `pb-subdomain-takeover`.
- A verbose 500 page, stack trace, or debug console reachable without special conditions.
  - Routinely leaks file paths, environment variable names, sometimes values.
- A key-shaped string in a JS bundle.
  - AWS-style access keys, `sk_live_`/`sk_test_` Stripe keys, `ghp_`/`github_pat_` tokens, a suspiciously long-lived JWT, a base64 blob sitting near an auth-header assignment.
  - Cross-reference `bb-code` output rather than re-grepping bundles already covered there.

## Enumeration
1. Build a standard sensitive-path checklist once, then run it across every in-scope host.
   - `/.git/HEAD`, `/.git/config`, `/.svn/entries`, `/.env`, `/.env.bak`, `/config.yml`, `/wp-config.php.bak`, `/backup.zip`, `/dump.sql`, `/.DS_Store`, `/web.config`, plus any path pattern specific to the target's known stack.
2. Cross-reference every host already ingested from `bb-recon`.
   - This is a breadth pass across the whole in-scope host list, not a deep dive on one host.
3. Enumerate cloud storage references separately.
   - Bucket-style names seen in DNS, in JS bundles (`s3.amazonaws.com/...`, `storage.googleapis.com/...`), or named inside any exposed config file.
4. For JS bundles and mobile binaries already pulled for `bb-code`, treat the secrets grep as one pass of that same reading exercise.
   - Not a fresh re-download and re-read.
5. Capture verbose-error/debug surfaces the moment they appear incidentally during other testing.
   - A stack trace triggered while testing something else, rather than waiting for a dedicated sweep.
6. The surface is covered once the standard checklist has run against every in-scope host, every JS bundle has had one secrets pass, and every cloud-storage reference found anywhere has been checked for listability.
   - Not once a handful of paths on the main host came back clean.

## Test procedure
1. Request the candidate path and read the full response, not just the status.
   - A custom error page can return 200 with content that looks like "not found," and a real hit can occasionally arrive on a non-200 status.
2. For a `.git` hit, confirm it's a real, current repo before treating it as more than a lead.
   - Readable `HEAD`, `config`, at least one object — an intentionally-public open-source mirror is a different result.
3. For a suspected backup/config file, confirm the content is genuinely sensitive.
   - Real connection strings, real keys, real internal paths — not a checked-in template with placeholder values (`your-api-key-here`, `CHANGEME`).
4. For a cloud bucket, the minimal non-destructive proof is a listing request.
   - Does the provider return an object list rather than access-denied. Don't download, modify, or delete contents beyond what's needed to confirm listability and, if permitted, sample a small number of file names.
5. For a live-looking credential, the proof of validity is the smallest call that confirms acceptance.
   - An unauthenticated "whoami"/introspection-style call the provider itself offers for that key type — never a call that reads, writes, or exfiltrates the data the key protects.
   - If no safe minimal-validity check exists for that credential type, stop at "found, valid-shaped, unconfirmed" rather than improvising a riskier one.
6. Never pivot with a found credential.
   - Don't use it to log into the target app, don't enumerate further resources with it, don't chain it into a second system — it's a distinct evidence item, not a foothold to keep exploring with.
7. For verbose error/debug endpoints, trigger the minimum input needed to produce the disclosure once, capture it, and stop.
   - Repeated triggering to "see what else leaks" adds probing/DoS risk without adding evidentiary value.

## Evidence to capture
- The exact request (method, full URL) and full response for each confirmed exposure.
  - Headers and enough body to prove sensitivity, not a full large-file dump.
- For credentials: a redacted form for the report, the full value stored only in the evidence store, and the specific minimal validity check performed plus its result.
  - Never the output of using the key beyond that check.
- For buckets: the listing response, or a representative excerpt, and file names present — not full object downloads.
- For `.git` exposure: proof of a real, current repo — one meaningful file or commit reference recovered, not a full local clone kept as evidence.
- Timestamp of discovery.
  - Exposed artifacts get removed quickly once found, and the window matters for triage.
- Store everything via `mcp__bb__store_evidence`.
  - Never paste a live secret in plaintext into chat or notes — reference it as stored evidence instead.

## Escalation
- A single exposed non-sensitive file — a default framework README, a public changelog — is not a finding.
  - Escalate only artifacts that actually name internal infrastructure or contain credential material.
- Severity scales with what the secret unlocks, not with the fact that something was found.
  - A key scoped to one low-value read-only resource is Low/Medium; a key with broad write/admin scope, or one unlocking a second in-scope system, is High/Critical — name the specific scope rather than assuming worst-case from the key's shape.
- A `.git` exposure escalates sharply if the *history*, not just the current tree, contains a credential later removed.
  - Check commit history for that pattern once repo access is confirmed — "secret was in the code once" is a common, high-value variant.
- Chain with `pb-idor-bola`/`pb-ssrf` when an exposed config file reveals an internal hostname or endpoint.
  - The exposure is the entry, but the second system's own access control is a separate bug to test and report distinctly.
- An open bucket containing PII or authentication material — session tokens, password hashes — is materially bigger than one containing only static assets.
  - Name the data class explicitly.

## Out-of-scope traps
- An example/placeholder key from well-known SDK documentation, or an obvious `test`/`demo` credential, is not a finding.
  - Confirm the value doesn't match a published example before reporting.
- A key already expired, revoked, or explicitly scoped to a sandbox/test environment the program has disclaimed is not in-scope impact even if technically reachable.
  - Check program rules on test/staging credentials.
- Self-hosted or intentionally-committed test fixtures — a `.env.example`, an obviously-fake seed-data dump — are working as intended.
  - Verify the data is real before treating a "database dump" as a breach.
- A `.git` directory that 404s cleanly, or a bucket that returns proper access-denied, is coverage, not a lead.
  - Record the clean result.
- Information already intentionally public — an open-source component's own repo, a documented client-side key meant to be public (a referrer-restricted maps key) — is not a secret.
  - Check whether the program's own docs describe it as public by design.
- Verbose errors leaking only generic framework version info already disclosed elsewhere, e.g. via headers, add little beyond a duplicate of an existing low-severity finding.
  - Don't inflate a repeat disclosure into a new one.

## Integration
- Record every path/host checked with `mcp__bb__record_coverage`, including clean results across the standard checklist.
  - A clean sweep is coverage worth keeping.
- Bank a found-but-unconfirmed secret — valid-shaped, validity check not yet authorized or run — as a primitive via `mcp__bb__add_primitive` rather than losing it.
- The assistant identifies candidate paths/patterns and describes the minimal validity check for a given credential type.
  - The human sends every request, including the validity check itself, and judges whether returned content is genuinely sensitive.
- Never claim a secret confirmed live or a bucket confirmed exposed until the human has run the check and reported the result.
  - `record_coverage(status="confirmed")` follows the human's confirmation, not a pattern match on the string's shape.
