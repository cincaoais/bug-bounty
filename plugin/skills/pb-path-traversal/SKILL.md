---
name: pb-path-traversal
description: Methodology playbook for finding path/directory traversal on a real target. Load when testing filename/path parameters, download/export/include features, or when bb-next surfaces a path-traversal test case.
---

# pb-path-traversal

## When this applies
Any parameter that looks like it names or partially names a location the server resolves to a filesystem path: `?file=`, `?path=`, `?template=`, `/download/{filename}`, `/export?report=`, `/static/{path}`, a "theme"/"locale" selector that maps to a file server-side, or a ZIP/archive extraction or backup-restore import feature. Covers WSTG-ATHZ-01 (directory traversal / file include). The question is whether the server normalizes and constrains the resolved path to an intended directory, or whether attacker-supplied `../`-style segments (or platform/encoding variants of the same idea) escape that boundary. This is a containment property, not a blocklist property: the correct fix is resolving the path and verifying it still sits under the intended root, and a lot of broken implementations instead try to blocklist specific sequences, which is exactly what the encoding and absolute-path checks below are designed to reveal.

## First signals
- A parameter value that is, or resembles, a filename or relative path, inferred from behavior (different content per value) rather than source access.
- An error message that leaks a filesystem path or a "file not found: /var/app/uploads/..." string — this tells you the parameter reaches a real path-resolution call before a single traversal sequence is sent.
- A "download," "export," "print," or "report" feature that takes a filename/report-ID and serves a file — often less scrutinized than the main upload/storage path because it "just reads what write-side already validated."
- A theme, locale, template, or plugin-name selector that likely maps directly to `templates/{value}.html`-style paths server-side.
- Archive upload/extraction features (ZIP import, backup restore) where a crafted archive entry's own internal path might be honored on extraction — a distinct entry point from a URL parameter, sometimes called "zip slip" conceptually.
- A parameter accepted as a bare filename or path where the app's own file-listing/attachment feature shows legitimate values — giving a real anchor to test against instead of guessing blind.
- Static file serving behind a reverse proxy or app framework where the same path parameter is handled at two layers — normalization done by one and not the other is a common bypass source.
- A "file include" style parameter (a plugin loader, a language/locale-pack selector, a module name) that maps a short identifier onto a full path server-side with string concatenation rather than a lookup table.
- Symlink- or mount-aware storage (user directories mapped under a shared root) where a traversal-adjacent bug might cross between two users' otherwise-separate storage areas rather than reaching the OS itself — a distinct, IDOR-flavored variant worth noting as such.

Quick map of where a normalization gap typically hides, for triage when time is short:

| Check performed | What's missed | Detection probe |
|---|---|---|
| Strips literal `../` | Encoded/double-encoded variant not decoded first | `%2e%2e%2f` |
| Rejects relative traversal | Absolute path replaces base entirely | Absolute path input |
| Checks path string | Never re-checks the resolved/canonical path | Compare declared vs. actual serving root |
| Validates URL parameter | Archive entry names on extraction ungoverned | Crafted archive entry path |

## Enumeration
1. List every parameter across the app that accepts a filename, path fragment, template name, locale code, or report identifier — query strings, path segments, form fields, and JSON bodies alike.
2. For each, note a legitimate value from normal use, and identify one benign file within the app's own known directory structure to use as a traversal *target* — a static asset, a public template, a known-readable config sample — rather than a system path.
3. Note the underlying platform if discoverable (Linux vs. Windows separators, case sensitivity), since traversal depth and separator style differ.
4. Check whether the same parameter is reachable through more than one route (web UI download link vs. a "share this export" API vs. a mobile equivalent) — normalization is commonly applied inconsistently across duplicated code paths.
5. Identify any encoding layers between you and the file-resolution code (URL-decoding, a reverse proxy, a WAF) — behavior can differ meaningfully between a raw `../` and an encoded or double-encoded variant; this is an observation about normalization order, not an evasion technique.
6. Note whether the parameter's legitimate values come from a small, enumerable set (a fixed list of report types, a small set of locales) versus free-form text — a free-form parameter that reaches the filesystem is inherently higher risk, since a fixed-set parameter may simply never accept anything traversal-shaped in the first place.
7. Coverage is exhausted once every filename/path-shaped parameter has a recorded observation for baseline behavior, a single normalized traversal probe, and at least one encoding variant — not once the first parameter tried came back clean.

## Test procedure
1. Baseline: request the feature with its normal, intended value and note the exact response — status, content-type, body shape, size.
2. Establish a safe target file: pick a file already known to exist and be non-sensitive within the app's own tree (a static asset, a sample template, something the app itself lists elsewhere) — never a system file like `/etc/passwd` or `C:\Windows\win.ini` as the initial probe target.
3. Single traversal probe: substitute a small number of `../` (or `..\`) segments aimed at the safe target instead of the intended file, and compare against the baseline — a recognizably different file's content coming back is the signal, not a changed status code alone.
4. Normalization check: if the direct probe is blocked, try one encoded variant (URL-encoded `%2e%2e%2f`, or the platform's alternate separator) to distinguish "sequences are stripped/rejected" from "sequences are checked only in literal, unencoded form."
5. Absolute-path check: test whether an absolute path outright is honored differently than a relative sequence — some validation only strips leading `../` and never considers an absolute path replacing the base entirely.
6. Legacy-truncation check: on plausibly old stacks (older PHP, certain native extensions), note whether a trailing null-terminator-style suffix changes behavior — a normalization observation, not a technique to force a specific extension.
7. Archive-extraction variant: with a small, harmless archive containing one entry whose internal name includes a traversal sequence, observe where extraction actually places the file — target only a location still inside your own test workspace, never outside the app's own designated storage.
8. Confirm containment on a clean result: verify a failed probe is a genuine path-resolution denial (e.g. a "not found" for a path that plainly doesn't exist) rather than the feature always returning that response regardless of input — a negative control matters here as much as in IDOR testing.
9. Cross-route parity check: repeat the same baseline-plus-single-probe pair (steps 1–3) against every sibling route carrying the same parameter shape identified in enumeration — a fix on the primary download page is frequently absent on an export, print, or admin-lite variant.

### Worked example of the comparison
```
Baseline:
  GET /export?report=quarterly.pdf  -> 200, PDF report content

Safe-target probe:
  GET /export?report=../../static/robots.txt  -> 200, body is the app's robots.txt

Negative control:
  GET /export?report=does-not-exist.pdf  -> 404, {"error": "report not found"}
```
The middle result is the finding: a file outside the reports directory came back through a parameter meant only to select among reports. The negative control shows the endpoint can genuinely deny an unresolvable path, which rules out "it always returns 200" as an alternate explanation.

## Evidence to capture
- The exact parameter, full request, and every value tried (baseline, safe-target probe, encoded variant), with the response for each.
- The specific content proving the safe target file's content came back (a string only that file would contain), not just a changed status or size.
- Any filesystem path fragment revealed via an error message, verbatim.
- For archive-extraction findings, the archive's entry name and the actual location the extracted file ended up at.
- The platform/encoding detail that mattered (e.g. "blocked when unencoded, served when `%2e%2e%2f`-encoded") — central to explaining root cause.
- For cross-route parity results, at least one clear pass/fail pair per sibling route tested, not only the first route that confirmed the bug.
- Store via `mcp__bb__store_evidence`.

## Escalation
- Reading one safe, known app file proves the mechanism; escalation is naming what *sensitive* file classes the same mechanism could reach in principle — source revealing secrets, configuration with credentials, other users' adjacently-stored uploads — with the human deciding how far to actually verify beyond the initial safe-file proof.
- A read-only traversal with a write/extraction counterpart (the archive-import case) is a materially higher-severity primitive — arbitrary file write/overwrite — and should be flagged distinctly from read-only disclosure.
- If the traversal reaches application source, check whether it discloses further primitives (hardcoded secrets, other endpoints, a JWT signing key) and bank each separately rather than folding everything into one write-up.
- A traversal reachable pre-authentication is a materially different severity than one requiring a valid session — state the auth requirement explicitly.
- If the same base parameter is shared by multiple features (download, preview, export), check whether the traversal reaches all of them or is specific to one — broader reach is a stronger, more systemic finding.
- A symlink/mount-boundary variant that crosses between two users' storage areas rather than into the OS is effectively an IDOR reached via path manipulation — bank it as a primitive and cross-reference `pb-idor-bola` when writing it up, since the report should credit the correct root cause.
- Encoding-dependent bypasses (works only when double-encoded, or only through a specific proxy layer) are worth stating precisely in the escalation notes, since they tell the triager exactly which layer needs the fix — the app's own normalization, or the proxy's.

## Out-of-scope traps
- A path that fails to escape the intended directory — normalized by the framework, or the app double-checks the resolved path is still within an allowed root — is a clean result, not a partial finding; record it and move on.
- Being served a *different but still-intended* file (the parameter is really an enum of report names, and an unmatched traversal sequence just falls back to a default) is not traversal — confirm the returned content is actually the targeted file, not a default/error page returning 200.
- A path parameter that's really just an opaque ID looked up in a database, never touching the filesystem, doesn't belong here — if it's an ID with a missing ownership check, that's `pb-idor-bola` instead.
- A verbose error revealing a path without any actual content read achieved is a weaker information-disclosure lead, not a demonstrated read — don't conflate the two.
- Traversal confirmed only against files already reachable through their normal path anyway (your own uploaded file) demonstrates the mechanism but not unauthorized access — pick a genuinely out-of-normal-reach safe file for the strongest proof.
- Never attempt to read actual system-sensitive files (`/etc/passwd`, `/etc/shadow`, SAM/registry hives, cloud credential files) to establish the initial finding — the safe in-app target is sufficient evidence; going further is the human's call under program rules, not a default next step.
- A parameter that accepts a path but resolves it through a fixed, enumerable allowlist (only ever serving one of N known-good files regardless of what traversal-shaped input is supplied) is a clean result — confirm the returned content never varies before ruling this out as a false lead.
- A traversal sequence that's accepted syntactically (no error) but resolves to nothing useful because the app runs in a container/chroot where there's genuinely nothing sensitive above the intended root is a weaker finding than the same mechanism on a conventional host — note the runtime environment when it affects how much the mechanism actually proves.

## Integration
- Record each parameter tested with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, using test_case_ids like `traversal-baseline`, `traversal-encoded-variant`, `traversal-archive-extract` — a clean containment result is as valuable to record as a hit.
- Bank a confirmed traversal mechanism with unclear sensitive-file reach via `mcp__bb__add_primitive` — "parameter X reads arbitrary files within the app's file-serving directory, sensitive-file reach not yet confirmed" is real and reusable even before scope is agreed.
- File an untested hypothesis (e.g. "this export parameter might share the confirmed-vulnerable download parameter's file-resolution code") as a lead via `mcp__bb__add_lead`.
- The assistant proposes which safe target file to use and what sequence to try; the human sends every request and confirms what content actually came back. Never claim a finding is real — that's `mcp__bb__promote_to_finding(..., human_confirmed=True)` after the human's own reproduction.
