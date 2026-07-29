---
name: pb-file-upload
description: Methodology playbook for finding file-upload flaws (extension/content-type/magic-byte bypass, stored-file exposure) on a real target. Load when testing upload/import/avatar features or when bb-next surfaces a file-upload test case.
---

# pb-file-upload

## When this applies
Any feature that accepts a file: avatar/profile photo, attachment on a ticket or message, document/import feature, bulk CSV import, logo upload, resume upload, chat file share, or an "import from URL" variant (cross-reference `pb-ssrf` if the file is fetched server-side from a URL rather than uploaded directly). Covers WSTG-BUSL-08 (unexpected file types) and WSTG-BUSL-09 (malicious file upload). The bug isn't "the app accepts files" — it's whether extension, content-type, and content are each independently validated, and whether the stored result is ever served or rendered in a context that turns permissive storage into actual impact. This is a client-independent server property: whatever the web form's `accept=` attribute or client-side JS claims to restrict, the same HTTP endpoint is reachable directly, so every check here is about what the server does when that restriction is simply absent from the request.

## First signals
- What file types the client-side hint (an `accept=` attribute, a UI dropdown) advertises versus whether the server enforces the same list at all — client-side hints are not validation.
- Where the uploaded file ends up: a path you can guess, a URL echoed back to you, or a predictable naming scheme (original filename preserved, sequential ID).
- Whether storage is same-origin with the app (served from the app's own domain — higher risk for HTML/SVG rendering) versus a separate storage domain/CDN/bucket (usually lower risk for execution, but still relevant if that domain is trusted by the app elsewhere).
- A post-upload response that echoes extra detail — a full stored path, an internal filename, a content-type the server assigned that differs from what you sent.
- Multiple upload fields with visibly different validation depth on the same app (a strict avatar upload, a loose comment attachment) — validation is frequently duplicated per-endpoint rather than centralized.
- An "import" feature (CSV/XML/JSON config import) that's really an upload with a parser attached — a different risk profile (parser behavior) from a media upload.
- A preview/thumbnail feature that renders the file after upload — a strong signal the server actually opens and parses content, not just stores bytes.
- An upload endpoint reachable from more than one client (web form, mobile API, a public partner/integration API) where each entry point might independently re-implement the same validation with different rigor.
- A "replace" or "re-upload" action on an existing object that reuses the original object's stored path/URL — worth checking separately, since overwrite semantics can differ from first-time upload validation.

Quick map of where validation gaps typically cluster, for triage when time is short:

| Validation layer | What a gap looks like | Detection probe |
|---|---|---|
| Extension | Checks only final or only first segment | Double extension |
| Content-Type | Trusts the client-declared header | Header-swap on a benign file |
| Magic bytes | Never inspected, extension/type is enough | Renamed text file, no matching header |
| Serving context | Wrong origin/content-type lets browser render | SVG/HTML-as-image |
| Access control | Stored URL guessable or unauthenticated | Cross-account fetch |

## Enumeration
1. List every upload-shaped feature: avatar, attachment, import, logo, resume, chat/message file share, bulk-data import, profile document.
2. For each, note accepted extensions as advertised, max size, and whether auth/ownership scoping applies to who can upload and who can later fetch the result.
3. Determine the storage/serving model per feature: same-origin static serving, a separate storage subdomain, a presigned/signed URL, or content proxied through the app on every fetch.
4. Note any visible post-upload processing (thumbnailing, virus-scan message, format conversion, OCR) — each is a distinct parser with its own bug surface; flag it as a candidate for separate research rather than testing it here.
5. Note whether the serving response includes hardening headers relevant to this class — `X-Content-Type-Options: nosniff` and a restrictive `Content-Security-Policy` on the storage origin change how much a content-type mismatch actually matters in a browser, so record their presence or absence per storage origin, not per file.
6. Check whether the same object type (e.g. "attachment") is reachable through more than one upload route (web composer, email-to-ticket ingestion, a public API) — each ingestion path may run different validation code even though the stored result lands in the same place.
7. Coverage is exhausted once every upload field has a recorded observation for extension enforcement, content-type/magic-byte enforcement, and serving context — not once a handful of extensions have been tried on the first field found.

## Test procedure
1. Baseline: upload a plainly allowed file (a small `.txt` or `.png`) and record exactly how it's stored and served — URL, returned content-type, filename handling.
2. Extension-check probe: rename a harmless text file with a double extension (e.g. `notes.txt.php`, `image.png.html` — inert content, no script) and observe whether the check inspects only the final segment, the first segment, or performs a real allowlist match. Record what the server stored it as and what content-type it later served, not just whether the upload succeeded.
3. Content-type probe: upload the same harmless file with its `Content-Type` header manually changed to a value outside the declared allowlist, and observe whether the server trusts the client-declared header or inspects content independently.
4. Magic-byte probe: upload a plain-text file renamed with an image extension and no image header, to distinguish "checks the extension" from "checks the leading bytes."
5. Case/trailing-character variants: try alternate casing (`.PHP`) or a trailing dot/space as a check on whether the allowlist match is exact-string or normalized — a normalization check, not an attempt to smuggle an executable payload through.
6. SVG/HTML-as-image probe: if images are accepted, upload a minimal, inert SVG or HTML file (comment-only body, no script) with an image extension, and check whether it's served back with a content-type that would let a browser render it as markup rather than display it as an image — this is the detection step for stored-XSS-via-upload; payload construction is out of scope here.
7. Filename/path-control probe: if the filename you supply appears to influence the stored path rather than being replaced with a generated ID, try a filename containing a path-separator-like segment and observe whether it's normalized — cross-reference `pb-path-traversal` if this looks promising, since it's the same class reached through a different entry point.
8. Access-check probe: once a file is stored, check whether its serving URL requires the same authentication/ownership as the upload did, or whether a guessable URL exposes it to any authenticated (or unauthenticated) user.
9. Metadata/filename-field probe: if the upload form carries a separate display-name or description field distinct from the actual filename, check whether that field is rendered unescaped elsewhere in the app (a file listing, a shared-with-me view) — a common secondary injection point that has nothing to do with the file's own content or extension.
10. Hardening-header check: alongside every fetch above, record `X-Content-Type-Options` and `Content-Security-Policy` on the response — their absence is what lets a content-type mismatch actually be exploited in a browser, and their presence is a mitigating factor worth stating even when a bypass is otherwise confirmed.

### Worked example of a double-extension result
```
Upload:   avatar.png.php  (content: plain ASCII text, no script)
Response: 200, stored as "avatar.png.php"
Fetch:    GET /uploads/avatar.png.php
          -> 200, Content-Type: text/html; charset=UTF-8

Baseline: avatar.png (real PNG bytes)
Fetch:    GET /uploads/avatar.png
          -> 200, Content-Type: image/png
```
The extension survived unmodified and the server picked a content-type from it rather than from the actual bytes — that's the finding's mechanism, stated precisely: extension allowlist checks the wrong segment, content-type is extension-derived not content-derived. Nothing here required the file to contain a script for the observation to be conclusive.

## Evidence to capture
- The exact file sent (name, declared content-type, and a description of the benign content used) and the full multipart request.
- The stored filename/path/URL the server assigned, and the content-type header served back on retrieval.
- For the SVG/HTML/double-extension probes: the full response headers on fetch (content-type, content-disposition) — this proves execution-context risk, not the upload response alone.
- Whether fetching the stored file required the uploader's own session, any authenticated session, or no auth at all.
- The presence or absence of `X-Content-Type-Options`/`Content-Security-Policy` on the storage origin's response, since it materially affects whether the report can claim browser-side execution risk.
- Store via `mcp__bb__store_evidence`.

## Escalation
- Extension/content-type bypass alone is a primitive, not a finding, until paired with a serving context that renders or executes the result — bank it via `add_primitive` the moment it's confirmed, even before serving context is known.
- Stored file served from the app's own origin with a browser-renderable content-type is the path to stored XSS — frame the impact as "this becomes stored XSS when viewed," and let the human confirm actual rendering in a real browser before calling it more than a primitive.
- Filename/path control on the stored location escalates toward overwrite of another user's file or, if steerable outside the intended directory, into `pb-path-traversal`'s territory — hand it off rather than duplicating the write-up.
- A processing step (thumbnailing, conversion, document parsing) that errors unusually on a malformed-but-harmless input is worth noting as a lead for a parser-specific issue, but testing a parser exploit is out of scope here.
- Check whether a bypass found on the loosest field (e.g. attachments) also reaches the strictest field's serving path (e.g. avatars shown to every user) — shared backend code multiplies impact.
- A confirmed unauthenticated or cross-account read of another user's stored upload (from the access-check probe) is a distinct IDOR-shaped finding on top of any content/type gap — cross-reference `pb-idor-bola` and report both mechanisms rather than merging them into one.

## Out-of-scope traps
- A file that uploads successfully but is never served back anywhere, or is only ever served with a forced `Content-Disposition: attachment` and no content-type ambiguity, isn't reportable on its own — confirm the file is actually reachable in a rendering context first.
- Storage on a separate, sandboxed domain that never executes scripts and isn't trusted by the main app usually blunts stored-XSS impact even with a wrong content-type — check the serving domain's actual behavior, not just that the type looks wrong.
- Client-side-only extension filtering with no server-side check ever exercised is only worth reporting once you've shown the server-side path independently accepts what the UI blocks.
- An antivirus/malware-scan rejection is a sign a control exists, not a bypass — a harmless test file isn't what the scanner is designed to catch.
- Size-limit or rate-limit enforcement working as intended is not a finding just because a large or repeated upload was inconvenient to test.
- Never construct or upload an actual web shell, script payload, or anything designed to execute code on the target — the probes above are sufficient to prove the validation gap; anything beyond that is the human's call under program rules.
- `X-Content-Type-Options: nosniff` combined with a served `Content-Disposition: attachment` on the storage origin often neutralizes a content-type mismatch in practice — verify both headers before claiming a rendering-based finding still holds.

## Integration
- Record every field tested with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, using test_case_ids like `upload-ext-bypass`, `upload-contenttype-bypass`, `upload-magicbyte-check`, `upload-storage-context` per field.
- Bank a confirmed bypass with unclear serving impact via `mcp__bb__add_primitive` — "accepts `.html` disguised as `.png`, serving context not yet confirmed executable" is exactly the half-finding this system exists to keep.
- File an untested hypothesis (e.g. "the avatar CDN might be same-origin enough to matter") as a lead via `mcp__bb__add_lead` rather than testing further without the human's go-ahead.
- The assistant proposes which benign probe files to send and what to look for; the human constructs and sends every file and reads back the actual headers/body. Never claim a finding is real — that's `mcp__bb__promote_to_finding(..., human_confirmed=True)` after the human's own reproduction.
