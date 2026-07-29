---
name: pb-injection
description: Methodology playbook for finding SSTI, OS command injection, and XXE on a real target. Load when testing a template-rendering, shell-invoking, or XML-parsing surface, or when bb-next surfaces one of these test cases.
---

# pb-injection

## When this applies
- **SSTI**: input that ends up inside a server-rendered template — customizable email/notification templates, "preview" features, report/invoice generators, CMS page-builder fields, error pages that echo input through a templating engine. Covers WSTG-INPV-11.
- **Command injection**: input that plausibly reaches a shell invocation or subprocess call — file-conversion tools (image resize, PDF generation, video transcode), ping/traceroute/network-diagnostic features, filename/path/hostname parameters handed to a CLI utility, archive-extraction naming. Covers WSTG-INPV-12.
- **XXE**: any endpoint accepting and parsing XML, or a format that resolves to XML underneath (SOAP, some RSS/Atom import, DOCX/XLSX/ODF uploads which are zipped XML, SAML responses, legacy API content-types) where the parser might process entities or DTDs. Covers WSTG-INPV-07.

## First signals
**SSTI** — a reflected value changed in a way plain HTML-escaping wouldn't explain (an evaluated-looking result where none was in the input); a "customize your notification/report template" feature with visible templating delimiters (`{{ }}`, `${ }`, `<% %>`) in existing templates or docs; an error naming a template engine (Jinja2, Twig, FreeMarker, Velocity, Handlebars) directly.

**Command injection** — a feature whose whole job maps onto a CLI tool (format conversion, ping/resolve, thumbnailing, archive extraction, a diagnostic tool); a parameter resembling a filename/path/hostname handed to an external process, especially alongside visible per-request temp files or spawned processes; shell metacharacters handled inconsistently in a filename/hostname field (accepted generally, mangled specifically around characters that matter to a shell).

**XXE** — any `Content-Type: application/xml`/`text/xml` endpoint, or a file upload whose format is XML-based even if the UI doesn't call it that (DOCX, XLSX, ODT, SVG, config-import); a SOAP API or "legacy"/enterprise integration endpoint, which disproportionately still runs older, permissively-configured parsers; an XML-accepting endpoint that also does SAML, a heavily-targeted XXE surface historically.

## Enumeration
**SSTI**: (1) list every feature offering user-influenceable "template-like" text — email/notification customization, invoice/report templates, page builders, message previews. (2) Note any delimiter syntax already visible in the UI/docs — it often names the engine family before you send anything. (3) Separate "rendered back to me" from "stored and rendered into a template evaluated later for someone else" (a ticket-triggered notification email) — the latter has a different delivery/impact story.

**Command injection**: (1) list every feature that plausibly shells out — format conversion, network diagnostics, archive handling, PDF/image generation, an admin "run this against the server" tool. (2) For each, note the exact parameter and its expected shape (filename, hostname, numeric option) — risk concentrates where that shape is loosely validated. (3) Note whether the feature is synchronous (result in the response) or async (job queue, background worker) — async surfaces are easy to overlook since there's no immediate response to inspect.

**XXE**: (1) list every endpoint accepting XML directly or an XML-based file format, including undeclared ones (a "config import," an SVG avatar upload, a DOCX report upload). (2) Note whether the parser/library in use is identifiable (error messages, response headers, SDK fingerprint). (3) Note whether XML is parsed synchronously and inline versus off to a backend worker (a converted PDF, an indexed document) — a delayed pipeline changes what evidence is available and when.

Coverage is exhausted once every candidate surface across all three sub-classes has a recorded result — a template-looking feature that turned out to be safe, sandboxed substitution is still a completed, valuable test.

## Test procedure

### SSTI
1. Baseline: submit a harmless unique marker and confirm it reflects verbatim, unmodified.
2. The standard, minimal probe to distinguish a real template engine from plain reflection is a basic arithmetic expression using the syntax already observed or a common delimiter family (multiplying two small numbers via the engine's own expression syntax). If the response shows the COMPUTED result rather than the literal expression text, the input is being evaluated as template code — that alone is sufficient to prove SSTI; no further payload is needed at the detection stage.
3. If arithmetic evaluates, identify the engine family from which specific delimiter/operator style actually evaluated, then stop at identification. Don't chain into a working code-execution proof — that step needs explicit sign-off outside this ingest-only, defensive posture.
4. If arithmetic does NOT evaluate but the value still transforms unexpectedly, suspect a partial filter or a non-template transform (a markdown processor, a string formatter) rather than SSTI — describe the actual observed transform.

### Command injection
1. Baseline: submit a normal, valid value and note the full expected output (a converted file, a ping result, a resolved hostname).
2. The standard, minimal detection probe is a single OS-appropriate command-separator character followed by a harmless, side-effect-free proof-of-execution marker. The concept is "cause one distinguishable second command to run" — never a real payload (no file writes, no network callbacks, no reverse shells, nothing destructive or resource-heavy). The marker's output appearing in the response, or a clearly intentional and observable timing/behavioral change, is the entire proof needed.
3. If the separator has no effect, try one different, common separator variant only far enough to establish whether shell interpretation happens at all versus a safe argument-array (`execve`-style) call, which metacharacters can't reach — stop once that's established, not once every known separator has been tried.
4. Never chain into an interactive shell, an outbound network connection, or persistence. The detection probe's entire job is proving execution occurred, once, harmlessly, and observably.

### XXE
1. Baseline: submit valid XML in the expected shape and confirm normal processing.
2. The standard, minimal detection probe is a benign, DTD-only definition of a locally-defined (not externally fetched) entity that resolves to a short string already known to you. If that string appears reflected in the response, the parser processes DTDs/entities at all — this alone establishes the parser's posture without an external or out-of-band reference.
3. Only if internal entity resolution is confirmed, treat external/parameter entity support as a structural question, not a further live probe by default: identify the parser/library and reason from its documented defaults where possible. If confirming external-entity handling is genuinely necessary, point it only at infrastructure you control (mirroring the SSRF-detection posture in `pb-ssrf`) — never at an internal target, and never as a means to read a real file.
4. Test the same input shape across every place it's accepted (direct API, wrapped in SOAP, embedded in a zipped office-document format) — a hardened parser on the main endpoint doesn't guarantee the same hardening on a secondary import path using the same underlying library.
5. Cross-reference this system's own ingest posture: `mcp__bb__ingest_file` and `store_evidence` exist specifically so XML/config data pulled from a target or a Burp export is parsed defensively — the same "don't process untrusted DTDs" principle under test on the target applies to this tooling. Never hand-paste a target's raw untrusted XML into anything other than the redacting `store_evidence`/`ingest_file` path.

## Evidence to capture
- **SSTI**: the exact expression sent, the raw response showing computed vs. literal output, and the specific delimiter/engine family identified.
- **Command injection**: the exact separator and harmless marker used, and the raw response/output proving the marker executed — never capture output beyond what proves execution (no directory listings, file contents, or environment dumps).
- **XXE**: the exact XML/DTD sent and the raw response showing the internal entity resolved; for any external-entity structural observation, evidence of parser/library identification rather than an actual out-of-band retrieval.
- All three: baseline request/response next to the probe request/response, stored via `mcp__bb__store_evidence`, so the delta is self-evident to a triager.
- Timing evidence wherever a delay-based signal was used, with the delay value stated explicitly.

## Escalation
- **SSTI**: engine identification plus confirmed expression evaluation is the ceiling for a detection-stage report. Naming the specific engine and confirming code evaluation (not full execution) is itself a strong, reportable primitive — frame the write-up around "this engine's syntax evaluates attacker input" and let the program's own triage pursue further impact.
- **Command injection**: a confirmed harmless marker execution is the primitive. Escalating to proving file read/write or network reachability moves outside a detection playbook's remit — name the primitive and the realistic blast radius (what account the process runs as, what it can plausibly reach) without demonstrating it further.
- **XXE**: internal-entity resolution alone is a real, bankable primitive. The jump from there to file disclosure or SSRF-via-XXE is a distinct, higher-impact escalation — cross-reference `pb-ssrf` for that chain and hold it to the same "point only at infrastructure you control" discipline.
- Across all three: if the underlying process/account has broad reach (a template engine with filesystem access, a command run as a privileged service account, a parser inside a service with internal network access), name that reach explicitly — severity comes from what the primitive can reach, not how cleverly it was triggered.
- Bank each confirmed detection (engine identified, marker executed, entity resolved) via `add_primitive` even when deliberately stopping short of full exploitation — that's the correct, intended outcome here, not an incomplete one.

## Out-of-scope traps
- **SSTI**: a value merely escaped or reformatted differently, or passed through a non-evaluating string formatter with no attacker-controlled format string, is not SSTI — confirm actual expression evaluation, not just unusual-looking output.
- **Command injection**: a feature using a native library call (a language's built-in image-resize or DNS API) rather than shelling out to a CLI binary cannot have command injection regardless of how "shell-like" it looks from the UI — check for actual process-spawn behavior first.
- **Command injection**: an argument-array (`execve`-style) call with no shell interpretation step isn't vulnerable to metacharacter injection the way a shell string-concatenation call is — a probe with no effect may mean "safe by design," not "try harder."
- **XXE**: many modern XML libraries disable external entity/DTD processing by default (recent Java, .NET, and Python XML libraries) — no entity resolution is a real, valid "not vulnerable" result, not a reason to escalate the probe.
- **XXE**: a parser resolving internal entities but visibly blocking anything external (a distinct error only on the external-reference test) is a materially smaller finding than full external/parameter entity support — report the actual boundary observed.
- All three: behavior only reachable from an already-privileged internal context (an admin-only report builder requiring an admin session to trigger) is a much weaker finding — grade against the access level actually required, per program policy.

## Integration
- Record each tested surface with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, using sub-class-scoped test_case_ids (`ssti-arithmetic-probe`, `cmdi-separator-probe`, `xxe-internal-entity`) rather than one blanket "injection" result per endpoint.
- Bank each confirmed-but-deliberately-limited detection (engine identified, marker fired, entity resolved) via `mcp__bb__add_primitive` — these are exactly the half-results this system exists to keep instead of losing to memory.
- The assistant proposes which surfaces, sub-class, and probe to try next; the human sends every request and reads the actual response before anything above "candidate" is claimed.
- Never assert SSTI, command injection, or XXE is confirmed from a described behavior alone — that's `record_coverage(status="confirmed")` or `promote_to_finding(..., human_confirmed=True)` after the human's own reproduction.
