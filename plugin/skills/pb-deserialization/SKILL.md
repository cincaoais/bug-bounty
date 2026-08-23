---
name: pb-deserialization
description: Methodology playbook for unsafe deserialization, prototype pollution, and parser-class vulnerabilities. Load when a feature accepts serialized data (Java/PHP/Python/.NET), performs JSON deep merges, parses XML/SOAP/Office input, or when bb-next surfaces a deserialization test case.
---

# pb-deserialization

## When this applies
- Serialized data enters the application: Java `readObject`/`XMLDecoder`, PHP `unserialize`/phar deserialization, Python `pickle.loads`, .NET `BinaryFormatter`/`XmlSerializer`.
- Serialized-looking values in the wild: base64 or hex blobs in cookies/parameters, `rO0AB` (Java), `a:{...}` / `O:8:` (PHP object) prefixes.
- JSON deep-merge or deep-copy operations on user input (Node.js prototype pollution).
- `yaml.load` without a safe loader, XML import/SOAP endpoints, Office/Excel parsing, SVG upload.
- Code audit surfaced a dangerous function (see pb-source-audit).

Division of labor: basic XXE lives in `pb-injection` (its input-reaches-parser family). This playbook owns deserialization, prototype pollution, and the parser-class attacks *beyond* a simple XXE read — the two cross-reference rather than duplicate.

## First signals
- A cookie, hidden field, or parameter whose value is a long base64 blob that decodes to a serialization format — the format prefix alone identifies the language and the risk.
- Error messages naming classes: `java.io.ObjectInputStream`, `unserialize()`, `pickle`, `ObjectManager` — the parser is talking, and class names in errors are the deserialization fingerprint.
- A feature that "imports" XML/Excel/CSV, a SOAP endpoint, or document preview/conversion — parsers are the least-guarded input path in most apps.
- An object-merge behavior: configuration or query parameters merged deeply into app state, or an API that accepts a full JSON object and merges it into a user record.
- YAML config or import features where the loader flavor isn't visible.
- Timing or reflection-visible behavior that changes when you alter a serialized field (a value you "shouldn't" control affecting a response) — the app is reading more of your blob than the UI shows.

## Enumeration
1. Inventory every place serialized or parsed data enters: cookies (PHP/Laravel sessions are a classic), request parameters, file imports (XML/Excel/Office/SVG), SOAP interfaces, message queues, template/cache keys.
2. Identify the language and format for each entry point — the prefix, the base64/hex wrapper, the field names. Format identification comes before any payload thinking.
3. For deep-merge features, list every merge target: profile objects, query builders, config objects, template locals. Prototype pollution matters where a polluted `Object.prototype` property changes a later decision (auth flag, template option, environment).
4. For YAML, determine the loader: `yaml.load` (unsafe) vs `yaml.safe_load` — the code (pb-source-audit) or a loader-identifying error is the way to tell.
5. Cross-check each entry point against WAF/filter position (pb-waf-bypass) — serialized blobs are often untouched by filters that scan for obvious injection strings.

## Test procedure
Work the three families separately; each has its own confirmation bar.

### Deserialization
1. Establish the input is actually deserialized: send the *unmodified* blob and record the normal behavior; then send a structurally-broken blob and record the error. A parse error quoting the deserializer (or a class name) confirms the path.
2. Identify the encoding wrapper (base64, hex, URL-encoding) so you know what the app unwraps before parsing.
3. Determine the observable channel: does the app echo a field from the deserialized object? Show errors with class names? Change behavior based on a field value? The channel decides how you *confirm* the rest.
4. Gadget selection is a tooling step, not a writing step: for Java the standard gadget libraries (CommonsCollections, CommonsBeanutils) and chain builders (ysoserial-class tools), for PHP POP chains and phpggc-class tools, for .NET ysoserial.NET — pick from the ecosystem for the *version you identified*. This playbook names the categories; it does not carry chains.
5. Confirm impact at the lowest tier that proves the point: does a gadget with an observable benign effect (a DNS/callback interaction, a sleep, an echoed marker) fire? A deserialization finding is confirmed when *you observe the side effect*, not when the chain "should" work. Command execution is the last step, only where the program allows it, and only after the benign tier already proved the chain runs.
6. Never run gadget enumeration against a live target blindly — each gadget attempt is a real action; test the minimum set implied by the version fingerprint.

### Prototype pollution
7. Probe merge depth with benign keys and observe: does `__proto__`/`constructor.prototype` survive the merge into `Object.prototype`? Confirmation is a *visible* polluted default — a property that now appears on fresh objects created after your merge (e.g. a value showing up in a response where the code reads `obj.someKey` with no prior assignment).
8. From a confirmed pollution, look for the exploitable consumers: auth checks reading a polluted flag, template engines reading polluted options (pug/ejs-style `env`/options paths), libraries that trust polluted defaults. The pollution is the primitive; the consumer is the vulnerability.
9. Test the same merge through every content type and endpoint variant — pollution often works only on one parser path.

### Parser-class attacks (beyond basic XXE)
10. For XML import/SOAP/Office: confirm external-entity and file-read behavior per pb-injection's XXE procedure; escalate to out-of-band exfiltration or SSRF only where the program allows and the app's channel supports it.
11. For SVG upload: the parser runs on an image upload point — test whether entity processing fires; the file-upload methodology (pb-file-upload) covers getting the file stored and served.
12. For Office parsing (docx/xlsx): the document is a zip of XML — the injection point is the inner XML, and the trigger is the import/preview feature.

### Worked example
```
Input:  cookie "session" = base64 blob; decoded prefix = a:3:{... (PHP serialized array)
Probe:  corrupt one length field → 500 with "unserialize(): Error at offset 47"
        -> deserialization path confirmed, PHP confirmed
Probe:  minimal known POP chain for the framework version (benign callback gadget)
Result: listener receives the callback → chain execution confirmed at benign tier
```
Report the tier reached: "deserializer confirmed" is not "chain executes"; "chain executes benignly" is not "RCE demonstrated" until an actually harmful effect is observed (and only where authorized).

## Evidence to capture
- The entry point, the raw serialized value, and the decoded format fingerprint.
- The parse-error evidence that confirms the deserialization path.
- The exact framework/library version the gadget choice depends on.
- The benign-tier side effect observed (callback receipt, timing, echoed marker) and the exact chain/tool version used to produce it.
- For pollution: the merge input, the polluted property, and the consumer behavior before/after.
- For parser attacks: the document/XML submitted and the out-of-band or file-read result.
- Every tier claimed with its observation — never the tier name alone.

## Escalation
- Deserialization escalates in a strict ladder: format/parse confirmed → side-effect confirmed (benign) → harmful effect confirmed (only where authorized). Each rung needs its own evidence.
- A PHP/Java session-blob deserialization is usually *highest severity once a chain runs* — but the chain must actually run on the deployed version; a chain for the wrong library version is a guess.
- Prototype pollution escalates only through its consumer — a confirmed pollution with no affected decision is a primitive, not a finding; find the consumer before writing it up.
- Out-of-band-only parser findings (blind exfiltration) are reportable when the exfiltrated data is actually received and demonstrably from the target — a DNS hit alone is the weak tier.
- Pre-auth deserialization beats post-auth: note the session state at the entry point in the report.
- WAF context matters: a deserialization blob that the WAF passes through unchanged is the standard case — no bypass story is needed unless one was.

## Out-of-scope traps
- Do not treat "the deserializer is present" as the finding — programs pay for demonstrated execution, not for the existence of `readObject` on an unreachable path.
- Blind gadget enumeration against production is abuse, not testing — work from the version fingerprint and test the minimum.
- A gadget that "should" work is not confirmation — only the observed side effect counts, and confabulated results poison the whole report (bb-gate will kill them).
- Prototype pollution of your own session's object is self-inflicted; the finding requires an effect that reaches other users or bypasses a real check.
- Out-of-band testing with third-party callback services leaks target data off-box — use infrastructure you control, and only what the program permits.
- Command execution beyond a benign tier is a legal-gate class in this system — the shape of the action matters as much as the target's authorization.
- XML/Office parsers in third-party libraries may be the library vendor's bug, not the program's — attribute the vulnerable code path correctly.

## Integration
- Record each entry point tested with `mcp__bb__record_coverage`, including the format fingerprint, so the same cookie isn't re-analyzed next session.
- Bank unconfirmed primitives with `mcp__bb__add_primitive`: "PHP session deserializes, version unknown", "merge passes __proto__ but no consumer found" — chaining fuel for bb-correlate.
- Source-level discovery routes through pb-source-audit; a payload blocked at the WAF routes through pb-waf-bypass; the final finding goes through bb-gate before bb-report.
- The assistant proposes the entry points, the version-driven gadget categories, and the tier definitions; the human runs every request and confirms every observed effect.
