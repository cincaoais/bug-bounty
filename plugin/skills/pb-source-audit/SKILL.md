---
name: pb-source-audit
description: Methodology playbook for static source-code audit. Load when you have source code, code fragments, or decompiled artifacts for the target (open-source repo, leaked code, source maps, APK decompiles) and want to trace inputs to dangerous sinks across PHP/Java/Python/Node/Go.
---

# pb-source-audit

## When this applies
- You have the target's source: an open-source project, leaked code, a source-map reconstruction, or decompiled artifacts from pb-apk-reversing.
- The user hands you a code fragment and asks for an audit.
- You need to answer "does this input reach this dangerous function, and what check stands in between?"
- A runtime signal (from any other playbook) needs its root cause located in code.

Division of labor: `bb-code` reads *client-side* JS and source-available code for hidden endpoints, secrets, and weak authorization on the zero-traffic surface. This playbook is the general static-analysis method for any language, with the input→sink discipline and the cross-language dangerous-function reference.

## First signals
- Source, fragments, or decompiles that include routing, controllers, or input-handling code — the interesting file is usually where request parameters are read.
- Concatenation of variables into strings that look like queries, paths, templates, or commands — even without knowing the sink, the pattern is the signal.
- Deserialization calls on data that could be user-shaped; template rendering fed by user input; file operations whose path is partly dynamic.
- Auth checks that exist on some routes and conspicuously not on others — especially catch-all handlers, callback endpoints, and static-file whitelists.
- Error handling that echoes exception text or stack traces back to the caller.

## Enumeration
The audit skeleton is `input point → propagation chain → dangerous sink`. Enumerate in that order:

1. Input points: every place attacker data enters — request parameters, headers, cookies, uploaded files, message-queue payloads, database rows that were themselves user-written. List them per route/handler.
2. Propagation: follow each input through assignments, transformations, and cross-function calls. Note every validation or sanitization it passes (or skips) along the way — the gap between "validated" and "executed" is the bug.
3. Sinks: classify each dangerous function reached, by class:
   - Concatenation sinks: SQL, OS commands, file paths, templates.
   - Deserialization sinks (see pb-deserialization for the exploitation method).
   - Template/expression sinks: user input entering a template engine or expression evaluator (pb-injection).
   - File-operation sinks: upload, download, include, delete (pb-file-upload / pb-path-traversal).
   - Authz branch sinks: privileged operations with no ownership or role check (pb-idor-bola / pb-broken-access-control).
4. Output per candidate: the call chain (input → propagation → sink), the key code fragment, and the trigger condition (which parameter values and which preconditions make it fire). A finding without a trigger condition is a guess.

## Test procedure
1. Start from routes/handlers, not from grep hits — the question is always "which input reaches this sink *from a reachable entry point*", and grep hits without a path are noise.
2. Work the per-language dangerous-function quick reference below when hunting sinks:

| Language | Watch for |
|---|---|
| PHP | eval, assert, system, exec, passthru, shell_exec, popen, include/require with a variable path, file_get_contents on user-shaped paths, unserialize, preg_replace with the /e modifier (legacy), create_function, `$$` variable-variable assignment |
| Java | Runtime.exec, ProcessBuilder, ObjectInputStream.readObject, XMLDecoder, expression languages (SpEL/OGNL/MVEL/EL), JNDI lookup, JdbcRowSetImpl/TemplatesImpl as deserialization markers |
| Python | eval, exec, os.system, subprocess with shell=True, pickle.loads, yaml.load with an unsafe Loader, `__import__`, compile |
| Node.js | eval, Function constructor, child_process.exec/spawn, vm.runInContext, `__proto__`/constructor.prototype merges (prototype pollution) |
| Go | os/exec.Command, text/template or html/template on user input, string-built SQL, unsafe deserialization (gob on untrusted input) |

3. At each candidate sink, ask the boundary question: is the data length/type checked against what the sink assumes; is the value whitelisted or merely blacklisted; is the check on the same value that executes (or a copy)?
4. Audit authorization separately — the cheapest high-severity wins are usually here:
   - Is there one central auth middleware, or per-route checks that some routes forgot?
   - Which routes are exempt (whitelists, static files, callbacks) and are any of them actually privileged?
   - Is role/ownership decided server-side or from a client-supplied value?
   - Object-level: does the code check login only, or also ownership (`WHERE id = ? AND owner = ?`)?
5. For each confirmed chain, write the deliverable triple: input point / propagation path / sink, plus the missing check that would have stopped it.
6. Do not stop at the first bug class — a single source tree is worth a full sweep of all five sink classes before you move on.

### Worked example
```
Input:  GET /report?template=quarterly        (controller reads `template`)
Chain:  template = request.get("template")  →  render("reports/" + template + ".html")
Sink:   file include with user-shaped path, no allowlist
Missing check: template not validated against a fixed set
Trigger: any value reaching a file the app can read → path traversal (hand off to pb-path-traversal)
```
The audit artifact is the chain plus the trigger condition — the actual confirmation happens under the class playbook.

## Evidence to capture
- The exact file and line for input point, propagation, and sink; the surrounding fragment.
- The trigger condition: parameter names, values, and preconditions.
- For auth findings: the routes with and without the check, side by side.
- Anything that shows the code is *live* (repo version matches the deployed version — a commit hash in a banner, a behavior only the new code has) — auditing an old branch is a classic waste.
- Reachability proof where cheap: the route is registered, the handler is exported, the feature exists in the deployed app.

## Escalation
- A sink found is not a finding until the class playbook confirms it — escalate each confirmed chain to the owning playbook: injection → pb-injection/pb-sql-injection, deserialization → pb-deserialization, file ops → pb-file-upload/pb-path-traversal, auth gaps → pb-idor-bola/pb-broken-access-control.
- A chain that is unconfirmed but plausible belongs in `mcp__bb__add_primitive`, with the trigger condition attached.
- Auth-gap findings escalate fast: a privileged route missing the check that its neighbors have is often directly reportable once reachable.
- Version-mismatch kills reports: escalate only chains you can show are in the deployed build.
- Multiple sinks reached from one input point is a stronger report than one — the audit pass should collect the full set before you write anything up.

## Out-of-scope traps
- Grep hits are not findings: a dangerous function present in code says nothing until an attacker-controlled path to it is demonstrated.
- Static-only claims need the reachability argument — the triager's first question is "is this actually reachable, and is this the deployed version?"
- Don't audit vendor libraries: bugs in framework code belong to that project's program; the target's bug is in *its own* code misusing the API.
- Sanitization you can't see through (a wrapper that "cleans" input) is not automatically a finding — follow the code; if the check is real, the sink is not reached.
- Redact extracted source before storing: source trees contain keys and PII; the ledger redacts on ingest but keep only what the finding needs.
- Fix suggestions belong in the report, not in the coverage ledger — record the finding shape, not a patch.

## Integration
- Record audited files/modules with `mcp__bb__record_coverage` so the same tree isn't re-read next session.
- Bank each unconfirmed chain with `mcp__bb__add_primitive`, including the trigger condition — these are the cheapest high-value primitives bb-correlate can act on.
- Every confirmed chain routes to its class playbook for live confirmation; a fully confirmed chain then goes to bb-report via bb-gate.
- The assistant traces input→sink and proposes which chain to verify next; the human decides what counts as confirmed and runs any live checks.
