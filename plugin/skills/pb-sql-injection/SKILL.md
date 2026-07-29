---
name: pb-sql-injection
description: Methodology playbook for finding SQL injection on a real target. Load when testing a parameter that plausibly reaches a database query, or when bb-next surfaces a SQLi test case.
---

# pb-sql-injection

## When this applies
Any parameter, header, or body field whose value plausibly flows into a SQL query: search/filter/sort params, IDs used in a `WHERE` clause, login/lookup fields, "remember me"/API-key lookups, admin report builders, an `order_by`/`sort` param passed through unmodified, GraphQL resolvers backed by raw SQL, or a stored procedure invoked with user-controlled arguments. Covers WSTG-INPV-05.

## First signals
Notice these before knowing whether there's a bug:
- An error page or stack trace naming a DB driver, table/column, or a SQL syntax fragment — even one leaked word is worth a closer look, not proof on its own.
- A parameter whose value changes the SHAPE of the response beyond its literal content — different row counts, fields present/absent, or status code — when varied in ways that shouldn't matter to legitimate logic.
- Numeric-looking parameters accepted with no visible type/format check (`?id=5` also silently accepting `id=5abc` rather than erroring the way a strict integer parser would).
- Sort/filter parameters mapping directly onto column names in the UI (`sort=price`, `sort=-created_at`) — these are frequently unparameterized even in otherwise-safe query builders, since `ORDER BY` can't usually take a bind parameter.
- Response time visibly varying with input in a way unrelated to data volume — the classic tell for a time-based condition, worth noting before you understand the query shape.
- Search/autocomplete endpoints backed by a `LIKE`-style query, often built by string concatenation even where the rest of the codebase parameterizes everything else.
- A login/lookup field behaving differently between "no such record" and "record exists but wrong secret" — an authentication-bypass-flavored injection candidate.

## Enumeration
1. List every parameter across every endpoint that plausibly reaches a query: filters, sorts, pagination cursors, IDs, search boxes, login/lookup fields, report/export builders, GraphQL args mapped to resolvers.
2. Classify each by likely query role: `WHERE`-clause value, `ORDER BY` column/direction, `LIMIT`/`OFFSET`, a dynamic table/column selector (reporting tools), or a raw fragment passed to a stored procedure.
3. Note the apparent expected type (integer, string, constrained enum/dropdown) — type mismatches are often under-validated even where the "normal" type is checked.
4. Identify the DB backend if visible anywhere (driver name in an error, ORM fingerprint, a vendor-specific error string, a timing signature) — it shapes which blind-inference concepts and syntax are relevant, without needing anything destructive to learn it.
5. Group parameters by the code path likely handling them (same framework action, same ORM call) — a parameterization pattern on one is a reasonable predictor for siblings, but each still needs its own confirmed test.
6. Coverage is exhausted once every identified query-reaching parameter has a recorded result — "not vulnerable" is a real, valuable outcome that stops re-suggestion, not a skip.

## Test procedure
1. Baseline: request with a normal, valid value and note the full response — status, shape, timing, row count if visible.
2. Send a single quote (or the backend-appropriate string delimiter) in the candidate parameter and compare against baseline: a SQL error, a broken query, a changed row count, or a changed status is the classic first signal that input reaches an unparameterized part of a query. This one character is the entire detection probe at this stage.
3. If a quote breaks it, follow with one different delimiter/escape variant only far enough to distinguish "input reaches the query" from "the app rejects unusual characters generically" — e.g. an unrelated non-SQL special character a well-behaved validator should reject the same way, to rule out a plain input-validation reject.
4. Boolean-style inference is a CONCEPT to confirm, not a script to run: a condition that's always-true vs. always-false should produce an observably different response shape (row count, presence/absence of a result) even with no error message. Confirm the concept with at most one true-condition and one false-condition comparison — do not build a character-by-character extraction sequence.
5. Time-based inference is the same concept applied to timing: a conditional delay construct that only sleeps when a condition is true is detectable via response-time difference. Confirm with a single, short, clearly-intentional delay value and stop — a full blind-extraction timing script is out of scope for detection.
6. Test `ORDER BY`/sort parameters separately from `WHERE`-clause values — try a bare identifier variant that breaks column-name resolution, since sort params are commonly unparameterized even in otherwise-safe builders.
7. Test the same parameter across every place it's accepted (query string, JSON body, header, cookie) — validation and parameterization are frequently applied inconsistently by input location, not just by name.
8. If the app filters or strips characters, note exactly which ones and how (removed vs. escaped vs. whole-request rejection) — this fingerprints whether an allowlist, a blocklist, or a prepared-statement boundary is actually doing the protecting, without needing to try to defeat it.

### Worked example of the comparison (illustrative shape, not a script)
```
Baseline:        ?id=42        -> 200, one row (the record for id 42)
Delimiter probe: ?id=42'       -> 500, backend syntax error mentioning the driver

Boolean concept (construct the actual always-true / always-false condition
in the target's own query syntax — don't reuse a canned string from elsewhere):
  always-true condition on id=42   -> same row(s) as baseline
  always-false condition on id=42  -> zero rows / empty result
```
The delimiter probe alone proves the break. The boolean row is the concept you're confirming exists — one true/false pair is enough evidence; it is not the start of a row-by-row extraction.

## Evidence to capture
- Baseline response next to the single-quote (or delimiter) response, full status/headers/body, showing the exact difference.
- Any raw leaked error text verbatim, via `mcp__bb__store_evidence` — exact wording (driver name, query fragment) matters for triage.
- For boolean inference: the true-condition and false-condition request/response pair side by side, showing the observable difference.
- For time-based inference: the delay-triggering request and its measured time next to a baseline's response time, with the delay value used stated explicitly.
- The parameter, its location (query/body/header/cookie), and the exact value sent, so it's reproducible without guessing.
- Backend fingerprint evidence (error text, timing signature) if identified — it affects how a triager scopes the fix.

## Escalation
- A confirmed break with no further signal is a real but early-stage finding — the escalation step is establishing which inference channel is usable (error-based, boolean, time-based), not pushing extraction further than detection requires.
- Naming the accessible data class (a `users` table, an internal admin table, a cross-tenant table) without extracting real records is normally sufficient to demonstrate impact — describe the exposure boundary, not the contents.
- On a login/auth query, note explicitly whether boolean-inference behavior alone distinguishes valid usernames or conceptually bypasses authentication — this is a distinct, higher-severity escalation from data-disclosure SQLi.
- Stacked-query or DB-level command-execution capability (where the backend/driver allows multiple statements or OS-level calls) is categorically higher than data read/write — note only whether the backend appears to structurally allow it, without running a real second statement beyond what's needed to observe that.
- If the same unparameterized pattern (e.g., `ORDER BY` built by concatenation) repeats across endpoints sharing a code path, name that as a systemic pattern — more valuable to a triager fixing root cause than N near-identical reports.
- Bank a confirmed break with unclear extraction value (quote breaks it, but no boolean/timing channel established) via `add_primitive` rather than dropping it — a later-found response-shape difference might complete it.

## Out-of-scope traps
- A SQL error leaking version/table/column info but showing no evidence of actual condition manipulation (row count/shape unaffected by any true/false variant) is information disclosure, not proven SQL injection — report at the severity the leaked detail alone supports.
- An ORM that visibly parameterizes (bound-parameter syntax in an error's stack trace, not concatenated literals) isn't vulnerable just because an error surfaced — read what actually broke before concluding injection.
- Input that causes a 500 with no behavioral difference between a true-shaped and false-shaped probe is a robustness/crash finding, not confirmed SQLi.
- Numeric parameters cast server-side before reaching the query (a distinct, consistent type-error response rather than a query-syntax error) close off the injection path here even if the same parameter is vulnerable elsewhere in a string context.
- A single slow response on a time-based probe can be noise (load, jitter) — confirm with a second, differently-timed comparison before treating it as a real signal.
- "Confirmed only by an automated scanner, never manually verified" still needs manual reproduction with the minimal probes above before submission, regardless of what the scanner reported.

## Integration
- Record each tested parameter with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, noting which channel (error-based/boolean/time-based/none) was checked, even on a clean result.
- Bank a confirmed syntax-break with no usable inference channel yet via `mcp__bb__add_primitive` rather than losing it — a later-discovered response difference may complete it.
- The assistant proposes the parameter, probe sequence, and comparison to make; the human sends every request and reads the actual response before anything above "candidate" is claimed.
- Never state SQL injection is confirmed from a described behavior alone — that's `record_coverage(status="confirmed")` or `promote_to_finding(..., human_confirmed=True)` after the human's own reproduction.
