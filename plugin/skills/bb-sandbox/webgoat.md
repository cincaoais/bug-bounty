# WebGoat — sandbox reference

App-specific detail for `bb-sandbox`. Source-verified against `WebGoat/WebGoat@main`. Read this once per mission, then work from the oracle — do not re-derive these facts mid-hunt.

## Run

| App | Port | Context path |
|---|---|---|
| WebGoat | 8080 | `/WebGoat` |
| WebWolf (companion, separate session) | 9090 | `/WebWolf` |

`docker run -it -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat` (README-documented, already loopback-bound).

## Auth

1. **Register:** `POST /WebGoat/register.mvc`, form-encoded body:
   | Field | Constraint |
   |---|---|
   | `username` | 6–45 chars, `[a-z0-9-]*` only |
   | `password` | 6–10 chars |
   | `matchingPassword` | 6–10 chars, must equal `password` |
   | `agree` | required, non-null |

   A successful registration logs you in immediately and redirects to `/attack` — no separate login call needed right after registering.

2. **Login (existing session):** `POST /WebGoat/login`, form fields `username`/`password` (Spring Security default form login; no `loginProcessingUrl` override, so the processing endpoint is the framework default `/login` under the `/WebGoat` context path — **not** `/login.mvc`).

3. **CSRF is globally disabled** (`WebSecurityConfig`: `.csrf(csrf -> csrf.disable())`). No token to fetch or carry.

4. **Hold the `JSESSIONID` cookie** across every request — WebGoat is session-authenticated, not token-authenticated.

5. **Send `X-Requested-With: <any non-null value>`** (conventionally `XMLHttpRequest`) on every request. `AjaxAuthenticationEntryPoint` checks only for the header's *presence*: if present and the session has expired/isn't authenticated, you get a clean `401`; if absent, you get a `302` redirect to the login **page HTML** instead — which will silently break a script expecting JSON.

## Oracle — the only thing that counts as "solved"

`GET /WebGoat/service/reportcard.mvc`:

```json
{ "totalNumberOfLessons": 42, "totalNumberOfAssignments": 107,
  "numberOfAssignmentsSolved": 3, "numberOfLessonsSolved": 1,
  "lessonStatistics": [ { "name": "Cross-Site Scripting", "solved": false, "numberOfAttempts": 4 } ] }
```

Completion is derived server-side by `LessonTrackerInterceptor` from each assignment's own check — not spoofable, and `lessonStatistics` is per-**lesson**, not per-assignment.

For per-**assignment** detail: `GET /WebGoat/service/lessonoverview.mvc/{lesson}`, where `{lesson}` is the *lesson's* simple class name (e.g. `AuthBypass` for the lesson package `authbypass` — not the package name itself, and not any individual assignment's class name). Returns a list of `{assignment: {name, path, hints}, solved: bool}` — **`path` is the assignment's actual submission endpoint**, hand-declared per assignment in Java (`new Assignment(name, path, hints)`), so this call is how you discover the real URL instead of guessing one from the objective id.

Assignment POSTs return an `AttackResult`: `{lessonCompleted, feedback, output, assignment, attemptWasMade}`. `lessonCompleted` reflects that one assignment, not the whole lesson — always re-check `reportcard.mvc`/`lessonoverview.mvc` before crediting, don't trust the POST response alone as the oracle.

## Discovering endpoints (no uniform scheme — build the table live)

There is no fixed URL convention across lessons; each assignment declares its own `path` in source. Discover it in order:

1. `GET /WebGoat/service/lessonmenu.mvc` — full left-nav: `[{name, type: CATEGORY|LESSON, children:[...], complete, link, ranking}]`. Gives you every lesson's `link` (a `#lesson/<ClassName>.lesson` fragment — `<ClassName>` is the `{lesson}` value for the next call) and whether that whole lesson is already complete.
2. `GET /WebGoat/service/lessonoverview.mvc/{lesson}` per lesson of interest — gives every assignment's real submission `path` and its individual `solved` state (see Oracle above).
3. Record each discovered `(lesson, assignment name, path)` via `mcp__plugin_bb_bb__add_endpoints` as you go — this *is* the recon phase for WebGoat; there's no shortcut, and the objective catalog (`webgoat-lessons.json`) only stores `lessonPackage/ClassName` + metadata, never the HTTP path.

Worked example of why you can't guess it: objective `webgoat:authbypass/VerifyAccount` is the assignment class `VerifyAccount` in lesson package `authbypass` (lesson class `AuthBypass`, so `{lesson}` = `AuthBypass`). Its actual submission endpoint is `POST /WebGoat/auth-bypass/verify-account` — a hyphenated path that matches neither the package name (`authbypass`) nor the class name (`VerifyAccount`) directly. Every assignment is like this; always confirm via `lessonoverview.mvc`, never pattern-match from the objective id.

## Hard parts

- **Ordered session state.** Many lessons require assignments to be attempted in sequence within a `LessonSession` — jumping straight to assignment 3 of a lesson can fail even with a technically-correct payload if assignment 1/2 haven't been touched this session. Work lessons top-to-bottom on a first pass.
- **Browser-only / WebWolf-dependent assignments.** Some assignments need a real DOM interaction (client-side validation bypass, DOM XSS) or the WebWolf companion app (port 9090, its own separate OAuth2-flavored session) — e.g. lessons that have you receive a phishing mail or host an attacker page. Route these to the Chrome tools; don't force an HTTP-only solve.
- **`restartlesson.mvc` is destructive — never call it in a retry path.** `GET /WebGoat/service/restartlesson.mvc/{lesson}` doesn't just reset one lesson's progress: the handler calls `userTracker.reset(lesson)` and then `flyway.clean()` + `flyway.migrate()`, which drops and reinitializes the lesson database schema. Treat it as a nuclear option the human invokes deliberately, not something the run loop ever calls automatically on a failed attempt.

## Difficulty

WebGoat has no native difficulty rating (no field like Juice Shop's `difficulty`). The bundled catalog (`plugin/reference/webgoat-lessons.json`) hand-tiers every objective to 1, 3, or 5 — treat these as curated estimates, not app-reported truth.

## Objective ids

Objective ids are `webgoat:<lessonPackage>/<ClassName>` — e.g. `webgoat:authbypass/VerifyAccount`, where `authbypass` is the Java package and `VerifyAccount` is the **assignment's** class name. Neither half is directly usable as the `{lesson}` path parameter in `lessonoverview.mvc`/`lessonmenu.mvc`, which instead wants the *lesson* class's simple name (`AuthBypass`, distinct from both the package and the assignment class — see the worked example above). To correlate a solved assignment back to its objective id: call `lessonoverview.mvc/{lesson}` for the lesson you're working, match the returned `assignment.name`/`path` to the objective's `native_id`/`description` in the catalog (which records the lesson package and class name), not a literal string match against the URL.
