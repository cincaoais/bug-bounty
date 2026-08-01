# Juice Shop — sandbox reference

App-specific detail for `bb-sandbox`. Source-verified against `juice-shop/juice-shop@master`. Read this once per mission, then work from the oracle — do not re-derive these facts mid-hunt.

**IPv6 loopback note:** if you ever address the container over IPv6, use `127.0.0.1` or the schemeless `[::1]:3000` form, not scheme'd `http://[::1]:3000` — the hook's URL matcher fails closed on that exact shape (see SKILL.md's Command conventions). In practice `127.0.0.1`/`localhost` cover every command in this file.

## Oracle — the only thing that counts as "solved"

`GET /api/Challenges/` (finale-rest auto-CRUD over the `Challenge` model) returns every challenge:

```json
{ "id": 12, "key": "adminSectionChallenge", "name": "Admin Section",
  "category": "Broken Access Control", "difficulty": 2, "solved": true, ... }
```

- `solved` is flipped server-side only, by `challengeUtils.solve()` when a challenge's own detection criteria fires (`lib/challengeUtils.ts`). It is never client-writable — there is no field on this resource you can PATCH to fake a win.
- **Compute `solved`/`total` live from this response every time.** Never hardcode the total. The bundled catalog (`plugin/reference/juiceshop-challenges.json`) has 113 entries as of this build, but Docker `latest` trails `master` — a live instance can have more, fewer, or renamed challenges. Objectives absent from the catalog still exist in the app; record them anyway.
- `key` is the stable identifier — use it to correlate against the objective catalog (see **Objective ids** below). `id` is a DB row number and not stable across resets/versions.
- **Optional aids, not required for scoring:**
  - Socket.IO emits event `'challenge solved'` with the challenge payload the instant a challenge flips — useful for a live feed if you're watching the socket, but polling `/api/Challenges/` is sufficient and simpler.
  - `GET /rest/continue-code` returns `{ continueCode }` — a hashids-encoded snapshot of every currently-solved challenge id. `PUT /rest/continue-code/apply/:continueCode` restores that exact solved-set later. Handy to snapshot before you start (compare against your baseline poll) or to restore progress after a container restart instead of re-solving everything.

## Driver routing — pick the tool per challenge, not per session

Most challenges are **API-solvable**: the server inspects the request or response itself, so `curl`/Python is sufficient and faster than a browser.

| Signal | Route to |
|---|---|
| Challenge is about a request/response the server validates (SQLi, IDOR, mass assignment, JWT, path traversal, most "Broken Access Control"/"Injection") | `curl` or a Python harness — HTTP is ground truth here |
| Challenge requires a script to actually **execute** in a real DOM context (sandbox-bypass XSS, some "Improper Input Validation" DOM challenges, UI easter eggs) | Chrome tools — HTTP diffing cannot see script execution |
| You want the request captured in proxy history for later replay/inspection | Burp MCP send tools |

If unsure which bucket a challenge falls in, check its category first, then read its leaked source (below) — the vulnerable line usually makes the right driver obvious.

## Leaked-source assist — read the vulnerable line, don't guess

Juice Shop *deliberately* leaks its own vulnerable source. Use this before black-box probing:

| Path | What it gives you |
|---|---|
| `GET /snippets/:challenge` | The actual vulnerable source snippet for a given challenge key, e.g. `GET /snippets/loginAdminChallenge` |
| `POST /snippets/verdict` | Submit which lines you think are vulnerable (self-check tool, not required for the oracle) |
| `GET /snippets/fixes/:key` / `POST /snippets/fixes` | Code-fixing side-challenges (coding-challenge track, separate from the exploit track) |
| `GET /ftp` (dir listing) + `GET /ftp/:file` | Deliberately exposed FTP-style file share |
| `GET /ftp/package.json.bak%2500.md` | Poison-null-byte bypass: the allowlist check only requires the raw filename to *end* in `.md`/`.pdf`/an exact allowed name, and only *after* that check does `security.cutOffPoisonNullByte()` truncate at `%00`, so a `.bak` file smuggled behind a `%00.md` suffix passes the filter and serves the real `.bak` content |
| `GET /robots.txt` | Itself points at `/ftp` as `Disallow` — a hint, not a real block |
| `GET /security.txt` / `GET /.well-known/security.txt` | Standard leak target |

## Auth & JWT

- JWTs are signed **RS256 with a hardcoded private key** bundled in the source (`lib/insecurity.ts`) — forgeable if you can obtain or derive the key material; several challenges are built around this.
- Passwords are hashed with **plain MD5** (`crypto.createHash('md5')`, no salt) — relevant for any challenge involving a leaked password hash.
- `POST /rest/user/login` builds its SQL lookup via raw string interpolation of `email` (`SELECT * FROM Users WHERE email = '${email}' AND password = '...'`) — this endpoint is both the normal login route *and* the login-bypass SQLi target (`' OR 1=1--` class payloads in the `email` field).

## Key endpoints

| Endpoint | Why it matters |
|---|---|
| `POST /rest/user/login` | Login + SQLi-in-`email` target (see above) |
| `POST /api/Users` | Mass assignment: `finale.resource({model: UserModel, excludeAttributes: ['password','totpSecret']})` — `role` is **not** excluded, so POSTing `"role":"admin"` on registration works |
| `GET /rest/products/search?q=` | SQLi: `q` is interpolated directly into a raw SQL string in `routes/search.ts` |
| `POST /api/Feedbacks` | IDOR via `UserId` in the body — the `Feedback` finale resource has no exclusions and no ownership hook, so you can attribute/read feedback for a `UserId` that isn't yours |
| `GET /rest/basket/:id` | IDOR — `retrieveBasket()` fetches `BasketModel.findOne({where:{id}})` with **no ownership filter at all**; the only place your own basket id (`user.bid`) is even referenced is inside the challenge-detection closure, not as an access-control gate |
| `GET /api/Challenges/` | The oracle (see above) |

## Gotchas

- **State is in-memory and resets on container restart** — no volume by default. A clean re-run costs nothing; use it deliberately if you want a fresh solved-set, or snapshot first via `continue-code` if you don't.
- Some challenges carry a `disabledEnv` field on the `Challenge` model — a challenge can be unavailable in a given deployment/environment. If a challenge you expect never appears solvable and isn't visible in `/api/Challenges/`, check whether it's disabled in this build rather than assuming your exploit is wrong.
- **The feedback "captcha" is not a real rate limiter.** `captchaBypassChallenge` rewards submitting 10+ customer feedbacks within 20 seconds — the arithmetic captcha (`routes/captcha.ts`) only checks the answer, with no attempt throttling behind it.
- **Forgot-password IS genuinely rate-limited** — `POST /rest/user/reset-password` is wrapped in `express-rate-limit` (5-minute window, max 100 requests). Note its bucket key is `X-Forwarded-For` if present, else IP (`resetPasswordMortyChallenge`'s own vulnerable line) — the limiter is real, but its key is attacker-influenceable.

## Objective ids

Objective ids in the bundled catalog are `juice-shop:<challengeKey>` — e.g. `juice-shop:adminSectionChallenge`. To credit a solve: poll `/api/Challenges/`, find the entry whose `key` matches the challenge you just solved and confirm `solved:true`, then call `record_objective_result(..., objective_id="juice-shop:<key>", solved=true, evidence_id=...)`.

A `key` present in the live app but absent from the bundled catalog (version drift) always counts toward the *app's own* `solved`/`total` when you poll `/api/Challenges/` — but the plugin's `mission_scorecard` is computed by joining `mission_objective_result` against the catalogued `objective` table, so an uncatalogued challenge won't appear in the plugin's scorecard even if you call `record_objective_result` for it. Note the app-reported total vs. the plugin-scored total separately in the after-action report rather than letting them silently disagree; log the extra solve via `log_attempt`/`add_note` so it isn't lost.
