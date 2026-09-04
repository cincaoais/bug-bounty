# Spec — bb egress chokepoint (active-mode milestone 1)

- **Date:** 2026-09-04
- **Status:** Approved design, pre-implementation
- **Related:** `docs/field-notes/rnd-active-mode-containment-2026-09-02.md` (R&D + ROE check)

## 1. Context & motivation

bb is ingest-only: it never sends traffic to a target. The R&D field note recommends a staged, opt-in, attended path toward an *active* mode, and the ROE check concluded that **constrained, low-volume, per-request active testing is broadly permitted while autonomous mass-scanning is not** — so a per-host request-rate ceiling is not merely a safety feature, it is the rules-of-engagement compliance control.

Two facts set the scope of this milestone:

1. **The scope-guard hook is not a network boundary.** It parses shell-command strings on a best-effort basis and its own docstring admits `$(...)` and base64 obfuscation can evade it. It is a strong guard against drift and mistakes, not a hard boundary. Milestone 1 builds the network-layer boundary the hook cannot be.
2. **Active-lab is the inverse of sandbox mode, not an extension of it.** Sandbox mode (`plugin/mcp/sandbox.py`, `bb-sandbox`) enforces **localhost-only + total egress BLOCK**, verifies the container *cannot* reach the internet, and *requires `HTTP(S)_PROXY` to be unset* because it treats a proxy as a redirection threat. Active-lab needs the opposite posture: **egress to exactly one external target ALLOWED, everything else denied, and all traffic forced THROUGH a controlled proxy.** bb's "what is true" checker pattern (`sandbox.network_isolation_check`, which makes no network calls and consumes probe evidence) ports cleanly to verifying the new posture — but that verification is a later milestone.

## 2. Goals (milestone 1)

- A standalone, **stdlib-only** forward proxy that enforces a **destination allowlist**, a **per-host request-rate ceiling**, and an **append-only audit**.
- The following behaviours proven by test:
  - **(a)** an out-of-scope destination is blocked regardless of how the client's command was constructed (`$(...)` / base64 obfuscation is structurally irrelevant to the proxy);
  - **(b)** a redirect-following request (`curl -L`) from an allowed origin to an out-of-scope host is refused **before any name resolution or connection**, and the out-of-scope origin is **never contacted**;
  - **(c)** the per-host rate ceiling is enforced (the request over threshold is refused).
- **Zero new runtime dependencies.** The policy logic is unit-testable with no sockets and no real clock.

## 3. Non-goals (explicitly deferred)

Stated so the milestone stays honest about what it does and does not contain:

- **No egress-firewall backstop.** Milestone 1 assumes tools honour the proxy environment. A tool that ignores it (raw sockets, unset proxy env) is *not* contained until the milestone-2 firewall. M1 is therefore a boundary for cooperating tools, not yet a hard boundary against a hostile one.
- **No `active-lab` mode wiring** into the live plugin, hook, MCP server, or preflight.
- **No per-program "active testing permitted?" gate** (a `bb-scope`/`bb-start` fact) — milestone 2.
- **No auto-pause / health monitoring / guardian model** — later milestones.
- **No change to the ingest-only default.** The live plugin is untouched; this ships as new, unwired modules plus tests.

## 4. Architecture

Two modules, splitting **policy** (pure) from **transport** (I/O) — the same separation that keeps `sandbox.py` pure while the hook and server do I/O.

### 4.1 `plugin/mcp/egress.py` — pure policy (no I/O, no sockets, no ambient clock)

- `EgressPolicy` (dataclass): `allowlist: list[Rule]`, `rate_capacity: int`, `rate_refill_per_sec: float`, `audit_path: str | None`.
- `Rule(host: str, port: int | None)` — `port is None` means any port on that host.
- `Allowlist.allows(host, port) -> tuple[bool, str]` — normalises both sides through `sandbox.canonical_host` so IP / hostname / loopback spellings fold consistently and inherit the existing evasion-resistant handling.
- `TokenBucket` — per-host bucket keyed by canonical host; `try_consume(host, now) -> tuple[bool, float]` (allowed, retry_after). The clock is an injected value (`now: float`), so tests are deterministic and never sleep.
- `PolicyDecision` (dataclass): `allow: bool`, `code: int` (200 / 403 / 429), `reason: str`, `gate: str` ("destination" | "rate"), `host`, `port`.
- `decide(host, port, now, policy, buckets) -> PolicyDecision` — the single entry the transport calls. **Deny-by-default:** an empty allowlist denies all; an unparseable host denies; destination check precedes rate check.
- `AuditRecord` (dataclass) + `to_json_line() -> str` — typed, append-only record: timestamp, host, port, kind (`CONNECT` | HTTP verb), decision, reason, gate, rate-state.

Depends only on `sandbox.canonical_host` and the standard library.

### 4.2 `plugin/tools/egress_proxy.py` — transport only (stdlib `asyncio`)

- An asyncio server bound to `127.0.0.1:PORT`.
- Handles two request shapes:
  - **HTTPS via `CONNECT host:port`** — parse the target, call `egress.decide`; on ALLOW open the upstream connection and pipe bytes bidirectionally; on DENY write `403`/`429` and close.
  - **HTTP absolute-form** (`GET http://host/path`) — dest from the request line; same decide → forward-or-refuse path.
- **Ordering that matters:** the upstream origin is resolved/dialled **only after an ALLOW decision**. A denied destination is refused before any DNS lookup or socket to the origin.
- **Rate-bucket granularity:** `decide` (and therefore one token consumption) runs **once per `CONNECT`** and **once per absolute-form HTTP request** — i.e. per-connection for HTTPS tunnels, per-request for plaintext HTTP. This is the per-connection limitation noted in §8, made explicit here so the counting unit is unambiguous.
- Appends one `AuditRecord` JSON line per request to `audit_path`.
- CLI: `python egress_proxy.py --port P --allow host[:port] [--allow ...] --rate N --refill R --audit PATH`.

Depends on `egress.py` + stdlib `asyncio`. Single responsibility: parse → ask policy → forward or refuse → audit.

## 5. Data flow

```
tool (HTTPS_PROXY=127.0.0.1:PORT)
  → proxy receives  CONNECT target:443
    → egress.decide(target, 443, now, policy, buckets)
        ALLOW → asyncio.open_connection(target, 443) → bidirectional pipe → audit ALLOW
        DENY  → write 403 (destination) / 429 (rate) → close   [origin NEVER dialled] → audit DENY
```

HTTP absolute-form is identical with the destination taken from the request line; a denied request returns `403`/`429` without forwarding.

## 6. Security properties → success-criteria mapping

- **Command-obfuscation independence (a):** the proxy decides on the destination it actually receives, never on a shell-command string — so `$(...)`/base64 in the client's invocation cannot change the decision. The boundary does not parse commands.
- **Refuse-before-resolve (b):** the decide → dial ordering means an out-of-scope host is rejected before name resolution; the integration test asserts the spy out-of-scope server received zero connections.
- **Rate ceiling (c) + fail-closed:** per-host token bucket refuses the over-threshold request; empty allowlist and parse failures deny by default.

## 7. Testing strategy

- **Unit — `tests/test_egress.py`** (no sockets, injected clock): allowlist in/out + explicit port match + `canonical_host` folding (IP vs hostname vs loopback spellings); token-bucket consume / refill / deny-over-threshold; `decide` precedence and fail-closed cases; `AuditRecord.to_json_line` shape.
- **Integration — `tests/test_egress_proxy.py`** (real proxy on an ephemeral `127.0.0.1` port, stdlib client through it):
  - **(a)** the client assembles the destination via base64 in its own invocation, yet the proxy receives and blocks `evil.example` — demonstrating the boundary is independent of command construction.
  - **(b)** an allowed stdlib origin returns `302` to an out-of-scope host; the redirect-follow issues a fresh request through the proxy, which refuses it before resolution, while a spy out-of-scope server asserts **zero** connections.
  - **(c)** the `(N+1)`th request to an allowed host within the window returns `429`.
  - Portability: tests use a stdlib client (no `curl` dependency) so they run on Windows/Linux; an optional `curl -L` variant is skipped when `curl` is absent.

## 8. Risks & open items

- **HTTPS opacity.** A CONNECT-allowlist proxy cannot rate-limit per-request inside a TLS tunnel — only per-connection. Accepted for M1 (destination allowlisting is the goal); revisit with an intercepting proxy only if per-request inspection is later required.
- **Proxy-ignoring tools.** Until the M2 egress firewall, a tool that bypasses the proxy env is not contained. This is documented so M1 is not mistaken for a hard boundary.
- **asyncio tunnelling on Windows.** Bidirectional CONNECT piping is validated by the integration tests on the primary platform.

## 9. Milestone boundary / what comes next

Milestone 2 (separate spec): the egress-firewall backstop (hard-contain proxy-ignoring tools), an `active-lab` preflight posture checker extending the `network_isolation_check` pattern, the per-program "active testing permitted?" gate captured by `bb-scope`/`bb-start`, and auto-pause on anomaly.
