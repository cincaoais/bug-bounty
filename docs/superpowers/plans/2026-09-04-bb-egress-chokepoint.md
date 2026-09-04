# bb Egress Chokepoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone, stdlib-only forward proxy that enforces a destination allowlist + per-host request-rate ceiling + append-only audit — the network-layer boundary the string-parsing scope-guard hook cannot be.

**Architecture:** Two modules split policy from transport. `plugin/mcp/egress.py` is pure decision logic (allowlist via `sandbox.canonical_host`, per-host token bucket with an injected clock, `decide()` deny-by-default, `AuditRecord`). `plugin/tools/egress_proxy.py` is a stdlib `asyncio` forward proxy handling HTTPS `CONNECT` and HTTP absolute-form, refusing an out-of-scope destination **before** any DNS/connect. No new runtime dependencies; the live plugin is untouched.

**Tech Stack:** Python 3.13 standard library only (`asyncio`, `argparse`, `dataclasses`, `json`, `socket`, `http.server`, `urllib.request` in tests). Reuses `plugin/mcp/sandbox.py:canonical_host`.

**Spec:** `docs/superpowers/specs/2026-09-04-bb-egress-chokepoint-design.md`

## Global Constraints

- **Python 3.13, standard library only** — no new runtime dependency may be added.
- **Live plugin/hook untouched** — create only the four files below; do not modify `scope-guard.py`, `server.py`, any skill, README, or counts. Ingest-only stays the default.
- **Deny-by-default everywhere** — empty allowlist denies all; unparseable host denies; destination check precedes rate check.
- **Refuse-before-resolve** — the upstream origin is dialled only after an ALLOW decision.
- **Files (only these):** `plugin/mcp/egress.py`, `plugin/tools/egress_proxy.py`, `tests/test_egress.py`, `tests/test_egress_proxy.py`.
- **Import convention:** tests import `egress`/`sandbox` directly (`conftest.py` puts `plugin/mcp` on `sys.path`); `egress_proxy.py` inserts `plugin/mcp` on `sys.path` at startup (mirroring `scope-guard.py`) before `import egress`.
- **Commit after every task.**

---

## File Structure

- `plugin/mcp/egress.py` — pure policy: `Rule`, `Allowlist`, `TokenBucket`, `PolicyDecision`, `decide()`, `AuditRecord`. No sockets, no ambient clock, no I/O.
- `plugin/tools/egress_proxy.py` — asyncio transport: parse → `egress.decide` → forward-or-refuse → audit. CLI entry, prints `LISTENING host:port` on startup.
- `tests/test_egress.py` — unit tests for the policy module (no sockets, injected clock).
- `tests/test_egress_proxy.py` — integration tests (real proxy subprocess on an ephemeral loopback port, stdlib client).

---

### Task 1: `egress.py` — Rule + Allowlist

**Files:**
- Create: `plugin/mcp/egress.py`
- Test: `tests/test_egress.py`

**Interfaces:**
- Consumes: `sandbox.canonical_host(str) -> str | None` (existing).
- Produces:
  - `Rule(host: str, port: int | None = None)` — frozen dataclass; `port=None` means any port.
  - `Allowlist(rules: Iterable[Rule])` with `.allows(host: str, port: int | None) -> tuple[bool, str]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_egress.py
import egress
from egress import Rule, Allowlist


def test_allowlist_allows_exact_host_and_port():
    al = Allowlist([Rule("example.com", 443)])
    assert al.allows("example.com", 443)[0] is True


def test_allowlist_denies_wrong_port():
    al = Allowlist([Rule("example.com", 443)])
    ok, reason = al.allows("example.com", 80)
    assert ok is False and "allowlist" in reason.lower()


def test_allowlist_denies_off_allowlist_host():
    al = Allowlist([Rule("example.com", 443)])
    assert al.allows("evil.example", 443)[0] is False


def test_allowlist_empty_denies_all():
    assert Allowlist([]).allows("example.com", 443)[0] is False


def test_allowlist_none_port_rule_allows_any_port():
    al = Allowlist([Rule("example.com", None)])
    assert al.allows("example.com", 8443)[0] is True


def test_allowlist_folds_loopback_spelling():
    # canonical_host folds 2130706433 -> 127.0.0.1
    al = Allowlist([Rule("127.0.0.1", 3000)])
    assert al.allows("2130706433", 3000)[0] is True


def test_allowlist_denies_invalid_host():
    assert Allowlist([Rule("example.com", 443)]).allows("", 443)[0] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_egress.py -q`
Expected: FAIL (`ModuleNotFoundError: No module named 'egress'`).

- [ ] **Step 3: Write minimal implementation**

```python
# plugin/mcp/egress.py
"""Active-lab egress policy (milestone 1): pure decision logic, no I/O.

Standalone; NOT wired into the live plugin. Unlike sandbox mode, non-loopback
hosts ARE allowed here — this is the active-lab posture (one authorized external
target, deny everything else). See
docs/superpowers/specs/2026-09-04-bb-egress-chokepoint-design.md
"""
from __future__ import annotations

from dataclasses import dataclass

import sandbox  # plugin/mcp on sys.path (conftest / proxy startup insert)


@dataclass(frozen=True)
class Rule:
    host: str
    port: int | None = None  # None = any port on this host


class Allowlist:
    """Destination allowlist. Deny-by-default."""

    def __init__(self, rules):
        self.rules = list(rules)

    def allows(self, host, port) -> tuple[bool, str]:
        ch = sandbox.canonical_host(host)
        if ch is None:
            return (False, "invalid/empty host (deny-by-default)")
        if not self.rules:
            return (False, "empty allowlist (deny-by-default)")
        for rule in self.rules:
            rh = sandbox.canonical_host(rule.host)
            if rh is not None and rh == ch and (rule.port is None or rule.port == port):
                shown = rule.port if rule.port is not None else "*"
                return (True, f"matches allowlist rule {rule.host}:{shown}")
        return (False, f"{ch}:{port} not on allowlist (deny-by-default)")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_egress.py -q`
Expected: PASS (7 passed).

- [ ] **Step 5: Commit**

```bash
git add plugin/mcp/egress.py tests/test_egress.py
git commit -m "feat(egress): destination allowlist with canonical-host folding"
```

---

### Task 2: `egress.py` — TokenBucket

**Files:**
- Modify: `plugin/mcp/egress.py`
- Test: `tests/test_egress.py`

**Interfaces:**
- Produces: `TokenBucket(capacity: int, refill_per_sec: float)` with `.try_consume(host: str, now: float) -> tuple[bool, float]` returning `(allowed, retry_after_seconds)`. Deterministic — the caller supplies `now`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_egress.py
from egress import TokenBucket


def test_token_bucket_allows_up_to_capacity_then_denies():
    tb = TokenBucket(capacity=3, refill_per_sec=0.0)
    assert tb.try_consume("h", now=0.0)[0] is True
    assert tb.try_consume("h", now=0.0)[0] is True
    assert tb.try_consume("h", now=0.0)[0] is True
    allowed, retry = tb.try_consume("h", now=0.0)
    assert allowed is False and retry > 0


def test_token_bucket_refills_over_time():
    tb = TokenBucket(capacity=1, refill_per_sec=1.0)
    assert tb.try_consume("h", now=0.0)[0] is True
    assert tb.try_consume("h", now=0.0)[0] is False      # empty
    assert tb.try_consume("h", now=1.0)[0] is True        # 1s -> 1 token


def test_token_bucket_is_per_host():
    tb = TokenBucket(capacity=1, refill_per_sec=0.0)
    assert tb.try_consume("a", now=0.0)[0] is True
    assert tb.try_consume("b", now=0.0)[0] is True        # separate bucket
    assert tb.try_consume("a", now=0.0)[0] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_egress.py -k token_bucket -q`
Expected: FAIL (`ImportError: cannot import name 'TokenBucket'`).

- [ ] **Step 3: Write minimal implementation**

```python
# append to plugin/mcp/egress.py
class TokenBucket:
    """Per-host token bucket. Deterministic: the caller passes `now` (seconds).
    One token consumed per request; refills at `refill_per_sec`."""

    def __init__(self, capacity, refill_per_sec):
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self._state: dict[str, tuple[float, float]] = {}  # host -> (tokens, last_ts)

    def try_consume(self, host, now) -> tuple[bool, float]:
        tokens, last = self._state.get(host, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
        if tokens >= 1.0:
            self._state[host] = (tokens - 1.0, now)
            return (True, 0.0)
        needed = 1.0 - tokens
        retry_after = needed / self.refill_per_sec if self.refill_per_sec > 0 else float("inf")
        self._state[host] = (tokens, now)
        return (False, retry_after)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_egress.py -q`
Expected: PASS (10 passed).

- [ ] **Step 5: Commit**

```bash
git add plugin/mcp/egress.py tests/test_egress.py
git commit -m "feat(egress): per-host token bucket with injected clock"
```

---

### Task 3: `egress.py` — PolicyDecision + decide()

**Files:**
- Modify: `plugin/mcp/egress.py`
- Test: `tests/test_egress.py`

**Interfaces:**
- Produces:
  - `PolicyDecision(allow: bool, code: int, reason: str, gate: str, host: str, port: int | None)` — `code` is 200/403/429; `gate` is `"allow"|"destination"|"rate"`.
  - `decide(host, port, now, allowlist: Allowlist, buckets: TokenBucket) -> PolicyDecision`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_egress.py
from egress import PolicyDecision, decide


def test_decide_allows_in_scope_within_rate():
    al = Allowlist([Rule("example.com", 443)])
    tb = TokenBucket(capacity=5, refill_per_sec=0.0)
    d = decide("example.com", 443, 0.0, al, tb)
    assert d.allow is True and d.code == 200 and d.gate == "allow"


def test_decide_denies_off_scope_with_403_and_does_not_consume_token():
    al = Allowlist([Rule("example.com", 443)])
    tb = TokenBucket(capacity=1, refill_per_sec=0.0)
    d = decide("evil.example", 443, 0.0, al, tb)
    assert d.allow is False and d.code == 403 and d.gate == "destination"
    # token was NOT consumed by the off-scope request
    assert tb.try_consume("example.com", 0.0)[0] is True


def test_decide_denies_over_rate_with_429():
    al = Allowlist([Rule("example.com", 443)])
    tb = TokenBucket(capacity=1, refill_per_sec=0.0)
    assert decide("example.com", 443, 0.0, al, tb).allow is True
    d = decide("example.com", 443, 0.0, al, tb)
    assert d.allow is False and d.code == 429 and d.gate == "rate"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_egress.py -k decide -q`
Expected: FAIL (`ImportError: cannot import name 'decide'`).

- [ ] **Step 3: Write minimal implementation**

```python
# append to plugin/mcp/egress.py
@dataclass(frozen=True)
class PolicyDecision:
    allow: bool
    code: int          # 200 | 403 | 429
    reason: str
    gate: str          # "allow" | "destination" | "rate"
    host: str
    port: int | None


def decide(host, port, now, allowlist, buckets) -> PolicyDecision:
    ch = sandbox.canonical_host(host) or host
    ok, reason = allowlist.allows(host, port)
    if not ok:
        return PolicyDecision(False, 403, reason, "destination", ch, port)
    allowed, retry = buckets.try_consume(ch, now)
    if not allowed:
        return PolicyDecision(False, 429, f"rate limit exceeded (retry after {retry:.2f}s)",
                              "rate", ch, port)
    return PolicyDecision(True, 200, reason, "allow", ch, port)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_egress.py -q`
Expected: PASS (13 passed).

- [ ] **Step 5: Commit**

```bash
git add plugin/mcp/egress.py tests/test_egress.py
git commit -m "feat(egress): decide() — deny-by-default, destination before rate"
```

---

### Task 4: `egress.py` — AuditRecord

**Files:**
- Modify: `plugin/mcp/egress.py`
- Test: `tests/test_egress.py`

**Interfaces:**
- Produces:
  - `AuditRecord(ts, host, port, kind, decision, code, gate, reason)` frozen dataclass.
  - `AuditRecord.from_decision(kind: str, d: PolicyDecision, ts: float | None = None) -> AuditRecord`.
  - `AuditRecord.to_json_line() -> str` (compact JSON + trailing newline).

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_egress.py
import json
from egress import AuditRecord


def test_audit_record_from_decision_and_json_line():
    al = Allowlist([Rule("example.com", 443)])
    tb = TokenBucket(capacity=1, refill_per_sec=0.0)
    d = decide("evil.example", 443, 0.0, al, tb)
    rec = AuditRecord.from_decision("CONNECT", d, ts=1234.5)
    obj = json.loads(rec.to_json_line())
    assert obj["host"] == "evil.example"
    assert obj["kind"] == "CONNECT"
    assert obj["decision"] == "deny"
    assert obj["code"] == 403
    assert obj["gate"] == "destination"
    assert obj["ts"] == 1234.5
    assert rec.to_json_line().endswith("\n")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_egress.py -k audit -q`
Expected: FAIL (`ImportError: cannot import name 'AuditRecord'`).

- [ ] **Step 3: Write minimal implementation**

```python
# add near the top of plugin/mcp/egress.py imports:
#   import json, time as _time
# append to plugin/mcp/egress.py
@dataclass(frozen=True)
class AuditRecord:
    ts: float
    host: str
    port: int | None
    kind: str          # "CONNECT" | HTTP verb ("GET", ...)
    decision: str      # "allow" | "deny"
    code: int
    gate: str
    reason: str

    @classmethod
    def from_decision(cls, kind, d: "PolicyDecision", ts=None) -> "AuditRecord":
        return cls(
            ts=ts if ts is not None else _time.time(),
            host=d.host, port=d.port, kind=kind,
            decision="allow" if d.allow else "deny",
            code=d.code, gate=d.gate, reason=d.reason,
        )

    def to_json_line(self) -> str:
        return json.dumps({
            "ts": self.ts, "host": self.host, "port": self.port, "kind": self.kind,
            "decision": self.decision, "code": self.code, "gate": self.gate,
            "reason": self.reason,
        }, separators=(",", ":")) + "\n"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_egress.py -q`
Expected: PASS (14 passed).

- [ ] **Step 5: Commit**

```bash
git add plugin/mcp/egress.py tests/test_egress.py
git commit -m "feat(egress): typed append-only AuditRecord"
```

---

### Task 5: `egress_proxy.py` — asyncio transport + CLI

**Files:**
- Create: `plugin/tools/egress_proxy.py`
- Test: `tests/test_egress_proxy.py`

**Interfaces:**
- Consumes: `egress.Allowlist`, `egress.TokenBucket`, `egress.decide`, `egress.AuditRecord`, `egress.Rule`.
- Produces: a runnable proxy. CLI: `python egress_proxy.py --host 127.0.0.1 --port 0 --allow host[:port] [--allow ...] --rate N --refill R --audit PATH`. Prints `LISTENING <host>:<port>` to stdout once bound, then serves. `403` for destination deny, `429` for rate deny, `502` for upstream-connect failure after allow.

- [ ] **Step 1: Write the failing test (transport happy-path + basic deny)**

```python
# tests/test_egress_proxy.py
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROXY = Path(__file__).resolve().parent.parent / "plugin" / "tools" / "egress_proxy.py"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _OK(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def _http_server(port, handler):
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _start_proxy(allow, rate=100, refill=100.0, audit=None):
    args = [sys.executable, str(PROXY), "--port", "0", "--rate", str(rate), "--refill", str(refill)]
    for a in allow:
        args += ["--allow", a]
    if audit:
        args += ["--audit", str(audit)]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = proc.stdout.readline()
    assert line.startswith("LISTENING"), f"unexpected startup line: {line!r}"
    port = int(line.strip().rsplit(":", 1)[1])
    return proc, port


def test_http_absolute_form_allowed_forwards_to_origin():
    _OK.hits = 0
    origin = _free_port()
    _http_server(origin, _OK)
    proc, pport = _start_proxy(allow=[f"127.0.0.1:{origin}"])
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"127.0.0.1:{pport}"}))
        resp = opener.open(f"http://127.0.0.1:{origin}/", timeout=5)
        assert resp.read() == b"ok"
        assert _OK.hits == 1
    finally:
        proc.terminate()


def test_connect_denied_returns_403():
    proc, pport = _start_proxy(allow=["127.0.0.1:9"])  # non-empty allowlist, different port
    try:
        s = socket.create_connection(("127.0.0.1", pport), timeout=5)
        s.sendall(b"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n")
        resp = s.recv(1024).decode("latin-1")
        s.close()
        assert "403" in resp
    finally:
        proc.terminate()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_egress_proxy.py -q`
Expected: FAIL (proxy script does not exist → startup line assertion fails).

- [ ] **Step 3: Write minimal implementation**

```python
# plugin/tools/egress_proxy.py
#!/usr/bin/env python3
"""Active-lab egress chokepoint (milestone 1): a deny-by-default forward proxy.

Standalone; NOT wired into the live plugin. All allow/deny/rate decisions come
from egress.py. Refuse-before-resolve: an out-of-scope destination is rejected
before any DNS lookup or upstream socket.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp"))
import egress  # noqa: E402


class Proxy:
    def __init__(self, allowlist, buckets, audit_path=None, clock=time.time):
        self.allowlist = allowlist
        self.buckets = buckets
        self.audit_path = audit_path
        self.clock = clock

    def _audit(self, kind, decision):
        rec = egress.AuditRecord.from_decision(kind, decision, ts=self.clock())
        if self.audit_path:
            with open(self.audit_path, "a", encoding="utf-8") as fh:
                fh.write(rec.to_json_line())

    async def handle(self, reader, writer):
        try:
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return
            parts = request_line.decode("latin-1").rstrip("\r\n").split(" ")
            if len(parts) < 3:
                await self._refuse(writer, 400, "bad request line")
                return
            method, target = parts[0], parts[1]
            if method.upper() == "CONNECT":
                await self._connect(reader, writer, target)
            else:
                await self._http(reader, writer, method, target)
        except Exception:
            try:
                writer.close()
            except Exception:
                pass

    async def _connect(self, reader, writer, target):
        host, _, port_s = target.rpartition(":")
        if not host:
            host, port = target, 443
        else:
            port = int(port_s) if port_s.isdigit() else 443
        while True:  # drain remaining CONNECT headers
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        d = egress.decide(host, port, self.clock(), self.allowlist, self.buckets)
        self._audit("CONNECT", d)
        if not d.allow:
            await self._refuse(writer, d.code, d.reason)
            return
        try:
            up_r, up_w = await asyncio.open_connection(host, port)
        except OSError as e:
            await self._refuse(writer, 502, f"upstream connect failed: {e}")
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._pipe(reader, writer, up_r, up_w)

    async def _http(self, reader, writer, method, target):
        if "://" not in target:
            await self._refuse(writer, 400, "non-absolute-form request")
            return
        rest = target.split("://", 1)[1]
        hostport, _, path = rest.partition("/")
        host, _, port_s = hostport.partition(":")
        port = int(port_s) if port_s.isdigit() else 80
        d = egress.decide(host, port, self.clock(), self.allowlist, self.buckets)
        self._audit(method.upper(), d)
        if not d.allow:
            await self._refuse(writer, d.code, d.reason)
            return
        try:
            up_r, up_w = await asyncio.open_connection(host, port)
        except OSError as e:
            await self._refuse(writer, 502, f"upstream connect failed: {e}")
            return
        up_w.write(f"{method} /{path} HTTP/1.1\r\n".encode("latin-1"))
        while True:  # copy request headers (incl. Host) verbatim
            line = await reader.readline()
            up_w.write(line)
            if line in (b"\r\n", b"\n", b""):
                break
        await up_w.drain()
        await self._pipe(reader, writer, up_r, up_w)

    async def _refuse(self, writer, code, reason):
        body = f"{code} {reason}".encode("utf-8")
        writer.write(
            f"HTTP/1.1 {code} Blocked\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n".encode("latin-1") + body)
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()

    async def _pipe(self, c_r, c_w, u_r, u_w):
        async def copy(src, dst):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass
        await asyncio.gather(copy(c_r, u_w), copy(u_r, c_w))


def _rules_from_allow(allow_list):
    rules = []
    for a in allow_list:
        host, _, port_s = a.rpartition(":")
        if host and port_s.isdigit():
            rules.append(egress.Rule(host, int(port_s)))
        else:
            rules.append(egress.Rule(a, None))
    return rules


async def _serve(args):
    allowlist = egress.Allowlist(_rules_from_allow(args.allow))
    buckets = egress.TokenBucket(args.rate, args.refill)
    proxy = Proxy(allowlist, buckets, audit_path=args.audit)
    server = await asyncio.start_server(proxy.handle, args.host, args.port)
    addr = server.sockets[0].getsockname()
    print(f"LISTENING {addr[0]}:{addr[1]}", flush=True)
    async with server:
        await server.serve_forever()


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--allow", action="append", default=[], help="host[:port]; repeatable")
    p.add_argument("--rate", type=int, default=100, help="token-bucket capacity")
    p.add_argument("--refill", type=float, default=100.0, help="tokens per second")
    p.add_argument("--audit", default=None)
    args = p.parse_args(argv)
    try:
        asyncio.run(_serve(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_egress_proxy.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add plugin/tools/egress_proxy.py tests/test_egress_proxy.py
git commit -m "feat(egress-proxy): asyncio CONNECT+HTTP forward proxy, refuse-before-resolve"
```

---

### Task 6: Integration tests — the three success criteria

**Files:**
- Modify: `tests/test_egress_proxy.py`

**Interfaces:**
- Consumes: helpers from Task 5 (`_free_port`, `_http_server`, `_start_proxy`, `_OK`).

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_egress_proxy.py
import base64
import json


def test_out_of_scope_blocked_regardless_of_command_obfuscation(tmp_path):
    # (crit a) the proxy decides on the destination it RECEIVES, not on any
    # command string — so a base64-assembled host is still seen and blocked.
    audit = tmp_path / "audit.jsonl"
    proc, pport = _start_proxy(allow=["127.0.0.1:9"], audit=audit)
    try:
        host = base64.b64decode(b"ZXZpbC5leGFtcGxl").decode()  # "evil.example"
        s = socket.create_connection(("127.0.0.1", pport), timeout=5)
        s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        resp = s.recv(1024).decode("latin-1")
        s.close()
        assert "403" in resp
    finally:
        proc.terminate()
    records = [json.loads(x) for x in audit.read_text().splitlines() if x.strip()]
    assert any(r["host"] == "evil.example" and r["decision"] == "deny"
               and r["gate"] == "destination" for r in records)


def test_redirect_to_out_of_scope_blocked_and_origin_never_contacted():
    # (crit b) allowed origin 302-redirects to an out-of-scope port; the
    # redirect-follow is refused at the proxy; the spy server gets 0 hits.
    allowed = _free_port()
    spy = _free_port()

    class _Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{spy}/")
            self.end_headers()

        def log_message(self, *a):
            pass

    _OK.hits = 0
    _http_server(allowed, _Redirect)
    _http_server(spy, _OK)   # out-of-scope: different port -> not on allowlist
    proc, pport = _start_proxy(allow=[f"127.0.0.1:{allowed}"])
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"127.0.0.1:{pport}"}))
        try:
            opener.open(f"http://127.0.0.1:{allowed}/", timeout=5)
            assert False, "expected the out-of-scope redirect target to be blocked"
        except urllib.error.HTTPError as e:
            assert e.code == 403
    finally:
        proc.terminate()
    assert _OK.hits == 0  # spy (out-of-scope) never contacted


def test_per_host_rate_limit_returns_429():
    # (crit c) capacity 3, no refill -> 4th request over the ceiling is 429.
    allowed = _free_port()
    _OK.hits = 0
    _http_server(allowed, _OK)
    proc, pport = _start_proxy(allow=[f"127.0.0.1:{allowed}"], rate=3, refill=0.0)
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"127.0.0.1:{pport}"}))
        codes = []
        for _ in range(4):
            try:
                codes.append(opener.open(f"http://127.0.0.1:{allowed}/", timeout=5).status)
            except urllib.error.HTTPError as e:
                codes.append(e.code)
        assert codes[:3] == [200, 200, 200]
        assert codes[3] == 429
    finally:
        proc.terminate()
```

- [ ] **Step 2: Run tests to verify they pass (implementation already exists from Task 5)**

Run: `python -m pytest tests/test_egress_proxy.py -q`
Expected: PASS (5 passed). If any fail, fix `egress_proxy.py`/`egress.py` until green — these three tests ARE the milestone's success criteria.

- [ ] **Step 3: Commit**

```bash
git add tests/test_egress_proxy.py
git commit -m "test(egress): prove obfuscation-independent block, redirect block, rate 429"
```

---

### Task 7: Full-suite verification & isolation check

**Files:** none (verification only).

- [ ] **Step 1: Run the full Python suite**

Run: `python -m pytest -q`
Expected: all prior tests still pass PLUS the new `test_egress*` (was 457; now 457 + new egress tests).

- [ ] **Step 2: Run the node skill-verification suite (must be unaffected)**

Run: `node --test tools/verify-ported-skills.test.js`
Expected: `# pass 4  # fail 0` — unchanged (no skills/counts touched).

- [ ] **Step 3: Confirm the live plugin is untouched**

Run: `git diff --name-only main -- plugin/hooks plugin/mcp/server.py plugin/mcp/scope-guard.py plugin/skills README.md .claude-plugin`
Expected: EMPTY output (only `plugin/mcp/egress.py`, `plugin/tools/egress_proxy.py`, and the two test files are new; nothing existing was modified).

- [ ] **Step 4: Commit (if any verification-driven fixes were needed; otherwise skip)**

```bash
git add -A
git commit -m "chore(egress): milestone-1 verification green (pytest + node)"
```

---

## Self-Review

**1. Spec coverage** (each spec section → task):
- §4.1 `egress.py` policy → Tasks 1–4 (Allowlist, TokenBucket, decide, AuditRecord). ✓
- §4.2 `egress_proxy.py` transport (CONNECT + HTTP, refuse-before-resolve, 403/429/502, audit, `LISTENING` startup, CLI) → Task 5. ✓
- §6 success-criteria mapping (a obfuscation-independent, b redirect-blocked + origin-never-contacted, c rate) → Task 6. ✓
- §7 testing strategy (unit no-sockets; integration ephemeral loopback, stdlib client, no curl dep) → Tasks 1–6. ✓
- §3 non-goals (no firewall, no mode wiring, no per-program gate, no live-plugin change) → enforced by Global Constraints + Task 7 Step 3 isolation check. ✓
- §8 risks (per-connection rate on HTTPS; proxy-ignoring tools uncontained) → documented; not code tasks (correctly deferred to M2). ✓

**2. Placeholder scan:** no TBD/TODO; every code step contains the actual implementation. ✓

**3. Type consistency:** `Rule(host, port|None)`, `Allowlist.allows(host, port)->(bool,str)`, `TokenBucket.try_consume(host, now)->(bool,float)`, `PolicyDecision(allow,code,reason,gate,host,port)`, `decide(host,port,now,allowlist,buckets)`, `AuditRecord.from_decision(kind,d,ts)`/`.to_json_line()` — names and signatures identical across Tasks 1–6 and the proxy. ✓

**Known platform note for the executor:** integration tests distinguish allowed vs out-of-scope by **port on `127.0.0.1`**, because `sandbox.canonical_host` folds all of `127.0.0.0/8` to `127.0.0.1` (so `127.0.0.2` would wrongly match a `127.0.0.1` rule). Off-scope *hostname* cases use an unresolvable name (`evil.example`) that is denied before resolution — never dialled — so tests never hang.
