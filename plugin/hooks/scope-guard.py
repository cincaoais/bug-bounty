#!/usr/bin/env python3
"""PreToolUse hook: deny out-of-scope actions before they run.

This is the ONE enforcement point that lives outside the model. It cannot be
prompt-injected, forgotten after compaction, or reasoned around, because it is a
separate process that inspects every matched tool call and returns a decision.

Contract (Claude Code PreToolUse):
  stdin  = JSON with tool_name, tool_input, permission_mode, ...
  stdout = optional JSON {hookSpecificOutput:{permissionDecision: deny|ask|allow, ...}}
  exit 0 always (JSON carries the decision); no JSON => defer to normal flow.

Honest limits (documented in the plan, §5): host extraction from a shell command
is best-effort. curl "$(...)" and base64-encoded hosts can evade it. This is a
strong guard against DRIFT AND MISTAKES — the real risk in ingest-only use, where
nobody is trying to evade it — not a hard security boundary. It errs toward DENY:
unknown host => blocked. Clear a false positive with the mcp__bb__scope_override
tool.

Sandbox mode (docs/02-PLAN.md Slice 2.2, `target.mode=='sandbox'`): a separate,
stricter, EARLY-branching decision path (`_decide_sandbox`) that auto-allows
active-testing tool calls to the declared sandbox host:port only, denies
everything else including on ambiguity/zero-candidate, and never consults
scope_override. This hook is still only the first of two layers there too — the
real containment backstop is network isolation (`--network internal` +
127.0.0.1-only bind), verified at the skill's preflight, not by this file.
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

# import the shared scope + registry modules (same definitions the MCP server uses)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp"))
import registry  # noqa: E402
import sandbox  # noqa: E402  (canonical_host — closes the bare-IP gap below)
import mission  # noqa: E402  (log_sandbox_decision — sandbox-branch audit trail)


URL_RE = re.compile(r'https?://[^\s"\'`<>|)\]}]+', re.I)
# bare host: label(.label)+.tld  — at least one dot and an alphabetic TLD
HOST_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$', re.I)
# dotted-quad IPv4, optionally followed by :PORT — the unconditional (always
# extracted, no positional discipline needed) IP-literal matcher.
IPV4_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b')
# same dotted-quad shape, anchored, used to recognise "already handled by
# IPV4_RE above" tokens in the bare-token loop so they aren't double-processed.
_DOTTED_QUAD_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
# bare non-dotted-quad numeric host candidates: decimal, hex (0x...), or a
# short inet_aton-style dotted form (1-4 parts, e.g. "127.1"). These are the
# forms sandbox.canonical_host knows how to fold to a loopback identity.
_NUMERIC_HOST_RE = re.compile(r'^(?:0x[0-9a-f]+|\d+(?:\.\d+){0,3})$', re.I)

# Bare domains are only treated as network targets when they sit in a network
# CONTEXT. Without this, every `word.ext` token — filenames (server.py,
# plugin.json), module refs (json.load, sys.stdin) — reads as a host and gets
# denied, which breaks routine shell use the moment a target is active.
# URLs and IP literals are always extracted; only BARE domains need the context.
_NET_TOOLS = frozenset({
    "curl", "wget", "nc", "ncat", "netcat", "telnet", "ping", "nslookup", "dig",
    "host", "nmap", "masscan", "ffuf", "nuclei", "httpx", "katana", "gobuster",
    "feroxbuster", "wfuzz", "hydra", "openssl", "socat", "amass", "subfinder",
})
_URL_FLAGS = frozenset({"-u", "--url", "--target", "-target", "--host"})
_NET_PRESENT = re.compile(
    r"(?i)(?:^|[\s/\\|&;`(])(" + "|".join(sorted(_NET_TOOLS)) + r")(?:\s|$)")
_STRIP = "'\"`(),;|&<>"


def extract_targets(tool_name: str, tool_input: dict) -> list[tuple[str, int | None, str | None]]:
    """Return [(host, port, path_or_None)] candidates found in the tool input.

    We look at the whole stringified input so we catch hosts in any tool's args,
    not just Bash commands. Dedup is BY HOST (first-seen port+path wins) — the
    same granularity as before port existed as a concept. This matters: it keeps
    the exact set of (host, path) pairs fed to the real-program scope check
    identical to pre-port-carry behaviour, so real-program decisions don't shift
    just because a second scan pass (e.g. the unconditional IPv4 literal scan
    re-matching an IP embedded in an already-extracted URL) now also produces a
    port. A future sandbox-branch slice that needs multiple distinct ports for
    the same host in one command will need a different data path — see notes
    in docs/02-PLAN.md Slice 2.2.
    """
    # Burp send tools (send_http1_request / send_http2_request / send_to_intruder)
    # put traffic on the wire and carry the authoritative destination in
    # `targetHostname` (+ `targetPort`). Gate on THOSE FIELDS ONLY — never scan
    # the raw `content`, which legitimately contains other hosts (an
    # out-of-scope URL placed in a parameter to test SSRF, a redirect target,
    # etc.). Scanning content would falsely block in-scope testing. Falls
    # through to generic extraction only if the required field is somehow absent.
    if tool_name.startswith("mcp__burp__send") and isinstance(tool_input, dict):
        h = tool_input.get("targetHostname")
        if h:
            host = str(h).split(":", 1)[0].strip().rstrip(".").lower()
            port = _as_port(tool_input.get("targetPort"))
            return [(host, port, None)] if host else []

    # Scan the RAW command for Bash (so tokenisation and the network-context
    # check see real shell tokens, not JSON-quoted ones). Other tools: stringify.
    raw_cmd = tool_input.get("command") if isinstance(tool_input, dict) else None
    text = raw_cmd if isinstance(raw_cmd, str) else _stringify(tool_input)
    found: dict[str, tuple[int | None, str | None]] = {}

    # Explicit URLs and IP literals: always extracted — unambiguous network targets.
    for m in URL_RE.finditer(text):
        host, port, path = _split_url(m.group(0))
        if host:
            found.setdefault(host, (port, path))
    for m in IPV4_RE.finditer(text):
        host = m.group(1)
        port = _as_port(m.group(2)) if m.group(2) else None
        found.setdefault(host, (port, None))

    # Bare domains AND bare non-dotted-quad numeric IPs (2130706433, 127.1, ...):
    # only when a network tool appears in the command, and only for a token
    # whose PRECEDING token is that tool or a URL flag. This is what keeps
    # `cat plugin.json` / `python -m pytest test_hook.py` — and `--max-time
    # 2130706433` — from being read as hosts.
    if _NET_PRESENT.search(text):
        toks = text.split()
        for i, raw in enumerate(toks):
            tok = raw.strip(_STRIP)
            if not tok:
                continue
            host_part, port = _split_bare_hostport(tok)
            if not host_part or _DOTTED_QUAD_RE.match(host_part):
                continue                        # dotted-quad: already handled above

            candidate_host = None
            if HOST_RE.match(host_part):
                candidate_host = host_part      # already lowercased by the splitter
            elif _NUMERIC_HOST_RE.match(host_part):
                # Close the bare-IP gap: decimal/hex/octal/short-dotted numeric
                # forms (2130706433, 0x7f000001, 127.1, ...) never match HOST_RE
                # or IPV4_RE. Only treat one as a host when it canonicalizes to
                # a loopback identity, or is already a directly-parseable IP —
                # NOT an arbitrary large number that merely looks numeric-IP-ish
                # (e.g. an out-of-place decimal that isn't loopback and isn't a
                # real IP stays inert, deny-by-default has nothing to act on).
                canon = sandbox.canonical_host(host_part)
                if canon is not None and (canon in ("127.0.0.1", "::1") or _is_plain_ip(host_part)):
                    candidate_host = canon
            if candidate_host is None:
                continue

            prev = toks[i - 1].strip(_STRIP).lower() if i > 0 else ""
            prev_base = prev.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if prev_base in _NET_TOOLS or prev in _URL_FLAGS:
                found.setdefault(candidate_host, (port, None))

    return [(host, port, path) for host, (port, path) in found.items()]


def _as_port(value) -> int | None:
    """Coerce a candidate port value (str/int/whatever) to a valid TCP port,
    or None if it isn't one. Centralised so every extraction site agrees on
    what counts as a port."""
    try:
        p = int(value)
    except (TypeError, ValueError):
        return None
    return p if 0 <= p <= 65535 else None


def _split_hostport(hostport: str) -> tuple[str, int | None]:
    """Split 'host[:port]' or '[ipv6]:port' into (host_lowercased_stripped, port)."""
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            return hostport.rstrip(".").lower(), None
        host = hostport[1:end].rstrip(".").lower()
        tail = hostport[end + 1:]
        port = _as_port(tail[1:]) if tail.startswith(":") else None
        return host, port
    if ":" in hostport:
        h, _, p = hostport.rpartition(":")
        if h:
            return h.rstrip(".").lower(), _as_port(p)
        return hostport.rstrip(".").lower(), None
    return hostport.rstrip(".").lower(), None


def _split_bare_hostport(tok: str) -> tuple[str, int | None]:
    """Schemeless bare token -> (host, port). Any trailing '/path' is dropped:
    bare (non-URL) tokens have never carried path context here — only port
    capture is new (docs/02-PLAN.md Slice 2.1)."""
    netloc = tok.split("/", 1)[0]
    return _split_hostport(netloc)


def _is_plain_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def _stringify(obj) -> str:
    if isinstance(obj, str):
        return obj
    try:
        return json.dumps(obj)
    except (TypeError, ValueError):
        return str(obj)


def _split_url(url: str) -> tuple[str, int | None, str | None]:
    """Split a scheme://... URL into (host, port, path). Port is the explicit
    :PORT if present, else the scheme default (80/http, 443/https), else None
    (a URL always has http:// or https:// per URL_RE, so one of the two
    defaults always applies when no explicit port is given)."""
    if "://" in url:
        scheme, rest = url.split("://", 1)
        scheme = scheme.lower()
    else:
        scheme, rest = "", url
    if "/" in rest:
        hostport, path = rest.split("/", 1)
        path = "/" + path
    else:
        hostport, path = rest, None
    if "@" in hostport:
        hostport = hostport.rsplit("@", 1)[1]
    host, port = _split_hostport(hostport)
    if port is None:
        if scheme == "https":
            port = 443
        elif scheme == "http":
            port = 80
    return host, port, path


# ---- sandbox-only extraction (docs/02-PLAN.md Slice 2.2) ---------------------

_SANDBOX_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# Tools whose network destination is best read as a structured field rather
# than text-scanned — more robust than scanning a JSON-stringified blob (see
# #9 below), and it's the authoritative destination for these tools anyway.
_CHROME_URL_TOOLS = frozenset({
    "mcp__claude-in-chrome__navigate",
    "mcp__claude-in-chrome__tabs_create_mcp",
})


def _extract_sandbox_candidates(tool_name: str, tool_input: dict) -> list[tuple[str, int | None]]:
    """Sandbox-only candidate extraction: (host, port) pairs, keyed by the PAIR
    (not by host alone — see below).

    Includes everything the real-program `extract_targets` finds, PLUS:

    - Structured URL extraction for WebFetch and the chrome navigate/
      tabs_create_mcp tools: reads tool_input["url"] directly instead of
      text-scanning the JSON-stringified input. More robust in general, and
      it specifically fixes a real misfire: `navigate(url="localhost:3000")`
      stringifies to `{"url": "localhost:3000"}`, whose JSON quoting/braces
      corrupt the bare-token scan below (the trailing `"}` glued onto the
      port breaks `_as_port`), so the schemeless form was wrongly read as
      zero candidates and DENIED. Reading the field directly sidesteps that
      entirely.
    - An INDEPENDENT re-scan of the text with `URL_RE`/`_split_url`, keyed by
      (host, port). `extract_targets` dedups its own output by HOST ALONE
      (see its docstring) — so two scheme'd URLs to the same host on
      different ports, e.g. `curl http://localhost:3000/a && curl
      http://localhost:9999/b`, would otherwise lose the second port
      entirely and let it slip through unevaluated. Re-scanning independently
      here, keyed by the pair, closes that gap without changing
      `extract_targets`'s real-program behavior at all.
    - Schemeless loopback tokens the normal extractor cannot see:
      `extract_targets`'s bare-token path requires `HOST_RE` (a dot —
      "localhost" has none) or a numeric form, so a plain `curl
      localhost:3000/x` produces ZERO candidates today even though it
      plainly targets the sandbox. We re-tokenise the same text and accept
      any bare `localhost:PORT`, `127.0.0.1:PORT`, or `[::1]:PORT` token
      outright — no positional/network-tool discipline needed here, because
      this helper is only ever called once the caller (`_decide_sandbox`)
      has already classified the tool call itself as network-capable.

    Keyed by (host, port), NOT by host: a command touching the same host on
    two different ports must surface BOTH candidates. `extract_targets`
    dedups by host alone; reusing that grouping here would silently drop the
    second, out-of-allow-list port — exactly the leak this helper exists to
    prevent.
    """
    seen: set[tuple[str, int | None]] = set()
    out: list[tuple[str, int | None]] = []

    def _add(host: str | None, port: int | None) -> None:
        if not host:
            return
        key = (host, port)
        if key not in seen:
            seen.add(key)
            out.append(key)

    if isinstance(tool_input, dict) and (tool_name == "WebFetch" or tool_name in _CHROME_URL_TOOLS):
        url_val = tool_input.get("url")
        if isinstance(url_val, str) and url_val:
            if "://" in url_val:
                host, port, _path = _split_url(url_val)
            else:
                host, port = _split_bare_hostport(url_val)
            _add(host, port)

    for host, port, _path in extract_targets(tool_name, tool_input):
        _add(host, port)

    raw_cmd = tool_input.get("command") if isinstance(tool_input, dict) else None
    text = raw_cmd if isinstance(raw_cmd, str) else _stringify(tool_input)

    for m in URL_RE.finditer(text):
        host, port, _path = _split_url(m.group(0))
        _add(host, port)

    for raw in text.split():
        tok = raw.strip(_STRIP)
        if not tok or "://" in tok:
            continue                      # scheme'd URLs: already handled above
        host_part, port = _split_bare_hostport(tok)
        if port is None or host_part not in _SANDBOX_LOOPBACK_HOSTS:
            continue
        _add(host_part, port)

    return out


def decide(event: dict) -> dict | None:
    """Return the hookSpecificOutput payload, or None to defer (silent)."""
    if registry.is_sandbox():
        return _decide_sandbox(event)

    active = registry.active_target()
    if active is None:
        return None                       # nothing to enforce against yet

    candidates = extract_targets(event.get("tool_name", ""), event.get("tool_input", {}))
    if not candidates:
        return None                       # non-network action; let normal flow decide

    denials = []
    for host, port, path in candidates:
        # Real-program path: unchanged decision. `port` is threaded through so
        # a later sandbox-aware branch (docs/02-PLAN.md Slice 2.2) can read it;
        # today's check_scope ignores it entirely.
        ok, reason = registry.check_scope(host, path, port=port)
        if not ok:
            denials.append(f"{host}{path or ''} — {reason}")

    if denials:
        return {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "Blocked by bb scope-guard (target '%s'). Out of scope:\n  - %s\n"
                "If this is authorized, run mcp__bb__scope_override then retry."
                % (active["handle"], "\n  - ".join(denials))
            ),
        }

    # all candidates in scope; surface staleness as context without blocking
    st = registry.scope_status()
    if st.get("stale"):
        return {
            "hookEventName": "PreToolUse",
            "additionalContext": (
                "bb: scope for '%s' is stale (fetched %s). Consider refreshing before testing."
                % (active["handle"], st.get("fetched_at"))
            ),
        }
    return None


# ---- sandbox decision path (docs/02-PLAN.md Slice 2.2) -----------------------

_CHROME_TOOL_RE = re.compile(r'^mcp__claude-in-chrome__')
_BURP_SEND_TOOL_RE = re.compile(r'^mcp__burp__send_')


def _is_sandbox_network_call(tool_name: str, command: str) -> bool:
    """Is this tool call 'active-testing / network-capable' in sandbox mode?

    Bash: iff the command text contains a network-capable tool name. We reuse
    sandbox.py's own tool set (`_NET_TOOL_RE`), NOT scope-guard's `_NET_TOOLS`
    — sandbox.py's set additionally includes python/python3/node, because a
    Python/Node harness making an HTTP request is exactly the case the plan's
    "Command conventions" section requires a visible URL for (zero candidate
    from such a harness must DENY, not defer as harmless local shell).
    WebFetch and the chrome/burp-send MCP tools are always network-capable.
    Everything else (ls, cat, grep, git, ...) is not.
    """
    if tool_name == "Bash":
        return bool(sandbox._NET_TOOL_RE.search(command or ""))
    if tool_name == "WebFetch":
        return True
    if _CHROME_TOOL_RE.match(tool_name) or _BURP_SEND_TOOL_RE.match(tool_name):
        return True
    return False


def _decide_sandbox(event: dict) -> dict | None:
    """Sandbox-mode decision path — fail-closed, deliberately stricter than the
    real-program path above:
      - `registry.take_override` is NEVER consulted (a denied sandbox host is
        the thing being contained, never a false positive to wave through);
      - a network-capable command that resolves to ZERO in-sandbox candidates
        is DENIED, not deferred (an unreadable target is not a safe default);
      - `sandbox.is_ambiguous` on a Bash command is an outright DENY;
      - every allow/deny is appended to the `sandbox_audit` table via
        `mission.log_sandbox_decision`; a logging failure is swallowed so it
        can never flip or block the security decision itself.
    Non-network shell (ls/cat/grep/git on local files) defers (returns None)
    exactly like the real-program path does for non-matching commands.
    """
    active = registry.active_target()
    tool_name = event.get("tool_name", "")
    raw_input = event.get("tool_input", {})
    tool_input = raw_input if isinstance(raw_input, dict) else {}
    command = tool_input.get("command", "") if isinstance(tool_input.get("command"), str) else ""

    if active is None:
        # Unreachable in practice (decide() only calls us when
        # registry.is_sandbox() is True, which itself requires an active
        # target) — kept as a fail-closed guard, not a silent defer.
        return {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "bb scope-guard: sandbox mode active but no active target (fail-closed)",
        }

    if not _is_sandbox_network_call(tool_name, command):
        return None                       # defer: routine, non-network shell

    def _audit(decision: str, host: str | None, port: int | None, reason: str) -> None:
        try:
            mission.log_sandbox_decision(
                active["handle"], tool_name, decision, host or "", port, reason,
                command[:200],
            )
        except Exception:
            pass                           # logging must never change the decision

    def _deny(reason: str) -> dict:
        _audit("deny", None, None, reason)
        return {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "Blocked by bb scope-guard (sandbox mode, target '%s'): %s"
                % (active["handle"], reason)
            ),
        }

    if tool_name == "Bash":
        ambiguous, amb_reason = sandbox.is_ambiguous(command)
        if ambiguous:
            return _deny(amb_reason)
    elif _CHROME_TOOL_RE.match(tool_name):
        # Chrome tools carry arbitrary JS (javascript_tool) or navigation
        # args, not a shell command — but the same escape shapes apply:
        # $(...)/backticks, a decode pipe, or an inline proxy assignment
        # constructed inside a JS string are just as hidden from the hook
        # here as they would be in a Bash command. Run the same matcher over
        # the stringified tool_input. This is deliberately broad (a legit JS
        # template literal also contains backticks) — see the "Residual gap"
        # note in SKILL.md/docs/sandbox-setup.md: sandbox mode errs toward
        # deny here rather than trying to parse JS.
        ambiguous, amb_reason = sandbox.is_ambiguous(_stringify(tool_input))
        if ambiguous:
            return _deny(amb_reason)

    candidates = _extract_sandbox_candidates(tool_name, tool_input)
    if not candidates:
        return _deny(
            "network command with no resolvable in-sandbox target; "
            "sandbox mode denies rather than defers"
        )

    rules = registry.sandbox_rules()
    verdicts = [(host, port, *sandbox.sandbox_allows(host, port, rules)) for host, port in candidates]
    for host, port, ok, reason in verdicts:
        _audit("allow" if ok else "deny", host, port, reason)

    denied = [(host, port, reason) for host, port, ok, reason in verdicts if not ok]
    if denied:
        offending = "\n  - ".join(f"{h}:{p} — {r}" for h, p, r in denied)
        return {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "Blocked by bb scope-guard (sandbox mode, target '%s'). Not on the sandbox "
                "allow-list:\n  - %s" % (active["handle"], offending)
            ),
        }

    return {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": "bb sandbox mode: sandbox target, host+port in allow-list",
    }


def _decide_session_start(event: dict) -> dict | None:
    """SessionStart: announce sandbox mode once, cheaply, via additionalContext.
    Defers (returns None) for a bounty/no-active-target session — no output,
    no behavior change."""
    if not registry.is_sandbox():
        return None
    active = registry.active_target()
    handle = active["handle"] if active else "?"
    return {
        "hookEventName": "SessionStart",
        "additionalContext": (
            "bb sandbox mode ACTIVE for %s — active testing auto-allowed to the "
            "declared sandbox host:port only; all other hosts denied." % handle
        ),
    }


def main() -> int:
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
    except (ValueError, OSError):
        return 0                          # never break the tool flow on a hook parse error

    if event.get("hook_event_name") == "SessionStart":
        out = _decide_session_start(event)
    else:
        out = decide(event)

    if out is not None:
        print(json.dumps({"hookSpecificOutput": out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
