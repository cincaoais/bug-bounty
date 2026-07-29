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
nobody is trying to evade it — not a sandbox. It errs toward DENY: unknown host
=> blocked. Clear a false positive with the mcp__bb__scope_override tool.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# import the shared scope + registry modules (same definitions the MCP server uses)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp"))
import registry  # noqa: E402


URL_RE = re.compile(r'https?://[^\s"\'`<>|)\]}]+', re.I)
# bare host: label(.label)+.tld  — at least one dot and an alphabetic TLD
HOST_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$', re.I)
IPV4_RE = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')

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


def extract_targets(tool_name: str, tool_input: dict) -> list[tuple[str, str | None]]:
    """Return [(host, path_or_None)] candidates found in the tool input.

    We look at the whole stringified input so we catch hosts in any tool's args,
    not just Bash commands. Dedup preserves first-seen path info.
    """
    # Burp send tools (send_http1_request / send_http2_request / send_to_intruder)
    # put traffic on the wire and carry the authoritative destination in
    # `targetHostname`. Gate on THAT FIELD ONLY — never scan the raw `content`,
    # which legitimately contains other hosts (an out-of-scope URL placed in a
    # parameter to test SSRF, a redirect target, etc.). Scanning content would
    # falsely block in-scope testing. Falls through to generic extraction only
    # if the required field is somehow absent.
    if tool_name.startswith("mcp__burp__send") and isinstance(tool_input, dict):
        h = tool_input.get("targetHostname")
        if h:
            host = str(h).split(":", 1)[0].strip().rstrip(".").lower()
            return [(host, None)] if host else []

    # Scan the RAW command for Bash (so tokenisation and the network-context
    # check see real shell tokens, not JSON-quoted ones). Other tools: stringify.
    raw_cmd = tool_input.get("command") if isinstance(tool_input, dict) else None
    text = raw_cmd if isinstance(raw_cmd, str) else _stringify(tool_input)
    found: dict[str, str | None] = {}

    # Explicit URLs and IP literals: always extracted — unambiguous network targets.
    for m in URL_RE.finditer(text):
        host, path = _split_url(m.group(0))
        if host:
            found.setdefault(host, path)
    for m in IPV4_RE.finditer(text):
        found.setdefault(m.group(0), None)

    # Bare domains: only when a network tool appears in the command, and only for
    # a token whose PRECEDING token is that tool or a URL flag. This is what keeps
    # `cat plugin.json` / `python -m pytest test_hook.py` from being read as hosts.
    if _NET_PRESENT.search(text):
        toks = text.split()
        for i, raw in enumerate(toks):
            tok = raw.strip(_STRIP)
            if IPV4_RE.fullmatch(tok) or not HOST_RE.match(tok):
                continue
            prev = toks[i - 1].strip(_STRIP).lower() if i > 0 else ""
            prev_base = prev.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if prev_base in _NET_TOOLS or prev in _URL_FLAGS:
                found.setdefault(tok.lower(), None)

    return list(found.items())


def _stringify(obj) -> str:
    if isinstance(obj, str):
        return obj
    try:
        return json.dumps(obj)
    except (TypeError, ValueError):
        return str(obj)


def _split_url(url: str) -> tuple[str, str | None]:
    rest = url.split("://", 1)[1] if "://" in url else url
    if "/" in rest:
        host, path = rest.split("/", 1)
        path = "/" + path
    else:
        host, path = rest, None
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    host = host.split(":", 1)[0].rstrip(".").lower()
    return host, path


def decide(event: dict) -> dict | None:
    """Return the hookSpecificOutput payload, or None to defer (silent)."""
    active = registry.active_target()
    if active is None:
        return None                       # nothing to enforce against yet

    candidates = extract_targets(event.get("tool_name", ""), event.get("tool_input", {}))
    if not candidates:
        return None                       # non-network action; let normal flow decide

    denials = []
    for host, path in candidates:
        ok, reason = registry.check_scope(host, path)
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


def main() -> int:
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
    except (ValueError, OSError):
        return 0                          # never break the tool flow on a hook parse error
    out = decide(event)
    if out is not None:
        print(json.dumps({"hookSpecificOutput": out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
