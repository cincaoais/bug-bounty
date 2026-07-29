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
HOST_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b', re.I)
IPV4_RE = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')


def extract_targets(tool_name: str, tool_input: dict) -> list[tuple[str, str | None]]:
    """Return [(host, path_or_None)] candidates found in the tool input.

    We look at the whole stringified input so we catch hosts in any tool's args,
    not just Bash commands. Dedup preserves first-seen path info.
    """
    blob = _stringify(tool_input)
    found: dict[str, str | None] = {}

    for m in URL_RE.finditer(blob):
        host, path = _split_url(m.group(0))
        if host:
            found.setdefault(host, path)

    for m in IPV4_RE.finditer(blob):
        found.setdefault(m.group(0), None)

    for m in HOST_RE.finditer(blob):
        host = m.group(0).lower()
        if host not in found:
            found[host] = None

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
