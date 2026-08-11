#!/usr/bin/env python3
"""Throwaway diagnostic hook for verifying how Reasonix drives a PreToolUse hook.

This is NOT part of the shipped guard. Wire it in TEMPORARILY as a PreToolUse
hook on Reasonix, poke it a few times, then read the dump file. It answers the
three questions that decide whether scope-guard.py runs unmodified:

  1. Does the interpreter even resolve?  -> if REASONIX_PROBE_LOG never appears,
     the `python`/`python3` command in the hook config didn't run at all
     (the silent fail-open case). Fix the interpreter before trusting anything.

  2. What shape is stdin?  -> the dump records whether the payload arrives as
     Claude-shape (`tool_name` / `tool_input`, meaning PayloadFormat=="claude",
     i.e. it imported as a plugin and the JSON-deny path is honored) or native
     (`toolName` / `toolArgs`, meaning the JSON-deny path is SKIPPED -> the real
     guard would fail open on this install).

  3. Is a JSON-only deny (exit 0) actually honored?  -> run any tool call whose
     text contains the sentinel  REASONIX_DENY_TEST  (e.g. `echo REASONIX_DENY_TEST`).
     This probe then emits a Claude-format deny on stdout and EXITS 0 (it does
     NOT use exit 2). If the call is blocked, the JSON path is live and the guard
     works unmodified. If the call goes through, JSON-deny is being ignored ->
     you need the exit-2 adapter (or, better, install as a plugin instead of
     hand-writing settings.json).

Read the dump:   cat "$REASONIX_PROBE_LOG"   (defaults to ~/reasonix-probe.log)
Exit code is 0 on every path except nothing — it never blocks except the sentinel
test, which blocks via JSON only (on purpose, to isolate which path fires).
"""
from __future__ import annotations

import json
import os
import sys

LOG_PATH = os.environ.get("REASONIX_PROBE_LOG") or os.path.expanduser("~/reasonix-probe.log")
SENTINEL = "REASONIX_DENY_TEST"


def _dump(record: dict) -> None:
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, indent=2, default=str))
            fh.write("\n---\n")
    except Exception as exc:  # never let logging failure change the exit code
        print(f"reasonix-probe: could not write {LOG_PATH}: {exc}", file=sys.stderr)


def main() -> int:
    raw = sys.stdin.read()

    try:
        payload = json.loads(raw) if raw.strip() else {}
        parsed_ok = True
    except Exception:
        payload, parsed_ok = {}, False

    keys = sorted(payload.keys()) if isinstance(payload, dict) else []
    # Which contract are we on? Claude-shape vs Reasonix-native.
    claude_shape = "tool_name" in keys or "tool_input" in keys
    native_shape = "toolName" in keys or "toolArgs" in keys

    record = {
        "argv": sys.argv,
        "stdin_parsed_as_json": parsed_ok,
        "stdin_top_level_keys": keys,
        "verdict_stdin_shape": (
            "claude (tool_name/tool_input) -> JSON-deny path honored, guard runs unmodified"
            if claude_shape else
            "native (toolName/toolArgs) -> JSON-deny path SKIPPED, guard would fail open"
            if native_shape else
            "unknown/empty -> inspect raw_stdin below"
        ),
        "env_of_interest": {
            k: os.environ.get(k)
            for k in ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PROJECT_DIR",
                      "REASONIX_HOME", "REASONIX_PLUGIN_ROOT")
        },
        "raw_stdin": raw,
    }
    _dump(record)

    # Deny-path discriminator: block ONLY via Claude JSON on stdout, exit 0.
    # If Reasonix honors this, PayloadFormat=="claude" is active.
    if SENTINEL in raw:
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "reasonix-probe: JSON-only deny test. If you see this block, "
                    "the exit-0 JSON deny path is honored and scope-guard.py works "
                    "unmodified. If the command ran anyway, JSON-deny is ignored."
                ),
            }
        }))
        return 0  # deliberately NOT exit 2 — we are testing the JSON path in isolation

    return 0


if __name__ == "__main__":
    sys.exit(main())
