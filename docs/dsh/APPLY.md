# bb on DeepSeek Harness — final state (verified)

All three layers are wired and working:

| Layer | Mechanism | Status |
|---|---|---|
| 48 skills | `.dsh/skills` (junction to `plugin/skills`) | live — in the session catalog |
| MCP state server | `@deepseek-ai/dsh-mcp-client` (`bb-mcp`) → `plugin/mcp/server.py` (stdio) | live — `mcp__bb__health_check` all green |
| scope-guard hook | native plugin `dsh-bb-guard` (`bb-guard`) → hooks `tools/pre-execute` and forwards to `plugin/hooks/scope-guard.py` | live — denies out-of-scope / unattested live traffic from inside `run_code` |

## Plugins installed into the `web` profile

```text
dsh plugin --profile web add @deepseek-ai/dsh-hooks-claude-code@0.1.1-rc.2   # superseded by dsh-bb-guard (optional to remove)
dsh plugin --profile web add @deepseek-ai/dsh-hook-protocol                    # dependency of the above (optional to remove)
dsh plugin --profile web add D:/Github/bug-bounty/plugin/dsh-bb-guard          # the native guard (REQUIRED)
```

The native guard replaces the Claude-hooks bridge: the bridge did not gate tool calls made
from inside `run_code` (this web session only exposes `run_code` as a model-facing tool), while the
native plugin registers directly on `tools/pre-execute`, which the registry runs for every sub-dispatch.

## The guard behavior

- Gates only `pwsh`, `bash`, `web_fetch` (and `mcp__burp__send_*` / `mcp__hexstrike__*` / `mcp__claude-in-chrome__*`).
- Defers (allows) until a target is ACTIVE, and skips the spawn until `~/.bb-bounty` exists.
- Forwards each gated call to bb `scope-guard.py` and maps `deny` → deny, `ask` → ask, else allow.
- Fail-closed on the legal gate: in bounty (live) mode the first traffic-generating action is denied until you record legal posture.

## Before you can test a real program

1. Create your target: `mcp__bb__create_target(handle, mode='bounty')`, then `mcp__bb__set_scope_rules(...)`.
2. Record legal posture ONCE: `mcp__bb__legal_attest(jurisdiction, tester_location, cssp_licensed, authorization_ref)`.
   Until this is recorded, live traffic is denied (this is bb fail-closed legal gate, by design).
3. The scope hook then allows in-scope hosts and denies everything else. Test with an out-of-scope host:
   `curl https://blocked.invalid/probe` should be denied.

## Optional cleanup

The `dsh-hooks-claude-code` / `dsh-hook-protocol` packages are no longer referenced by the profile patch and can be removed:

```text
dsh plugin --profile web remove @deepseek-ai/dsh-hooks-claude-code
dsh plugin --profile web remove @deepseek-ai/dsh-hook-protocol
```

`.dsh/hooks.json` is also unused by the native guard (it reads paths from plugin defaults / env) but kept as documentation.

## Notes

- **Python**: the MCP server + hook use `C:/Users/johan/AppData/Local/Programs/Python/Python314/python.exe` with `mcp==1.29.0` (`requirements.txt` pinned to `mcp>=1.2,<2`; mcp 2.x moved FastMCP).
- **Sandbox mode** (`bb-sandbox`): the native guard reuses `scope-guard.py` unchanged, so sandbox mode works for `pwsh`/`web_fetch` without the old `Bash`/`WebFetch` name aliasing — the guard forwards the DSH tool name and `scope-guard.py` general path scans the command generically. (No manual patch to scope-guard.py needed.)
- **Autonomous use**: bb is still *ingest-only by design* for real programs; the guard is the mechanical backstop, but keep the sandbox (localhost, network-isolated) for any autonomous exploit runs.
