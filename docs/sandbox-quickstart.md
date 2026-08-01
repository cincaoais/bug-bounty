# Sandbox mode — run-on-any-device quickstart

End-to-end steps to get **autonomous sandbox mode** (`bb-sandbox`) running on a fresh
machine and score a real OWASP Juice Shop / WebGoat run. Device-agnostic — replace
`<REPO>` with wherever you clone the repo (e.g. `~/GitHub/bug-bounty` on Linux/macOS,
`C:\Users\<you>\Documents\GitHub\bug-bounty` on Windows).

For the deeper *why* behind each safety step, see [`docs/sandbox-setup.md`](sandbox-setup.md)
(containment) and [`docs/setup.md`](setup.md) (base plugin install). This file is the
condensed "do these in order" path.

> **Prerequisite on the SOURCE machine (this one):** the code lives on the branch
> `feat/autonomous-sandbox-mode`, which must be **pushed** before another device can pull
> it: `git push -u origin feat/autonomous-sandbox-mode`. (`main` is already on
> `origin`; this branch is not, until you push it.)

---

## 0. Prerequisites [terminal]
- **Python 3.13** + the MCP package: `python -m pip install mcp` (the server is otherwise stdlib-only).
- **Claude Code** installed and signed in.
- **A target host:**
  - **Contained run → VirtualBox** with a Linux VM (the only topology that truly egress-locks — see step 4A), OR
  - **Preview only → Docker Desktop** (reachable but NOT egress-locked — step 4B).
- `ANTHROPIC_API_KEY` **unset** (so Claude Code uses your subscription, not metered API): `echo $ANTHROPIC_API_KEY` (PowerShell: `echo $env:ANTHROPIC_API_KEY`) should be empty.

## 1. Get the code [terminal]
```
git clone git@github.com:cincaoais/bug-bounty.git <REPO>
cd <REPO>
git checkout feat/autonomous-sandbox-mode
python -m pytest -q          # sanity: expect "394 passed"
```

## 2. Install + enable the plugin — then RESTART [Claude Code]
```
/plugin marketplace add <REPO>
/plugin install bb
```
**Then fully restart Claude Code** (quit and relaunch — not `/reload-plugins`). This is
required: MCP servers and plugin hooks load at startup, so the new sandbox tools
(`create_sandbox_mission`, `seed_objectives`, `sandbox_preflight`, …) and the sandbox
hook matchers only appear after a restart.

_If `/plugin` errors on your version_, use the deterministic fallback in
[`docs/setup.md`](setup.md) §3 (copy `plugin/skills/*` into `~/.claude/skills/`,
`claude mcp add bb -- python "<REPO>/plugin/mcp/server.py"`, add the hook to
`settings.json`) — but add all four PreToolUse matchers from
`plugin/.claude-plugin/plugin.json` (`Bash`, `WebFetch`, `mcp__burp__send_.*`,
`mcp__claude-in-chrome__.*`) and the `SessionStart` hook, or sandbox enforcement is incomplete.

## 3. Verify sandbox mode is live [Claude Code]
1. Ask Claude to run `health_check` — data dir safe, no API-key override.
2. Ask it to run `sandbox_preflight` — if the tool exists and returns a checklist, the
   new MCP tools loaded. (If "unknown tool", the restart didn't take — redo step 2.)
3. Prove the sandbox hook denies escape: create a sandbox target and confirm a deny:
   ```
   create_target "hooktest" mode="sandbox" sandbox_app="juice-shop"
   set_scope_rules "hooktest" [{"pattern":"localhost:3000","in_scope":true}]
   ```
   then ask it to `curl http://localhost:9999/x` — the hook must **deny** it (wrong port).

## 4. Stand up + contain the target

### 4A. Contained run — VirtualBox host-only VM (recommended)
Full steps in [`docs/sandbox-setup.md`](sandbox-setup.md) → "Contained topology". In short:
1. VM: Adapter 1 = NAT (to pull images), Adapter 2 = Host-only (`vboxnet0`).
2. Inside the VM, pull the image, then **disable Adapter 1** so there's no internet route.
3. Run bound to the host-only IP: `docker run -d --name juice-shop -p <VM_HOSTONLY_IP>:3000:3000 bkimminich/juice-shop`.
4. **Verify egress is blocked** from inside the VM: `curl --max-time 5 http://1.1.1.1 || echo EGRESS_BLOCKED`.
5. Reach it from your host at `http://<VM_HOSTONLY_IP>:3000`; declare that IP:port as the allow-list.

### 4B. Preview only — Docker Desktop (NOT egress-locked)
Docker Desktop can't publish a port AND block egress at once (verified). Use only for a
quick `curl`-driven preview, staying off SSRF challenges:
```
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```
`sandbox_preflight`'s egress probe will report `EGRESS_OPEN` and refuse an autonomous run — that's intended.

## 5. Run it [Claude Code]
With the target up, just say (plain language triggers the `bb-sandbox` skill):
```
try to find bugs in OWASP Juice Shop, it's at http://localhost:3000
```
The skill runs its Phase-0 preflight (proxy check, `docker inspect` + egress probe →
`sandbox_preflight`, reachability, baseline), **hard-aborts unless containment is
verified**, then hunts → verifies against the app's own solve-state → scores → gives you
an after-action report. WebGoat is the same shape with `sandbox_app="webgoat"` on port
8080 (+9090 for WebWolf) and `http://localhost:8080/WebGoat`.

## 6. Reset / teardown [terminal]
- Clean slate (progress is in-memory): `docker restart juice-shop`.
- Remove: `docker rm -f juice-shop`; reclaim space: `docker rmi bkimminich/juice-shop`.

---

### Cheat sheet
| Step | Command / action |
|---|---|
| push branch (source machine) | `git push -u origin feat/autonomous-sandbox-mode` |
| clone + checkout | `git clone … && git checkout feat/autonomous-sandbox-mode` |
| install plugin | `/plugin marketplace add <REPO>` → `/plugin install bb` → **restart** |
| verify | `sandbox_preflight` tool exists; wrong-port curl denied |
| target (contained) | VirtualBox host-only VM, egress verified blocked |
| run | "find bugs in Juice Shop at http://localhost:3000" |
