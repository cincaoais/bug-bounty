# Sandbox setup — operator runbook for autonomous sandbox mode

This is the runbook for **`bb-sandbox`**, the one skill in this plugin that sends real
traffic. It only ever runs against a local, deliberately-vulnerable training target
(OWASP Juice Shop, OWASP WebGoat) — never a real program. Read this before your first
`bb-sandbox` run; the skill's own preflight (Phase 0 in
[`plugin/skills/bb-sandbox/SKILL.md`](../plugin/skills/bb-sandbox/SKILL.md)) checks
some of this for you and **aborts if it can't confirm containment** — it does not
proceed on trust.

Background and the full escape analysis this runbook implements:
[`docs/01-RND.md`](01-RND.md) Theme 6 ("Sandbox containment & safety").

Legend: **[you, terminal]** run a command · **[you, Claude Code]** type in the Claude
Code prompt · **[you, GUI]** click through an app.

---

## Why containment is two layers, not one

> **The scope-guard hook is the first layer. Network isolation is the real backstop.
> Neither is optional.**

The hook (`plugin/hooks/scope-guard.py`) is a deterministic allow-list check that runs
before every Bash / WebFetch / Burp-send / Chrome-MCP call: in sandbox mode it only
lets traffic through to a declared `(host, port)` pair — `127.0.0.1` / `localhost` /
`[::1]` on the target's own port — and denies everything else, with no override and
deny-on-ambiguity (any `$(...)`, decode pipe, `--resolve`, inline proxy var, or a
network command that yields zero in-sandbox candidate is denied outright).

But a `PreToolUse` hook is software running alongside the model — it cannot see
**inside** what it approves. Once a command is allowed, the hook cannot stop:

- the sandboxed **app itself** making a server-side request out (SSRF turned against
  the real internet — the exact scenario in Anthropic's own sandbox-containment
  incident, cited in `docs/01-RND.md` Theme 4/6);
- a redirect the app follows on your behalf;
- arbitrary code a Python/Node exploit harness executes once it's running;
- a **browser click or JS-driven navigation** the agent makes inside a Chrome tab —
  this is invisible to a hook that only inspects tool-call arguments.

That's why the target itself must run with **no route off the sandbox network** —
Docker's `--internal` network mode or a VirtualBox host-only adapter with no internet
route. If the container/VM can't reach the outside world at the network layer, none of
the above failure modes matter, regardless of what the hook approved.

---

## Default topology — Docker Desktop (hardened)

Use this if Docker Desktop is installed and working on your Windows box. This is the
default; use the VirtualBox fallback below only if Docker Desktop isn't available.

### 1. Create the egress-locked network [you, terminal, one-time]

```
docker network create --internal bb-sandbox
```

**Why `--internal`:** containers on an internal network get no default route to any
other network — Docker's own docs put it plainly: *"no default route is configured and
firewall rules are set up to drop all traffic to or from other networks."* A container
on `bb-sandbox` cannot phone out, full stop. This is what actually blocks
server-side SSRF from inside the app — not the hook, not a firewall rule you have to
remember.

### 2. Run the targets, bound to loopback only

```
docker run -d --rm --name juice-shop --network bb-sandbox -p 127.0.0.1:3000:3000 bkimminich/juice-shop

docker run -d --rm --name webgoat --network bb-sandbox -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat
```

(`-d` runs it in the background so your terminal stays free; `--name` gives the
preflight's `docker inspect <container>` step something stable to point at — pick
different names if you already use these.)

**Why `-p 127.0.0.1:PORT:PORT`** (not bare `-p PORT:PORT`): a bare publish binds
`0.0.0.0`, which is reachable from anywhere on your LAN — including anyone else on your
Wi-Fi. Binding to `127.0.0.1` means only processes on this machine can reach it.

**Caveat — read this carefully:** `--internal` blocks *outbound* traffic from the
container to other networks; it does **not** block the *inbound* published port.
Docker's port-publishing sets up host-level forwarding independent of the container's
own routing table, so `http://localhost:3000` still works from your host even though
the container itself has no way out. That's the intended shape — you (and Claude,
through the hook) reach the target over loopback; the target cannot reach anything
else. Don't mistake "I can still browse to it" for "isolation isn't working."

**If `--internal` breaks the image pull:** `docker run --network bb-sandbox <image>`
will implicitly pull if the image isn't already local, and pulling on the isolated
network can fail in some Docker Desktop configurations. Fix: pull first on your normal
network, then run on the internal one.

```
docker pull bkimminich/juice-shop
docker pull webgoat/webgoat
docker network create --internal bb-sandbox
docker run -d --rm --name juice-shop --network bb-sandbox -p 127.0.0.1:3000:3000 bkimminich/juice-shop
docker run -d --rm --name webgoat --network bb-sandbox -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat
```

### 3. Verify containment yourself before trusting the skill's preflight

```
docker inspect juice-shop --format "{{.HostConfig.NetworkMode}} {{json .NetworkSettings.Ports}}"
```

Expect the network mode to name your `bb-sandbox` internal network and the port
mapping to show `HostIp: "127.0.0.1"` — not `0.0.0.0`, not empty. This is exactly the
check `bb-sandbox`'s Phase 0 preflight asks you to run and paste back (see
**Preflight** below).

---

## Fallback topology — VirtualBox host-only VM

Use this only if Docker Desktop isn't installed/usable. Runs the target inside the
existing Linux VM (per `docs/00-BRIEF.md` A3 / `README.md`'s VirtualBox section),
reachable from Windows Chrome over a **host-only** adapter — `192.168.56.0/24` by
default, which VirtualBox does not route to the internet.

### One-time VM network setup [you, GUI, VM powered off]

1. VirtualBox → the VM → **Settings → Network**.
2. **Adapter 1** stays as whatever gives the VM internet today (NAT/Bridged) — you
   need this to install Docker and pull images once.
3. **Adapter 2** → check **Enable Network Adapter** → **Attached to: Host-only
   Adapter** → pick (or create) `vboxnet0`. This is the isolated leg — VirtualBox's
   host-only networking connects only the VM and the Windows host, with no path to the
   WAN.
4. Start the VM. Confirm the host-only interface got an address in `192.168.56.0/24`:
   `ip addr show` (look for the `enp0s8`/`eth1`-style interface, not the NAT one).

### Pull-then-isolate bootstrap [you, terminal, inside the VM]

Install Docker and pull the images **while Adapter 1 (internet) is still attached**:

```
sudo apt-get update && sudo apt-get install -y docker.io   # or your distro's equivalent
docker pull bkimminich/juice-shop
docker pull webgoat/webgoat
```

Then **isolate**: VirtualBox → **Devices → Network → uncheck "Connect Network Adapter
1"** (or power off, disable Adapter 1 in Settings, power back on) so the VM has *only*
the host-only adapter live — no internet route from this point on. Now run the
containers, bound to the host-only IP so Windows Chrome can reach them and nothing
else can:

```
docker run -d --rm --name juice-shop -p 192.168.56.101:3000:3000 bkimminich/juice-shop
docker run -d --rm --name webgoat -p 192.168.56.101:8080:8080 -p 192.168.56.101:9090:9090 webgoat/webgoat
```

(Replace `192.168.56.101` with whatever `ip addr` actually reports for the host-only
interface.) From Windows Chrome: `http://192.168.56.101:3000`.

Note this fallback does **not** give you a `bb-sandbox` scope handle of `localhost` —
declare the VM's host-only IP as the allow-listed host instead (a single `/32`, never
the `/24` — the whole `192.168.56.0/24` includes other VMs and the host itself, which
must stay out of scope).

---

## Browser containment

Everything above stops network egress; it does **not** stop a Chrome tab from clicking
a link or running injected JS that the hook's argument-level checks can't see (the one
gap called out above). Two mitigations, both required:

1. **Use a disposable Chrome profile** for sandbox runs — a fresh profile with no
   saved logins, no autofill, no extensions beyond what you need. If a challenge
   somehow tricks a click into navigating off-target, there's nothing sensitive in that
   profile to leak or act on.
2. **Scope the `claude-in-chrome` extension's site permission to the sandbox origin**
   (e.g. `http://localhost:3000`) — not "all sites." This is the one place in the whole
   safety model that isn't backstopped by the hook or the network layer: the extension
   permission is what stops the agent from opening a *new* tab to somewhere else
   entirely. Set it narrowly, per sandbox app, before starting a run.

**Residual gap — be honest about what this does and doesn't close.** The hook now also
runs its ambiguity matcher (`$(...)`/backticks/decode-pipe/proxy-flag shapes) over
chrome-tool inputs, not just Bash — but that is a text-level check on the tool-call
arguments, not analysis of what a page's own JavaScript computes at runtime. A URL
built dynamically inside browser JS (string concatenation, a template literal, a
fetch target assembled from page state) is not something the hook can see or evaluate,
same as `$(...)` obfuscation in a shell command. This is **not** closed by the hook, and
it can't be: Chrome here is the user's real, ordinary browser, running outside the
target's `--network internal` container, so a JS-driven navigation to somewhere
unexpected is a real request from the user's machine, not a contained one. The two
mitigations above (disposable origin-scoped profile, narrow extension permission) are
what actually bound the damage — prefer `curl`/API testing over browser JS whenever a
challenge is API-solvable, and treat the browser driver as the exception, not the
default.

---

## Preflight — do this before every run

`bb-sandbox`'s Phase 0 is a hard gate and narrates each check; you can also run these
yourself first:

1. **Unset proxy env vars** — a proxy can silently redirect what looks like
   `localhost` traffic off-box, defeating the loopback bind entirely:
   ```
   Remove-Item Env:HTTP_PROXY,Env:HTTPS_PROXY,Env:ALL_PROXY -ErrorAction SilentlyContinue
   ```
   Confirm they're gone: `Get-ChildItem Env: | Where-Object Name -match 'PROXY'`
   should return nothing.
2. **Containment must be verified, not assumed.** The skill runs
   `docker inspect <container> --format '{{.HostConfig.NetworkMode}} {{json .NetworkSettings.Ports}}'`
   and passes the result to the `sandbox_preflight` MCP tool (`mcp__plugin_bb_bb__sandbox_preflight`,
   live in `plugin/mcp/server.py`) as `network_mode`/`port_bindings`, which checks it against
   `network_isolation_verified` before it will start — this is backed by the pure-function
   checker in `plugin/mcp/sandbox.py` (`network_isolation_check`), which only pattern-matches
   text you/the skill paste in; per the plugin's no-network-calls invariant, nothing in the
   MCP server runs `docker` itself.
   > `sandbox_preflight`'s top-level `ready` is `True` only when EVERY check passes AND
   > `network_isolation_verified` is specifically `"pass"` — an unconfirmed `"warn"` (no
   > `docker inspect` output supplied yet) is NOT good enough to run autonomously, even
   > though it isn't a hard "fail" either. `SKILL.md`'s Phase 0 hard-aborts unless `ready`
   > is exactly `True`; there is no "check yourself" fallback — call the tool.
3. **Reachability** — `curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/`
   returns a live HTTP code.
4. **Target + allow-list exist** — the skill creates these if missing; see Usage below.

If any check fails, the skill aborts rather than proceeding on trust. Don't override
that by hand.

---

## Reset — getting back to a clean slate

Both apps hold challenge/lesson progress **in memory**, so the container itself is the
reset button:

```
docker restart juice-shop
docker restart webgoat
```

Juice Shop also supports snapshot/restore without a restart via its `continue-code`
(`GET /rest/continue-code` to snapshot the current solved set, then apply it later) —
useful if you want to preserve progress across a session boundary instead of wiping it.

---

## Usage

Once the container(s) are up and containment is verified, the start command is just a
plain-language ask:

```
try to find bugs in OWASP Juice Shop, it's at http://localhost:3000
```

Behind that sentence, the skill (not you) does the mode/scope bookkeeping — a sandbox
target must exist with `mode=sandbox` and a loopback:port allow-list before any traffic
is allowed:

```
mcp__plugin_bb_bb__create_target(handle="juiceshop", mode="sandbox", sandbox_app="juice-shop")
mcp__plugin_bb_bb__set_scope_rules(handle="juiceshop", rules=[
  {"pattern":"127.0.0.1:3000","in_scope":true},
  {"pattern":"localhost:3000","in_scope":true},
  {"pattern":"[::1]:3000","in_scope":true}])
```

All three loopback spellings are declared because the scope-guard hook treats them as
distinct identities — the skill does this for you, but if you're setting up a target by
hand, don't skip any of the three. WebGoat is the same shape on port 8080 (plus 9090
for WebWolf), with `sandbox_app="webgoat"`.

If the active target isn't `mode=='sandbox'`, `bb-sandbox` refuses to run — it will not
"help out" against a real program.

---

## Safety model — the two layers, together

| Layer | What it does | What it can't do |
|---|---|---|
| **Scope-guard hook** (`plugin/hooks/scope-guard.py`) | Deny-by-default; allow-list is `(host, port)` — mandatory port, no wildcards/CIDR, and loopback-only unconditionally (a non-loopback host is denied even if a scope rule somehow names one); deny-on-ambiguity for anything that hides its target (`$(...)`, decode pipes, `--resolve`, `-x`/`--proxy`, inline proxy vars — checked on Bash AND chrome-tool inputs); **no override** in sandbox mode (`scope_override` cannot clear a sandbox deny); zero-candidate network commands are denied, not deferred. | See inside an approved command — SSRF from the app itself, redirects, harness-internal code, and browser click/dynamically-constructed JS navigation are all outside its view (see "Residual gap" above). |
| **Network isolation** (`--network internal` + `127.0.0.1` bind, or the VirtualBox host-only/no-internet-route equivalent) | Removes the target's own route off-box, at the OS/network level — this is what actually stops SSRF-turned-outward, regardless of what any tool call looked like. | Nothing — it's not a decision layer, it's a hard wall. It also doesn't replace the hook: without the hook, nothing stops a request that *stays inside* the sandbox from being aimed at, say, another local dev server on a different port. |

Both layers are required. The hook without network isolation is instruction-following
with extra steps; network isolation without the hook still lets scoped-looking traffic
wander to other localhost services. Run with both, every time.
