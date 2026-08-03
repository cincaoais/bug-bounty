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

That's why the target itself must run with **no route off the sandbox network**. Which
topology actually delivers that is not obvious — a live test on 2026-08-01 settled it:

> **⚠️ Verified finding (2026-08-01): Docker Desktop for Windows cannot give you
> "reachable from the host AND egress-locked" with plain Docker networking.**
> - `--network internal` blocks egress but **won't publish `-p` ports** on Docker
>   Desktop — the target becomes unreachable (`docker port` shows no binding).
> - A bridge with `com.docker.network.bridge.enable_ip_masquerade=false` publishes the
>   port but **does not block egress** under the WSL2 backend — a container on it still
>   reached `1.1.1.1`.
>
> You get one or the other, never both. For a genuinely **contained** autonomous run,
> use the **VirtualBox host-only VM** (below) — no NAT/internet route by design. Docker
> Desktop is fine only for a **reduced-containment preview** where you drive by `curl`
> and deliberately avoid the SSRF/external-fetch challenges. The skill's preflight now
> runs a real egress probe and will (correctly) **abort** a Docker Desktop run that
> isn't actually egress-locked — the network's *name* is never taken as proof.

---

## Preview topology — Docker Desktop (reachable, but NOT egress-locked)

Use this ONLY for a quick **preview** of the capability. Per the finding above, Docker
Desktop can't egress-lock a published container, so this does **not** contain
server-side egress — drive everything by `curl`/API and deliberately stay off the
SSRF/external-fetch challenges. For any autonomous run, use the VirtualBox VM below.

```
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
docker run -d --name webgoat  -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat
```

**What this DOES give you:** `-p 127.0.0.1:PORT:PORT` (not bare `-p PORT:PORT`) keeps the
deliberately-vulnerable app off your LAN — loopback only, not `0.0.0.0`. That part is
real and worth keeping.

**What it CANNOT give you:** an egress lock. `--network internal` would block egress but
then won't publish the port (target unreachable); a masquerade-off bridge publishes but
still egresses (both verified live). So the container here **can reach the internet**.
That is why this is preview-only — and why the skill's `sandbox_preflight` egress probe
reports `EGRESS_OPEN` and **refuses** an autonomous run against it (intended
fail-closed behavior). Reset any Docker preview target with `docker restart <name>`.

---

## Contained topology — VirtualBox host-only VM (recommended for autonomous runs)

**This is the topology that actually delivers containment** (the Docker preview above
does not). Runs the target inside the existing Linux VM (per `docs/00-BRIEF.md` A3 /
`README.md`'s VirtualBox section), egress-locked at the VM's network boundary.

> **Reach it over a host loopback tunnel, NOT the VM's host-only IP.** The scope-guard
> hook is loopback-only and *unconditional*: `sandbox_allows` denies any non-loopback
> host — `192.168.56.x` included — regardless of any declared rule (see
> `plugin/mcp/sandbox.py`, the `_LOOPBACK_HOSTS` invariant). So you do **not** allow-list
> the host-only IP. Instead you bind the container to the VM's own loopback and forward
> it to a Windows loopback port with SSH; Windows Chrome / Claude Code then talk to
> `http://localhost:3000` (which the hook allows) while egress stays blocked inside the VM.

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
containers, bound to the **VM's own loopback** (so the hook's loopback rule matches once
you tunnel in — see the note above):

```
docker run -d --rm --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
docker run -d --rm --name webgoat -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat
```

Then, from **Windows**, open an SSH loopback tunnel to the VM over the host-only adapter
(replace `192.168.56.101`/`user` with your VM's host-only IP and login; the VM needs
`sshd` running):

```
ssh -L 127.0.0.1:3000:127.0.0.1:3000 user@192.168.56.101                                    # Juice Shop
ssh -L 127.0.0.1:8080:127.0.0.1:8080 -L 127.0.0.1:9090:127.0.0.1:9090 user@192.168.56.101   # WebGoat
```

Now Windows Chrome / Claude Code reach the target at `http://localhost:3000` — a loopback
address the hook allows — and every request tunnels into the egress-locked VM. The SSH
session is host→VM inbound only; it gives the VM no route out, so the target's own
server-side egress stays blocked.

### Verify egress is actually blocked [you, terminal, inside the VM]

Don't trust that isolating Adapter 1 worked — prove it. From inside the VM:

```
curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 http://1.1.1.1 || echo "EGRESS_BLOCKED (good)"
```

Expect a failure/timeout (`EGRESS_BLOCKED`). If it returns an HTTP code, Adapter 1 (the
internet leg) is still attached — disable it before running. This is the `EGRESS_BLOCKED`
verdict the skill's preflight requires; pass it to `sandbox_preflight(egress_test=...)`.

Because you reach the target over a loopback tunnel, the allow-list is the **normal
loopback triple** — `127.0.0.1:PORT`, `localhost:PORT`, `[::1]:PORT` — exactly as in the
Docker case (the skill sets these for you). Do **not** try to allow-list the VM's
host-only IP: the hook denies every non-loopback host unconditionally, so a
`192.168.56.x` rule would never match and the run couldn't start.

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
2. **Containment must be verified empirically, not assumed — and not inferred from the
   network name.** The skill gathers THREE things and passes them to the `sandbox_preflight`
   MCP tool (`mcp__plugin_bb_bb__sandbox_preflight`, live in `plugin/mcp/server.py`):
   ```
   # (a) network mode + port bindings
   docker inspect <container> --format "{{.HostConfig.NetworkMode}} {{json .NetworkSettings.Ports}}"
   # (b) an ACTUAL egress probe — a throwaway container on the SAME network must FAIL to reach the internet
   docker run --rm --network <net> alpine sh -c "wget -T5 -q -O/dev/null http://1.1.1.1 && echo EGRESS_OPEN || echo EGRESS_BLOCKED"
   ```
   → `sandbox_preflight(network_mode=..., port_bindings=..., egress_test=...)`. It checks these
   against `network_isolation_verified` via the pure-function checker in `plugin/mcp/sandbox.py`
   (`network_isolation_check`), which only pattern-matches text you/the skill paste in; per the
   plugin's no-network-calls invariant, nothing in the MCP server runs `docker` itself.
   > `network_isolation_verified` is `"pass"` only when the port bind is `127.0.0.1`-only AND
   > the egress probe returned `EGRESS_BLOCKED`. An `EGRESS_OPEN` result (the Docker Desktop
   > case) is a hard fail; an unconfirmed/empty probe is a `"warn"`. `ready` is `True` only when
   > EVERY check passes AND `network_isolation_verified == "pass"`. `SKILL.md`'s Phase 0
   > hard-aborts unless `ready` is exactly `True`; there is no "check yourself" fallback.
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
| **Network isolation** (VirtualBox host-only VM with no internet route, reached via a host-loopback SSH tunnel — **not** Docker Desktop, which can't publish + egress-lock at once; egress is **probe-verified**, never inferred from the network name) | Removes the target's own route off-box, at the OS/network level — this is what actually stops SSRF-turned-outward, regardless of what any tool call looked like. Verified by an actual egress probe at preflight (`EGRESS_BLOCKED`). | Nothing — it's not a decision layer, it's a hard wall. It also doesn't replace the hook: without the hook, nothing stops a request that *stays inside* the sandbox from being aimed at, say, another local dev server on a different port. Docker Desktop can only provide the loopback bind, not the egress lock — preview-only. |

Both layers are required. The hook without network isolation is instruction-following
with extra steps; network isolation without the hook still lets scoped-looking traffic
wander to other localhost services. Run with both, every time.
