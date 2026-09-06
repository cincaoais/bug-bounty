# Active-lab setup — verified containment posture (milestone 2)

> Active-lab lets you *set up and verify* a contained environment for active testing of
> ONE authorized target. It grants no traffic on its own: `active_lab_preflight` returns a
> `ready` verdict for a human to read. Opening the valve (the hook granting rate-limited
> active traffic) is a later milestone.

## The two enforcement layers

1. **The M1 egress proxy** (`plugin/tools/egress_proxy.py`) — a deny-by-default forward
   proxy: tools point `HTTPS_PROXY`/`HTTP_PROXY` at it, and it refuses any destination not
   on its allowlist before resolving it. This contains a *cooperating* tool.
2. **The VM egress firewall (this doc)** — the hard backstop that contains a tool which
   ignores the proxy env. Without it, a raw-socket tool bypasses layer 1.

## VM firewall — default-deny egress except via the proxy

Run active-lab tooling inside a Linux VM (VirtualBox), never on the host — the same reason
sandbox mode uses a VM: Docker Desktop cannot truly block egress. Inside the VM, allow
outbound only from the proxy process to the single target, and drop everything else. With
nftables:

```
# Replace <TARGET_IP> with the one authorized target's IP, <PROXY_UID> with the uid the
# egress proxy runs as. Everything else outbound is dropped.
nft add table inet activelab
nft add chain inet activelab out '{ type filter hook output priority 0 ; policy drop ; }'
nft add rule inet activelab out ct state established,related accept
nft add rule inet activelab out oif lo accept
nft add rule inet activelab out meta skuid <PROXY_UID> ip daddr <TARGET_IP> accept
```

The proxy (running as `<PROXY_UID>`) may reach the target; no other process may reach
anything off-box. Adjust for iptables if you prefer; the property is what matters:
**direct egress is dropped; only the proxy reaches the target.**

## The three preflight probes

`active_lab_preflight` takes these three human-run verdicts (it makes no network call):

| Argument | Probe (run inside the VM) | Report |
|---|---|---|
| `proxy_reachable` | the proxy is listening on its loopback port (a plain TCP connect succeeds, independent of the target): `bash -c 'exec 3<>/dev/tcp/127.0.0.1/<PORT>' 2>/dev/null && echo UP || echo DOWN` | `UP` (else `DOWN`) |
| `firewall_direct_egress` | a DIRECT request bypassing the proxy FAILS: `curl --noproxy '*' --max-time 5 http://1.1.1.1/` times out / is refused | `BLOCKED` (else `OPEN`) |
| `proxy_to_target` | a request to the target THROUGH the proxy SUCCEEDS: `curl -x http://127.0.0.1:<PORT> --max-time 10 http://<TARGET>/ -o /dev/null -w '%{http_code}'` returns a live code | `OK` (else `FAIL`) |

## Running the check

```
set_active_permission(permitted=true, note="<program policy quote>")   # ROE gate
legal_attest(...)                                                       # tester posture
# configure the proxy allowlist to the one target; apply the VM firewall; run the 3 probes
active_lab_preflight(allowlist_hosts=["<TARGET>"], proxy_reachable="UP",
                     firewall_direct_egress="BLOCKED", proxy_to_target="OK")
```

`ready: true` means all five checks hold: legal attestation present, ROE gate = yes, the
allowlist is entirely in scope and non-empty, the proxy is up, and the firewall is sealed.
Any missing or unsafe evidence fails closed.

## Active-lab state & rate mechanism (bookkeeping — enforcement deferred)

These tools record an active-lab **posture** and a per-host **rate mechanism**. They are
**inert**: the scope-guard hook does NOT read this state, so nothing here grants or throttles
real traffic yet. Wiring the hook to enforce it (deny active traffic unless engaged + ready +
not-paused + rate-ok, as a strict superset of bounty-mode denials) is a separate,
explicitly-authorized milestone.

| Tool | Effect (bookkeeping only) |
|---|---|
| `active_lab_engage(rate_per_min)` | engaged=1, ready=0, paused=0, sets the per-host req/min ceiling (must be > 0) |
| `active_lab_preflight(...)` | when engaged, stores its `ready` verdict onto the target |
| `active_lab_pause(reason)` | paused=1 — record an anomaly (target 5xx, lockout, WAF) |
| `active_lab_resume()` | paused=0 AND ready=0 — a resumed target must re-run preflight |
| `active_lab_disengage()` | engaged=0 |
| `active_lab_status()` | engaged / paused / ready / rate / engaged_at |

The rate mechanism (`registry.active_lab_rate_consume`) is a ledger-backed per-host token
bucket: capacity = `rate_per_min`, refilling at `rate_per_min / 60` tokens per second, and it
fails closed (denies) when no ceiling is set. It is built and tested now so the future hook
edit only has to *call* it — it is not called by any live decision path in this milestone.
