# Lab network artifacts

Reference configs for the pre-BB network layer described in
`docs/field-notes/rnd-autonomous-kali-hexstrike-2026-08-04.md` **§9**.

**What this is / isn't.** mihomo (Clash.Meta, the core inside Clash Verge Rev)
filters at the **DNS/domain layer** and routes by rule. It is a useful *first*
filter against known-bad domains and the right tool for rule-based egress
splitting. It is **not** antivirus/EDR — it can't scan a payload, catch raw-IP
C2, or block a not-yet-listed domain. Treat it as "reduce exposure to known-bad
domains" + "force one VM down a chosen path," never as malware defense on its own.

`mihomo-gateway.yaml` is the config; it serves both modes below.

---

## Mode A — host hygiene (workstation-wide, §9a)

Run mihomo on the Kali box itself; the §9a blocklists cover everything you do.

1. In `mihomo-gateway.yaml`: set `tun.enable: true`, `dns.listen: 127.0.0.1:53`.
2. Replace the `proxy-providers.vpn.url` (or delete the group + its rules if you
   only want blocklisting, no VPN).
3. Run: `mihomo -d . -f mihomo-gateway.yaml` (or point Clash Verge Rev at it).

The `SRC-IP-CIDR` lab rules are inert here (no lab subnet); the `RULE-SET,reject`
/ `GEOSITE` REJECT rules do the work.

---

## Mode B — gateway VM (lab split-routing, §9b)

This is what makes the split **real**: mihomo runs on a dedicated router VM that
sits in the analysis VM's path, so the analysis VM cannot bypass it.

**Topology**
```
[ analysis / malware VM ]---.
  gw + DNS = 10.0.99.1       \        eth0 (WAN/NAT)
                              [ gateway VM 10.0.99.1 ]------> internet
  10.0.99.20                   mihomo (this config)          (vpn-gw only for .20;
  (internal net only)                                          REJECT for the rest)
```
- Both VMs on an **Internal**/host-only network (`10.0.99.0/24`). The analysis VM
  has **no NAT adapter** of its own — its only route out is this gateway.
- Analysis VM: default gateway `10.0.99.1`, DNS `10.0.99.1`, its own IP `10.0.99.20`
  (match the `SRC-IP-CIDR` rule).

**Gateway VM setup**
1. In `mihomo-gateway.yaml`: keep `tun.enable: false`, uncomment `tproxy-port: 7893`,
   keep `allow-lan: true`, `dns.listen: 0.0.0.0:53`. Replace the VPN provider URL.
2. Enable forwarding + TPROXY capture of **forwarded** traffic:
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1

   # TPROXY table: send forwarded TCP/UDP from the lab into mihomo's tproxy-port.
   sudo nft -f - <<'EOF'
   table inet clash {
     chain prerouting {
       type filter hook prerouting priority mangle; policy accept;
       iifname "eth1" meta l4proto { tcp, udp } \
         ip daddr != 10.0.99.0/24 \
         meta mark set 1 tproxy to :7893 accept
     }
   }
   EOF
   # (eth1 = the internal-net interface facing the lab; adjust the name.)
   ```
3. Run mihomo: `sudo mihomo -d . -f mihomo-gateway.yaml`.

**What the rules then enforce** (top-to-bottom in the config):
- known-bad domains → `REJECT` for the whole lab;
- `10.0.99.20` (analysis VM) → **`vpn-gw` only** — attributable to the VPN, not your home IP;
- everything else in `10.0.99.0/24` → **`REJECT`** (fail-closed, no accidental egress);
- the gateway's own traffic → `DIRECT`.

---

## The caveat that overrides all of the above (§9b)

For **detonating real malware**, do **not** route live traffic through your own
egress, even split. Use **isolation + fake internet**: analysis VM on
**Internal** networking pointed at a **REMnux gateway running INetSim / FakeNet-NG**,
which impersonates the whole internet and captures every callback while nothing
leaves. Use the mihomo VPN-split here **only** when you deliberately want
controlled, VPN-attributable egress (e.g. pulling a second stage you accept the
risk of) — and keep the rest of the subnet `REJECT`.

Layering: **INetSim/FakeNet for detonation → mihomo VPN-gw only when you allow
egress → `REJECT` for everything else.**

## Sources
- mihomo docs — [Route Rules](https://wiki.metacubex.one/en/config/rules/) ·
  [rule-providers](https://wiki.metacubex.one/en/config/rule-providers/content/)
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) (reject/malware/phishing sets)
- [Mandiant/Google — Linux support for FakeNet-NG](https://cloud.google.com/blog/topics/threat-intelligence/introducing-linux-support-fakenet-ng-flares-next-generation-dynamic-network-analysis-tool)
