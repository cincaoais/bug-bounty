"""Deterministic sandbox allow-list + ambiguity matcher. Pure functions, no I/O,
no network, no LLM. `proxy_env_set` is the sole exception: it reads os.environ,
which is a local process-state check, not network I/O.

Security-critical: this decides whether traffic is allowed to leave the model's
control loop toward a *local* target, in sandbox mode. Two invariants:
  1. Deny-by-default — a host:port not exactly on the declared allow-list is denied.
     No wildcards, no CIDR, no "close enough".
  2. Mandatory port — sandbox targets are identified by (host, port) together,
     because on localhost a different port is a different system (someone's dev
     server, a database, Claude Code's own MCP process). `port is None` is
     always a deny, never a "defer".

This module does not know about scope-guard.py's extraction, registry.py's
target state, or SQLite. It is handed a host token, a port, and a list of
declared rules, and it answers a yes/no question. The caller (the PreToolUse
hook, in a later slice) owns wiring this into the real decision path.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


@dataclass(frozen=True)
class SandboxRule:
    """One declared (host, port) the sandbox allow-list permits.

    host is a literal identity, not a pattern — one of the canonical forms
    `canonical_host` produces ("127.0.0.1", "::1", "localhost") or, in
    principle, any other literal `canonical_host` would pass through
    unchanged. There is no wildcard/CIDR support by design (see module
    docstring): a sandbox target is one specific process on one specific port.
    """
    host: str
    port: int            # mandatory — a sandbox rule without a port is meaningless


# ---- canonical_host -----------------------------------------------------------

def _parse_int_part(token: str) -> int | None:
    """Parse one dotted-quad segment (or a whole legacy numeric IPv4 literal) as
    decimal, hex (0x-prefixed), or octal (leading-zero) — the historical
    inet_aton conventions that Python's strict `ipaddress` module deliberately
    rejects (CVE-2021-29921: leading zeros are ambiguous, so it refuses them
    rather than guess). We *do* want to recognize them here, specifically so we
    can canonicalize them to the loopback they represent and deny them as any
    other loopback spelling — not so we can be lenient elsewhere.
    """
    t = token.strip()
    if not t:
        return None
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        if len(t) > 1 and t[0] == "0":
            return int(t, 8)
        return int(t, 10)
    except ValueError:
        return None


def _parse_legacy_ipv4(token: str) -> int | None:
    """Parse decimal/hex/octal and inet_aton-style short dotted IPv4 forms
    (`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`) into a 32-bit int, or
    None if the token isn't one of these forms at all.

    inet_aton shorthand: with N dotted parts (1-4), the first N-1 parts are
    8-bit octets and the LAST part absorbs the remaining (32 - 8*(N-1)) bits.
    `127.1` = 127 (top 8 bits) . 1 (bottom 24 bits) = 127.0.0.1.
    """
    if not token:
        return None
    parts = token.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = [_parse_int_part(p) for p in parts]
    if any(n is None or n < 0 for n in nums):
        return None
    if len(nums) == 1:
        value = nums[0]
        return value if 0 <= value <= 0xFFFFFFFF else None
    if any(n > 0xFF for n in nums[:-1]):
        return None
    remaining_bits = 32 - 8 * (len(nums) - 1)
    if nums[-1] > (1 << remaining_bits) - 1:
        return None
    value = 0
    for n in nums[:-1]:
        value = (value << 8) | n
    return (value << remaining_bits) | nums[-1]


def canonical_host(token: str) -> str | None:
    """Canonicalize a bare host token (no scheme, no port — callers split
    host:port before calling this) to one of three loopback identities, a
    lowercased passthrough for anything else recognizable, or None for
    empty/garbage input.

    Loopback forms folded to "127.0.0.1" (IPv4) or "::1" (IPv6) — every one of
    these names the same interface, and sandbox mode must not let an unusual
    spelling slip past a rule written in the obvious form:
      - standard dotted quad: 127.0.0.1
      - decimal 32-bit: 2130706433
      - hex 32-bit: 0x7f000001
      - octal-dotted (leading zero per octet): 0177.0.0.1
      - inet_aton short forms: 127.1, 127.0.1
      - IPv4-mapped IPv6: ::ffff:127.0.0.1
      - any other IPv4/IPv6 address `ipaddress` reports as loopback

    "localhost" (any case) canonicalizes to the literal string "localhost" —
    deliberately NOT merged into "127.0.0.1". The sandbox allow-list treats
    {127.0.0.1, ::1, localhost} as three distinct declared identities (see
    docs/02-PLAN.md, Slice 1.2); a rule for one does not imply the others.

    A normal hostname or non-loopback IP is returned lowercased, unchanged —
    the caller still needs it to run the rule match and DENY it; canonicalizing
    it away would hide what was actually requested.

    None means "could not even be treated as a host" — empty string, or any
    token containing whitespace (a real host token never does).
    """
    if not isinstance(token, str):
        return None
    t = token.strip()
    if not t or any(c.isspace() for c in t):
        return None

    low = t.lower()
    if low.startswith("["):
        if not low.endswith("]"):
            return None                     # unmatched bracket: garbage
        low = low[1:-1]
        if not low:
            return None

    if low == "localhost":
        return "localhost"

    try:
        ip = ipaddress.ip_address(low)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_loopback:
            if ip.version == 6 and ip.ipv4_mapped is None:
                return "::1"
            return "127.0.0.1"
        return low

    legacy = _parse_legacy_ipv4(low)
    if legacy is not None:
        ipv4 = ipaddress.IPv4Address(legacy)
        if ipv4.is_loopback:
            return "127.0.0.1"
        return low                           # numeric but not loopback: passthrough to deny

    return low                               # ordinary hostname


# ---- sandbox_allows -------------------------------------------------------------

def sandbox_allows(host: str, port: int | None, rules: list[SandboxRule]) -> tuple[bool, str]:
    """(allowed, reason). Deny-by-default; port is mandatory; no wildcards.

    Allowed only when some rule's canonical host equals this host's canonical
    form AND the rule's port equals this port exactly. Both sides are run
    through `canonical_host` so a rule declared in an unusual spelling still
    matches the same set of loopback tokens a caller might present.

    HARD invariant, enforced unconditionally: the queried host's canonical
    form must be one of {127.0.0.1, ::1, localhost} (`_LOOPBACK_HOSTS`) or
    this denies outright, REGARDLESS of what `rules` declares. A rule can
    only narrow the loopback allow-list (to a specific port); it can never
    widen sandbox mode to a non-loopback host. Without this, a scope_rule
    pattern like "evil.com:443" — however it got there — would be able to
    authorize sandbox traffic straight off the box.
    """
    if port is None:
        return (False, "no port; sandbox requires host:port")

    ch = canonical_host(host)
    if ch is None:
        return (False, "empty/invalid host (deny-by-default)")

    if ch not in _LOOPBACK_HOSTS:
        return (False, f"{ch}:{port} not on sandbox allow-list (deny-by-default): "
                        "non-loopback host, denied regardless of any declared rule")

    for rule in rules:
        rule_host = canonical_host(rule.host)
        if rule_host is not None and rule_host == ch and rule.port == port:
            return (True, f"matches sandbox rule: {rule.host}:{rule.port}")

    return (False, f"{ch}:{port} not on sandbox allow-list (deny-by-default)")


# ---- is_ambiguous -----------------------------------------------------------------

_NETWORK_TOOLS = frozenset({
    "curl", "wget", "nc", "ncat", "netcat", "telnet", "ping", "nslookup", "dig",
    "host", "nmap", "masscan", "ffuf", "nuclei", "httpx", "katana", "gobuster",
    "feroxbuster", "wfuzz", "hydra", "openssl", "socat", "amass", "subfinder",
    "python", "python3", "node",
})
_NET_TOOL_RE = re.compile(
    r"(?i)(?:^|[\s/\\|&;`(])(" + "|".join(sorted(_NETWORK_TOOLS)) + r")(?:\s|$)")
_CURL_RE = re.compile(r"(?i)(?:^|[\s/\\|&;`(])curl(?:\s|$)")
_PROXY_VAR_RE = re.compile(r"(?i)\b(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY)\s*=")
_PROXY_FLAG_RE = re.compile(r"(?i)(?:^|\s)(-x|--proxy)(?:[=\s])")
_PRINTF_HEX_RE = re.compile(r"printf\s+[\"']?\\x[0-9a-fA-F]{2}")
_FLAG_RE = re.compile(r"(?<!\S)(--?[A-Za-z][A-Za-z-]*)")


def _has_decode_pipe(cmd: str) -> bool:
    low = cmd.lower()
    if "base64 -d" in low or "base64 --decode" in low or "xxd -r" in low:
        return True
    return bool(_PRINTF_HEX_RE.search(cmd))


def _curl_location_flag(cmd: str) -> bool:
    """True if a curl-style auto-follow flag is present: the long form
    `--location`, or a short-flag cluster containing `L` (curl allows combining
    short options, e.g. the extremely common `curl -fsSL ...` or `curl -sL ...`
    — checking only a standalone `-L` token would miss these).
    """
    for tok in _FLAG_RE.findall(cmd):
        if tok.startswith("--"):
            if tok == "--location" or tok.startswith("--location="):
                return True
        elif "L" in tok[1:]:
            return True
    return False


def is_ambiguous(command: str) -> tuple[bool, str]:
    """(ambiguous, reason). True means: sandbox mode cannot safely determine
    the real destination of this command, so the caller must deny it outright
    rather than defer or guess. Each trigger, and why it's banned:

      - `$(...)` / backticks — command substitution. The real argument isn't
        in the text the hook can see; it's produced at run time.
      - a decode pipe (`base64 -d`, `base64 --decode`, `xxd -r`, or a `printf`
        hex-escape like `printf '\\x68\\x74...'`) — these construct a string
        (often a URL or host) that never appears in the command as plain text.
      - `curl --resolve` / `curl --connect-to` — override curl's own DNS/
        connection target independent of the URL in the command text.
      - `curl -L` / `curl --location` (including short-flag clusters like
        `-fsSL`) — auto-follows redirects to a host the hook never evaluated.
      - an inline `HTTP_PROXY=` / `HTTPS_PROXY=` / `ALL_PROXY=` assignment
        (any case) feeding a network-capable tool in the same command —
        transparently redirects that tool's traffic to an unevaluated proxy.
      - a proxy FLAG (`-x`/`--proxy`, e.g. `curl -x proxyhost:8080 ...` or
        `curl --proxy attacker.example:9090 ...`) alongside a network tool —
        same escape as the inline env-var case, just spelled as a curl flag
        instead of an environment assignment.

    False (with empty reason) otherwise — including a clean
    `curl http://localhost:3000/x`, which contains none of the above.
    """
    cmd = command or ""

    if "$(" in cmd or "`" in cmd:
        return (True, "command substitution ($(...) or `...`) hides the real target from the hook")

    if _has_decode_pipe(cmd):
        return (True, "decode pipe (base64/xxd/printf hex-escape) can construct a hidden target")

    has_curl = bool(_CURL_RE.search(cmd))
    if has_curl and ("--resolve" in cmd or "--connect-to" in cmd):
        return (True, "curl --resolve/--connect-to overrides the target the hook evaluated")

    if has_curl and _curl_location_flag(cmd):
        return (True, "curl -L/--location auto-follows redirects the hook never evaluated")

    if _PROXY_VAR_RE.search(cmd) and _NET_TOOL_RE.search(cmd):
        return (True, "inline HTTP(S)_PROXY/ALL_PROXY assignment can redirect a network tool's traffic")

    if _NET_TOOL_RE.search(cmd) and _PROXY_FLAG_RE.search(cmd):
        return (True, "proxy flag (-x/--proxy) can redirect a network tool's traffic to an unevaluated proxy")

    return (False, "")


# ---- proxy_env_set -----------------------------------------------------------------

def proxy_env_set() -> tuple[bool, str]:
    """(set, which). Checks os.environ (any case) for HTTP_PROXY / HTTPS_PROXY /
    ALL_PROXY. The only function in this module that reads process state —
    that's local, not network I/O, and sandbox preflight needs it: a proxy
    var can silently redirect traffic the hook believes is going to localhost.
    """
    for key in os.environ:
        if key.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            return (True, key)
    return (False, "")


# ---- network_isolation_check ------------------------------------------------------

_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def network_isolation_check(network_mode: str, port_bindings: str,
                            egress_test: str = "") -> tuple[str, str]:
    """(status, detail) for sandbox_preflight's `network_isolation_verified` check.
    status is one of "pass" | "warn" | "fail".

    This module still makes no subprocess/network call (module docstring's
    invariant): all three params are TEXT the SKILL pasted in after running
    the probes itself. It only pattern-matches that text.

    Containment requires BOTH, verified empirically:
      1. port_bindings shows a 127.0.0.1-only bind (no `0.0.0.0`/LAN/public IP);
      2. egress_test proves the container CANNOT reach the internet.

    Egress is checked by an ACTUAL probe, not by the network name — a network
    can be named/flagged "internal" and still egress (verified on Docker
    Desktop's WSL2 backend, where an `--internal` net won't publish a port and
    a masquerade-disabled bridge still reaches the internet; see
    docs/sandbox-setup.md). The SKILL runs, e.g.,
      docker run --rm --network <net> alpine sh -c \
        "wget -T5 -q -O/dev/null http://1.1.1.1 && echo EGRESS_OPEN || echo EGRESS_BLOCKED"
    and pastes the verdict as `egress_test`. `network_mode` is now advisory
    only (kept in the detail string as a hint).

      - "warn": nothing to check yet, or binding is loopback-only but egress is
        still unconfirmed — NOT ready (an unconfirmed boundary is not a boundary).
      - "pass": loopback-only bind AND egress probe positively BLOCKED.
      - "fail": a non-loopback bind, or the egress probe shows the internet is
        reachable (not contained).
    """
    nm = (network_mode or "").strip()
    pb = (port_bindings or "").strip()
    et = (egress_test or "").strip().lower()

    if not nm and not pb and not et:
        return ("warn",
                "unconfirmed — run `docker inspect <container> --format "
                "'{{.HostConfig.NetworkMode}}'`, a port-binding check (`docker port "
                "<container>`), AND an egress probe (see docs/sandbox-setup.md); pass "
                "the results as network_mode/port_bindings/egress_test before a run")

    ips = _IPV4_RE.findall(pb)
    bound_localhost = "127.0.0.1" in ips
    non_loopback = any(ip != "127.0.0.1" for ip in ips)

    egress_open = any(t in et for t in ("egress_open", "reachable", "not contained"))
    egress_blocked = (not egress_open) and any(
        t in et for t in ("egress_blocked", "blocked", "unreachable", "no route", "timed out", "timeout"))

    if bound_localhost and not non_loopback and egress_blocked:
        info = "127.0.0.1-only bind; egress probe confirms BLOCKED"
        if "internal" in nm.lower():
            info += f"; network_mode={nm!r} is internal"
        return ("pass", info)

    # "warn" ONLY when the binding is positively loopback-only and egress simply
    # hasn't been probed yet. A missing/partial input (no port binding) is a
    # fail-closed FAIL, not a warn — you can't confirm what you weren't shown.
    if bound_localhost and not non_loopback and not et:
        return ("warn",
                "port binding is loopback-only but egress is unconfirmed — run the egress "
                "probe (docs/sandbox-setup.md) and pass its result as egress_test")

    reasons = []
    if not bound_localhost:
        reasons.append(f"port_bindings does not show a 127.0.0.1 bind: {pb!r}")
    if non_loopback:
        reasons.append(f"port_bindings shows a non-loopback bind: {pb!r}")
    if egress_open:
        reasons.append("egress probe shows the container CAN reach the internet (not contained) — "
                       "Docker Desktop cannot egress-lock a published container; use a "
                       "VirtualBox host-only VM (docs/sandbox-setup.md)")
    elif et and not egress_blocked:
        reasons.append(f"egress_test {et!r} is inconclusive (expected EGRESS_BLOCKED / EGRESS_OPEN)")
    return ("fail", "; ".join(reasons) or "containment not established")


if __name__ == "__main__":  # tiny self-check; real coverage is tests/test_sandbox.py
    rules = [SandboxRule("localhost", 3000)]
    assert sandbox_allows("localhost", 3000, rules)[0] is True
    assert sandbox_allows("localhost", 9999, rules)[0] is False
    assert sandbox_allows("evil.com", 3000, rules)[0] is False
    assert sandbox_allows("localhost", None, rules)[0] is False
    assert canonical_host("2130706433") == "127.0.0.1"
    assert canonical_host("127.1") == "127.0.0.1"
    assert canonical_host("::ffff:127.0.0.1") == "127.0.0.1"
    assert canonical_host("::1") == "::1"
    assert is_ambiguous("curl http://localhost:3000/x")[0] is False
    assert is_ambiguous("curl $(cat host.txt)")[0] is True
    assert proxy_env_set()[0] in (True, False)
    print("sandbox self-check ok")
