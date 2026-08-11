"""Deterministic legal action-class gate. Pure functions, no I/O, no network, no LLM.

Security-critical, and DELIBERATELY the second of two axes:

  scope.py answers "is the DESTINATION HOST authorized?" (CCA 1997 s.3).
  legalgate.py answers "is the SHAPE OF THE ACTION one that crosses a statutory
  line?" — independent of the host, because a destructive write against an
  in-scope host is still a s.5 problem, and `hashcat hash.txt` / `rm -rf /`
  have no network target at all yet must still be caught.

The four gated classes map to Malaysian statute (see plugin/reference/
legal-gate-map.json for the auditable source of truth, incl. the Cybercrimes
Bill 2026 successor mapping):

  destructive  — CCA 1997 s.5  (unauthorised modification), plus a narrow
                 catastrophic-local-shell subset as machine safety.
  dos          — CMA 1998 s.233 (improper use of network facilities).
  credential   — CCA 1997 s.6 / s.8 (wrongful communication of / possession
                 of access codes; s.8 shifts the burden onto the possessor).
  pii          — PDPA 2010 (bulk extraction of real personal data).

Design posture — CONSERVATIVE, high-confidence signatures only. Over-blocking
trains the user to reflex-override, which destroys the gate's value. So plain
POST/GET, default-concurrency recon, single-record reads, and `rm -rf ./build`
are all deliberately NOT flagged. A caller (the PreToolUse hook) turns a
non-empty result into a deny + single-use logged override.

Honest limits (same posture as scope.py's docstring): a payload encoded past a
regex, or a credential the model writes into a note, is not caught here.
$(...)/decode-pipe escapes are denied separately by sandbox.is_ambiguous in
sandbox mode; storage-side leakage is scrubbed by redact.py. These layers
compose as defense in depth; none is complete alone.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Violation:
    gate_class: str    # "destructive" | "dos" | "credential" | "pii"
    statute: str       # e.g. "CCA 1997 s.5"
    signature: str     # the matched token/shape — for the deny message + audit
    reason: str        # human-readable why-this-is-gated


# ---- thresholds --------------------------------------------------------------
# Only ever applied to flags EXPLICITLY present in the command. A command that
# omits -t/--rate runs at the tool's own default and is never flagged here.
_CONCURRENCY_THRESHOLD = 50     # -t / -c / --threads over this = DoS-shaped
_RATE_THRESHOLD = 100           # --rate / --min-rate / -rl over this = DoS-shaped


# ---- tool-name sets ----------------------------------------------------------
_DOS_TOOLS = frozenset({
    "hydra", "thc-hydra", "medusa", "patator", "ncrack",          # brute-force
    "wrk", "siege", "slowloris", "slowhttptest", "t50",           # flood/stress
    "goldeneye", "mhddos",
    # NB: ApacheBench ("ab") and "hulk" are deliberately omitted — the names
    # collide with ordinary tokens (`cat ab.txt`). Their real high-volume runs
    # are still caught by the concurrency/rate thresholds below.
})
_CRED_TOOLS = frozenset({
    "hashcat", "john", "johntheripper",                           # offline cracking
    "responder", "mimikatz", "secretsdump", "impacket-secretsdump", "lsassy",
})


def _tool_re(names) -> re.Pattern[str]:
    # a tool token at start-of-string or after a shell separator (space, pipe,
    # semicolon, path separator, subshell paren), and NOT followed by another
    # word char or hyphen — so `secretsdump.py` / `hydra` match but `secretsdumps`
    # or a token merely containing the name does not. Same discipline the hook
    # and sandbox.py use for network-tool detection, with a `.ext` allowance.
    return re.compile(r"(?i)(?:^|[\s/\\|&;`(])(" + "|".join(sorted(names)) + r")(?![\w-])")


_DOS_TOOL_RE = _tool_re(_DOS_TOOLS)
_CRED_TOOL_RE = _tool_re(_CRED_TOOLS)

# crackmapexec / nxc harvesting secrets from a host (SAM/LSA/NTDS dumps).
_CME_SECRETS_RE = re.compile(r"(?i)\b(?:crackmapexec|cme|nxc)\b.*--(?:sam|lsa|ntds)\b")


# ---- destructive: HTTP mutating verbs ----------------------------------------
# curl/wget-style verb flags, and a raw HTTP request-line (unanchored, so it is
# still seen inside a JSON-stringified Burp `content` where CRLFs are escaped).
_VERB_FLAG_RE = re.compile(r"(?i)(?:^|\s)(?:-X|--request)[=\s]+(DELETE|PUT|PATCH)\b")
_VERB_REQUEST_LINE_RE = re.compile(r"(?i)\b(DELETE|PUT|PATCH)\s+\S+\s+HTTP/\d")


# ---- destructive: SQL DDL/DML ------------------------------------------------
# High-signal, rarely-in-benign-traffic keywords ONLY. UPDATE...SET and INSERT
# INTO are deliberately excluded (too common in ordinary request bodies).
_SQL_DESTRUCTIVE_RE = re.compile(
    r"(?i)\b(DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE(?:\s+TABLE)?|"
    r"DELETE\s+FROM|ALTER\s+TABLE)\b")

# sqlmap flags that mutate the target (shell/file write / arbitrary SQL exec).
_SQLMAP_MUTATE_RE = re.compile(
    r"(?i)--(os-shell|os-cmd|os-pwn|file-write|file-dest|sql-query)\b")

# WebGoat's lesson-reset endpoint drops+recreates the lesson DB schema — the repo
# already documents it as destructive (bb-sandbox/webgoat.md).
_WEBGOAT_RESET_RE = re.compile(r"(?i)restartlesson\.mvc")


# ---- destructive: catastrophic local shell (machine safety, adjacent to s.5) -
def _is_catastrophic_rm(cmd: str) -> bool:
    """A recursive+force rm aimed at a root/home/wildcard target. `rm -rf ./build`
    and `rm file.txt` are deliberately NOT caught."""
    if not re.search(r"(?i)(?:^|[\s|&;`(])rm\b", cmd):
        return False
    has_recursive = bool(re.search(r"(?i)\brm\b[^\n|&;]*?(?:-\w*r\w*|--recursive)", cmd))
    has_force = bool(re.search(r"(?i)\brm\b[^\n|&;]*?(?:-\w*f\w*|--force)", cmd))
    if not (has_recursive and has_force):
        return False
    # a dangerous target: filesystem root, a top-level system dir, home, or a
    # bare wildcard. Absolute project paths under /home/... also count as root-ish
    # and are worth a speed-bump (override is one call away).
    return bool(re.search(
        r"(?i)(?:^|\s)(/(?:\s|$|\*|etc|usr|bin|sbin|var|lib|lib64|boot|dev|sys|root|opt|home)"
        r"|~(?:/\S*)?|\$HOME(?:/\S*)?|\*)(?:\s|;|\||&|$)", cmd))


_DD_TO_DEVICE_RE = re.compile(r"(?i)\bdd\b[^\n|&;]*\bof=/dev/\w+")
_MKFS_RE = re.compile(r"(?i)\bmkfs(?:\.\w+)?\b")
_REDIRECT_DEVICE_RE = re.compile(r">\s*/dev/(?:sd|nvme|hd|disk)\w*")
_FORK_BOMB_RE = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")


# ---- DoS ---------------------------------------------------------------------
_FLOOD_FLAG_RE = re.compile(r"(?i)(?:^|\s)--flood\b")
_NMAP_AGGRESSIVE_TIMING_RE = re.compile(r"(?i)(?<!\S)-T[45]\b")

_CONCURRENCY_FLAGS = ("-t", "-c", "--threads", "--concurrency")
_RATE_FLAGS = ("--rate", "--min-rate", "-rl", "--rate-limit")


def _numeric_flag_values(text: str, flags) -> list[tuple[str, int]]:
    """Return [(flag, value)] for `-t 200`, `-t=200`, `--rate 500`, `--rate=500`.
    A non-numeric or absent value never matches (so curl `-c cookies.txt` — a
    filename, not a number — is not read as a concurrency flag)."""
    out: list[tuple[str, int]] = []
    for f in flags:
        for m in re.finditer(r"(?i)(?<!\S)" + re.escape(f) + r"[=\s]+(\d+)\b", text):
            out.append((f, int(m.group(1))))
    return out


# ---- PII ---------------------------------------------------------------------
_SQLMAP_DUMP_RE = re.compile(r"(?i)--dump(?:-all)?\b")
_SQLMAP_PRESENT_RE = re.compile(r"(?i)(?:^|[\s/\\|&;`(])sqlmap\b")
# a mass SELECT over a table whose name reads as personal data.
_PII_TABLE = (r"users?|customers?|accounts?|members?|clients?|patients?|"
              r"profiles?|people|persons?|contacts?|subscribers?|employees?")
_MASS_SELECT_RE = re.compile(
    r"(?i)\bselect\b.{0,200}?\bfrom\s+[`'\"]?(" + _PII_TABLE + r")\b")


# ---- text assembly -----------------------------------------------------------
def _stringify(obj) -> str:
    if isinstance(obj, str):
        return obj
    try:
        return json.dumps(obj)
    except (TypeError, ValueError):
        return str(obj)


def _search_text(tool_name: str, tool_input) -> str:
    """The searchable text for a call. For Bash, the RAW command (real shell
    tokens, not JSON-quoted). For everything else, structured target/body fields
    are already inside the stringified input; a `method` field, if present, is
    appended so a structured `method='DELETE'` is seen too.

    HexStrike MCP tools carry the WRAPPED tool's identity in the MCP tool NAME
    (`mcp__hexstrike__hydra`), not in the args — so the suffix is appended to the
    text. That way a `mcp__hexstrike__hydra` call whose only argument is a
    structured `rhosts` field is still recognised as a brute-force (DoS) tool,
    which is exactly the HexStrike misuse the repo's field notes warn about."""
    if isinstance(tool_input, dict):
        cmd = tool_input.get("command")
        base = cmd if isinstance(cmd, str) else _stringify(tool_input)
        method = tool_input.get("method")
        if isinstance(method, str) and method:
            base = base + " -X " + method
    else:
        base = _stringify(tool_input)
    if tool_name.startswith("mcp__hexstrike__"):
        base = base + " " + tool_name.rsplit("__", 1)[-1].replace("_", " ")
    return base


# ---- the classifier ----------------------------------------------------------
def classify(tool_name: str, tool_input: dict) -> list[Violation]:
    """Return every legal-gate Violation the call's action-shape matches.

    Empty list => nothing gated (the common case). A call may match more than
    one class; results are de-duplicated by (class, signature) and returned in a
    stable class order (destructive, dos, credential, pii)."""
    text = _search_text(tool_name, tool_input)
    out: list[Violation] = []
    seen: set[tuple[str, str]] = set()

    def add(gate_class: str, statute: str, signature: str, reason: str) -> None:
        key = (gate_class, signature)
        if key not in seen:
            seen.add(key)
            out.append(Violation(gate_class, statute, signature, reason))

    # -- destructive (CCA s.5) --
    for m in _VERB_FLAG_RE.finditer(text):
        add("destructive", "CCA 1997 s.5", m.group(1).upper() + " (HTTP verb)",
            "modifies target state via an HTTP mutating verb")
    for m in _VERB_REQUEST_LINE_RE.finditer(text):
        add("destructive", "CCA 1997 s.5", m.group(1).upper() + " (HTTP request-line)",
            "modifies target state via an HTTP mutating verb")
    for m in _SQL_DESTRUCTIVE_RE.finditer(text):
        add("destructive", "CCA 1997 s.5", m.group(1).upper(),
            "destructive SQL against the target")
    for m in _SQLMAP_MUTATE_RE.finditer(text):
        add("destructive", "CCA 1997 s.5", "sqlmap --" + m.group(1),
            "sqlmap flag that writes to / executes on the target")
    if _WEBGOAT_RESET_RE.search(text):
        add("destructive", "CCA 1997 s.5", "restartlesson.mvc",
            "drops and recreates the WebGoat lesson database")
    if _is_catastrophic_rm(text):
        add("destructive", "CCA 1997 s.5 (machine safety)", "rm -rf <root/home/wildcard>",
            "recursive force-delete of a root/home/wildcard path")
    if _DD_TO_DEVICE_RE.search(text):
        add("destructive", "CCA 1997 s.5 (machine safety)", "dd of=/dev/...",
            "raw write to a block device")
    if _MKFS_RE.search(text):
        add("destructive", "CCA 1997 s.5 (machine safety)", "mkfs",
            "formats a filesystem")
    if _REDIRECT_DEVICE_RE.search(text):
        add("destructive", "CCA 1997 s.5 (machine safety)", "> /dev/<disk>",
            "redirect over a block device")
    if _FORK_BOMB_RE.search(text):
        add("destructive", "CCA 1997 s.5 (machine safety)", "fork bomb",
            "resource-exhaustion fork bomb")

    # -- dos (CMA s.233) --
    m = _DOS_TOOL_RE.search(text)
    if m:
        add("dos", "CMA 1998 s.233", m.group(1).lower(),
            "brute-force / flooding / stress tool")
    if _FLOOD_FLAG_RE.search(text):
        add("dos", "CMA 1998 s.233", "--flood", "packet/request flood flag")
    if _NMAP_AGGRESSIVE_TIMING_RE.search(text):
        mm = _NMAP_AGGRESSIVE_TIMING_RE.search(text)
        add("dos", "CMA 1998 s.233", mm.group(0), "aggressive nmap timing template")
    for flag, val in _numeric_flag_values(text, _CONCURRENCY_FLAGS):
        if val > _CONCURRENCY_THRESHOLD:
            add("dos", "CMA 1998 s.233", f"{flag} {val}",
                f"concurrency {val} over the {_CONCURRENCY_THRESHOLD} threshold")
    for flag, val in _numeric_flag_values(text, _RATE_FLAGS):
        if val > _RATE_THRESHOLD:
            add("dos", "CMA 1998 s.233", f"{flag} {val}",
                f"request rate {val} over the {_RATE_THRESHOLD} threshold")

    # -- credential (CCA s.6/s.8) --
    m = _CRED_TOOL_RE.search(text)
    if m:
        add("credential", "CCA 1997 s.6/s.8", m.group(1).lower(),
            "credential cracking / harvesting / relay tool")
    if _CME_SECRETS_RE.search(text):
        add("credential", "CCA 1997 s.6/s.8", "crackmapexec --sam/--lsa/--ntds",
            "dumps stored credential material from the host")

    # -- pii (PDPA) --
    if _SQLMAP_PRESENT_RE.search(text) and _SQLMAP_DUMP_RE.search(text):
        add("pii", "PDPA 2010", "sqlmap --dump", "bulk extraction of database records")
    for m in _MASS_SELECT_RE.finditer(text):
        add("pii", "PDPA 2010", f"SELECT ... FROM {m.group(1)}",
            "mass select over a personal-data table")

    return out


def classes(violations: list[Violation]) -> list[str]:
    """Distinct gate classes in a violation list, in stable first-seen order."""
    out: list[str] = []
    for v in violations:
        if v.gate_class not in out:
            out.append(v.gate_class)
    return out


if __name__ == "__main__":  # tiny self-check; real coverage is tests/test_legalgate.py
    # destructive
    assert any(v.gate_class == "destructive"
               for v in classify("Bash", {"command": "curl -X DELETE https://api.acme.com/u/1"}))
    assert any(v.gate_class == "destructive"
               for v in classify("Bash", {"command": "sqlmap -u http://x/y --os-shell"}))
    assert classify("Bash", {"command": "curl -X POST https://api.acme.com/login"}) == []
    assert any(v.gate_class == "destructive"
               for v in classify("Bash", {"command": "rm -rf /"}))
    assert classify("Bash", {"command": "rm -rf ./build"}) == []
    # dos
    assert any(v.gate_class == "dos" for v in classify("Bash", {"command": "hydra -l a -P w ssh://h"}))
    assert any(v.gate_class == "dos" for v in classify("Bash", {"command": "ffuf -u http://x/FUZZ -t 200"}))
    assert classify("Bash", {"command": "ffuf -u http://x/FUZZ -t 40"}) == []
    # credential
    assert any(v.gate_class == "credential" for v in classify("Bash", {"command": "hashcat -m 0 h.txt w"}))
    # pii
    assert any(v.gate_class == "pii"
               for v in classify("Bash", {"command": "sqlmap -u http://x/y --dump -T users"}))
    # burp send with a DELETE request-line in the (stringified) content
    assert any(v.gate_class == "destructive" for v in classify(
        "mcp__burp__send_http1_request",
        {"targetHostname": "api.acme.com", "content": "DELETE /u/1 HTTP/1.1\r\n"}))
    print("legalgate self-check ok")
