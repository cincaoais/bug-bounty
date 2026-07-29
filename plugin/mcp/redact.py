"""Deterministic secret/PII scrubber. Pure functions, no I/O, no network, no LLM.

Security-critical. Everything stored as evidence passes through here first, so
this is what keeps session tokens, API keys, and other users' personal data out
of files on disk and out of report drafts.

Design posture — targeted patterns, NOT a generic entropy sweep:

  A high-entropy heuristic sounds appealing and is a trap here. Bug bounty
  evidence is full of legitimate high-entropy strings: request ids, CSRF tokens
  that are the actual subject of the finding, hashes, base64 payloads, UUIDs.
  Scrubbing those destroys the evidence the report is built from. A researcher
  who cannot write a report from redacted evidence goes back to pasting raw
  traffic into a chat window, which leaks strictly more.

  So: match on the CONTEXT that marks a value as secret (an auth header, a
  key-ish parameter name, a known key prefix, a PEM block), not on the value's
  shape alone. Under-redaction of an unlabelled blob is an accepted, documented
  limit; over-redaction of evidence is not.

Order matters: longest/most-specific patterns run first so a bearer token is
consumed as a bearer token rather than half-matched by a later rule.
"""
from __future__ import annotations

import re

PLACEHOLDER = "[REDACTED:{kind}]"

# Each rule: (kind, compiled regex, group index to replace).
# Group 0 means replace the whole match; otherwise only that capture group is
# replaced so the surrounding label ("Authorization: Bearer ") stays readable.
_RULES: list[tuple[str, re.Pattern[str], int]] = [
    # PEM private key blocks — whole block, before anything else can nibble it.
    ("private-key",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                re.S), 0),

    # JWTs: three base64url segments. Distinctive enough to match on shape.
    ("jwt",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0),

    # Authorization header values.
    ("bearer-token",
     re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)([A-Za-z0-9._~+/=-]{12,})"), 2),
    ("basic-auth",
     re.compile(r"(?i)\b(authorization\s*:\s*basic\s+)([A-Za-z0-9+/=]{8,})"), 2),
    ("auth-header",
     re.compile(r"(?i)\b(authorization\s*:\s*)([^\r\n]{12,})"), 2),

    # Cookie / Set-Cookie: redact each name=value pair's VALUE, keep the names.
    # Handled specially below (needs per-pair substitution), see _redact_cookies.

    # Known vendor key prefixes.
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("google-oauth-secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{10,}\b"), 0),
    ("stripe-key", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"), 0),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), 0),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0),

    # key-ish NAME = long-ish VALUE. The name is what marks it secret.
    ("keyed-secret",
     re.compile(
         r"(?i)\b((?:aws_secret_access_key|aws_access_key_id|secret_access_key|"
         r"client_secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|"
         r"auth[_-]?token|private[_-]?key|passwd|password|pwd|session[_-]?key|"
         r"x-api-key)"
         r"\s*[:=]\s*)"
         r"(\"[^\"\r\n]{6,}\"|'[^'\r\n]{6,}'|[^\s,;&\"'\r\n]{6,})"), 2),

    # Personal data.
    ("email",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0),
    ("card-number",
     re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), 0),
]

_COOKIE_LINE = re.compile(r"(?i)^(\s*(?:set-)?cookie\s*:\s*)(.+)$", re.M)
_COOKIE_PAIR = re.compile(r"([A-Za-z0-9_.-]+)=([^;,\r\n]*)")
# Cookie attributes are metadata, not secrets — keep them so the evidence reads.
_COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "samesite",
                 "secure", "httponly", "version", "comment", "priority"}
_ALREADY = re.compile(r"\[REDACTED:[a-z-]+\]")


_BENIGN_COOKIE_MAX = 12


def _is_benign_cookie_value(v: str) -> bool:
    """Keep short, simple cookie values like theme=dark, role=user, lang=en-US.

    Why this exists: 'the cookie says role=user, change it to role=admin' is a
    textbook authorization finding. Blanket-redacting every cookie value would
    scrub the exact evidence such a report is built from.

    ponytail: length + charset heuristic, no entropy math. A session token
    shorter than 12 chars would be trivially brute-forceable and is not a shape
    worth protecting; if one ever shows up, tighten _BENIGN_COOKIE_MAX.
    """
    if len(v) > _BENIGN_COOKIE_MAX:
        return False
    # word-ish values only: letters/digits with . _ - separators, and must not
    # look like a compact random token (needs a vowel or a separator to pass)
    if not re.fullmatch(r"[A-Za-z0-9._-]+", v):
        return False
    return bool(re.search(r"[aeiouAEIOU._-]", v)) or v.isdigit()


def _redact_cookies(text: str, counts: dict[str, int]) -> str:
    def fix_line(m: re.Match[str]) -> str:
        head, body = m.group(1), m.group(2)

        def fix_pair(pm: re.Match[str]) -> str:
            name, value = pm.group(1), pm.group(2)
            v = value.strip()
            if name.lower() in _COOKIE_ATTRS or not v:
                return pm.group(0)
            if _ALREADY.fullmatch(v):
                return pm.group(0)
            if _is_benign_cookie_value(v):
                return pm.group(0)
            counts["cookie"] = counts.get("cookie", 0) + 1
            return f"{name}={PLACEHOLDER.format(kind='cookie')}"

        return head + _COOKIE_PAIR.sub(fix_pair, body)

    return _COOKIE_LINE.sub(fix_line, text)


def redact(text: str) -> tuple[str, list[dict]]:
    """Scrub secrets/PII. Returns (redacted_text, [{kind, count}, ...]).

    The log names the CLASS of thing removed and never echoes the value — it is
    shown to the user and may itself be written to disk.
    """
    if not text:
        return ("", [])

    counts: dict[str, int] = {}
    out = _redact_cookies(text, counts)

    for kind, pattern, group in _RULES:
        def sub(m: re.Match[str], _kind=kind, _group=group) -> str:
            target = m.group(_group)
            if not target or _ALREADY.search(target):
                return m.group(0)          # already redacted; keep it idempotent
            counts[_kind] = counts.get(_kind, 0) + 1
            replacement = PLACEHOLDER.format(kind=_kind)
            if _group == 0:
                return replacement
            return m.group(0).replace(target, replacement, 1)

        out = pattern.sub(sub, out)

    log = [{"kind": k, "count": v} for k, v in sorted(counts.items())]
    return (out, log)


if __name__ == "__main__":  # real coverage lives in tests/test_redact.py
    blob = ("POST /api/v1/profile HTTP/1.1\n"
            "Host: api.acme.test\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop\n"
            "Cookie: session=deadbeefcafebabe0123456789abcdef; Path=/\n"
            "X-Api-Key: 9a8b7c6d5e4f30219a8b7c6d5e4f3021\n"
            '{"email":"alice@example.com","role":"user"}\n')
    out, log = redact(blob)
    for s in ["deadbeefcafebabe", "9a8b7c6d5e4f3021", "alice@example.com", "eyJhbGciOiJIUzI1NiJ9"]:
        assert s not in out, s
    assert "Host: api.acme.test" in out and '"role":"user"' in out
    assert redact(out)[0] == out                      # idempotent
    assert all("deadbeef" not in str(e) for e in log)  # log never echoes values
    print("redact self-check ok")
