"""Recon-tool output ingestion: nuclei, httpx, subfinder, ffuf, katana, burp.

HOSTILE-INPUT POSTURE: every byte in these files was produced by (or reflects
observations of) systems under test — an attacker-adjacent surface, not a
trusted source. This module never runs a tool and never makes a network call;
it only opens files the user already generated on disk and reads them
defensively:

  - Size is capped (MAX_FILE_BYTES) and checked with os.path.getsize() BEFORE
    any read. JSONL/plain-text formats are streamed line by line, never
    slurped with .read().
  - JSON goes through json.loads only. No eval/exec/pickle/yaml.load anywhere.
  - XML (Burp) is parsed with a raw xml.parsers.expat parser wired to reject
    ANY <!ENTITY ...> declaration outright (belt: EntityDeclHandler +
    UnparsedEntityDeclHandler raise; suspenders: ExternalEntityRefHandler
    refuses, and no DTD/parameter-entity fetching is enabled). This blocks
    both XXE (file/URL disclosure via entities) and billion-laughs (entity
    expansion bombs) at the declaration, before a single entity is expanded.
    xml.etree.ElementTree.XMLParser is NOT used directly for this because
    CPython's C-accelerated _elementtree implementation does not expose the
    underlying expat parser object to wire handlers onto (verified against
    this project's Python 3.13); TreeBuilder is used as the assembly target
    instead, fed by hand from our own expat callbacks.
  - A malformed record (bad JSON line, an <item> with no <url>, ...) is
    skipped and counted, never fatal to the whole file. Only a rejected
    entity declaration is fatal (raises ValueError) — that one is a deliberate
    "stop, this file is hostile" signal, not a parse hiccup.
  - Every extracted string is stripped of ASCII control characters and capped
    at 2000 chars (_clean) before it is ever put in a dict we return or store.
  - Extracted values are never interpreted: no shelling out, no building
    SQL/paths from them. Endpoint persistence goes through
    coverage.add_endpoints(), which parameterizes everything.
"""
from __future__ import annotations

import base64
import json
import os
import re
import xml.parsers.expat as expat
from urllib.parse import parse_qsl, urlsplit
from xml.etree.ElementTree import TreeBuilder

import coverage
import db

SUPPORTED = ("nuclei", "httpx", "subfinder", "ffuf", "katana", "burp")
MAX_FILE_BYTES = 50 * 1024 * 1024

_MAX_STR = 2000
_MAX_SIGNALS = 200
_CTRL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_INTERESTING_HTTPX_STATUS = {401, 403, 500, 503}
_AUTH_STATUS = {401, 403}
_HOSTNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
_REQUEST_LINE_RE = re.compile(r"^[A-Z]+\s+(\S+)\s+HTTP/")


# ---- shared helpers ---------------------------------------------------------

def _clean(s) -> str:
    """Strip control chars and cap length. Every attacker-influenced string
    passes through here before it's stored anywhere."""
    if s is None:
        return ""
    return _CTRL_RE.sub("", str(s))[:_MAX_STR]


def _check_size(path: str) -> None:
    size = os.path.getsize(path)
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file too large ({size} bytes > {MAX_FILE_BYTES} cap): {path}")


def _qs_param_names(url: str) -> list[str]:
    try:
        return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    except ValueError:
        return []


def _looks_like_hostname(s: str) -> bool:
    return bool(s) and not s.startswith("{") and bool(_HOSTNAME_RE.match(s))


def _dedup(names: list[str]) -> list[str]:
    return list(dict.fromkeys(n for n in names if n))


# ---- format sniffing ---------------------------------------------------------

def sniff_kind(path: str) -> str | None:
    """Best-effort format detection from the first ~4KB. Returns one of
    SUPPORTED or None. Deliberately shallow — a heuristic, not a validator;
    parse_file() still has to survive being handed the wrong kind."""
    _check_size(path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            head = f.read(4096)
    except OSError:
        return None
    stripped = head.lstrip()

    if stripped.startswith("<?xml") and ("<issues" in head or "<items" in head):
        return "burp"

    if stripped.startswith("{"):
        # ponytail: substring check on the first 4KB, not a real JSON parse of
        # the (possibly huge) "results" array — good enough to tell ffuf's
        # whole-document shape apart from the JSONL formats below.
        if '"results"' in head:
            return "ffuf"
        first_line = next((l for l in head.splitlines() if l.strip()), "")
        try:
            obj = json.loads(first_line)
        except (ValueError, json.JSONDecodeError):
            return None
        if isinstance(obj, dict):
            if "template-id" in obj or "template_id" in obj:
                return "nuclei"
            if "request" in obj:
                return "katana"
            if ("url" in obj or "input" in obj) and "status_code" in obj:
                return "httpx"
        return None

    lines = [l.strip() for l in head.splitlines() if l.strip() and not l.strip().startswith("#")]
    if lines and all(_looks_like_hostname(l) for l in lines[:5]):
        return "subfinder"
    return None


# ---- per-format parsers ------------------------------------------------------
# Each returns (endpoints, signals, parsed, skipped, warnings).

def _parse_nuclei(path: str):
    endpoints, signals, warnings = [], [], []
    parsed = skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                skipped += 1
                continue
            if not isinstance(obj, dict):
                skipped += 1
                continue
            parsed += 1
            matched = _clean(obj.get("matched-at") or obj.get("host") or "")
            if matched:
                url = matched if "://" in matched else f"https://{matched}"
                endpoints.append({
                    "method": "GET", "url": url, "params": _qs_param_names(url),
                    "auth_hint": "", "source": "nuclei",
                })
            info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
            if len(signals) < _MAX_SIGNALS:
                signals.append({
                    "kind": "nuclei",
                    "severity": _clean(info.get("severity") or ""),
                    "title": _clean(info.get("name") or obj.get("template-id") or obj.get("template_id") or ""),
                    "url": matched,
                    "detail": _clean(obj.get("template-id") or obj.get("template_id") or ""),
                })
    return endpoints, signals, parsed, skipped, warnings


def _parse_httpx(path: str):
    endpoints, signals, warnings = [], [], []
    parsed = skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                skipped += 1
                continue
            if not isinstance(obj, dict):
                skipped += 1
                continue
            parsed += 1
            url = _clean(obj.get("url") or obj.get("input") or "")
            if not url:
                continue
            status = obj.get("status_code")
            title = _clean(obj.get("title") or "")
            tech = obj.get("tech") or obj.get("technologies") or []
            tech_s = ", ".join(_clean(t) for t in tech) if isinstance(tech, list) else _clean(tech)
            webserver = _clean(obj.get("webserver") or "")
            auth_hint = "likely-auth" if status in _AUTH_STATUS else ""
            endpoints.append({
                "method": "GET", "url": url, "params": _qs_param_names(url),
                "auth_hint": auth_hint, "source": "httpx",
            })
            if (status in _INTERESTING_HTTPX_STATUS or title or tech_s) and len(signals) < _MAX_SIGNALS:
                detail_bits = [f"status={status}"]
                if tech_s:
                    detail_bits.append(f"tech={tech_s}")
                if webserver:
                    detail_bits.append(f"webserver={webserver}")
                signals.append({
                    "kind": "httpx",
                    "severity": "notable" if status in _INTERESTING_HTTPX_STATUS else "info",
                    "title": title or f"status {status}",
                    "url": url,
                    "detail": _clean("; ".join(detail_bits)),
                })
    return endpoints, signals, parsed, skipped, warnings


def _parse_subfinder(path: str):
    endpoints, signals, warnings = [], [], []
    parsed = skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            host = line
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except (ValueError, json.JSONDecodeError):
                    skipped += 1
                    continue
                if not isinstance(obj, dict) or not obj.get("host"):
                    skipped += 1
                    continue
                host = obj["host"]
            host = _clean(host)
            if not host:
                skipped += 1
                continue
            parsed += 1
            endpoints.append({
                "method": "GET", "url": f"https://{host}/", "params": [],
                "auth_hint": "", "source": "subfinder",
            })
    return endpoints, signals, parsed, skipped, warnings


def _parse_ffuf(path: str):
    endpoints, signals, warnings = [], [], []
    parsed = skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        try:
            doc = json.loads(f.read())
        except (ValueError, json.JSONDecodeError) as e:
            warnings.append(f"ffuf file did not parse as JSON: {e}")
            return endpoints, signals, parsed, skipped, warnings
    results = doc.get("results") if isinstance(doc, dict) else None
    if not isinstance(results, list):
        warnings.append("ffuf JSON had no top-level 'results' list")
        return endpoints, signals, parsed, skipped, warnings
    for r in results:
        if not isinstance(r, dict):
            skipped += 1
            continue
        url = _clean(r.get("url") or "")
        if not url:
            skipped += 1
            continue
        parsed += 1
        params = _qs_param_names(url)
        inp = r.get("input")
        if isinstance(inp, dict):
            params = _dedup(params + [_clean(k) for k in inp.keys()])
        status = r.get("status")
        endpoints.append({
            "method": _clean(r.get("method") or "GET").upper() or "GET",
            "url": url, "params": params, "auth_hint": "", "source": "ffuf",
        })
        if status is not None and status != 404 and len(signals) < _MAX_SIGNALS:
            signals.append({
                "kind": "ffuf", "severity": "info", "title": f"status {status}",
                "url": url,
                "detail": _clean(", ".join(f"{k}={v}" for k, v in inp.items())) if isinstance(inp, dict) else "",
            })
    return endpoints, signals, parsed, skipped, warnings


def _parse_katana(path: str):
    endpoints, signals, warnings = [], [], []
    parsed = skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                skipped += 1
                continue
            req = obj.get("request") if isinstance(obj, dict) else None
            if not isinstance(req, dict):
                skipped += 1
                continue
            url = _clean(req.get("endpoint") or req.get("url") or "")
            if not url:
                skipped += 1
                continue
            parsed += 1
            method = _clean(req.get("method") or "GET").upper() or "GET"
            endpoints.append({
                "method": method, "url": url, "params": _qs_param_names(url),
                "auth_hint": "", "source": "katana",
            })
    return endpoints, signals, parsed, skipped, warnings


# ---- burp XML, hardened against XXE / billion-laughs ------------------------

class _EntityRejected(ValueError):
    """Raised the instant a DTD entity declaration is seen. Never let this be
    caught and swallowed as an ordinary malformed-XML warning — it means the
    file is trying to declare entities, which is the attack itself."""


def _reject_entity(*_a, **_k):
    raise _EntityRejected("XML entity declaration rejected (XXE / billion-laughs guard)")


def _safe_burp_root(path: str):
    """Parse Burp's XML export with a hand-wired expat parser that refuses to
    know what a <!ENTITY> is. xml.etree.ElementTree.XMLParser is NOT used
    here: CPython's C-accelerated _elementtree implementation doesn't expose
    the underlying expat object to attach handlers to (checked against this
    project's Python 3.13 — dir(ET.XMLParser()) has no .parser/._parser).
    TreeBuilder is used purely as the tree-assembly target; expat itself is
    driven by hand so the entity handlers are guaranteed to be in effect for
    every byte parsed.
    """
    target = TreeBuilder()
    parser = expat.ParserCreate()
    parser.buffer_text = True
    parser.ordered_attributes = True

    parser.StartElementHandler = lambda name, attrs: target.start(
        name, dict(zip(attrs[0::2], attrs[1::2])) if attrs else {}
    )
    parser.EndElementHandler = target.end
    parser.CharacterDataHandler = target.data
    # The guard: declaring ANY entity — internal (billion-laughs) or external
    # (XXE file/URL disclosure) — raises immediately, before expansion.
    parser.EntityDeclHandler = _reject_entity
    parser.UnparsedEntityDeclHandler = _reject_entity
    parser.ExternalEntityRefHandler = lambda *a: False  # refuse to resolve; aborts parse

    with open(path, "rb") as f:
        data = f.read()
    parser.Parse(data, True)
    return target.close()


def _extract_body_param_names(raw: str) -> list[str]:
    """Best-effort param NAMES from a raw HTTP request blob: the request-line
    query string plus a urlencoded form body.
    # ponytail: regex/split parsing, not a real HTTP parser — multipart and
    # JSON bodies aren't covered. Upgrade to a proper request parser if a
    # target's forms turn out to matter and this keeps missing params.
    """
    names: list[str] = []
    lines = raw.splitlines()
    if lines:
        m = _REQUEST_LINE_RE.match(lines[0])
        if m:
            names.extend(_qs_param_names(m.group(1)))
    body = ""
    if "\r\n\r\n" in raw:
        body = raw.split("\r\n\r\n", 1)[1]
    elif "\n\n" in raw:
        body = raw.split("\n\n", 1)[1]
    body = body.strip()
    if body and "=" in body and "\n" not in body:
        try:
            names.extend(k for k, _ in parse_qsl(body, keep_blank_values=True))
        except ValueError:
            pass
    return names


def _parse_burp(path: str):
    endpoints, signals, warnings = [], [], []
    parsed = skipped = 0
    try:
        root = _safe_burp_root(path)
    except _EntityRejected:
        raise  # hard stop: must propagate as ValueError, never be swallowed
    except expat.ExpatError as e:
        warnings.append(f"burp XML did not parse: {e}")
        return endpoints, signals, parsed, skipped, warnings

    for item in root.iter("item"):
        url_el = item.find("url")
        url = _clean(url_el.text if url_el is not None else "")
        if not url:
            skipped += 1
            continue
        parsed += 1
        method_el = item.find("method")
        method = _clean((method_el.text if method_el is not None else "") or "GET").upper() or "GET"
        params = list(_qs_param_names(url))
        for tag in ("request", "response"):
            el = item.find(tag)
            if el is None or not (el.text or "").strip():
                continue
            raw = el.text
            if el.get("base64") == "true":
                try:
                    raw = base64.b64decode(el.text, validate=False).decode("utf-8", "replace")
                except (ValueError, UnicodeDecodeError):
                    continue
            params.extend(_extract_body_param_names(raw))
        endpoints.append({
            "method": method, "url": url, "params": _dedup(_clean(p) for p in params),
            "auth_hint": "", "source": "burp",
        })
    return endpoints, signals, parsed, skipped, warnings


_PARSERS = {
    "nuclei": _parse_nuclei,
    "httpx": _parse_httpx,
    "subfinder": _parse_subfinder,
    "ffuf": _parse_ffuf,
    "katana": _parse_katana,
    "burp": _parse_burp,
}


# ---- public API ---------------------------------------------------------

def parse_file(path: str, kind: str = "") -> dict:
    _check_size(path)
    k = kind or sniff_kind(path)
    if k not in SUPPORTED:
        raise ValueError(f"unrecognized or unsupported format for {path!r} (kind={kind!r})")

    endpoints, signals, parsed, skipped, warnings = _PARSERS[k](path)

    deduped, seen = [], set()
    for e in endpoints:
        key = (e.get("method", ""), e.get("url", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(e)

    if len(signals) > _MAX_SIGNALS:
        signals = signals[:_MAX_SIGNALS]
    if len(signals) == _MAX_SIGNALS:
        warnings = warnings + [f"signals truncated to {_MAX_SIGNALS}"]

    return {
        "kind": k, "endpoints": deduped, "signals": signals,
        "parsed": parsed, "skipped": skipped, "warnings": warnings,
    }


def ingest_file(handle: str, path: str, kind: str = "") -> dict:
    result = parse_file(path, kind)
    ins = coverage.add_endpoints(handle, result["endpoints"])
    # These two are NOT the same thing and must not be folded together:
    # malformed records mean the user's recon output is broken and they should
    # look at it; duplicates are the expected, healthy result of re-ingesting.
    return {
        "kind": result["kind"],
        "parsed": result["parsed"],
        "inserted": ins["inserted"],
        "skipped_malformed": result["skipped"],
        "skipped_duplicate": ins["skipped"],
        "skipped": result["skipped"] + ins["skipped"],   # kept for convenience
        "signals": result["signals"][:50],
        "warnings": result["warnings"],
        "signal_count": len(result["signals"]),
    }


if __name__ == "__main__":
    import tempfile

    os.environ["BB_DATA_DIR"] = tempfile.mkdtemp()
    tmp = tempfile.mkdtemp()
    handle = "selftest"

    def _write(name: str, content: str) -> str:
        p = os.path.join(tmp, name)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        return p

    nuclei_p = _write("nuclei.jsonl", (
        '{"template-id":"tech-detect","info":{"name":"Tech Detect","severity":"info"},'
        '"matched-at":"https://example.com/","host":"https://example.com"}\n'
        '{"template-id":"exposed-panel","info":{"name":"Admin\\u0007Panel","severity":"medium"},'
        '"matched-at":"https://example.com/admin"}\n'
        'not valid json {\n'
    ))
    httpx_p = _write("httpx.jsonl", (
        '{"url":"https://example.com/","status_code":200}\n'
        '{"url":"https://example.com/admin?x=1","input":"https://example.com/admin?x=1",'
        '"status_code":403,"title":"Admin\\u0007Login","tech":["nginx"]}\n'
    ))
    subfinder_p = _write("subfinder.txt", "sub1.example.com\nsub2.example.com\n# comment\n\n")
    ffuf_p = _write("ffuf.json", json.dumps({
        "commandline": "ffuf -u https://example.com/FUZZ",
        "results": [
            {"url": "https://example.com/admin", "status": 200, "method": "GET",
             "input": {"FUZZ": "admin"}},
            {"url": "https://example.com/xyz", "status": 404, "method": "GET"},
        ],
    }))
    katana_p = _write("katana.jsonl", (
        '{"request":{"method":"GET","endpoint":"https://example.com/path?x=1"}}\n'
    ))
    burp_req_b64 = base64.b64encode(b"GET /path?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\n\r\n").decode()
    burp_p = _write("burp.xml", (
        '<?xml version="1.0"?>\n<items>\n<item>\n'
        f'<url>https://example.com/path?a=1&amp;b=2</url>\n<method>GET</method>\n'
        f'<request base64="true">{burp_req_b64}</request>\n'
        '</item>\n</items>\n'
    ))
    burp_bomb_p = _write("burp_bomb.xml", (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE items [\n'
        '<!ENTITY lol "lol">\n'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
        ']>\n<items>\n<item><url>&lol2;</url></item>\n</items>\n'
    ))

    # control-char stripping + length cap, direct
    assert _clean("ab\x07cd") == "abcd"
    assert len(_clean("x" * 5000)) == _MAX_STR

    for name, path, expect_kind in [
        ("nuclei", nuclei_p, "nuclei"),
        ("httpx", httpx_p, "httpx"),
        ("subfinder", subfinder_p, "subfinder"),
        ("ffuf", ffuf_p, "ffuf"),
        ("katana", katana_p, "katana"),
        ("burp", burp_p, "burp"),
    ]:
        assert sniff_kind(path) == expect_kind, f"{name}: sniff got {sniff_kind(path)!r}"
        res = ingest_file(handle, path)
        assert res["kind"] == expect_kind, f"{name}: {res}"
        assert res["inserted"] > 0, f"{name}: no endpoints inserted: {res}"

    # nuclei: one malformed line skipped, not fatal; control char stripped from title
    nuclei_res = parse_file(nuclei_p)
    assert nuclei_res["skipped"] == 1, nuclei_res
    assert any("\x07" not in s["title"] and "Panel" in s["title"] for s in nuclei_res["signals"])

    # httpx: 403 -> likely-auth + a signal with tech captured
    httpx_res = parse_file(httpx_p)
    admin_ep = [e for e in httpx_res["endpoints"] if "admin" in e["url"]][0]
    assert admin_ep["auth_hint"] == "likely-auth", admin_ep
    assert any("nginx" in s["detail"] for s in httpx_res["signals"]), httpx_res["signals"]
    assert "\x07" not in [s for s in httpx_res["signals"] if "admin" in s["url"]][0]["title"]

    # ffuf: 404 result produces no signal, 200 does; input param captured
    ffuf_res = parse_file(ffuf_p)
    assert len(ffuf_res["signals"]) == 1, ffuf_res["signals"]
    admin_ffuf = [e for e in ffuf_res["endpoints"] if "admin" in e["url"]][0]
    assert "FUZZ" in admin_ffuf["params"], admin_ffuf

    # burp: query param names extracted from both URL and decoded base64 request
    burp_res = parse_file(burp_p)
    assert burp_res["endpoints"], burp_res
    ep = burp_res["endpoints"][0]
    assert set(ep["params"]) >= {"a", "b"}, ep

    # burp entity bomb: must raise ValueError, never expand
    try:
        parse_file(burp_bomb_p, kind="burp")
        raise SystemExit("XML entity bomb was not rejected")
    except ValueError:
        pass

    # unsupported/undetectable kind
    junk_p = _write("junk.bin", "\x01\x02\x03 not a recognized format")
    assert sniff_kind(junk_p) is None
    try:
        parse_file(junk_p)
        raise SystemExit("unsupported format was not rejected")
    except ValueError:
        pass

    # oversized file rejected before read
    big_p = os.path.join(tmp, "big.jsonl")
    with open(big_p, "wb") as f:
        f.seek(MAX_FILE_BYTES + 1)
        f.write(b"\x00")
    try:
        parse_file(big_p)
        raise SystemExit("oversized file was not rejected")
    except ValueError:
        pass

    print("ingest self-check ok")
