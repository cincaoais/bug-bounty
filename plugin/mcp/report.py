"""Evidence storage and report assembly — the last stop before a human submits
a bug report to a program.

Two hard rules govern this whole module:

  1. Nothing unredacted ever touches disk. Every byte of evidence content
     (raw or read from a file) is passed through redact.redact() BEFORE it is
     written anywhere. If redact.py cannot be imported, this module fails to
     import at all — there is deliberately no fallback path that stores
     unredacted text, because that is the one failure this system must never
     have.

  2. assemble_report() never invents technical content. It is a pure
     re-assembly of what is already sitting in the `finding`, `evidence`, and
     `endpoint` tables. Any report section with nothing stored behind it
     becomes the literal string "[YOU MUST FILL THIS IN: ...]" — never a
     plausible-sounding guess — so a human reviewer sees at a glance exactly
     what is still missing before this goes near a real submission form.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import re
from pathlib import Path

import db
import redact

VALID_EVIDENCE_KINDS = {"request", "response", "screenshot-note", "output", "other"}
MAX_EVIDENCE_BYTES = 5 * 1024 * 1024
VALID_PLATFORMS = {"generic", "hackerone", "bugcrowd", "intigriti"}
VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}

_MAX_SUMMARY = 200

# ponytail: finding -> evidence/endpoint linkage has no FK in the schema (the
# `finding` table only has title/severity/status/body_md/human_confirmed). The
# mechanical, explainable link used here is an explicit `evidence:<id>` /
# `endpoint:<id>` token inside body_md — same ref-string convention correlate.py
# already uses for notes/leads/primitives. Only IDs that actually resolve to a
# row are ever used; an unresolved or absent ref just means a gap. Upgrade to a
# real join table if grep-for-refs ever stops being good enough.
_REF_RE = re.compile(r"\b(evidence|endpoint)\s*[:#]\s*(\d+)\b", re.IGNORECASE)

# Accepts the three header styles people actually write findings in:
#   ## Steps to reproduce      (ATX)
#   **Steps to reproduce**     (bold line — very common in pasted write-ups)
#   Steps to reproduce         (bare label line ending in ':')
#
# Why bother: a missed header renders a FALSE gap. False gaps are worse than
# they look — the whole anti-fabrication mechanism rests on the user trusting
# that a [YOU MUST FILL THIS IN] marker means something is genuinely missing.
# A parser that cries wolf trains them to ignore markers, and then a real gap
# gets filled with a guess.
#
# ponytail: still not a markdown parser. Setext (===) underlines and headers
# inside fenced code blocks are not handled; upgrade only if that shows up in
# real use.
_HEADER_RE = re.compile(
    r"^(?:"
    r"#{1,6}[ \t]*(?P<atx>[^\r\n]+?)"                 # ## Header
    r"|\*\*(?P<bold>[^*\r\n]+?)\*\*:?"                # **Header**
    r"|(?P<bare>[A-Za-z][A-Za-z0-9 /()'-]{2,40}):"    # Header:
    r")[ \t]*$",
    re.MULTILINE,
)

_SECTION_ORDER = {
    "generic":   ["title", "summary", "assets", "steps", "poc", "impact", "remediation", "severity"],
    "hackerone": ["title", "summary", "steps", "poc", "assets", "impact", "severity", "remediation"],
    "bugcrowd":  ["title", "summary", "severity", "assets", "steps", "poc", "impact", "remediation"],
    "intigriti": ["title", "summary", "assets", "steps", "poc", "impact", "remediation", "severity"],
}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _open_target(handle: str):
    """For read paths that look up a specific id: a missing target db means
    the id can't exist, so that's a ValueError, not an empty result."""
    path = db.target_db_path(handle)
    if not path.exists():
        raise ValueError(f"no such target: {handle!r}")
    return path, db.connect(path)


def _evidence_dir(handle: str) -> Path:
    d = db.data_dir() / "targets" / f"{db.safe_handle(handle)}_evidence"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---- evidence ----------------------------------------------------------------

def store_evidence(handle: str, kind: str, content: str = "", source_path: str = "",
                    summary: str = "") -> dict:
    if kind not in VALID_EVIDENCE_KINDS:
        raise ValueError(f"invalid evidence kind {kind!r}, must be one of {sorted(VALID_EVIDENCE_KINDS)}")
    if bool(content) == bool(source_path):
        raise ValueError("store_evidence requires exactly one of content= or source_path=")

    if source_path:
        p = Path(source_path)
        if not p.is_file():
            raise ValueError(f"source_path does not exist or is not a regular file: {source_path!r}")
        size = p.stat().st_size
        if size > MAX_EVIDENCE_BYTES:
            raise ValueError(f"source file too large ({size} bytes > {MAX_EVIDENCE_BYTES} cap): {source_path!r}")
        raw_text = p.read_text(encoding="utf-8", errors="replace")
    else:
        if len(content.encode("utf-8")) > MAX_EVIDENCE_BYTES:
            raise ValueError(f"content too large (> {MAX_EVIDENCE_BYTES} byte cap)")
        raw_text = content

    # THE line: nothing past this point is ever the original text again.
    redacted_text, redactions = redact.redact(raw_text)

    if summary:
        summary_text = summary[:_MAX_SUMMARY]
    else:
        first_line = next((l.strip() for l in redacted_text.splitlines() if l.strip()), "")
        summary_text = first_line[:_MAX_SUMMARY]

    sha256 = hashlib.sha256(redacted_text.encode("utf-8")).hexdigest()

    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        cur = conn.execute(
            "INSERT INTO evidence (kind, blob_path, summary, redacted, sha256, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (kind, "", summary_text, 1, sha256, _now()),
        )
        evidence_id = cur.lastrowid
        blob_path = _evidence_dir(handle) / f"{evidence_id}.txt"
        with open(blob_path, "w", encoding="utf-8") as f:
            f.write(redacted_text)
        conn.execute("UPDATE evidence SET blob_path=? WHERE id=?", (str(blob_path), evidence_id))
        conn.commit()
    finally:
        conn.close()

    return {
        "id": evidence_id,
        "blob_path": str(blob_path),
        "redactions": redactions,
        "bytes": len(redacted_text.encode("utf-8")),
        "sha256": sha256,
    }


def get_evidence(handle: str, evidence_id: int, max_chars: int = 4000) -> dict:
    _, conn = _open_target(handle)
    try:
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise ValueError(f"no such evidence: {evidence_id}")

    blob_path = Path(row["blob_path"])
    body = blob_path.read_text(encoding="utf-8", errors="replace") if blob_path.exists() else ""
    truncated = len(body) > max_chars
    if truncated:
        body = body[:max_chars]
    return {
        "id": row["id"], "kind": row["kind"], "summary": row["summary"],
        "blob_path": row["blob_path"], "sha256": row["sha256"], "redacted": True,
        "body": body, "truncated": truncated,
    }


def list_evidence(handle: str, kind: str = "", limit: int = 50) -> list[dict]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        sql = "SELECT id, kind, blob_path, summary, redacted, sha256, created_at FROM evidence WHERE 1=1"
        args: list = []
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


# ---- body_md parsing (mechanical, explainable — see module/comment notes) ----

def _split_sections(body_md: str) -> dict[str, str]:
    """Split on ATX / bold / bare-label headers into {lowercased header: body}.
    No headers found -> empty dict (caller falls back to the whole body)."""
    matches = list(_HEADER_RE.finditer(body_md or ""))
    if not matches:
        return {}
    sections: dict[str, str] = {}
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body_md)
        label = m.group("atx") or m.group("bold") or m.group("bare") or ""
        key = label.strip().lower().rstrip(":").strip("* ")
        if key:
            sections[key] = body_md[start:end].strip()
    return sections


def _find_section(sections: dict[str, str], aliases: tuple[str, ...]) -> str:
    for key, val in sections.items():
        if val and any(alias in key for alias in aliases):
            return val
    return ""


def _referenced_ids(body_md: str, kind: str) -> list[int]:
    ids: list[int] = []
    for m in _REF_RE.finditer(body_md or ""):
        if m.group(1).lower() == kind:
            n = int(m.group(2))
            if n not in ids:
                ids.append(n)
    return ids


# ---- report assembly — THE anti-fabrication mechanism ------------------------

def assemble_report(handle: str, finding_id: int, platform: str = "generic") -> dict:
    if platform not in VALID_PLATFORMS:
        raise ValueError(f"invalid platform {platform!r}, must be one of {sorted(VALID_PLATFORMS)}")

    _, conn = _open_target(handle)
    try:
        frow = conn.execute("SELECT * FROM finding WHERE id=?", (finding_id,)).fetchone()
        if frow is None:
            raise ValueError(f"no such finding: {finding_id}")
        # HARD REQUIREMENT: an unconfirmed lead must never be turned into a
        # submittable report. `!= 1` also rejects NULL.
        if frow["human_confirmed"] != 1:
            raise ValueError(
                f"finding {finding_id} is not human_confirmed — refusing to assemble a report "
                "from an unconfirmed lead"
            )
        finding = dict(frow)
        body_md = finding["body_md"] or ""

        endpoints = []
        for eid in _referenced_ids(body_md, "endpoint"):
            r = conn.execute("SELECT * FROM endpoint WHERE id=?", (eid,)).fetchone()
            if r:
                endpoints.append(dict(r))

        evidence_rows = []
        for evid in _referenced_ids(body_md, "evidence"):
            r = conn.execute("SELECT id, kind, summary, blob_path FROM evidence WHERE id=?", (evid,)).fetchone()
            if r:
                evidence_rows.append(dict(r))
    finally:
        conn.close()

    sections = _split_sections(body_md)
    summary = _find_section(sections, ("summary", "description", "overview"))
    if not summary and not sections:
        # No structure at all in body_md -> treat the whole write-up as the
        # summary. This is a literal pass-through of stored text, not a guess.
        summary = body_md.strip()
    steps = _find_section(sections, ("steps to reproduce", "reproduction", "repro", "steps"))
    impact = _find_section(sections, ("impact", "risk"))
    remediation = _find_section(sections, ("remediation", "mitigation", "fix", "recommendation"))

    gaps: list[str] = []

    def _fill(label: str, content: str, what: str) -> str:
        if content.strip():
            return content.strip()
        gaps.append(label)
        return f"[YOU MUST FILL THIS IN: {what}]"

    summary_text = _fill("Summary", summary, "a plain-language summary of the vulnerability")
    steps_text = _fill("Steps to reproduce", steps, "numbered reproduction steps")
    impact_text = _fill("Impact", impact, "concrete impact of this vulnerability if exploited")
    remediation_text = _fill("Remediation", remediation, "a specific fix or mitigation")

    if endpoints:
        assets_text = "\n".join(f"- `{e['method']} {e['url']}`" for e in endpoints)
    else:
        gaps.append("Affected asset(s)")
        assets_text = ("[YOU MUST FILL THIS IN: the affected host/endpoint(s) — reference them "
                        "with `endpoint:<id>` in the finding body]")

    if evidence_rows:
        poc_text = "\n".join(
            f"- evidence #{e['id']} ({e['kind']}): {e['summary']} — `{e['blob_path']}`"
            for e in evidence_rows
        )
    else:
        gaps.append("Proof of concept / evidence")
        poc_text = ("[YOU MUST FILL THIS IN: store proof with store_evidence and reference it "
                     "with `evidence:<id>` in the finding body]")

    severity = finding["severity"] or ""
    severity_text = f"**{severity or 'unset'}** (proposed — a human must confirm this before submitting; not final)"

    section_md = {
        "title": f"# {finding['title']}",
        "summary": f"## Summary\n\n{summary_text}",
        "assets": f"## Affected asset(s)\n\n{assets_text}",
        "steps": f"## Steps to reproduce\n\n{steps_text}",
        "poc": f"## Proof of concept / evidence\n\n{poc_text}",
        "impact": f"## Impact\n\n{impact_text}",
        "remediation": f"## Remediation\n\n{remediation_text}",
        "severity": f"## Severity\n\n{severity_text}",
    }
    order = _SECTION_ORDER[platform]
    markdown = "\n\n".join(section_md[key] for key in order)

    return {
        "markdown": markdown,
        "gaps": gaps,
        "evidence_used": [e["id"] for e in evidence_rows],
        "platform": platform,
        "severity_proposed": severity,
    }


def report_checklist(handle: str, finding_id: int, platform: str = "generic") -> dict:
    path, conn = _open_target(handle)
    try:
        row = conn.execute("SELECT * FROM finding WHERE id=?", (finding_id,)).fetchone()
        if row is None:
            raise ValueError(f"no such finding: {finding_id}")
        finding = dict(row)
    finally:
        conn.close()

    body_md = finding["body_md"] or ""
    title = (finding["title"] or "").strip()
    sections = _split_sections(body_md)
    steps = _find_section(sections, ("steps to reproduce", "reproduction", "repro", "steps"))
    impact = _find_section(sections, ("impact", "risk"))
    ep_ids = _referenced_ids(body_md, "endpoint")
    ev_ids = _referenced_ids(body_md, "evidence")

    conn = db.connect(path)
    try:
        has_asset = any(
            conn.execute("SELECT 1 FROM endpoint WHERE id=?", (eid,)).fetchone() for eid in ep_ids
        )
        has_evidence = any(
            conn.execute("SELECT 1 FROM evidence WHERE id=?", (evid,)).fetchone() for evid in ev_ids
        )
    finally:
        conn.close()

    # bare vuln-class titles ("XSS", "SQL Injection") read short and generic —
    # a real title names what/where. Length + word-count is a cheap, explainable
    # stand-in for "specific", not a semantic check.
    title_specific = len(title) >= 15 and len(title.split()) >= 4

    checks = [
        {"name": "human_confirmed", "passed": finding["human_confirmed"] == 1,
         "detail": "confirmed by a human" if finding["human_confirmed"] == 1
         else "finding has not been human-confirmed"},
        {"name": "title", "passed": title_specific,
         "detail": f"title: {title!r}" if title_specific
         else "title must be >=15 chars and >=4 words, not a bare vuln class name"},
        {"name": "steps_to_reproduce", "passed": bool(steps.strip()),
         "detail": "present" if steps.strip()
         else "body_md has no Steps to reproduce (or similar) section"},
        {"name": "evidence_linked", "passed": bool(has_evidence),
         "detail": f"{len(ev_ids)} evidence reference(s) resolved" if has_evidence
         else "no `evidence:<id>` reference in body_md resolves to a stored evidence row"},
        {"name": "impact", "passed": bool(impact.strip()),
         "detail": "present" if impact.strip()
         else "body_md has no Impact (or similar) section"},
        {"name": "affected_asset", "passed": bool(has_asset),
         "detail": f"{len(ep_ids)} endpoint reference(s) resolved" if has_asset
         else "no `endpoint:<id>` reference in body_md resolves to a stored endpoint row"},
        {"name": "severity", "passed": finding["severity"] in VALID_SEVERITY,
         "detail": f"severity: {finding['severity']}" if finding["severity"] in VALID_SEVERITY
         else f"severity must be one of {sorted(VALID_SEVERITY)}"},
    ]
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    return {"checks": checks, "passed": passed, "failed": failed, "ready": failed == 0}


if __name__ == "__main__":
    import os
    import tempfile

    os.environ["BB_DATA_DIR"] = tempfile.mkdtemp()
    handle = "selftest"
    db.init_target_db(db.target_db_path(handle))

    # 1. redaction is mandatory: the secret must never reach disk.
    token = "Bearer sk_live_SECRETTOKEN12345"
    stored = store_evidence(handle, "request", content=f"Authorization: {token}\nGET /api/x HTTP/1.1")
    on_disk = Path(stored["blob_path"]).read_text(encoding="utf-8")
    assert token not in on_disk, "unredacted bearer token reached disk"
    assert stored["redactions"], "expected at least one reported redaction"
    assert stored["sha256"] == hashlib.sha256(on_disk.encode("utf-8")).hexdigest()

    # 2. exactly one of content / source_path
    try:
        store_evidence(handle, "request", content="a", source_path="b")
        raise SystemExit("both content and source_path not rejected")
    except ValueError:
        pass
    try:
        store_evidence(handle, "request")
        raise SystemExit("neither content nor source_path not rejected")
    except ValueError:
        pass

    # 3. an unconfirmed finding can never be assembled into a report
    path = db.target_db_path(handle)
    conn = db.connect(path)
    try:
        cur = conn.execute(
            "INSERT INTO finding (title, severity, status, body_md, human_confirmed, created_at) "
            "VALUES (?,?,?,?,?,?)",
            ("Reflected XSS", "medium", "open", "some notes", 0, _now()),
        )
        unconfirmed_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()
    try:
        assemble_report(handle, unconfirmed_id)
        raise SystemExit("unconfirmed finding was assembled into a report")
    except ValueError:
        pass

    # 4/5. confirmed finding, no evidence/endpoint refs -> gaps + placeholders,
    # and never a payout-style dollar figure.
    conn = db.connect(path)
    try:
        cur = conn.execute(
            "INSERT INTO finding (title, severity, status, body_md, human_confirmed, created_at) "
            "VALUES (?,?,?,?,?,?)",
            ("IDOR exposes other users invoices", "high", "open",
             "Found by changing the id parameter on the invoice endpoint.", 1, _now()),
        )
        bare_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()

    result = assemble_report(handle, bare_id)
    assert "[YOU MUST FILL THIS IN" in result["markdown"]
    assert result["gaps"], "expected at least one gap for a finding with no linked evidence/endpoints"
    assert "$" not in result["markdown"], "report must never contain payout-style figures"
    assert result["severity_proposed"] == "high"
    assert "proposed" in result["markdown"].lower()
    assert result["evidence_used"] == []

    # 6. checklist agrees this bare finding is not submittable
    checklist = report_checklist(handle, bare_id)
    assert checklist["ready"] is False
    assert checklist["failed"] > 0

    print("report self-check ok")
