"""Note -> lead -> primitive -> finding, plus mechanical cross-referencing.

The practitioner hierarchy this module stores:
  - note      a raw observation ("this endpoint returns 403 with a JSON body").
  - lead      an observation plus a hypothesis ("that body leaks a hostname;
              maybe a header bypass works").
  - primitive a CONFIRMED capability that is not a bug by itself ("I can
              control the Host header and it reaches the backend"). Primitives
              are the raw material of exploit chains and the thing beginners
              most consistently throw away because "it's not a bug on its own".
  - finding   a confirmed, reproducible security issue, promoted from a lead
              BY A HUMAN ONLY (see promote_to_finding).

suggest_correlations() is the other half: after weeks of short sessions a
researcher accumulates dozens of notes/leads/primitives and loses track of
which ones are actually about the same thing. This function proposes
candidate pairs using cheap, mechanical, EXPLAINABLE signals (shared
endpoint, shared host, shared param, shared vocabulary) and nothing more. It
deliberately does NOT do semantic/NLP matching: a wrong "these are related"
suggestion is worse than no suggestion, because it sends the human down a
false trail with borrowed confidence. Mechanical scoring is inspectable in
one glance ("why did this pair score 62? same-endpoint +50, shared-term
'hostname' +12") and a human or a language model applies judgment on top of
that — this module never claims to know what the overlap MEANS, only that it
exists.
"""
from __future__ import annotations

import datetime as _dt
import itertools
import json
import re

import db

VALID_CONFIDENCE = {"low", "medium", "high"}
VALID_LEAD_STATUS = {"open", "chasing", "dead", "promoted"}
VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = {
    "this", "that", "with", "from", "have", "when", "then", "they", "there",
    "which", "endpoint", "request", "response", "header", "returns", "param",
    "parameter", "value", "error", "about", "into", "does", "using", "seems",
    "maybe", "could", "would", "should", "might", "still", "only", "also",
    "some", "more", "than", "been", "were", "what", "where",
}

_MIN_SCORE = 20


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _truncate(text: str, n: int = 120) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def _tokenize(text: str) -> set[str]:
    words = _TOKEN_RE.findall((text or "").lower())
    toks = {w for w in words if len(w) >= 4 and w not in _STOPWORDS}
    # ponytail: cap is applied after dedup, sorted for determinism. Fine at
    # per-item text sizes seen here (notes/hypotheses, not whole reports).
    if len(toks) > 40:
        toks = set(sorted(toks)[:40])
    return toks


# ---- note / lead / primitive / finding CRUD --------------------------------

def add_note(handle: str, body: str, endpoint_id: int | None = None) -> dict:
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        cur = conn.execute(
            "INSERT INTO note (body_md, endpoint_id, created_at) VALUES (?,?,?)",
            (body, endpoint_id, _now()),
        )
        conn.commit()
        return {"id": cur.lastrowid}
    finally:
        conn.close()


def add_lead(handle: str, hypothesis: str, confidence: str = "medium",
             note_ids: list[int] | None = None) -> dict:
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(f"invalid confidence {confidence!r}, must be one of {sorted(VALID_CONFIDENCE)}")
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        cur = conn.execute(
            "INSERT INTO lead (hypothesis, confidence, status, created_at) VALUES (?,?,?,?)",
            (hypothesis, confidence, "open", _now()),
        )
        lead_id = cur.lastrowid
        for note_id in (note_ids or []):
            conn.execute("INSERT INTO lead_note (lead_id, note_id) VALUES (?,?)", (lead_id, note_id))
        conn.commit()
        return {"id": lead_id}
    finally:
        conn.close()


def add_primitive(handle: str, capability: str, description: str = "",
                   evidence_id: int | None = None) -> dict:
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        cur = conn.execute(
            "INSERT INTO primitive (capability, description, evidence_id, created_at) VALUES (?,?,?,?)",
            (capability, description, evidence_id, _now()),
        )
        conn.commit()
        return {"id": cur.lastrowid}
    finally:
        conn.close()


def list_notes(handle: str, endpoint_id: int | None = None, contains: str = "",
                limit: int = 50) -> list[dict]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        sql = "SELECT * FROM note WHERE 1=1"
        args: list = []
        if endpoint_id is not None:
            sql += " AND endpoint_id=?"
            args.append(endpoint_id)
        if contains:
            sql += " AND body_md LIKE ?"
            args.append(f"%{contains}%")
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


def list_leads(handle: str, status: str = "", limit: int = 50) -> list[dict]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        sql = "SELECT * FROM lead WHERE 1=1"
        args: list = []
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
        # ponytail: one query per lead for its linked notes (N+1). Fine at
        # bug-bounty scale (dozens of leads); switch to a single JOIN + GROUP
        # BY if this list ever needs to page through hundreds of leads.
        for r in rows:
            r["note_ids"] = [
                nr["note_id"] for nr in conn.execute(
                    "SELECT note_id FROM lead_note WHERE lead_id=? ORDER BY note_id", (r["id"],)
                )
            ]
        return rows
    finally:
        conn.close()


def list_primitives(handle: str, contains: str = "", limit: int = 50) -> list[dict]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        sql = "SELECT * FROM primitive WHERE 1=1"
        args: list = []
        if contains:
            sql += " AND (capability LIKE ? OR description LIKE ?)"
            args.extend([f"%{contains}%", f"%{contains}%"])
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


def list_findings(handle: str, status: str = "", limit: int = 50) -> list[dict]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        sql = "SELECT * FROM finding WHERE 1=1"
        args: list = []
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


def set_lead_status(handle: str, lead_id: int, status: str) -> dict:
    if status not in VALID_LEAD_STATUS:
        raise ValueError(f"invalid lead status {status!r}, must be one of {sorted(VALID_LEAD_STATUS)}")
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        cur = conn.execute("UPDATE lead SET status=? WHERE id=?", (status, lead_id))
        if cur.rowcount == 0:
            raise ValueError(f"no such lead: {lead_id}")
        conn.commit()
        return {"id": lead_id, "status": status}
    finally:
        conn.close()


def promote_to_finding(handle: str, lead_id: int, title: str, severity: str, body_md: str,
                        human_confirmed: bool = False) -> dict:
    # HARD REQUIREMENT: the model must never be able to create a finding on
    # its own. `is not True` rejects truthy-but-not-literal-True values too
    # (1, "yes", ...) so this can't be satisfied by accident.
    if human_confirmed is not True:
        raise ValueError("promote_to_finding requires human_confirmed=True — only a human promotes a lead")
    if severity not in VALID_SEVERITY:
        raise ValueError(f"invalid severity {severity!r}, must be one of {sorted(VALID_SEVERITY)}")
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        if conn.execute("SELECT id FROM lead WHERE id=?", (lead_id,)).fetchone() is None:
            raise ValueError(f"no such lead: {lead_id}")
        cur = conn.execute(
            "INSERT INTO finding (title, severity, status, body_md, human_confirmed, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (title, severity, "open", body_md, 1, _now()),
        )
        finding_id = cur.lastrowid
        conn.execute("UPDATE lead SET status='promoted' WHERE id=?", (lead_id,))
        conn.commit()
        return {"id": finding_id, "lead_id": lead_id, "status": "promoted"}
    finally:
        conn.close()


# ---- correlation -------------------------------------------------------------

def _collect_items(conn, endpoints: dict) -> list[dict]:
    items = []
    for row in conn.execute("SELECT id, body_md, endpoint_id FROM note"):
        eids = {row["endpoint_id"]} if row["endpoint_id"] is not None else set()
        items.append(_make_item(f"note:{row['id']}", "note", row["body_md"] or "", eids, endpoints))
    for row in conn.execute("SELECT id, hypothesis FROM lead"):
        # A lead has no endpoint_id of its own; it inherits the set of
        # endpoint_ids from whichever notes it's linked to.
        eids = {
            r["eid"] for r in conn.execute(
                "SELECT DISTINCT n.endpoint_id AS eid FROM lead_note ln "
                "JOIN note n ON n.id = ln.note_id "
                "WHERE ln.lead_id=? AND n.endpoint_id IS NOT NULL",
                (row["id"],),
            )
        }
        items.append(_make_item(f"lead:{row['id']}", "lead", row["hypothesis"] or "", eids, endpoints))
    for row in conn.execute("SELECT id, capability, description FROM primitive"):
        # Primitives have no endpoint linkage in this schema (only
        # evidence_id, and evidence has no endpoint_id either) — they can
        # only correlate via shared vocabulary, never same-endpoint/host/param.
        text = f"{row['capability'] or ''} {row['description'] or ''}".strip()
        items.append(_make_item(f"primitive:{row['id']}", "primitive", text, set(), endpoints))
    return items


def _make_item(ref: str, kind: str, text: str, endpoint_ids: set, endpoints: dict) -> dict:
    hosts = {endpoints[e]["host"] for e in endpoint_ids if e in endpoints and endpoints[e]["host"]}
    params: set = set()
    for e in endpoint_ids:
        if e in endpoints:
            params |= set(json.loads(endpoints[e]["params"] or "[]"))
    return {
        "ref": ref, "kind": kind,
        "endpoint_ids": endpoint_ids, "hosts": hosts, "params": params,
        "tokens": _tokenize(text),
        "summary": _truncate(text),
        "endpoints": {e: endpoints[e] for e in endpoint_ids if e in endpoints},
    }


def _score_pair(a: dict, b: dict) -> tuple[int, list[str], str]:
    """Symmetric in a/b: every signal below is a set operation, so callers
    don't need to normalise argument order before scoring (only for the
    final a_ref/b_ref presentation)."""
    score = 0
    signals: list[str] = []
    why_parts: list[str] = []

    common_eids = a["endpoint_ids"] & b["endpoint_ids"]
    if common_eids:
        score += 50
        signals.append("same-endpoint")
        eid = min(common_eids)
        ep = a["endpoints"].get(eid) or b["endpoints"].get(eid)
        if ep:
            why_parts.append(f"both touch {ep['method']} {ep['path']}")

    common_hosts = a["hosts"] & b["hosts"]
    if common_hosts:
        score += 25
        signals.append("same-host")
        if not common_eids:
            why_parts.append(f"both touch host {sorted(common_hosts)[0]}")

    common_params = sorted(a["params"] & b["params"])[:2]
    for p in common_params:
        score += 20
        signals.append(f"shared-param:{p}")
    if common_params:
        why_parts.append("both reference param " + ", ".join(f"'{p}'" for p in common_params))

    common_terms = sorted(a["tokens"] & b["tokens"])[:3]
    for t in common_terms:
        score += 12
        signals.append(f"shared-term:{t}")
    if common_terms:
        why_parts.append("both mention " + ", ".join(f"'{t}'" for t in common_terms))

    why = "; ".join(why_parts) if why_parts else "mechanical overlap only"
    return score, signals, why


def suggest_correlations(handle: str, limit: int = 20) -> list[dict]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        endpoints = {
            r["id"]: dict(r)
            for r in conn.execute("SELECT id, method, path, host, params FROM endpoint")
        }
        items = _collect_items(conn, endpoints)
        dismissed = {r["pair_key"] for r in conn.execute("SELECT pair_key FROM correlation_dismissed")}
    finally:
        conn.close()

    results = []
    # ponytail: O(n^2) pair scan over notes+leads+primitives, done in Python.
    # Fine at bug-bounty scale (a session accumulates dozens to low hundreds
    # of these, not thousands). If that ever changes, bucket items by
    # endpoint_id first so only same-endpoint candidates get the full compare.
    for a, b in itertools.combinations(items, 2):
        score, signals, why = _score_pair(a, b)
        if score < _MIN_SCORE:
            continue
        a_ref, b_ref = a["ref"], b["ref"]
        if a_ref > b_ref:
            a, b = b, a
            a_ref, b_ref = b_ref, a_ref
        pair_key = f"{a_ref}|{b_ref}"
        if pair_key in dismissed:
            continue
        results.append({
            "a_ref": a_ref, "a_kind": a["kind"], "a_summary": a["summary"],
            "b_ref": b_ref, "b_kind": b["kind"], "b_summary": b["summary"],
            "score": score, "signals": signals, "why": why,
        })
    results.sort(key=lambda r: (-r["score"], r["a_ref"], r["b_ref"]))
    return results[:limit]


def dismiss_correlation(handle: str, a_ref: str, b_ref: str, reason: str = "") -> dict:
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        lo, hi = sorted((a_ref, b_ref))
        pair_key = f"{lo}|{hi}"
        conn.execute(
            "INSERT INTO correlation_dismissed (pair_key, a_ref, b_ref, reason, dismissed_at) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(pair_key) DO UPDATE SET reason=excluded.reason, dismissed_at=excluded.dismissed_at",
            (pair_key, lo, hi, reason, _now()),
        )
        conn.commit()
        return {"pair_key": pair_key, "a_ref": lo, "b_ref": hi, "reason": reason}
    finally:
        conn.close()


if __name__ == "__main__":
    import os
    import tempfile

    os.environ["BB_DATA_DIR"] = tempfile.mkdtemp()
    handle = "selftest"
    path = db.target_db_path(handle)
    db.init_target_db(path)

    conn = db.connect(path)
    try:
        conn.execute(
            "INSERT INTO endpoint (id, method, url, host, path, params, auth_hint, first_seen, source) "
            "VALUES (1, 'GET', 'https://api.acme.com/api/v1/users/123', 'api.acme.com', "
            "'/api/v1/users/123', '[\"id\"]', '', '', '')"
        )
        conn.execute(
            "INSERT INTO endpoint (id, method, url, host, path, params, auth_hint, first_seen, source) "
            "VALUES (2, 'GET', 'https://other.example.com/status', 'other.example.com', "
            "'/status', '[]', '', '', '')"
        )
        conn.commit()
    finally:
        conn.close()

    # note1 + lead1 share endpoint 1 (and therefore its host) AND the
    # distinctive word "hostname" -> should dominate the ranking.
    note1 = add_note(handle, "Internal hostname disclosed in the error body of this endpoint.",
                      endpoint_id=1)
    lead1 = add_lead(handle, "Maybe that hostname leak allows a header bypass chain here.",
                      confidence="medium", note_ids=[note1["id"]])
    # primitive1 shares ONLY the single word "hostname" with note1/lead1, no
    # endpoint linkage (primitives never have one) -> must score below threshold.
    primitive1 = add_primitive(handle, "Host header injection reaches backend",
                                "Confirmed the request forwards a spoofed hostname")

    results = suggest_correlations(handle)
    assert results, "expected at least one correlation candidate"
    top = results[0]
    assert {top["a_ref"], top["b_ref"]} == {f"note:{note1['id']}", f"lead:{lead1['id']}"}
    assert "same-endpoint" in top["signals"]
    assert all(r["score"] >= _MIN_SCORE for r in results)
    refs_seen = {r["a_ref"] for r in results} | {r["b_ref"] for r in results}
    assert f"primitive:{primitive1['id']}" not in refs_seen, "single shared word should score below threshold"

    dismissed = dismiss_correlation(handle, top["a_ref"], top["b_ref"], reason="already one lead, tracked")
    assert dismissed["pair_key"] == "|".join(sorted([top["a_ref"], top["b_ref"]]))
    after = suggest_correlations(handle)
    assert after == [], "dismissed pair should not resurface"

    try:
        promote_to_finding(handle, lead1["id"], "Host header bypass", "high", "body",
                            human_confirmed=False)
        raise SystemExit("promote without human_confirmed not rejected")
    except ValueError:
        pass

    try:
        promote_to_finding(handle, lead1["id"], "Host header bypass", "not-a-severity", "body",
                            human_confirmed=True)
        raise SystemExit("bad severity not rejected")
    except ValueError:
        pass

    promoted = promote_to_finding(handle, lead1["id"], "Host header bypass via hostname leak",
                                   "high", "Full repro steps here.", human_confirmed=True)
    assert promoted["status"] == "promoted"
    leads_after = list_leads(handle)
    assert leads_after[0]["id"] == lead1["id"] and leads_after[0]["status"] == "promoted"
    assert leads_after[0]["note_ids"] == [note1["id"]]

    try:
        add_lead(handle, "bad confidence test", confidence="extreme")
        raise SystemExit("bad confidence not rejected")
    except ValueError:
        pass

    assert list_notes(handle, endpoint_id=1)[0]["id"] == note1["id"]
    assert len(list_primitives(handle, contains="hostname")) == 1
    findings = list_findings(handle)
    assert len(findings) == 1 and findings[0]["severity"] == "high"

    print("correlate self-check ok")
