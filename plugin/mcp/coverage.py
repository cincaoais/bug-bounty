"""Endpoint inventory, test-case catalogue, and coverage tracking.

Three tables (created by db.py, not here): endpoint, test_case, coverage.
This module is pure storage + one ranking function over them. No network,
no LLM.

next_actions() is the core feature: it ranks untested (endpoint, test_case)
pairs so the operator knows what to poke next. The ranking is a small
additive integer score with a human-readable `why` string built from the
same factors that produced the score — deliberately simple and inspectable
over anything "smarter" that can't be explained over a shoulder.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
from urllib.parse import urlsplit

import db

VALID_STATUSES = {"untested", "testing", "not-vulnerable", "suspicious", "confirmed", "n-a"}

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_ID_PARAM_RE = re.compile(r"(?i)(^|_)(id|uid|user|account|order|doc|file|key|ref)(_|$)|id$")
_REDIRECT_PARAM_RE = re.compile(r"(?i)url|next|redirect|return|dest|callback|continue")
_ADMIN_PATH_RE = re.compile(r"(?i)admin|internal|manage|console|staff")
_API_PATH_RE = re.compile(r"(?i)/api/|/v[0-9]+/|graphql")
_UPLOAD_PATH_RE = re.compile(r"(?i)upload|file|attach|import")
_NUMERIC_SEG_RE = re.compile(r"/\d+(/|$)")
_UUID_SEG_RE = re.compile(
    r"(?i)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)"
)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


# ---- endpoints -----------------------------------------------------------

def add_endpoints(handle: str, endpoints: list[dict]) -> dict:
    """Insert endpoints, deduped on (method, url). `params` is stored as a
    JSON list, host/path derived from url."""
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        inserted = 0
        for e in endpoints:
            method = (e.get("method") or "").strip().upper()
            url = (e.get("url") or "").strip()
            parts = urlsplit(url)
            cur = conn.execute(
                "INSERT OR IGNORE INTO endpoint "
                "(method, url, host, path, params, auth_hint, first_seen, source) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    method, url, parts.netloc, parts.path or "/",
                    json.dumps(e.get("params") or []),
                    e.get("auth_hint") or "", _now(), e.get("source") or "",
                ),
            )
            if cur.rowcount:
                inserted += 1
        conn.commit()
        return {"inserted": inserted, "skipped": len(endpoints) - inserted}
    finally:
        conn.close()


def list_endpoints(handle: str, has_params: bool | None = None, method: str = "",
                    host: str = "", untested_only: bool = False, limit: int = 50) -> list[dict]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        sql = "SELECT * FROM endpoint WHERE 1=1"
        args: list = []
        if method:
            sql += " AND method=?"
            args.append(method.strip().upper())
        if host:
            sql += " AND host=?"
            args.append(host)
        if untested_only:
            sql += " AND id NOT IN (SELECT endpoint_id FROM coverage)"
        sql += " ORDER BY id"
        rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()
    for r in rows:
        r["params"] = json.loads(r["params"] or "[]")
    if has_params is not None:
        rows = [r for r in rows if bool(r["params"]) == has_params]
    # ponytail: has_params is filtered in Python (params is a JSON blob, not
    # an indexable column). Fine at bug-bounty scale (hundreds of endpoints);
    # add a generated column + index if that stops being true.
    return rows[:limit]


# ---- test cases -----------------------------------------------------------

def seed_test_cases(handle: str, cases: list[dict]) -> dict:
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        for c in cases:
            level = c.get("scope_level", "endpoint")
            if level not in ("host", "endpoint"):
                raise ValueError(f"invalid scope_level {level!r} on {c.get('id')!r}")
            hint = c.get("path_hint") or None
            if hint:
                try:
                    re.compile(hint)
                except re.error as e:
                    raise ValueError(f"bad path_hint regex on {c.get('id')!r}: {e}") from e
            conn.execute(
                "INSERT OR REPLACE INTO test_case "
                "(id, category, title, tier, applies_to, scope_level, path_hint) "
                "VALUES (?,?,?,?,?,?,?)",
                (c["id"], c.get("category", ""), c.get("title", ""),
                 int(c.get("tier", 2)), json.dumps(c.get("applies_to") or []), level, hint),
            )
        conn.commit()
        return {"seeded": len(cases)}
    finally:
        conn.close()


# ---- coverage --------------------------------------------------------------

def record_coverage(handle: str, endpoint_id: int, test_case_id: str, status: str,
                     note: str = "", evidence_id: int | None = None) -> dict:
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status {status!r}, must be one of {sorted(VALID_STATUSES)}")
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        conn.execute(
            "INSERT INTO coverage (endpoint_id, test_case_id, status, tested_at, evidence_id, note) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(endpoint_id, test_case_id) DO UPDATE SET "
            "status=excluded.status, tested_at=excluded.tested_at, "
            "evidence_id=excluded.evidence_id, note=excluded.note",
            (endpoint_id, test_case_id, status, _now(), evidence_id, note),
        )
        conn.commit()
        return {"endpoint_id": endpoint_id, "test_case_id": test_case_id, "status": status}
    finally:
        conn.close()


def coverage_summary(handle: str) -> dict:
    path = db.target_db_path(handle)
    if not path.exists():
        return {"endpoints": 0, "test_cases": 0, "possible_pairs": 0, "tested_pairs": 0,
                "percent_tested": 0.0, "by_status": {}, "by_category": [], "untouched_endpoints": 0}
    conn = db.connect(path)
    try:
        n_endpoints = conn.execute("SELECT COUNT(*) c FROM endpoint").fetchone()["c"]
        n_test_cases = conn.execute("SELECT COUNT(*) c FROM test_case").fetchone()["c"]
        by_status = {
            r["status"]: r["c"]
            for r in conn.execute("SELECT status, COUNT(*) c FROM coverage GROUP BY status")
        }
        # ponytail: a coverage row with status='untested' is a placeholder,
        # not evidence of work done, so it doesn't count toward tested_pairs.
        tested_pairs = sum(c for status, c in by_status.items() if status != "untested")
        untouched = conn.execute(
            "SELECT COUNT(*) c FROM endpoint WHERE id NOT IN (SELECT endpoint_id FROM coverage)"
        ).fetchone()["c"]
        by_category = []
        for row in conn.execute("SELECT DISTINCT category FROM test_case ORDER BY category"):
            cat = row["category"]
            total_tc = conn.execute(
                "SELECT COUNT(*) c FROM test_case WHERE category=?", (cat,)
            ).fetchone()["c"]
            tested = conn.execute(
                "SELECT COUNT(*) c FROM coverage cov JOIN test_case tc ON tc.id = cov.test_case_id "
                "WHERE tc.category=? AND cov.status != 'untested'", (cat,)
            ).fetchone()["c"]
            by_category.append({"category": cat, "tested": tested, "total": total_tc * n_endpoints})
    finally:
        conn.close()
    possible_pairs = n_endpoints * n_test_cases
    percent_tested = (100.0 * tested_pairs / possible_pairs) if possible_pairs else 0.0
    return {
        "endpoints": n_endpoints, "test_cases": n_test_cases, "possible_pairs": possible_pairs,
        "tested_pairs": tested_pairs, "percent_tested": percent_tested, "by_status": by_status,
        "by_category": by_category, "untouched_endpoints": untouched,
    }


# ---- ranking ----------------------------------------------------------------

def session_activity(handle: str, since_hours: int = 24) -> dict:
    """What actually changed on this target recently — the factual basis for a
    retrospective.

    Exists so the end-of-session review reads from the LEDGER rather than from
    the conversation. Memory (the model's and the user's) inflates a quiet
    session; the tables do not. A session that tested three things and found
    nothing should read as exactly that.
    """
    path = db.target_db_path(handle)
    if not path.exists():
        return {"since_hours": since_hours, "coverage_records": [], "notes": [],
                "leads": [], "primitives": [], "findings": [], "endpoints_added": 0}
    cutoff = (_dt.datetime.now(_dt.timezone.utc)
              - _dt.timedelta(hours=max(1, int(since_hours)))).isoformat(timespec="seconds")
    conn = db.connect(path)
    try:
        cov = [dict(r) for r in conn.execute(
            "SELECT c.endpoint_id, c.test_case_id, c.status, c.tested_at, c.note, "
            "       e.method, e.url, t.title "
            "FROM coverage c "
            "LEFT JOIN endpoint e ON e.id = c.endpoint_id "
            "LEFT JOIN test_case t ON t.id = c.test_case_id "
            "WHERE c.tested_at >= ? ORDER BY c.tested_at DESC", (cutoff,))]
        notes = [dict(r) for r in conn.execute(
            "SELECT id, body_md, endpoint_id, created_at FROM note "
            "WHERE created_at >= ? ORDER BY created_at DESC", (cutoff,))]
        leads = [dict(r) for r in conn.execute(
            "SELECT id, hypothesis, confidence, status, created_at FROM lead "
            "WHERE created_at >= ? ORDER BY created_at DESC", (cutoff,))]
        prims = [dict(r) for r in conn.execute(
            "SELECT id, capability, description, created_at FROM primitive "
            "WHERE created_at >= ? ORDER BY created_at DESC", (cutoff,))]
        finds = [dict(r) for r in conn.execute(
            "SELECT id, title, severity, status, created_at FROM finding "
            "WHERE created_at >= ? ORDER BY created_at DESC", (cutoff,))]
        eps = conn.execute(
            "SELECT COUNT(*) c FROM endpoint WHERE first_seen >= ?", (cutoff,)).fetchone()["c"]
        # Open threads are what next session should start from, regardless of age.
        open_susp = [dict(r) for r in conn.execute(
            "SELECT c.endpoint_id, c.test_case_id, c.note, e.url "
            "FROM coverage c LEFT JOIN endpoint e ON e.id = c.endpoint_id "
            "WHERE c.status = 'suspicious' ORDER BY c.tested_at DESC LIMIT 25")]
        open_leads = [dict(r) for r in conn.execute(
            "SELECT id, hypothesis, confidence, status FROM lead "
            "WHERE status IN ('open','chasing') ORDER BY id DESC LIMIT 25")]
    finally:
        conn.close()
    return {
        "since_hours": since_hours, "since": cutoff,
        "coverage_records": cov, "notes": notes, "leads": leads,
        "primitives": prims, "findings": finds, "endpoints_added": eps,
        "open_suspicious": open_susp, "open_leads": open_leads,
        "quiet_session": not (cov or notes or leads or prims or finds or eps),
    }


def _endpoint_tags(method: str, path: str, params: list[str], auth_hint: str) -> set[str]:
    tags = {"any"}
    if params:
        tags.add("has-params")
    if any(_ID_PARAM_RE.search(p) for p in params):
        tags.add("id-param")
    if _NUMERIC_SEG_RE.search(path) or _UUID_SEG_RE.search(path):
        tags.add("numeric-id-path")
    if auth_hint:
        tags.add("authed")
    if method.upper() in _WRITE_METHODS:
        tags.add("write-method")
    if _ADMIN_PATH_RE.search(path):
        tags.add("admin-path")
    if _API_PATH_RE.search(path):
        tags.add("api-path")
    if _UPLOAD_PATH_RE.search(path):
        tags.add("upload-path")
    if any(_REDIRECT_PARAM_RE.search(p) for p in params):
        tags.add("redirect-param")
    return tags


def _applies(applies_to: list[str], tags: set[str]) -> bool:
    if not applies_to or "any" in applies_to:
        return True
    return bool(set(applies_to) & tags)


def next_actions(handle: str, limit: int = 15, per_endpoint: int = 3) -> list[dict]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        endpoints = [dict(r) for r in conn.execute("SELECT * FROM endpoint")]
        test_cases = [dict(r) for r in conn.execute("SELECT * FROM test_case")]
        # 'suspicious' deliberately does NOT close a pair: it means "something
        # looked off here" and is the highest-value thing to come back to. It
        # re-enters the ranking with a bonus below. Everything else with a real
        # status (not-vulnerable / confirmed / n-a / testing) is closed.
        covered = {
            (r["endpoint_id"], r["test_case_id"])
            for r in conn.execute(
                "SELECT endpoint_id, test_case_id FROM coverage "
                "WHERE status NOT IN ('untested', 'suspicious')"
            )
        }
        suspicious = {
            (r["endpoint_id"], r["test_case_id"])
            for r in conn.execute(
                "SELECT endpoint_id, test_case_id FROM coverage WHERE status = 'suspicious'"
            )
        }
        untouched = {
            r["id"] for r in conn.execute(
                "SELECT id FROM endpoint WHERE id NOT IN (SELECT endpoint_id FROM coverage)"
            )
        }
    finally:
        conn.close()

    # Host-level test cases are done ONCE per host, not once per endpoint. We pin
    # each to a single representative endpoint on that host (lowest id) so it
    # appears exactly once instead of N times.
    host_cases = [tc for tc in test_cases if (tc["scope_level"] or "endpoint") == "host"]
    endpoint_cases = [tc for tc in test_cases if (tc["scope_level"] or "endpoint") != "host"]
    rep_for_host: dict[str, int] = {}
    for ep in sorted(endpoints, key=lambda e: e["id"]):
        rep_for_host.setdefault(ep["host"] or "", ep["id"])

    results = []
    # ponytail: O(endpoints x test_cases) scan in Python, fine at bug-bounty
    # scale (dozens to low hundreds of each). Push into SQL if either table
    # ever grows into the thousands.
    for ep in endpoints:
        params = json.loads(ep["params"] or "[]")
        tags = _endpoint_tags(ep["method"] or "", ep["path"] or "", params, ep["auth_hint"] or "")
        is_host_rep = rep_for_host.get(ep["host"] or "") == ep["id"]
        applicable = endpoint_cases + (host_cases if is_host_rep else [])
        for tc in applicable:
            key = (ep["id"], tc["id"])
            if key in covered:
                continue
            is_host_level = (tc["scope_level"] or "endpoint") == "host"
            applies_to = json.loads(tc["applies_to"] or "[]")
            if not is_host_level:
                if not _applies(applies_to, tags):
                    continue
                # Flow-specific tests (2FA bypass, password reset, email-change ATO)
                # only apply where the flow actually lives. Without this they match
                # every authenticated POST and produce confident nonsense.
                hint = tc["path_hint"]
                if hint and not re.search(hint, ep["path"] or "", re.I):
                    continue
            score = 0
            why = []
            if is_host_level:
                why.append(f"host-level check for {ep['host']} (do once, not per endpoint)")
            elif tc["path_hint"]:
                why.append(f"path matches this flow (/{(ep['path'] or '').lstrip('/')})")
            if key in suspicious:
                score += 40
                why.append("previously marked SUSPICIOUS — unfinished lead, revisit first (+40)")
            if tc["tier"] == 1:
                score += 30
                why.append("tier-1 test case (+30)")
            elif tc["tier"] == 2:
                score += 10
                why.append("tier-2 test case (+10)")
            if "id-param" in tags or "numeric-id-path" in tags:
                score += 20
                why.append("id-like param or numeric/uuid path segment (+20)")
            if "admin-path" in tags:
                score += 15
                why.append("admin/internal-looking path (+15)")
            if "write-method" in tags:
                score += 10
                why.append("write method (+10)")
            if "api-path" in tags:
                score += 8
                why.append("api-shaped path (+8)")
            if "redirect-param" in tags or "upload-path" in tags:
                score += 5
                why.append("redirect param or upload path (+5)")
            if ep["id"] in untouched:
                score += 12
                why.append("endpoint has zero coverage rows so far (+12)")
            results.append({
                "endpoint_id": ep["id"], "method": ep["method"], "url": ep["url"],
                "test_case_id": tc["id"], "title": tc["title"], "category": tc["category"],
                "tier": tc["tier"], "scope_level": tc["scope_level"] or "endpoint",
                "score": score,
                "why": "; ".join(why) if why else "baseline (no extra signals)",
            })
    results.sort(key=lambda r: (-r["score"], r["endpoint_id"], r["test_case_id"]))
    return _spread(results, limit, per_endpoint=per_endpoint)


def _spread(ranked: list[dict], limit: int, per_endpoint: int = 3) -> list[dict]:
    """Take the top `limit` but cap how many land on any one endpoint.

    Without this the whole list clumps on the single juiciest endpoint, which
    hides the rest of the surface — the opposite of "what should I do next".
    Falls back to filling from the remainder if the cap leaves us short.
    """
    if per_endpoint <= 0:
        return ranked[:limit]
    picked, counts, overflow = [], {}, []
    for r in ranked:
        eid = r["endpoint_id"]
        if counts.get(eid, 0) < per_endpoint:
            picked.append(r)
            counts[eid] = counts.get(eid, 0) + 1
            if len(picked) == limit:
                return picked
        else:
            overflow.append(r)
    return (picked + overflow)[:limit]


if __name__ == "__main__":
    import os
    import tempfile

    os.environ["BB_DATA_DIR"] = tempfile.mkdtemp()
    handle = "selftest"
    db.init_target_db(db.target_db_path(handle))

    seeded = seed_test_cases(handle, [
        {"id": "idor-read", "category": "idor", "title": "IDOR on read",
         "tier": 1, "applies_to": ["id-param", "numeric-id-path"]},
        {"id": "admin-bypass", "category": "authz", "title": "Admin panel bypass",
         "tier": 1, "applies_to": ["admin-path"]},
        {"id": "open-redirect", "category": "redirect", "title": "Open redirect check",
         "tier": 2, "applies_to": ["redirect-param"]},
        {"id": "generic-fuzz", "category": "fuzz", "title": "Generic input fuzz",
         "tier": 2, "applies_to": ["any"]},
    ])
    assert seeded == {"seeded": 4}

    added = add_endpoints(handle, [
        {"method": "GET", "url": "https://api.acme.com/api/v1/users/123",
         "params": ["id"], "auth_hint": "bearer", "source": "manual"},
        {"method": "POST", "url": "https://acme.com/admin/manage/users",
         "source": "manual"},
        {"method": "GET", "url": "https://acme.com/redirect", "params": ["next"]},
        {"method": "GET", "url": "https://acme.com/about"},
        {"method": "PUT", "url": "https://acme.com/api/v2/upload/attachment",
         "params": ["attachment_name"], "auth_hint": "bearer"},
    ])
    assert added == {"inserted": 5, "skipped": 0}
    dupe = add_endpoints(handle, [{"method": "GET", "url": "https://acme.com/about"}])
    assert dupe == {"inserted": 0, "skipped": 1}

    eps = {e["path"]: e["id"] for e in list_endpoints(handle, limit=50)}
    assert len(eps) == 5

    record_coverage(handle, eps["/admin/manage/users"], "admin-bypass", "confirmed",
                     note="works with any low-priv session")
    record_coverage(handle, eps["/about"], "generic-fuzz", "not-vulnerable")

    try:
        record_coverage(handle, eps["/about"], "generic-fuzz", "bogus-status")
        raise SystemExit("bad status not rejected")
    except ValueError:
        pass

    actions = next_actions(handle, limit=10)
    assert actions, "next_actions returned nothing"
    top = actions[0]
    assert top["tier"] == 1
    assert top["test_case_id"] == "idor-read"
    assert top["endpoint_id"] == eps["/api/v1/users/123"]
    assert "id" in top["why"].lower()
    assert all(actions[i]["score"] >= actions[i + 1]["score"] for i in range(len(actions) - 1))

    summary = coverage_summary(handle)
    assert summary["endpoints"] == 5
    assert summary["test_cases"] == 4
    assert summary["possible_pairs"] == 20
    assert summary["tested_pairs"] == 2
    assert abs(summary["percent_tested"] - 10.0) < 1e-9
    assert summary["untouched_endpoints"] == 3
    assert 0.0 <= summary["percent_tested"] <= 100.0

    assert len(list_endpoints(handle, untested_only=True)) == 3
    assert len(list_endpoints(handle, method="post")) == 1
    with_params = list_endpoints(handle, has_params=True)
    assert len(with_params) == 3
    assert all(e["params"] for e in with_params)

    print("coverage self-check ok")
