"""Evidence storage and grounded report assembly.

The guarantees under test, in priority order:

1. Nothing unredacted ever reaches disk. Evidence files are what could leak an
   NDA-bound program's data or a live session token.
2. assemble_report never invents technical content. Missing sections become
   explicit [YOU MUST FILL THIS IN] markers, never plausible filler. Fabricated
   report content is the fastest way to destroy standing with a program.
3. Gap markers must not cry wolf. A parser that reports false gaps trains the
   user to ignore markers — and then a real gap gets filled with a guess.
4. An unconfirmed lead can never become a submittable report.
"""
import importlib
import os
import re

import pytest


@pytest.fixture()
def rep(tmp_path):
    os.environ["BB_DATA_DIR"] = str(tmp_path)
    import db
    importlib.reload(db)
    import redact
    importlib.reload(redact)
    import report
    importlib.reload(report)
    db.init_target_db(db.target_db_path("t"))
    return report


def _finding(body="", title="IDOR on order endpoint allows cross-user read",
             severity="high", confirmed=1):
    import db
    conn = db.connect(db.target_db_path("t"))
    try:
        cur = conn.execute(
            "INSERT INTO finding (title, severity, status, body_md, human_confirmed, created_at) "
            "VALUES (?,?,?,?,?,datetime('now'))",
            (title, severity, "open", body, confirmed),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# ---- evidence: nothing unredacted reaches disk -------------------------------

def test_stored_evidence_file_contains_no_secret(rep):
    secret = "deadbeefcafebabe0123456789abcdef"
    out = rep.store_evidence("t", "request",
                             content=f"GET /x\nCookie: session={secret}\n")
    on_disk = open(out["blob_path"], encoding="utf-8").read()
    assert secret not in on_disk, "unredacted secret written to disk"
    assert out["redactions"], "redaction happened but was not reported"


def test_stored_evidence_keeps_the_useful_structure(rep):
    out = rep.store_evidence("t", "request", content=(
        "POST /api/v1/profile HTTP/1.1\nHost: api.acme.test\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop\n"))
    body = open(out["blob_path"], encoding="utf-8").read()
    assert "POST /api/v1/profile HTTP/1.1" in body
    assert "Host: api.acme.test" in body


def test_evidence_written_outside_the_repo(rep, tmp_path):
    out = rep.store_evidence("t", "output", content="hello")
    assert str(tmp_path) in out["blob_path"], "evidence must live under BB_DATA_DIR"
    assert "bug-bounty" not in out["blob_path"].replace(str(tmp_path), "")


def test_content_xor_source_path(rep, tmp_path):
    p = tmp_path / "e.txt"
    p.write_text("data", encoding="utf-8")
    with pytest.raises(ValueError):
        rep.store_evidence("t", "output", content="x", source_path=str(p))
    with pytest.raises(ValueError):
        rep.store_evidence("t", "output")


def test_oversize_source_rejected(rep, tmp_path, monkeypatch):
    monkeypatch.setattr(rep, "MAX_EVIDENCE_BYTES", 128, raising=False)
    p = tmp_path / "big.txt"
    p.write_text("A" * 5000, encoding="utf-8")
    with pytest.raises(ValueError):
        rep.store_evidence("t", "output", source_path=str(p))


def test_get_evidence_truncates(rep):
    eid = rep.store_evidence("t", "output", content="B" * 9000)["id"]
    got = rep.get_evidence("t", eid, max_chars=500)
    assert len(got["body"]) <= 500 and got["truncated"] is True


def test_invalid_kind_rejected(rep):
    with pytest.raises(ValueError):
        rep.store_evidence("t", "not-a-kind", content="x")


# ---- the confirmation gate ---------------------------------------------------

def test_unconfirmed_finding_cannot_be_reported(rep):
    fid = _finding(body="## Impact\nstuff", confirmed=0)
    with pytest.raises(ValueError):
        rep.assemble_report("t", fid)


# ---- anti-fabrication --------------------------------------------------------

def test_missing_sections_become_explicit_markers(rep):
    fid = _finding(body="")
    out = rep.assemble_report("t", fid)
    assert "[YOU MUST FILL THIS IN" in out["markdown"]
    assert out["gaps"], "gaps must be reported, not silently filled"


def test_no_payout_figures_anywhere(rep):
    """Payout estimates bias toward severity inflation."""
    fid = _finding(body="## Impact\nAny user can read any order.")
    md = rep.assemble_report("t", fid)["markdown"]
    assert not re.search(r"\$\s*\d", md), "monetary figure in report draft"
    assert "bounty" not in md.lower() or "payout" not in md.lower()


def test_severity_is_labelled_proposed(rep):
    fid = _finding(body="## Impact\nx")
    out = rep.assemble_report("t", fid)
    assert out["severity_proposed"] == "high"
    assert "proposed" in out["markdown"].lower()


def test_evidence_included_by_reference_not_pasted(rep):
    marker = "UNIQUEEVIDENCEBODY12345"
    eid = rep.store_evidence("t", "response", content=f"HTTP/1.1 200 OK\n{marker}\n")["id"]
    fid = _finding(body=f"## Proof of concept\nSee evidence:{eid}\n## Impact\nx")
    md = rep.assemble_report("t", fid)["markdown"]
    assert marker not in md, "evidence body pasted into the draft instead of referenced"
    assert str(eid) in md


# ---- gap markers must not cry wolf ------------------------------------------

@pytest.mark.parametrize("body,style", [
    ("## Steps to reproduce\n1. Log in as A\n2. GET /api/orders/1042\n\n## Impact\nCross-user read.\n", "atx"),
    ("**Steps to reproduce**\n1. Log in as A\n2. GET /api/orders/1042\n\n**Impact**\nCross-user read.\n", "bold"),
    ("Steps to reproduce:\n1. Log in as A\n2. GET /api/orders/1042\n\nImpact:\nCross-user read.\n", "bare"),
])
def test_present_sections_are_not_reported_as_gaps(rep, body, style):
    """A false gap is not harmless: it teaches the user that markers are noise,
    and then a genuine gap gets filled with a guess."""
    fid = _finding(body=body)
    out = rep.assemble_report("t", fid)
    gaps_lower = " ".join(out["gaps"]).lower()
    assert "steps" not in gaps_lower, f"{style}: real steps reported as a gap"
    assert "impact" not in gaps_lower, f"{style}: real impact reported as a gap"
    assert "Log in as A" in out["markdown"]
    assert "Cross-user read." in out["markdown"]


def test_user_content_always_survives_into_the_draft(rep):
    """Whatever the formatting, the user's own words must reach the draft."""
    fid = _finding(body="~~~ odd formatting ~~~\nthe order_id parameter is not ownership-checked\n")
    md = rep.assemble_report("t", fid)["markdown"]
    assert "order_id parameter is not ownership-checked" in md


# ---- checklist ---------------------------------------------------------------

def test_checklist_blocks_a_bare_finding(rep):
    fid = _finding(body="")
    out = rep.report_checklist("t", fid)
    assert out["ready"] is False and out["failed"] > 0


def test_checklist_flags_a_vague_title(rep):
    fid = _finding(body="## Impact\nx", title="IDOR")
    out = rep.report_checklist("t", fid)
    names = " ".join(c["name"] for c in out["checks"] if not c["passed"]).lower()
    assert "title" in names


def test_checklist_requires_evidence(rep):
    fid = _finding(body="## Steps to reproduce\n1. x\n## Impact\ny")
    out = rep.report_checklist("t", fid)
    assert out["ready"] is False, "a report with no stored evidence is not ready"
