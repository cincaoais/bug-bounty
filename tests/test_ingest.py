"""Parser correctness tests against the fixture corpus.

Expected counts come from tests/fixtures/MANIFEST.md. Hostile-input behaviour
lives in test_ingest_security.py — this file is happy-path + format detection.
"""
import importlib
import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def ing(tmp_path):
    os.environ["BB_DATA_DIR"] = str(tmp_path)
    import db
    importlib.reload(db)
    import coverage
    importlib.reload(coverage)
    import ingest
    importlib.reload(ingest)
    db.init_target_db(db.target_db_path("t"))
    return ingest


def _fx(name):
    p = FIXTURES / name
    if not p.exists():
        pytest.skip(f"fixture {name} missing")
    return str(p)


# ---- format detection --------------------------------------------------------

@pytest.mark.parametrize("fname,kind", [
    ("nuclei.jsonl", "nuclei"),
    ("httpx.jsonl", "httpx"),
    ("subfinder.txt", "subfinder"),
    ("ffuf.json", "ffuf"),
    ("katana.jsonl", "katana"),
    ("burp.xml", "burp"),
])
def test_sniff_kind(ing, fname, kind):
    assert ing.sniff_kind(_fx(fname)) == kind


def test_sniff_unknown_returns_none(ing, tmp_path):
    p = tmp_path / "mystery.dat"
    p.write_text("this is not any known recon format\n", encoding="utf-8")
    assert ing.sniff_kind(str(p)) is None


# ---- per-format extraction (counts from MANIFEST.md) -------------------------

@pytest.mark.parametrize("fname,kind,expected", [
    ("nuclei.jsonl", "nuclei", 5),
    ("httpx.jsonl", "httpx", 6),
    ("subfinder.txt", "subfinder", 6),     # 8 lines: 1 blank + 1 comment skipped
    ("ffuf.json", "ffuf", 6),
    ("katana.jsonl", "katana", 5),
    ("burp.xml", "burp", 4),
])
def test_endpoint_counts(ing, fname, kind, expected):
    out = ing.parse_file(_fx(fname), kind)
    assert len(out["endpoints"]) == expected, out["endpoints"]


def test_autodetect_matches_explicit_kind(ing):
    for fname in ("nuclei.jsonl", "httpx.jsonl", "ffuf.json", "katana.jsonl", "burp.xml"):
        auto = ing.parse_file(_fx(fname))
        explicit = ing.parse_file(_fx(fname), ing.sniff_kind(_fx(fname)))
        assert len(auto["endpoints"]) == len(explicit["endpoints"]), fname


# ---- format-specific behaviour ----------------------------------------------

def test_httpx_auth_hint_on_401_403(ing):
    out = ing.parse_file(_fx("httpx.jsonl"), "httpx")
    hinted = [e for e in out["endpoints"] if e.get("auth_hint")]
    assert len(hinted) >= 2, "401/403 responses should set an auth hint"


def test_httpx_signals_captured(ing):
    out = ing.parse_file(_fx("httpx.jsonl"), "httpx")
    assert out["signals"], "interesting statuses/titles should produce signals"


def test_nuclei_signals_carry_severity(ing):
    out = ing.parse_file(_fx("nuclei.jsonl"), "nuclei")
    sev = {s.get("severity") for s in out["signals"]}
    assert {"high", "medium"} & sev, f"expected severities in signals, got {sev}"


def test_katana_extracts_param_names(ing):
    out = ing.parse_file(_fx("katana.jsonl"), "katana")
    withparams = [e for e in out["endpoints"] if e.get("params")]
    assert len(withparams) >= 3, "multi-param query strings should yield param names"


def test_katana_preserves_methods(ing):
    out = ing.parse_file(_fx("katana.jsonl"), "katana")
    methods = [e["method"] for e in out["endpoints"]]
    assert methods.count("POST") == 2 and methods.count("GET") == 3


def test_burp_preserves_methods(ing):
    out = ing.parse_file(_fx("burp.xml"), "burp")
    methods = sorted(e["method"] for e in out["endpoints"])
    assert methods == ["GET", "GET", "POST", "POST"], methods


def test_subfinder_skips_blank_and_comment(ing):
    out = ing.parse_file(_fx("subfinder.txt"), "subfinder")
    urls = [e["url"] for e in out["endpoints"]]
    assert not any(u.strip() == "" for u in urls)
    assert not any("#" in u for u in urls)


def test_source_recorded(ing):
    out = ing.parse_file(_fx("httpx.jsonl"), "httpx")
    assert all(e.get("source") == "httpx" for e in out["endpoints"])


def test_query_param_names_extracted_from_url(ing):
    out = ing.parse_file(_fx("burp.xml"), "burp")
    assert any(e.get("params") for e in out["endpoints"]), "query strings should yield params"


# ---- persistence -------------------------------------------------------------

def test_ingest_file_persists_endpoints(ing):
    import coverage
    r = ing.ingest_file("t", _fx("httpx.jsonl"), "httpx")
    assert r["inserted"] == 6
    assert len(coverage.list_endpoints("t")) == 6


def test_reingest_is_idempotent(ing):
    """Re-ingesting the same file must be safe — the user will do this."""
    import coverage
    ing.ingest_file("t", _fx("httpx.jsonl"), "httpx")
    r2 = ing.ingest_file("t", _fx("httpx.jsonl"), "httpx")
    assert r2["inserted"] == 0 and r2["skipped"] >= 6
    assert len(coverage.list_endpoints("t")) == 6


def test_ingest_feeds_next_actions(ing):
    """The whole point of ingest: real recon data produces real suggestions."""
    import coverage
    coverage.seed_test_cases("t", [
        {"id": "T-IDOR", "category": "Authorization", "title": "IDOR",
         "tier": 1, "applies_to": ["has-params", "id-param"], "scope_level": "endpoint"},
        {"id": "T-HOST", "category": "Configuration", "title": "TLS review",
         "tier": 2, "applies_to": ["any"], "scope_level": "host"},
    ])
    ing.ingest_file("t", _fx("katana.jsonl"), "katana")
    acts = coverage.next_actions("t", limit=20)
    assert acts, "ingested endpoints should produce next actions"


def test_malformed_and_duplicate_skips_reported_separately(ing):
    """'2 records were malformed' and '2 endpoints already known' are completely
    different situations for the user — one means their recon output is broken,
    the other is the healthy result of re-ingesting. Folding them hides a real
    problem behind a normal-looking number."""
    r1 = ing.ingest_file("t", _fx("httpx.jsonl"), "httpx")
    assert r1["skipped_malformed"] == 0
    assert r1["skipped_duplicate"] == 0

    r2 = ing.ingest_file("t", _fx("httpx.jsonl"), "httpx")   # same file again
    assert r2["skipped_malformed"] == 0, "re-ingest is not a parse failure"
    assert r2["skipped_duplicate"] == 6

    r3 = ing.ingest_file("t", _fx("malformed.jsonl"), "httpx")
    assert r3["skipped_malformed"] >= 1, "a truncated JSON line must be reported as malformed"


def test_signals_capped_in_ingest_result(ing):
    r = ing.ingest_file("t", _fx("nuclei.jsonl"), "nuclei")
    assert len(r.get("signals", [])) <= 50
    assert "signal_count" in r
