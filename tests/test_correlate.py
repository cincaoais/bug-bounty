"""Findings graph tests: note -> lead -> primitive -> finding, plus correlation.

Two things here matter more than the rest:

1. The model must NEVER be able to create a finding. `promote_to_finding`
   requires explicit human confirmation. If that guard fails, the system can
   manufacture vulnerabilities, which is the fastest way to destroy a
   researcher's reputation with a program.

2. Correlation must under-report rather than over-report. A single shared
   common word is not a connection. Over-correlation trains the user to ignore
   the feature, which silently removes its value.
"""
import importlib
import os

import pytest


@pytest.fixture()
def cor(tmp_path):
    os.environ["BB_DATA_DIR"] = str(tmp_path)
    import db
    importlib.reload(db)
    import correlate
    importlib.reload(correlate)
    db.init_target_db(db.target_db_path("t"))
    return correlate


def _endpoints(handle="t"):
    """Insert two endpoints directly; correlate.py doesn't own endpoint CRUD."""
    import coverage
    importlib.reload(coverage)
    coverage.add_endpoints(handle, [
        {"method": "GET", "url": "https://api.acme.test/v1/orders/12", "params": ["order_id"]},
        {"method": "POST", "url": "https://api.acme.test/v1/profile", "params": ["email"]},
    ])
    return [e["id"] for e in coverage.list_endpoints(handle)]


# ---- capture -----------------------------------------------------------------

def test_add_and_list_note(cor):
    nid = cor.add_note("t", "403 body names an internal service")["id"]
    rows = cor.list_notes("t")
    assert any(r["id"] == nid for r in rows)


def test_note_search_by_substring(cor):
    cor.add_note("t", "response leaks hostname internal-billing-01")
    cor.add_note("t", "unrelated observation about pagination")
    assert len(cor.list_notes("t", contains="hostname")) == 1


def test_add_lead_links_notes(cor):
    n1 = cor.add_note("t", "403 body names an internal service")["id"]
    n2 = cor.add_note("t", "Host header is reflected downstream")["id"]
    lid = cor.add_lead("t", "Host header may reach the internal service",
                       confidence="medium", note_ids=[n1, n2])["id"]
    lead = [l for l in cor.list_leads("t") if l["id"] == lid][0]
    assert set(lead["note_ids"]) == {n1, n2}


def test_invalid_confidence_rejected(cor):
    with pytest.raises(ValueError):
        cor.add_lead("t", "something", confidence="very-sure")


def test_add_primitive(cor):
    pid = cor.add_primitive("t", "controllable Host header",
                            "value reaches backend unvalidated")["id"]
    assert any(p["id"] == pid for p in cor.list_primitives("t"))


# ---- Slice 3.2/6.2 finding #13: mission_id cross-linking ----------------------

def test_note_with_mission_id_stored_and_filterable(cor):
    nid = cor.add_note("t", "leaked stack trace on /rest/admin", mission_id=7)["id"]
    cor.add_note("t", "unrelated observation, no mission")
    mission_notes = cor.list_notes("t", mission_id=7)
    assert [r["id"] for r in mission_notes] == [nid]
    assert mission_notes[0]["mission_id"] == 7


def test_note_without_mission_id_still_works(cor):
    """Regression: recording without mission_id must be unaffected."""
    nid = cor.add_note("t", "no mission attached")["id"]
    row = [r for r in cor.list_notes("t") if r["id"] == nid][0]
    assert row["mission_id"] is None


def test_lead_with_mission_and_objective_id_stored_and_filterable(cor):
    lid = cor.add_lead("t", "admin section reachable without auth",
                       mission_id=3, objective_id="juice-shop:adminSectionChallenge")["id"]
    cor.add_lead("t", "unrelated lead, no mission")
    mission_leads = cor.list_leads("t", mission_id=3)
    assert [r["id"] for r in mission_leads] == [lid]
    assert mission_leads[0]["objective_id"] == "juice-shop:adminSectionChallenge"


def test_lead_without_mission_id_still_works(cor):
    """Regression: recording without mission_id/objective_id must be unaffected."""
    lid = cor.add_lead("t", "no mission attached")["id"]
    row = [r for r in cor.list_leads("t") if r["id"] == lid][0]
    assert row["mission_id"] is None
    assert row["objective_id"] is None


def test_primitive_with_mission_id_stored_and_filterable(cor):
    pid = cor.add_primitive("t", "can reach /rest/admin without auth",
                            "confirmed via direct GET", mission_id=9)["id"]
    cor.add_primitive("t", "unrelated primitive, no mission")
    mission_primitives = cor.list_primitives("t", mission_id=9)
    assert [r["id"] for r in mission_primitives] == [pid]
    assert mission_primitives[0]["mission_id"] == 9


def test_primitive_without_mission_id_still_works(cor):
    """Regression: recording without mission_id must be unaffected."""
    pid = cor.add_primitive("t", "no mission attached")["id"]
    row = [r for r in cor.list_primitives("t") if r["id"] == pid][0]
    assert row["mission_id"] is None


def test_lead_status_transitions(cor):
    lid = cor.add_lead("t", "maybe idor")["id"]
    cor.set_lead_status("t", lid, "chasing")
    assert [l for l in cor.list_leads("t") if l["id"] == lid][0]["status"] == "chasing"
    cor.set_lead_status("t", lid, "dead")
    assert cor.list_leads("t", status="dead")


def test_invalid_lead_status_rejected(cor):
    lid = cor.add_lead("t", "x")["id"]
    with pytest.raises(ValueError):
        cor.set_lead_status("t", lid, "probably-fine")


# ---- the finding guard: the most important test in this file -----------------

def test_finding_requires_human_confirmation(cor):
    """The model must not be able to declare a vulnerability real."""
    lid = cor.add_lead("t", "looks like idor")["id"]
    with pytest.raises(ValueError):
        cor.promote_to_finding("t", lid, "IDOR on orders", "high", "body")


def test_finding_requires_human_confirmation_explicit_false(cor):
    lid = cor.add_lead("t", "looks like idor")["id"]
    with pytest.raises(ValueError):
        cor.promote_to_finding("t", lid, "IDOR", "high", "body", human_confirmed=False)


@pytest.mark.parametrize("truthy", [1, "true", "yes", [1], {"a": 1}])
def test_truthy_values_do_not_satisfy_the_guard(cor, truthy):
    """Must be exactly True. A truthy string or 1 slipping through would mean a
    sloppy caller can create findings by accident."""
    lid = cor.add_lead("t", "looks like idor")["id"]
    with pytest.raises(ValueError):
        cor.promote_to_finding("t", lid, "IDOR", "high", "body", human_confirmed=truthy)


def test_promotion_succeeds_with_confirmation(cor):
    lid = cor.add_lead("t", "confirmed idor")["id"]
    out = cor.promote_to_finding("t", lid, "IDOR on /v1/orders", "high",
                                 "steps...", human_confirmed=True)
    assert out.get("id")
    assert cor.list_findings("t")
    assert [l for l in cor.list_leads("t") if l["id"] == lid][0]["status"] == "promoted"


def test_invalid_severity_rejected(cor):
    lid = cor.add_lead("t", "x")["id"]
    with pytest.raises(ValueError):
        cor.promote_to_finding("t", lid, "T", "catastrophic", "b", human_confirmed=True)


# ---- correlation: must under-report, not over-report -------------------------

def test_same_endpoint_pair_ranks_top(cor):
    eids = _endpoints()
    cor.add_note("t", "403 with json error body", endpoint_id=eids[0])
    cor.add_note("t", "ownership check appears missing", endpoint_id=eids[0])
    out = cor.suggest_correlations("t", limit=10)
    assert out, "a shared endpoint is a real signal and must surface"
    assert "same-endpoint" in out[0]["signals"]


def test_why_names_the_concrete_overlap(cor):
    eids = _endpoints()
    cor.add_note("t", "a", endpoint_id=eids[0])
    cor.add_note("t", "b", endpoint_id=eids[0])
    why = cor.suggest_correlations("t", limit=5)[0]["why"]
    assert why and "seem related" not in why.lower()


def test_single_common_word_is_not_a_correlation(cor):
    """The main failure mode. Two notes sharing only an ordinary word must not
    be presented as connected."""
    cor.add_note("t", "the response was slow when loading the dashboard")
    cor.add_note("t", "the response included a footer link")
    assert cor.suggest_correlations("t", limit=10) == []


def test_distinctive_shared_term_does_correlate(cor):
    cor.add_note("t", "error mentions internal-billing-01 hostname")
    cor.add_primitive("t", "can set Host header",
                      "reaches internal-billing-01 hostname unvalidated")
    out = cor.suggest_correlations("t", limit=10)
    assert out, "a distinctive shared term should surface"


def test_dismissed_pair_never_resurfaces(cor):
    eids = _endpoints()
    cor.add_note("t", "x", endpoint_id=eids[0])
    cor.add_note("t", "y", endpoint_id=eids[0])
    first = cor.suggest_correlations("t", limit=10)[0]
    cor.dismiss_correlation("t", first["a_ref"], first["b_ref"], "coincidence")
    after = cor.suggest_correlations("t", limit=10)
    assert not any(r["a_ref"] == first["a_ref"] and r["b_ref"] == first["b_ref"]
                   for r in after)


def test_dismissal_is_order_independent(cor):
    """A-B and B-A are the same pair; dismissing one must dismiss both."""
    eids = _endpoints()
    cor.add_note("t", "x", endpoint_id=eids[0])
    cor.add_note("t", "y", endpoint_id=eids[0])
    first = cor.suggest_correlations("t", limit=10)[0]
    cor.dismiss_correlation("t", first["b_ref"], first["a_ref"], "reversed order")
    after = cor.suggest_correlations("t", limit=10)
    assert not any({r["a_ref"], r["b_ref"]} == {first["a_ref"], first["b_ref"]}
                   for r in after)


def test_item_never_correlates_with_itself(cor):
    cor.add_note("t", "internal-billing-01 hostname appears here")
    out = cor.suggest_correlations("t", limit=10)
    assert all(r["a_ref"] != r["b_ref"] for r in out)


def test_empty_graph_returns_empty(cor):
    assert cor.suggest_correlations("t", limit=10) == []


def test_scores_descend_and_limit_respected(cor):
    eids = _endpoints()
    for i in range(6):
        cor.add_note("t", f"observation {i} about internal-billing-01", endpoint_id=eids[0])
    out = cor.suggest_correlations("t", limit=4)
    assert len(out) == 4
    assert [r["score"] for r in out] == sorted((r["score"] for r in out), reverse=True)
