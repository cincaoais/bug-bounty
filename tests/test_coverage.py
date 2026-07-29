"""Coverage ledger tests — the core feature.

Written against the contract independently of the implementation, so these
verify the ledger actually behaves, not that it matches whatever got written.

The ledger is what makes the system worth building: it answers "what have I
already tested on this target, and what haven't I" across sessions.
"""
import importlib
import os
import tempfile

import pytest


@pytest.fixture()
def cov(tmp_path):
    os.environ["BB_DATA_DIR"] = str(tmp_path)
    import db
    importlib.reload(db)
    import coverage
    importlib.reload(coverage)
    db.init_target_db(db.target_db_path("t"))
    return coverage


CASES = [
    {"id": "T1-IDOR", "category": "Authorization", "title": "IDOR on object id",
     "tier": 1, "applies_to": ["id-param", "numeric-id-path"]},
    {"id": "T1-AUTHZ", "category": "Authorization", "title": "Vertical authz bypass",
     "tier": 1, "applies_to": ["authed", "admin-path"]},
    {"id": "T2-XSS", "category": "Input Validation", "title": "Reflected XSS",
     "tier": 2, "applies_to": ["has-params"]},
    {"id": "T2-ANY", "category": "Configuration", "title": "Security headers",
     "tier": 2, "applies_to": ["any"]},
]

ENDPOINTS = [
    {"method": "GET", "url": "https://api.acme.com/v1/orders/123", "params": ["order_id"]},
    {"method": "POST", "url": "https://acme.com/admin/users", "params": ["role"],
     "auth_hint": "session"},
    {"method": "GET", "url": "https://acme.com/about", "params": []},
]


def _seed(cov):
    cov.seed_test_cases("t", CASES)
    cov.add_endpoints("t", ENDPOINTS)


# ---- endpoints ---------------------------------------------------------------

def test_add_endpoints_inserts_and_dedupes(cov):
    r1 = cov.add_endpoints("t", ENDPOINTS)
    assert r1["inserted"] == 3
    r2 = cov.add_endpoints("t", ENDPOINTS)          # same set again
    assert r2["inserted"] == 0 and r2["skipped"] == 3


def test_add_endpoints_derives_host_and_path(cov):
    cov.add_endpoints("t", [{"method": "GET", "url": "https://api.acme.com/v1/x?a=1"}])
    rows = cov.list_endpoints("t")
    assert rows[0]["host"] == "api.acme.com"
    assert rows[0]["path"].startswith("/v1/x")


def test_list_endpoints_filters(cov):
    _seed(cov)
    assert len(cov.list_endpoints("t", method="POST")) == 1
    assert len(cov.list_endpoints("t", has_params=True)) == 2
    assert len(cov.list_endpoints("t", host="api.acme.com")) == 1


# ---- coverage recording ------------------------------------------------------

def test_record_coverage_and_upsert(cov):
    _seed(cov)
    eid = cov.list_endpoints("t")[0]["id"]
    cov.record_coverage("t", eid, "T1-IDOR", "testing")
    cov.record_coverage("t", eid, "T1-IDOR", "not-vulnerable", note="checked both roles")
    s = cov.coverage_summary("t")
    assert s["tested_pairs"] == 1                    # upsert, not duplicate
    assert s["by_status"].get("not-vulnerable") == 1


def test_invalid_status_rejected(cov):
    _seed(cov)
    eid = cov.list_endpoints("t")[0]["id"]
    with pytest.raises(ValueError):
        cov.record_coverage("t", eid, "T1-IDOR", "probably-fine")


def test_untested_only_excludes_covered(cov):
    _seed(cov)
    eid = cov.list_endpoints("t")[0]["id"]
    before = len(cov.list_endpoints("t", untested_only=True))
    cov.record_coverage("t", eid, "T1-IDOR", "not-vulnerable")
    after = len(cov.list_endpoints("t", untested_only=True))
    assert after == before - 1


# ---- summary -----------------------------------------------------------------

def test_coverage_summary_shape(cov):
    _seed(cov)
    s = cov.coverage_summary("t")
    assert s["endpoints"] == 3 and s["test_cases"] == 4
    assert s["tested_pairs"] == 0 and s["percent_tested"] == 0.0
    assert s["untouched_endpoints"] == 3
    assert isinstance(s["by_category"], list)


def test_summary_percent_moves_with_coverage(cov):
    _seed(cov)
    eid = cov.list_endpoints("t")[0]["id"]
    cov.record_coverage("t", eid, "T1-IDOR", "confirmed")
    s = cov.coverage_summary("t")
    assert s["tested_pairs"] == 1
    assert s["percent_tested"] > 0
    assert s["untouched_endpoints"] == 2


# ---- next_actions: THE core feature ------------------------------------------

def test_next_actions_non_empty_and_shaped(cov):
    _seed(cov)
    acts = cov.next_actions("t", limit=10)
    assert acts, "next_actions must return suggestions on a seeded target"
    a = acts[0]
    for k in ("endpoint_id", "method", "url", "test_case_id", "title",
              "category", "tier", "score", "why"):
        assert k in a, f"missing key {k}"
    assert isinstance(a["why"], str) and a["why"]


def test_next_actions_respects_limit(cov):
    _seed(cov)
    assert len(cov.next_actions("t", limit=2)) == 2


def test_next_actions_excludes_already_tested(cov):
    _seed(cov)
    top = cov.next_actions("t", limit=1)[0]
    cov.record_coverage("t", top["endpoint_id"], top["test_case_id"], "not-vulnerable")
    again = cov.next_actions("t", limit=50)
    assert not any(x["endpoint_id"] == top["endpoint_id"]
                   and x["test_case_id"] == top["test_case_id"] for x in again)


def test_next_actions_applicability_filter(cov):
    """A test case must not be suggested for an endpoint it doesn't apply to."""
    _seed(cov)
    acts = cov.next_actions("t", limit=100)
    about = [e for e in cov.list_endpoints("t") if e["path"] == "/about"][0]
    for a in acts:
        if a["endpoint_id"] == about["id"]:
            # /about has no params, no auth, not admin -> only the "any" case applies
            assert a["test_case_id"] == "T2-ANY", f"irrelevant suggestion: {a['test_case_id']}"


def test_next_actions_ranks_tier1_id_param_first(cov):
    _seed(cov)
    top = cov.next_actions("t", limit=5)[0]
    assert top["tier"] == 1, "tier-1 work should outrank tier-2"


def test_next_actions_scores_descend(cov):
    _seed(cov)
    scores = [a["score"] for a in cov.next_actions("t", limit=50)]
    assert scores == sorted(scores, reverse=True)


def test_next_actions_empty_target_is_empty_not_error(cov):
    assert cov.next_actions("t", limit=10) == []


# ---- session activity: the retrospective must read the ledger, not memory ----

def test_quiet_session_reported_as_quiet(cov):
    """A session that did nothing must read as nothing. Inflating it corrupts the
    record the next session depends on."""
    act = cov.session_activity("t", since_hours=24)
    assert act["quiet_session"] is True
    assert act["coverage_records"] == []


def test_session_activity_reports_what_was_tested(cov):
    _seed(cov)
    eid = cov.list_endpoints("t")[0]["id"]
    cov.record_coverage("t", eid, "T1-IDOR", "not-vulnerable", note="checked both roles")
    act = cov.session_activity("t", since_hours=24)
    assert act["quiet_session"] is False
    rec = act["coverage_records"][0]
    assert rec["test_case_id"] == "T1-IDOR" and rec["status"] == "not-vulnerable"
    assert rec["url"], "activity should join through to the endpoint url"


def test_open_threads_surface_regardless_of_age(cov):
    """Suspicious results and open leads are what next session starts from, even
    if they are older than the activity window."""
    _seed(cov)
    eid = cov.list_endpoints("t")[0]["id"]
    cov.record_coverage("t", eid, "T1-IDOR", "suspicious", note="odd 403 body")
    act = cov.session_activity("t", since_hours=1)
    assert act["open_suspicious"], "suspicious threads must always surface"


def test_closed_work_is_not_an_open_thread(cov):
    _seed(cov)
    eid = cov.list_endpoints("t")[0]["id"]
    cov.record_coverage("t", eid, "T1-IDOR", "not-vulnerable")
    act = cov.session_activity("t", since_hours=24)
    assert not act["open_suspicious"]


def test_session_activity_on_unknown_target_is_empty_not_error(cov):
    act = cov.session_activity("never-created", since_hours=24)
    assert act["coverage_records"] == [] and act["endpoints_added"] == 0


# ---- 'suspicious' must resurface (regression: it used to vanish forever) -----

def test_suspicious_pair_resurfaces(cov):
    """A suspicious result means 'something looked off here' — it is an unfinished
    lead, not a closed test. If it stops being suggested, the user silently loses
    their best leads. Closed statuses must still disappear."""
    _seed(cov)
    top = cov.next_actions("t", limit=1)[0]
    cov.record_coverage("t", top["endpoint_id"], top["test_case_id"], "suspicious",
                        note="403 body leaked an internal hostname")
    again = cov.next_actions("t", limit=50)
    match = [x for x in again
             if x["endpoint_id"] == top["endpoint_id"]
             and x["test_case_id"] == top["test_case_id"]]
    assert match, "suspicious pair must stay in the ranking"
    assert "SUSPICIOUS" in match[0]["why"].upper()


def test_suspicious_ranks_above_its_untouched_self(cov):
    _seed(cov)
    before = cov.next_actions("t", limit=50)
    target = before[-1]                                  # something low-ranked
    cov.record_coverage("t", target["endpoint_id"], target["test_case_id"], "suspicious")
    after = cov.next_actions("t", limit=50)
    now = [x for x in after if x["endpoint_id"] == target["endpoint_id"]
           and x["test_case_id"] == target["test_case_id"]][0]
    assert now["score"] > target["score"], "suspicious must raise the score, not lower it"


# ---- host-level vs endpoint-level, and result diversity ----------------------

HOST_CASES = CASES + [
    {"id": "H-TLS", "category": "Cryptography", "title": "Review TLS configuration",
     "tier": 2, "applies_to": ["any"], "scope_level": "host"},
    {"id": "H-GIT", "category": "Configuration", "title": "Check for exposed .git",
     "tier": 1, "applies_to": ["any"], "scope_level": "host"},
]


def test_host_level_case_suggested_once_per_host(cov):
    """A host-level test is done once for the site. Emitting it per endpoint is
    noise and inflates the coverage math."""
    cov.seed_test_cases("t", HOST_CASES)
    cov.add_endpoints("t", ENDPOINTS)          # 2 on acme.com, 1 on api.acme.com
    acts = cov.next_actions("t", limit=500, per_endpoint=0)
    for case_id in ("H-TLS", "H-GIT"):
        hits = [a for a in acts if a["test_case_id"] == case_id]
        hosts = {a["url"].split("/")[2] for a in hits}
        assert len(hits) == len(hosts), f"{case_id} emitted more than once per host"
        assert hits, f"{case_id} never emitted"


def test_host_level_marked_in_output(cov):
    cov.seed_test_cases("t", HOST_CASES)
    cov.add_endpoints("t", ENDPOINTS)
    acts = cov.next_actions("t", limit=500, per_endpoint=0)
    tls = [a for a in acts if a["test_case_id"] == "H-TLS"][0]
    assert tls["scope_level"] == "host"
    assert "host-level" in tls["why"]


# ---- flow-specific tests must not spray across unrelated endpoints -----------

FLOW_CASES = [
    {"id": "F-2FA", "category": "Authentication", "title": "2FA bypass",
     "tier": 1, "applies_to": ["authed", "write-method"], "scope_level": "endpoint",
     "path_hint": "2fa|mfa|otp|two-factor"},
    {"id": "F-RESET", "category": "Authentication", "title": "Password reset token reuse",
     "tier": 1, "applies_to": ["has-params"], "scope_level": "endpoint",
     "path_hint": "reset|forgot|recover"},
    {"id": "F-IDOR", "category": "Authorization", "title": "IDOR on object id",
     "tier": 1, "applies_to": ["id-param"], "scope_level": "endpoint"},
]

FLOW_ENDPOINTS = [
    {"method": "POST", "url": "https://acme.com/admin/users", "params": ["role"],
     "auth_hint": "session"},
    {"method": "POST", "url": "https://acme.com/account/2fa/verify", "params": ["code"],
     "auth_hint": "session"},
    {"method": "POST", "url": "https://acme.com/password/reset", "params": ["token"]},
]


def test_flow_test_only_matches_its_flow(cov):
    """A 2FA-bypass test must not be suggested for POST /admin/users. Confident
    nonsense is worse than no suggestion for someone learning the patterns."""
    cov.seed_test_cases("t", FLOW_CASES)
    cov.add_endpoints("t", FLOW_ENDPOINTS)
    acts = cov.next_actions("t", limit=500, per_endpoint=0)
    by_id = {e["path"]: e["id"] for e in cov.list_endpoints("t")}

    twofa = [a for a in acts if a["test_case_id"] == "F-2FA"]
    assert twofa, "2FA test never suggested anywhere"
    assert {a["endpoint_id"] for a in twofa} == {by_id["/account/2fa/verify"]}

    reset = [a for a in acts if a["test_case_id"] == "F-RESET"]
    assert {a["endpoint_id"] for a in reset} == {by_id["/password/reset"]}


def test_unhinted_test_still_matches_by_shape(cov):
    """Shape-driven tests must keep working — path_hint is opt-in, not required."""
    cov.seed_test_cases("t", FLOW_CASES)
    cov.add_endpoints("t", [{"method": "GET", "url": "https://acme.com/v1/orders/9",
                             "params": ["order_id"]}])
    acts = cov.next_actions("t", limit=50, per_endpoint=0)
    assert any(a["test_case_id"] == "F-IDOR" for a in acts)


def test_bad_path_hint_regex_rejected(cov):
    with pytest.raises(ValueError):
        cov.seed_test_cases("t", [{"id": "BAD", "category": "c", "title": "t", "tier": 1,
                                   "applies_to": ["any"], "scope_level": "endpoint",
                                   "path_hint": "("}])


def test_seed_rejects_bad_scope_level(cov):
    with pytest.raises(ValueError):
        cov.seed_test_cases("t", [{"id": "X", "category": "c", "title": "t",
                                   "tier": 1, "applies_to": ["any"],
                                   "scope_level": "galaxy"}])


def test_results_spread_across_endpoints(cov):
    """Without a per-endpoint cap the list clumps on the single juiciest endpoint
    and hides the rest of the surface. Uses a realistically-sized taxonomy so the
    cap can hold without needing the overflow fill."""
    many = CASES + [
        {"id": f"T-GEN{i}", "category": "Input Validation", "title": f"generic {i}",
         "tier": 2, "applies_to": ["has-params"], "scope_level": "endpoint"}
        for i in range(12)
    ]
    cov.seed_test_cases("t", many)
    cov.add_endpoints("t", ENDPOINTS)
    # limit 4 with cap 2: the two param-bearing endpoints can supply this without
    # overflow, so the cap is genuinely under test here.
    acts = cov.next_actions("t", limit=4, per_endpoint=2)
    counts = {}
    for a in acts:
        counts[a["endpoint_id"]] = counts.get(a["endpoint_id"], 0) + 1
    assert max(counts.values()) <= 2, f"clumped: {counts}"
    assert len(counts) > 1, "all suggestions landed on one endpoint"


def test_spread_overflow_fills_rather_than_starving(cov):
    """When there genuinely aren't enough diverse options, a slightly clumped
    full list beats a short 'clean' one. Overflow fill is deliberate."""
    cov.seed_test_cases("t", CASES)
    cov.add_endpoints("t", [ENDPOINTS[0]])
    acts = cov.next_actions("t", limit=3, per_endpoint=1)
    assert len(acts) == 3, "cap should overflow-fill rather than return a short list"


def test_per_endpoint_zero_disables_cap(cov):
    _seed(cov)
    acts = cov.next_actions("t", limit=100, per_endpoint=0)
    assert len(acts) == len(cov.next_actions("t", limit=100, per_endpoint=0))
    assert acts == sorted(acts, key=lambda r: (-r["score"], r["endpoint_id"], r["test_case_id"]))


@pytest.mark.parametrize("closed", ["not-vulnerable", "confirmed", "n-a", "testing"])
def test_closed_statuses_do_not_resurface(cov, closed):
    _seed(cov)
    top = cov.next_actions("t", limit=1)[0]
    cov.record_coverage("t", top["endpoint_id"], top["test_case_id"], closed)
    again = cov.next_actions("t", limit=50)
    assert not any(x["endpoint_id"] == top["endpoint_id"]
                   and x["test_case_id"] == top["test_case_id"] for x in again)
