"""Mission/scoring ledger tests.

Written against the contract independently of the implementation (mirrors
tests/test_coverage.py's style): a mission snapshots a baseline of
already-solved objectives, credit only ever counts NEW solves, credit is
monotonic (a later "unsolved" report can't take back a confirmed win), and a
completed mission's scorecard is frozen.
"""
import importlib
import os

import pytest


@pytest.fixture()
def ms(tmp_path):
    os.environ["BB_DATA_DIR"] = str(tmp_path)
    import db
    importlib.reload(db)
    import mission
    importlib.reload(mission)
    db.init_target_db(db.target_db_path("t"))
    return mission


OBJECTIVES = [
    {"id": "o-easy", "app": "app1", "native_id": "1", "name": "Easy One",
     "category": "misc", "difficulty": 1, "description": "d1"},
    {"id": "o-med", "app": "app1", "native_id": "2", "name": "Medium One",
     "category": "injection", "difficulty": 3, "description": "d2"},
    {"id": "o-hard", "app": "app1", "native_id": "3", "name": "Hard One",
     "category": "injection", "difficulty": 5, "description": "d3"},
]


def _seed(ms):
    return ms.seed_objectives("t", OBJECTIVES)


# ---- objectives ----------------------------------------------------------------

def test_seed_objectives_is_idempotent(ms):
    r1 = _seed(ms)
    assert r1 == {"seeded": 3}
    r2 = _seed(ms)                    # safe to re-run
    assert r2 == {"seeded": 3}
    assert len(ms.list_objectives("t", app="app1")) == 3


def test_list_objectives_filters(ms):
    _seed(ms)
    assert len(ms.list_objectives("t", category="injection")) == 2
    assert len(ms.list_objectives("t", difficulty=1)) == 1
    assert ms.list_objectives("t", app="nope") == []


# ---- mission creation & baseline snapshot ---------------------------------------

def test_create_mission_snapshots_baseline(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://localhost:3000",
                                 baseline=["o-easy"], human_ack=True)
    assert mission["objectives_seeded"] == 3
    objs = ms.list_objectives("t", app="app1", mission_id=mission["id"])
    by_id = {o["id"]: o for o in objs}
    assert by_id["o-easy"]["baseline_solved"] == 1
    assert by_id["o-easy"]["solved"] == 1          # last known true state
    assert by_id["o-med"]["baseline_solved"] == 0
    assert by_id["o-med"]["solved"] == 0


def test_list_objectives_unsolved_only_respects_mission(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=["o-easy"])
    unsolved = ms.list_objectives("t", mission_id=mission["id"], unsolved_only=True)
    assert {o["id"] for o in unsolved} == {"o-med", "o-hard"}


# ---- record_objective_result: evidence requirement + monotonic credit ----------

def test_record_solved_requires_evidence(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    with pytest.raises(ValueError):
        ms.record_objective_result("t", mission["id"], "o-med", solved=True, evidence_id=None)


def test_record_solved_with_evidence_succeeds(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    r = ms.record_objective_result("t", mission["id"], "o-med", solved=True, evidence_id=10)
    assert r["solved"] is True and r["refused_downgrade"] is False
    assert r["polls"] == 1


def test_downgrade_after_solve_is_refused_credit_kept(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    ms.record_objective_result("t", mission["id"], "o-med", solved=True, evidence_id=10)
    r = ms.record_objective_result("t", mission["id"], "o-med", solved=False, evidence_id=None)
    assert r["refused_downgrade"] is True
    assert r["solved"] is True, "credit must be kept, not reverted"


def test_baseline_solved_downgrade_also_refused(ms):
    """A baseline-solved objective starts solved=1 too (it's the last known
    true state) — attempting to unsolve it must be refused the same way."""
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=["o-easy"])
    r = ms.record_objective_result("t", mission["id"], "o-easy", solved=False, evidence_id=None)
    assert r["refused_downgrade"] is True
    assert r["solved"] is True


def test_polls_increments_across_calls(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    ms.record_objective_result("t", mission["id"], "o-hard", solved=False)
    r = ms.record_objective_result("t", mission["id"], "o-hard", solved=False)
    assert r["polls"] == 2


# ---- log_attempt: seq assignment + attempt cap ----------------------------------

def test_log_attempt_assigns_increasing_seq(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    a1 = ms.log_attempt("t", mission["id"], phase="recon", action_summary="poked around")
    a2 = ms.log_attempt("t", mission["id"], phase="exploit", action_summary="tried sqli")
    assert a2["seq"] == a1["seq"] + 1


def test_attempt_cap_flips_over_cap_after_five(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    results = [
        ms.log_attempt("t", mission["id"], phase="exploit", action_summary=f"try {i}",
                        objective_id="o-hard")
        for i in range(6)
    ]
    for r in results[:5]:
        assert r["over_cap"] is False
    assert results[4]["attempts_remaining"] == 0
    assert results[5]["over_cap"] is True
    assert results[5]["attempts_used"] == 6


def test_attempt_cap_is_per_objective(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    for _ in range(5):
        ms.log_attempt("t", mission["id"], phase="exploit", action_summary="x",
                        objective_id="o-hard")
    fresh = ms.log_attempt("t", mission["id"], phase="exploit", action_summary="y",
                            objective_id="o-med")
    assert fresh["over_cap"] is False and fresh["attempts_used"] == 1


def test_log_attempt_without_objective_has_no_cap(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    r = ms.log_attempt("t", mission["id"], phase="recon", action_summary="mapping surface")
    assert r["over_cap"] is False
    assert r["attempts_remaining"] is None


def test_mission_log_filters(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    ms.log_attempt("t", mission["id"], phase="recon", action_summary="a", objective_id="o-med")
    ms.log_attempt("t", mission["id"], phase="exploit", action_summary="b", objective_id="o-hard")
    log = ms.mission_log("t", mission["id"], objective_id="o-med")
    assert len(log) == 1 and log[0]["phase"] == "recon"


# ---- scorecard --------------------------------------------------------------------

def test_scorecard_excludes_baseline_and_matches_points_table(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=["o-easy"])
    ms.record_objective_result("t", mission["id"], "o-med", solved=True, evidence_id=1)
    card = ms.compute_scorecard("t", mission["id"])
    assert card["total"] == 3
    assert card["solved"] == 2                      # o-easy (baseline) + o-med
    expected_earned = ms.POINTS_BY_DIFFICULTY[3]     # only o-med is credited
    assert card["points_earned"] == expected_earned
    expected_total = (ms.POINTS_BY_DIFFICULTY[1] + ms.POINTS_BY_DIFFICULTY[3]
                       + ms.POINTS_BY_DIFFICULTY[5])
    assert card["points_total"] == expected_total
    assert card["by_category"]["injection"]["points_earned"] == expected_earned


def test_scorecard_grade_bands(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    # Solve every objective -> 100% -> grade A.
    ms.record_objective_result("t", mission["id"], "o-easy", solved=True, evidence_id=1)
    ms.record_objective_result("t", mission["id"], "o-med", solved=True, evidence_id=2)
    ms.record_objective_result("t", mission["id"], "o-hard", solved=True, evidence_id=3)
    card = ms.compute_scorecard("t", mission["id"])
    assert card["percent"] == 100.0
    assert card["grade"] == "A"


def test_scorecard_on_empty_mission_is_grade_d_not_error(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    card = ms.compute_scorecard("t", mission["id"])
    assert card["grade"] == "D"
    assert card["percent"] == 0.0


# ---- record_objective_result: immutable after mission completion (finding #6) -----

def test_record_objective_result_refused_after_mission_completed(ms):
    """MEDIUM (finding #6): once a mission is completed, record_objective_result
    must refuse (and change nothing) unless force=True. This matters beyond the
    frozen scorecard number: assemble_after_action_report reads
    mission_objective_result LIVE, so a late-arriving "solve" recorded after
    complete_mission would otherwise silently change the after-action report's
    Solved Objectives list even though the score itself stayed frozen."""
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    ms.complete_mission("t", mission["id"])

    result = ms.record_objective_result("t", mission["id"], "o-hard", solved=True, evidence_id=1)
    assert result["refused"] == "mission completed"

    report = ms.assemble_after_action_report("t", mission["id"])
    solved_section = report["markdown"].split("## Solved Objectives")[1].split("## Missed Objectives")[0]
    assert "o-hard" not in solved_section, "a refused post-completion solve must not appear as solved"
    missed_section = report["markdown"].split("## Missed Objectives")[1]
    assert "o-hard" in missed_section

    # force=True explicitly bypasses the refusal
    forced = ms.record_objective_result("t", mission["id"], "o-hard", solved=True,
                                         evidence_id=1, force=True)
    assert forced.get("refused") is None
    assert forced["solved"] is True


# ---- complete_mission: freeze once ------------------------------------------------

def test_complete_mission_freezes_scorecard(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    ms.record_objective_result("t", mission["id"], "o-med", solved=True, evidence_id=1)
    done = ms.complete_mission("t", mission["id"])
    assert done["already_completed"] is False
    frozen_points = done["scorecard"]["points_earned"]
    assert frozen_points == ms.POINTS_BY_DIFFICULTY[3]

    # A later result must NOT change the frozen scorecard -- and (finding #6:
    # a completed mission's rows are immutable) is refused outright unless
    # record_objective_result's OWN force=True is passed too.
    refused = ms.record_objective_result("t", mission["id"], "o-hard", solved=True, evidence_id=2)
    assert refused.get("refused") == "mission completed"
    served = ms.mission_scorecard("t", mission["id"])
    assert served["points_earned"] == frozen_points, "completed scorecard must stay frozen"

    # ...unless BOTH record_objective_result(force=True) records the new
    # solve AND complete_mission(force=True) explicitly recomputes from it.
    ms.record_objective_result("t", mission["id"], "o-hard", solved=True, evidence_id=2, force=True)
    redone = ms.complete_mission("t", mission["id"], force=True)
    assert redone["already_completed"] is False
    assert redone["scorecard"]["points_earned"] == frozen_points + ms.POINTS_BY_DIFFICULTY[5]
    served_after_force = ms.mission_scorecard("t", mission["id"])
    assert served_after_force["points_earned"] == frozen_points + ms.POINTS_BY_DIFFICULTY[5]


def test_complete_mission_twice_without_force_returns_frozen(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    first = ms.complete_mission("t", mission["id"])
    again = ms.complete_mission("t", mission["id"])
    assert again["already_completed"] is True
    assert again["scorecard"] == first["scorecard"]


def test_complete_mission_sets_duration(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[],
                                 started_at="2026-01-01T00:00:00+00:00")
    done = ms.complete_mission("t", mission["id"], ended_at="2026-01-01T00:10:00+00:00")
    assert done["duration_seconds"] == 600


def test_mission_scorecard_running_mission_computes_live(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    ms.record_objective_result("t", mission["id"], "o-easy", solved=True, evidence_id=1)
    live = ms.mission_scorecard("t", mission["id"])
    assert live["points_earned"] == ms.POINTS_BY_DIFFICULTY[1]


def test_complete_mission_unknown_id_raises(ms):
    _seed(ms)
    with pytest.raises(ValueError):
        ms.complete_mission("t", 99999)


# ---- list_missions -----------------------------------------------------------------

def test_list_missions_filters_by_status(ms):
    _seed(ms)
    m1 = ms.create_mission("t", "app1", "http://x", baseline=[])
    m2 = ms.create_mission("t", "app1", "http://x", baseline=[])
    ms.complete_mission("t", m1["id"])
    running = ms.list_missions("t", status="running")
    completed = ms.list_missions("t", status="completed")
    assert {m["id"] for m in running} == {m2["id"]}
    assert {m["id"] for m in completed} == {m1["id"]}


# ---- result_solved -----------------------------------------------------------------

def test_result_solved_false_until_recorded(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    assert ms.result_solved("t", mission["id"], "o-med") is False
    ms.record_objective_result("t", mission["id"], "o-med", solved=True, evidence_id=10)
    assert ms.result_solved("t", mission["id"], "o-med") is True


def test_result_solved_true_for_baseline_solved(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=["o-easy"])
    assert ms.result_solved("t", mission["id"], "o-easy") is True


def test_result_solved_missing_target_or_mission_is_false_not_error(ms):
    assert ms.result_solved("no-such-target", 1, "o-easy") is False
    _seed(ms)
    assert ms.result_solved("t", 99999, "o-easy") is False


# ---- assemble_after_action_report ---------------------------------------------------

def test_after_action_report_has_required_sections_and_gap_markers(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=["o-easy"])
    # o-easy is solved via the baseline snapshot only -> solved=1 but no
    # evidence_id and no mission_attempt rows logged at all.
    report = ms.assemble_after_action_report("t", mission["id"])
    md = report["markdown"]
    for heading in ("## Mission", "## Scorecard", "## Solved Objectives",
                    "## Missed Objectives", "## Timeline", "## What to Learn Next"):
        assert heading in md, f"missing section: {heading}"
    assert "[NO DATA" in md
    assert any("evidence" in g.lower() for g in report["gaps"]), report["gaps"]
    assert any("timeline" in g.lower() for g in report["gaps"]), report["gaps"]
    assert report["scorecard"]["total"] == 3


def test_after_action_report_unknown_mission_raises(ms):
    _seed(ms)
    with pytest.raises(ValueError):
        ms.assemble_after_action_report("t", 99999)


def test_after_action_report_unknown_handle_raises(ms):
    with pytest.raises(ValueError):
        ms.assemble_after_action_report("no-such-target", 1)


def test_after_action_report_learn_next_uses_wstg_hint(ms):
    ms.seed_objectives("t", [
        {"id": "o-hint", "app": "app2", "native_id": "1", "name": "Hinted Objective",
         "category": "injection", "difficulty": 3, "description": "d",
         "wstg_category_hint": "pb-sql-injection"},
    ])
    mission = ms.create_mission("t", "app2", "http://x", baseline=[])
    report = ms.assemble_after_action_report("t", mission["id"])
    assert "pb-sql-injection" in report["markdown"]
    assert "Hinted Objective" in report["markdown"]


def test_after_action_report_no_gap_when_fully_solved_and_evidenced(ms):
    _seed(ms)
    mission = ms.create_mission("t", "app1", "http://x", baseline=[])
    ms.record_objective_result("t", mission["id"], "o-easy", solved=True, evidence_id=1)
    ms.record_objective_result("t", mission["id"], "o-med", solved=True, evidence_id=2)
    ms.record_objective_result("t", mission["id"], "o-hard", solved=True, evidence_id=3)
    ms.log_attempt("t", mission["id"], phase="exploit", action_summary="did it",
                    objective_id="o-easy")
    report = ms.assemble_after_action_report("t", mission["id"])
    assert report["gaps"] == []
    assert "[NO DATA" not in report["markdown"]
    assert "every catalogued objective was solved" in report["markdown"]


# ---- sandbox_audit round trip -------------------------------------------------------

def test_log_sandbox_decision_round_trip(ms):
    import db
    r = ms.log_sandbox_decision("t", "Bash", "allow", "localhost", 3000,
                                 "in-sandbox host+port", "curl localhost:3000/api/x")
    assert r["decision"] == "allow"
    conn = db.connect(db.target_db_path("t"))
    try:
        row = conn.execute("SELECT * FROM sandbox_audit WHERE id=?", (r["id"],)).fetchone()
    finally:
        conn.close()
    assert row["tool_name"] == "Bash"
    assert row["host"] == "localhost"
    assert row["port"] == 3000
    assert row["command_excerpt"] == "curl localhost:3000/api/x"
