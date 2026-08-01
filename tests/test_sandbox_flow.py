"""Integration test for Slice 4.1's test gate: a MOCKED, end-to-end sandbox
mission lifecycle driven through the same MCP tool wrappers the bb-sandbox
skill calls (plugin/skills/bb-sandbox/SKILL.md). Fully offline -- no
network, no live Juice Shop/WebGoat, no Docker; every "poll the app's own
state" step is a hand-supplied evidence string standing in for the real
HTTP response the skill would have fetched.

Mirrors tests/test_server_smoke.py's tmp-dir + module-reload pattern
(`_reload_with_tmp`) and tests/test_mission.py's mission/scoring contract
(baseline snapshot, monotonic evidence-gated credit, frozen scorecard).
"""
import importlib
import json
import os
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="mcp SDK not installed")

REPO_ROOT = Path(__file__).resolve().parent.parent
REFERENCE_DIR = REPO_ROOT / "plugin" / "reference"
SKILL_DIR = REPO_ROOT / "plugin" / "skills" / "bb-sandbox"

JUICESHOP_CATALOG = json.loads(
    (REFERENCE_DIR / "juiceshop-challenges.json").read_text(encoding="utf-8")
)


def _reload_with_tmp(tmp):
    os.environ["BB_DATA_DIR"] = tmp
    import db, registry, server
    importlib.reload(db)
    importlib.reload(registry)
    importlib.reload(server)
    return server


# ---- the mocked mission lifecycle (steps 1-9 of the skill's run loop) ----------

def test_sandbox_mission_end_to_end_flow():
    """Walks the skill's own phases (preflight target/scope/catalog -> baseline
    mission -> hunt loop recording solves+attempts -> score -> freeze -> report
    -> preflight) against a temp store, with no traffic ever leaving the
    process."""
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)
        import mission as mission_mod

        handle = "juiceshop"

        # ---- 1. target + allow-list (SKILL.md Phase 0 step 4) ----
        created = server.create_target(handle, mode="sandbox", sandbox_app="juice-shop")
        assert created["mode"] == "sandbox" and created["sandbox_app"] == "juice-shop"
        rules_set = server.set_scope_rules(handle, [
            {"pattern": "127.0.0.1:3000", "in_scope": True},
            {"pattern": "localhost:3000", "in_scope": True},
            {"pattern": "[::1]:3000", "in_scope": True},
        ])
        assert rules_set["rules_set"] == 3

        # ---- 2. seed the REAL bundled catalog (SKILL.md Phase 0 step 5) ----
        assert len(JUICESHOP_CATALOG) > 100, "catalog fixture itself is suspiciously small"
        seeded = server.seed_objectives(handle, "juice-shop")
        assert "error" not in seeded, seeded
        assert seeded["seeded"] > 100, seeded

        # ---- 3. baseline poll + mission creation (SKILL.md Phase 0 step 6) ----
        baseline_entries = JUICESHOP_CATALOG[0:2]
        baseline_ids = [o["id"] for o in baseline_entries]
        m = server.create_sandbox_mission(handle, base_url="http://localhost:3000",
                                          human_ack=True, baseline=baseline_ids)
        assert "error" not in m, m
        assert m["status"] == "running"
        assert m["app"] == "juice-shop"
        mission_id = m["id"]
        assert isinstance(mission_id, int)

        # ---- 4. solve 3 OTHER objectives, each backed by stored evidence ----
        solved_entries = JUICESHOP_CATALOG[2:5]
        solved_ids = [o["id"] for o in solved_entries]
        for entry in solved_entries:
            ev = server.store_evidence(
                handle, "response",
                content=f"GET /api/Challenges shows {entry['native_id']} \"solved\":true",
            )
            result = server.record_objective_result(handle, mission_id, entry["id"], True,
                                                     evidence_id=ev["id"])
            assert result["solved"] is True
            assert result["refused_downgrade"] is False
            assert result["evidence_id"] == ev["id"]

        # a solve WITHOUT evidence_id must be rejected, not silently recorded
        with pytest.raises(ValueError):
            server.record_objective_result(handle, mission_id, JUICESHOP_CATALOG[5]["id"], True,
                                           evidence_id=None)

        # ---- 5. attempt cap: 6 attempts against ONE objective (cap=5) ----
        cap_target = JUICESHOP_CATALOG[6]["id"]
        attempts = [
            server.log_attempt(handle, mission_id, phase="exploit",
                               action_summary=f"payload variant {i}",
                               reasoning_md="probing the same objective repeatedly",
                               objective_id=cap_target, tool_used="curl", outcome="fail")
            for i in range(6)
        ]
        for a in attempts[:5]:
            assert a["over_cap"] is False
        assert attempts[4]["attempts_used"] == 5
        assert attempts[4]["attempts_remaining"] == 0
        assert attempts[5]["attempts_used"] == 6
        assert attempts[5]["over_cap"] is True, "6th attempt on one objective must trip the cap"

        # ---- 6. live scorecard: baseline NOT credited, the 3 new solves ARE ----
        card = server.mission_scorecard(handle, mission_id)
        expected_earned = sum(
            mission_mod.POINTS_BY_DIFFICULTY[int(e["difficulty"])] for e in solved_entries
        )
        assert card["points_earned"] == expected_earned, card
        # `solved` counts baseline + new (both are, in fact, solved); credited
        # (points-bearing) count must be only the 3 new ones -- by_difficulty's
        # per-bucket "solved" is only incremented for credited rows.
        assert card["solved"] == len(baseline_ids) + len(solved_ids)
        credited_count = sum(v["solved"] for v in card["by_difficulty"].values())
        assert credited_count == len(solved_ids), card["by_difficulty"]

        # ---- 7. complete_mission freezes the scorecard exactly once ----
        done = server.complete_mission(handle, mission_id)
        assert done["already_completed"] is False
        frozen_points = done["scorecard"]["points_earned"]
        assert frozen_points == expected_earned

        # a LATER record_objective_result must not move the frozen scorecard
        extra_entry = JUICESHOP_CATALOG[7]
        ev_extra = server.store_evidence(handle, "response",
                                         content=f"{extra_entry['native_id']} \"solved\":true")
        server.record_objective_result(handle, mission_id, extra_entry["id"], True,
                                       evidence_id=ev_extra["id"])
        served = server.mission_scorecard(handle, mission_id)
        assert served["points_earned"] == frozen_points, "completed scorecard must stay frozen"

        # ---- 8. after-action report: required sections + solved/missed content ----
        report = server.assemble_after_action_report(handle, mission_id)
        md = report["markdown"]
        for heading in ("## Mission", "## Scorecard", "## Solved Objectives",
                        "## Missed Objectives", "## Timeline", "## What to Learn Next"):
            assert heading in md, f"missing required section: {heading}"
        for oid in solved_ids:
            assert f"`{oid}`" in md, f"solved objective {oid} not named in the report"
        touched_ids = set(baseline_ids) | set(solved_ids) | {extra_entry["id"]}
        missed_ids = [o["id"] for o in JUICESHOP_CATALOG if o["id"] not in touched_ids]
        assert missed_ids, "catalog too small to have any missed objectives"
        assert f"`{missed_ids[0]}`" in md, "no missed objective named in the report"

        # ---- 9. sandbox_preflight: fail on a bounty target, pass once isolation confirmed ----
        server.create_target("acme-bounty", "hackerone", "public")   # switches active target
        bounty_check = server.sandbox_preflight()
        by_name = {c["name"]: c for c in bounty_check["checks"]}
        assert by_name["active_target_sandbox"]["status"] == "fail"
        assert bounty_check["ready"] is False

        server.switch_target(handle)   # back to the sandbox target + its allow-list
        ready_check = server.sandbox_preflight(network_mode="internal",
                                               port_bindings="127.0.0.1:3000->3000/tcp",
                                               egress_test="EGRESS_BLOCKED")
        by_name = {c["name"]: c for c in ready_check["checks"]}
        assert by_name["active_target_sandbox"]["status"] == "pass"
        assert by_name["allow_list_rules"]["status"] == "pass"
        assert by_name["network_isolation_verified"]["status"] == "pass"
        assert ready_check["ready"] is True


# ---- referenced-file existence (Slice 4.2 / 5.1 test gate) ---------------------

def test_bb_sandbox_reference_files_exist_and_are_nonempty():
    for name in ("SKILL.md", "juiceshop.md", "webgoat.md"):
        p = SKILL_DIR / name
        assert p.exists(), f"missing referenced file: {p}"
        assert p.stat().st_size > 0, f"referenced file is empty: {p}"
