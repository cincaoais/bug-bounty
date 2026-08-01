"""Smoke test: the MCP server imports, its tools are registered, and they work
end-to-end against a temp store. Guards against 'server won't boot' regressions
without needing a live MCP client.
"""
import os
import tempfile
import importlib

import pytest

pytest.importorskip("mcp", reason="mcp SDK not installed")


def _reload_with_tmp(tmp):
    os.environ["BB_DATA_DIR"] = tmp
    import db, registry, server
    importlib.reload(db)
    importlib.reload(registry)
    importlib.reload(server)
    return server


def test_server_imports_and_registers_tools():
    import server
    assert server.mcp.name == "bb"
    # tool functions are exposed as callables on the module
    for name in ("create_target", "switch_target", "list_targets",
                 "set_scope_rules", "check_scope", "scope_status", "scope_override"):
        assert callable(getattr(server, name)), f"missing tool: {name}"


def test_tools_work_end_to_end():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)
        server.create_target("acme", "hackerone", "public")
        server.set_scope_rules("acme", [
            {"pattern": "*.acme.com", "in_scope": True},
            {"pattern": "blog.acme.com", "in_scope": False},
        ])
        assert server.check_scope("api.acme.com")["in_scope"] is True
        assert server.check_scope("blog.acme.com")["in_scope"] is False
        assert server.check_scope("evil.com")["in_scope"] is False

        st = server.scope_status("acme")
        assert st["in_scope_rules"] == 1 and st["out_of_scope_rules"] == 1

        # one-time override
        server.scope_override("evil.com", "hand-verified")
        assert server.check_scope("evil.com")["in_scope"] is True
        assert server.check_scope("evil.com")["in_scope"] is False

        assert any(t["handle"] == "acme" for t in server.list_targets())


# ---- Slice 3.2: sandbox mission tools ------------------------------------------------

def test_seed_objectives_loads_real_juiceshop_catalog_and_rejects_unknown_app():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)
        server.create_target("juicebox", mode="sandbox", sandbox_app="juice-shop")

        result = server.seed_objectives("juicebox", "juice-shop")
        assert "error" not in result
        assert result["seeded"] > 100, result

        webgoat = server.seed_objectives("juicebox", "webgoat")
        assert "error" not in webgoat
        assert webgoat["seeded"] > 0

        bad = server.seed_objectives("juicebox", "not-a-real-app")
        assert bad["seeded"] == 0
        assert "error" in bad


def test_create_sandbox_mission_gating():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)

        # Bounty target active: refused even though human_ack=True -- the
        # server verifies mode itself, it never trusts the caller.
        server.create_target("acme", "hackerone", "public")
        refused_bounty = server.create_sandbox_mission("acme", "http://localhost:3000",
                                                         human_ack=True)
        assert "error" in refused_bounty

        # Sandbox target active, but human_ack not literally True: refused.
        server.create_target("juicebox", mode="sandbox", sandbox_app="juice-shop")
        server.seed_objectives("juicebox", "juice-shop")
        refused_ack = server.create_sandbox_mission("juicebox", "http://localhost:3000",
                                                      human_ack=False)
        assert "error" in refused_ack

        # Sandbox target active + human_ack=True: succeeds, app comes from
        # the active target's sandbox_app, not from the caller.
        ok = server.create_sandbox_mission("juicebox", "http://localhost:3000",
                                            human_ack=True)
        assert "error" not in ok
        assert ok["app"] == "juice-shop"
        assert ok["status"] == "running"
        assert ok["objectives_seeded"] > 100


def test_record_objective_result_reports_sanity_check():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)
        server.create_target("juicebox", mode="sandbox", sandbox_app="juice-shop")
        server.seed_objectives("juicebox", "juice-shop")
        m = server.create_sandbox_mission("juicebox", "http://localhost:3000", human_ack=True)

        # Evidence text contains the objective's native_id -> confirmed.
        obj_id = "juice-shop:adminSectionChallenge"
        ev = server.store_evidence("juicebox", "response",
                                    content="GET /api/Challenges shows adminSectionChallenge solved: true")
        r1 = server.record_objective_result("juicebox", m["id"], obj_id, True, evidence_id=ev["id"])
        assert r1["sanity_check"] == "confirmed"

        # Evidence text has nothing tying it to the claimed objective -> not confirmed.
        obj_id2 = "juice-shop:aiDebuggingChallenge"
        ev2 = server.store_evidence("juicebox", "response", content="totally unrelated body text")
        r2 = server.record_objective_result("juicebox", m["id"], obj_id2, True, evidence_id=ev2["id"])
        assert r2["sanity_check"] == "not confirmed in evidence text"

        # solved=False -> sanity_check not applicable, but the field is present.
        r3 = server.record_objective_result("juicebox", m["id"],
                                             "juice-shop:basketAccessChallenge", False)
        assert "sanity_check" in r3
        assert r3["sanity_check"] is None


def test_record_objective_result_refuses_solve_with_nonexistent_evidence():
    """HIGH (finding #5): a claimed solve must be backed by evidence that
    actually resolves. A nonexistent evidence_id must be refused outright --
    not recorded, and must NOT credit any points -- while a real stored
    evidence_id for the same objective still succeeds normally."""
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)
        server.create_target("juicebox", mode="sandbox", sandbox_app="juice-shop")
        server.seed_objectives("juicebox", "juice-shop")
        m = server.create_sandbox_mission("juicebox", "http://localhost:3000", human_ack=True)
        obj_id = "juice-shop:adminSectionChallenge"

        refused = server.record_objective_result("juicebox", m["id"], obj_id, True,
                                                  evidence_id=999999)
        assert refused.get("refused")
        assert refused.get("recorded") is False
        card = server.mission_scorecard("juicebox", m["id"])
        assert card["points_earned"] == 0
        assert server.list_objectives("juicebox", mission_id=m["id"],
                                      unsolved_only=True)  # objective still unsolved
        unsolved_ids = {o["id"] for o in server.list_objectives(
            "juicebox", mission_id=m["id"], unsolved_only=True)}
        assert obj_id in unsolved_ids, "a refused solve must not have recorded anything"

        ev = server.store_evidence("juicebox", "response",
                                   content="adminSectionChallenge solved: true")
        ok = server.record_objective_result("juicebox", m["id"], obj_id, True,
                                            evidence_id=ev["id"])
        assert "refused" not in ok
        assert ok["solved"] is True


def test_promote_to_finding_sandbox_auto_confirm_is_triple_gated():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)

        # --- bounty target: sandbox_auto_confirm must NOT bypass the wall ---
        server.create_target("acme", "hackerone", "public")
        lead = server.add_lead("acme", "maybe an IDOR here")
        with pytest.raises(ValueError):
            server.promote_to_finding("acme", lead["id"], "Some IDOR finding here", "high", "body",
                                      human_confirmed=False, sandbox_auto_confirm=True,
                                      mission_id=1, objective_id="whatever")

        # --- correlate.py's wall is untouched: a direct call still raises ---
        import correlate
        with pytest.raises(ValueError):
            correlate.promote_to_finding("acme", lead["id"], "Some IDOR finding here", "high",
                                         "body", human_confirmed=False)

        # --- sandbox target, unsolved objective: still refused ---
        server.create_target("juicebox", mode="sandbox", sandbox_app="juice-shop")
        server.seed_objectives("juicebox", "juice-shop")
        m = server.create_sandbox_mission("juicebox", "http://localhost:3000", human_ack=True)
        obj_id = "juice-shop:adminSectionChallenge"
        lead2 = server.add_lead("juicebox", "admin section reachable without auth")
        with pytest.raises(ValueError):
            server.promote_to_finding("juicebox", lead2["id"], "Broken access to admin section",
                                      "medium", "body", human_confirmed=False,
                                      sandbox_auto_confirm=True, mission_id=m["id"],
                                      objective_id=obj_id)

        # --- sandbox target, objective actually recorded solved: succeeds ---
        ev = server.store_evidence("juicebox", "response",
                                    content="adminSectionChallenge solved: true")
        server.record_objective_result("juicebox", m["id"], obj_id, True, evidence_id=ev["id"])
        result = server.promote_to_finding("juicebox", lead2["id"], "Broken access to admin section",
                                           "medium", "body", human_confirmed=False,
                                           sandbox_auto_confirm=True, mission_id=m["id"],
                                           objective_id=obj_id)
        assert result["status"] == "promoted"


def test_assemble_after_action_report_tool_returns_markdown():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)
        server.create_target("juicebox", mode="sandbox", sandbox_app="juice-shop")
        server.seed_objectives("juicebox", "juice-shop")
        m = server.create_sandbox_mission("juicebox", "http://localhost:3000", human_ack=True)
        report = server.assemble_after_action_report("juicebox", m["id"])
        assert "## Mission" in report["markdown"]
        assert "## Scorecard" in report["markdown"]
        assert isinstance(report["gaps"], list)


# ---- Slice 6.2: sandbox_preflight ----------------------------------------------

def test_sandbox_preflight_fails_when_not_sandbox_target():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)
        server.create_target("acme", "hackerone", "public")
        result = server.sandbox_preflight()
        by_name = {c["name"]: c for c in result["checks"]}
        assert by_name["active_target_sandbox"]["status"] == "fail"
        assert result["ready"] is False


def test_sandbox_preflight_network_isolation_warn_when_unconfirmed():
    """HIGH (finding #4): `ready` must require network_isolation_verified to
    be an explicit "pass", not merely "not fail". An unconfirmed ("warn")
    isolation check means containment was never actually verified, so `ready`
    must be False here -- the old version of this test asserted True, which
    encoded the spec violation the fix closes."""
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)
        server.create_target("juicebox", mode="sandbox", sandbox_app="juice-shop")
        server.set_scope_rules("juicebox", [{"pattern": "localhost:3000", "in_scope": True}])
        result = server.sandbox_preflight()
        by_name = {c["name"]: c for c in result["checks"]}
        assert by_name["network_isolation_verified"]["status"] == "warn"
        # an unconfirmed isolation check is not a FAIL, but it must not be
        # treated as ready for an autonomous run either.
        assert result["ready"] is False


def test_sandbox_preflight_all_pass_on_internal_network_and_loopback_bind():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)
        server.create_target("juicebox", mode="sandbox", sandbox_app="juice-shop")
        server.set_scope_rules("juicebox", [{"pattern": "localhost:3000", "in_scope": True}])
        result = server.sandbox_preflight(network_mode="internal",
                                          port_bindings="127.0.0.1:3000->3000/tcp")
        by_name = {c["name"]: c for c in result["checks"]}
        assert by_name["proxy_env"]["status"] == "pass"
        assert by_name["active_target_sandbox"]["status"] == "pass"
        assert by_name["allow_list_rules"]["status"] == "pass"
        assert by_name["network_isolation_verified"]["status"] == "pass"
        assert result["ready"] is True


def test_sandbox_preflight_fails_on_0_0_0_0_bind_even_when_internal():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_with_tmp(tmp)
        server.create_target("juicebox", mode="sandbox", sandbox_app="juice-shop")
        server.set_scope_rules("juicebox", [{"pattern": "localhost:3000", "in_scope": True}])
        result = server.sandbox_preflight(network_mode="internal",
                                          port_bindings="0.0.0.0:3000->3000/tcp")
        by_name = {c["name"]: c for c in result["checks"]}
        assert by_name["network_isolation_verified"]["status"] == "fail"
        assert result["ready"] is False
