import importlib
import pytest


def _fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("BB_DATA_DIR", str(tmp_path))
    import db, registry
    importlib.reload(db)
    importlib.reload(registry)
    return db, registry


def test_active_permission_defaults_to_not_permitted(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    assert registry.active_testing_permitted("acme") is False
    d = registry.get_active_permission("acme")
    assert d["active_testing_permitted"] is False and d["note"] == ""


def test_set_active_permission_roundtrip(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    out = registry.set_active_permission("acme", True, note="policy allows <=5rps")
    assert out["active_testing_permitted"] is True
    assert out["note"] == "policy allows <=5rps" and out["at"]
    assert registry.active_testing_permitted("acme") is True


def test_set_active_permission_false_returns_to_not_permitted(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.set_active_permission("acme", True, note="x")
    registry.set_active_permission("acme", False, note="reconsidered")
    assert registry.active_testing_permitted("acme") is False


def test_get_active_permission_unknown_target_is_not_permitted(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    d = registry.get_active_permission("does-not-exist")
    assert d["active_testing_permitted"] is False


def test_set_active_permission_unknown_target_raises(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        registry.set_active_permission("nope", True)


def test_gate_columns_present_and_init_idempotent(tmp_path, monkeypatch):
    db, _ = _fresh(tmp_path, monkeypatch)
    db.init_registry()
    db.init_registry()  # guarded ALTER: must not raise on re-run
    conn = db.connect(db.registry_path())
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(target)")}
    conn.close()
    assert {"active_testing_permitted", "active_permitted_note",
            "active_permitted_at"} <= cols


import activelab


def _all_good_kwargs(**over):
    base = dict(attested=True, active_permitted=True,
                allowlist_hosts=["api.acme.com"], offscope_allowlist_hosts=[],
                proxy_reachable="UP", firewall_direct_egress="BLOCKED",
                proxy_to_target="OK")
    base.update(over)
    return base


def _status(result, name):
    return {c["name"]: c["status"] for c in result["checks"]}[name]


def test_preflight_ready_when_all_pass():
    r = activelab.active_lab_preflight(**_all_good_kwargs())
    assert r["ready"] is True
    assert all(c["status"] == "pass" for c in r["checks"])


def test_preflight_fails_without_attestation():
    r = activelab.active_lab_preflight(**_all_good_kwargs(attested=False))
    assert r["ready"] is False and _status(r, "legal-attestation") == "fail"


def test_preflight_fails_without_roe_gate():
    r = activelab.active_lab_preflight(**_all_good_kwargs(active_permitted=False))
    assert r["ready"] is False and _status(r, "roe-gate") == "fail"


def test_preflight_fails_on_empty_allowlist():
    r = activelab.active_lab_preflight(**_all_good_kwargs(allowlist_hosts=[]))
    assert r["ready"] is False and _status(r, "allowlist-in-scope") == "fail"


def test_preflight_fails_on_offscope_allowlist_host():
    r = activelab.active_lab_preflight(
        **_all_good_kwargs(allowlist_hosts=["api.acme.com", "evil.example"],
                           offscope_allowlist_hosts=["evil.example"]))
    assert r["ready"] is False and _status(r, "allowlist-in-scope") == "fail"


def test_preflight_fails_closed_on_missing_proxy_evidence():
    r = activelab.active_lab_preflight(**_all_good_kwargs(proxy_reachable=""))
    assert r["ready"] is False and _status(r, "proxy-reachable") == "fail"


def test_preflight_fails_when_direct_egress_open():
    r = activelab.active_lab_preflight(**_all_good_kwargs(firewall_direct_egress="OPEN"))
    assert r["ready"] is False and _status(r, "firewall-sealed") == "fail"


def test_preflight_fails_when_proxy_to_target_fails():
    r = activelab.active_lab_preflight(**_all_good_kwargs(proxy_to_target="FAIL"))
    assert r["ready"] is False and _status(r, "firewall-sealed") == "fail"


import os
import tempfile


def _reload_server(tmp):
    os.environ["BB_DATA_DIR"] = tmp
    import db, registry, server
    importlib.reload(db)
    importlib.reload(registry)
    importlib.reload(server)
    return server


def test_tools_registered_and_callable():
    import server
    assert callable(getattr(server, "set_active_permission"))
    assert callable(getattr(server, "active_lab_preflight"))


def test_active_lab_preflight_tool_ready_end_to_end():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        server.set_scope_rules("acme", [{"pattern": "*.acme.com", "in_scope": True}])
        server.legal_attest(jurisdiction="MY", tester_location="MY", authorization_ref="hackerone.com/acme")
        server.set_active_permission(True, note="policy permits automated testing")
        r = server.active_lab_preflight(["api.acme.com"], proxy_reachable="UP",
                                        firewall_direct_egress="BLOCKED", proxy_to_target="OK")
        assert r["ready"] is True


def test_active_lab_preflight_tool_flags_offscope_allowlist():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        server.set_scope_rules("acme", [{"pattern": "*.acme.com", "in_scope": True}])
        server.legal_attest(authorization_ref="x")
        server.set_active_permission(True)
        r = server.active_lab_preflight(["api.acme.com", "evil.example"],
                                        proxy_reachable="UP",
                                        firewall_direct_egress="BLOCKED", proxy_to_target="OK")
        by = {c["name"]: c["status"] for c in r["checks"]}
        assert by["allowlist-in-scope"] == "fail" and r["ready"] is False


def test_active_lab_preflight_tool_no_target_is_not_ready():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        r = server.active_lab_preflight(["api.acme.com"], proxy_reachable="UP",
                                        firewall_direct_egress="BLOCKED", proxy_to_target="OK")
        assert r["ready"] is False


def test_set_active_permission_tool_no_target_errors():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        assert "error" in server.set_active_permission(True)


def test_active_lab_preflight_does_not_consume_scope_override():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        server.set_scope_rules("acme", [{"pattern": "*.acme.com", "in_scope": True}])
        server.legal_attest(authorization_ref="x")
        server.set_active_permission(True)
        server.scope_override("evil.example", "hand-verified")  # a one-time override on file
        # an override-gated host is NOT a stable in-scope allowlist entry -> fails
        r = server.active_lab_preflight(["evil.example"], proxy_reachable="UP",
                                        firewall_direct_egress="BLOCKED", proxy_to_target="OK")
        by = {c["name"]: c["status"] for c in r["checks"]}
        assert by["allowlist-in-scope"] == "fail"
        # and the preflight must NOT have consumed the override: a real check_scope still finds it
        assert server.check_scope("evil.example")["in_scope"] is True


def test_active_lab_state_defaults(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    st = registry.get_active_lab("acme")
    assert st == {"handle": "acme", "engaged": False, "paused": False, "pause_reason": "",
                  "ready": False, "rate_per_min": 0, "engaged_at": ""}


def test_active_lab_engage_sets_rate_and_clears_flags(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.set_active_lab_ready("acme", True)
    st = registry.active_lab_engage("acme", 30)
    assert st["engaged"] is True and st["rate_per_min"] == 30
    assert st["paused"] is False and st["ready"] is False and st["engaged_at"]


def test_active_lab_pause_resume(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.active_lab_engage("acme", 10)
    registry.set_active_lab_ready("acme", True)
    p = registry.active_lab_pause("acme", "5xx spike")
    assert p["paused"] is True and p["pause_reason"] == "5xx spike"
    r = registry.active_lab_resume("acme")
    assert r["paused"] is False and r["ready"] is False and r["pause_reason"] == ""


def test_active_lab_disengage(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.active_lab_engage("acme", 10)
    assert registry.active_lab_disengage("acme")["engaged"] is False


def test_active_lab_accessors_unknown_target_raise(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    import pytest as _pt
    with _pt.raises(ValueError):
        registry.active_lab_engage("nope", 10)


def test_active_lab_columns_and_rate_table_present(tmp_path, monkeypatch):
    db, _ = _fresh(tmp_path, monkeypatch)
    db.init_registry(); db.init_registry()  # idempotent
    conn = db.connect(db.registry_path())
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(target)")}
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert {"active_lab_engaged", "active_lab_paused", "active_lab_pause_reason",
            "active_lab_ready", "active_lab_rate_per_min", "active_lab_engaged_at"} <= cols
    assert "active_lab_rate" in tables


def test_rate_step_consume_refill_and_deny():
    import activelab
    ok, tok, retry = activelab.rate_step(3.0, 0.0, 3.0, 0.0)
    assert ok is True and abs(tok - 2.0) < 1e-9 and retry == 0.0
    ok, tok, retry = activelab.rate_step(0.0, 0.0, 3.0, 0.0)
    assert ok is False and retry == float("inf")
    ok, tok, _ = activelab.rate_step(0.0, 60.0, 3.0, 3.0 / 60.0)  # 60s * 0.05/s = 3 tokens
    assert ok is True and abs(tok - 2.0) < 1e-9


def test_rate_consume_persisted_allows_then_denies_then_refills(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.active_lab_engage("acme", 3)  # capacity 3, refill 3/60 per sec
    t0 = "2026-09-06T00:00:00+00:00"
    assert registry.active_lab_rate_consume("acme", "api.acme.com", now=t0)["allowed"] is True
    assert registry.active_lab_rate_consume("acme", "api.acme.com", now=t0)["allowed"] is True
    assert registry.active_lab_rate_consume("acme", "api.acme.com", now=t0)["allowed"] is True
    assert registry.active_lab_rate_consume("acme", "api.acme.com", now=t0)["allowed"] is False
    t1 = "2026-09-06T00:00:40+00:00"  # +40s -> +2 tokens
    assert registry.active_lab_rate_consume("acme", "api.acme.com", now=t1)["allowed"] is True


def test_rate_consume_per_host_isolated(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")
    registry.active_lab_engage("acme", 1)
    t0 = "2026-09-06T00:00:00+00:00"
    assert registry.active_lab_rate_consume("acme", "a.acme.com", now=t0)["allowed"] is True
    assert registry.active_lab_rate_consume("acme", "b.acme.com", now=t0)["allowed"] is True
    assert registry.active_lab_rate_consume("acme", "a.acme.com", now=t0)["allowed"] is False


def test_rate_consume_fail_closed_when_no_ceiling(tmp_path, monkeypatch):
    _, registry = _fresh(tmp_path, monkeypatch)
    registry.create_target("acme", "hackerone", "public")  # rate_per_min defaults 0
    out = registry.active_lab_rate_consume("acme", "api.acme.com", now="2026-09-06T00:00:00+00:00")
    assert out["allowed"] is False and out["capacity"] == 0.0


def test_active_lab_engage_tool_requires_positive_rate():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        assert "error" in server.active_lab_engage(0)
        assert server.active_lab_engage(20)["engaged"] is True


def test_active_lab_tools_pause_resume_status():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        server.active_lab_engage(10)
        assert server.active_lab_pause("waf")["paused"] is True
        r = server.active_lab_resume()
        assert r["paused"] is False and r["ready"] is False
        assert server.active_lab_status()["engaged"] is True
        assert server.active_lab_disengage()["engaged"] is False


def test_active_lab_preflight_stores_ready_when_engaged():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        server.set_scope_rules("acme", [{"pattern": "*.acme.com", "in_scope": True}])
        server.legal_attest(authorization_ref="x")
        server.set_active_permission(True)
        server.active_lab_engage(10)
        r = server.active_lab_preflight(["api.acme.com"], proxy_reachable="UP",
                                        firewall_direct_egress="BLOCKED", proxy_to_target="OK")
        assert r["ready"] is True
        assert server.active_lab_status()["ready"] is True  # stored


def test_active_lab_preflight_does_not_store_when_not_engaged():
    with tempfile.TemporaryDirectory() as tmp:
        server = _reload_server(tmp)
        server.create_target("acme", "hackerone", "public")
        server.set_scope_rules("acme", [{"pattern": "*.acme.com", "in_scope": True}])
        server.legal_attest(authorization_ref="x")
        server.set_active_permission(True)
        server.active_lab_preflight(["api.acme.com"], proxy_reachable="UP",
                                    firewall_direct_egress="BLOCKED", proxy_to_target="OK")
        assert server.active_lab_status()["ready"] is False  # not engaged -> not stored
