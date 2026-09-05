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
