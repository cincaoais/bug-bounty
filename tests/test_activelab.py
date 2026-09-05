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
