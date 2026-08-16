"""State-layer tests for the legal-gate: schema v3, legal overrides, attestation.

These exercise registry.py + db.py directly (the MCP server and the hook are
thin callers of these), so a regression in the audit-trail or the peek/consume
semantics is caught here rather than only through the hook.
"""
import importlib
import os
import tempfile

import db
import registry


def _fresh(tmp):
    os.environ["BB_DATA_DIR"] = tmp
    importlib.reload(db)
    importlib.reload(registry)


def test_schema_is_v3_with_legal_tables_and_columns():
    with tempfile.TemporaryDirectory() as tmp:
        _fresh(tmp)
        db.init_registry()
        conn = db.connect(db.registry_path())
        try:
            ver = conn.execute("PRAGMA user_version").fetchone()[0]
            assert ver == 3
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            assert "legal_override" in tables
            cols = {r[1] for r in conn.execute("PRAGMA table_info(target)").fetchall()}
            assert {"jurisdiction", "tester_location", "cssp_licensed",
                    "authorization_ref", "attested_at"} <= cols
        finally:
            conn.close()


def test_init_registry_is_idempotent():
    with tempfile.TemporaryDirectory() as tmp:
        _fresh(tmp)
        db.init_registry()
        db.init_registry()   # second run must not raise (guarded ALTER + CREATE IF NOT EXISTS)
        registry.create_target("acme", "hackerone", "public")
        assert registry.get_attestation("acme")["attested"] is False


def test_legal_override_peek_then_consume():
    with tempfile.TemporaryDirectory() as tmp:
        _fresh(tmp)
        registry.create_target("acme")
        assert registry.has_legal_override("pii") is False
        registry.add_legal_override("pii", "authorized single-table export")
        assert registry.has_legal_override("pii") is True
        assert registry.has_legal_override("pii") is True     # peek does not consume
        assert registry.unused_legal_overrides().get("pii") == 1
        assert registry.take_legal_override("pii") is True
        assert registry.take_legal_override("pii") is False   # single-use
        assert registry.has_legal_override("pii") is False


def test_legal_override_records_used_at_audit_trail():
    with tempfile.TemporaryDirectory() as tmp:
        _fresh(tmp)
        registry.create_target("acme")
        registry.add_legal_override("destructive", "why")
        registry.take_legal_override("destructive")
        conn = db.connect(db.registry_path())
        try:
            row = conn.execute(
                "SELECT used, used_at FROM legal_override WHERE gate_class='destructive'").fetchone()
        finally:
            conn.close()
        assert row["used"] == 1 and row["used_at"]   # consumption is timestamped


def test_legal_override_rejects_unknown_class():
    with tempfile.TemporaryDirectory() as tmp:
        _fresh(tmp)
        registry.create_target("acme")
        try:
            registry.add_legal_override("not-a-class", "x")
            assert False, "expected ValueError for unknown gate_class"
        except ValueError:
            pass


def test_attestation_round_trip():
    with tempfile.TemporaryDirectory() as tmp:
        _fresh(tmp)
        registry.create_target("acme")
        assert registry.is_attested("acme") is False
        out = registry.set_attestation("acme", jurisdiction="US", tester_location="MY",
                                       cssp_licensed=True, authorization_ref="h1/acme")
        assert out["attested"] is True and out["cssp_licensed"] is True
        got = registry.get_attestation("acme")
        assert got["jurisdiction"] == "US" and got["tester_location"] == "MY"
        assert registry.is_attested("acme") is True


def test_get_attestation_unknown_target():
    with tempfile.TemporaryDirectory() as tmp:
        _fresh(tmp)
        assert registry.get_attestation("ghost")["attested"] is False
