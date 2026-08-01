"""Tests for Slice 1.1: target.mode column + registry sandbox gate.

Mirrors the tmpdir/BB_DATA_DIR reload pattern used elsewhere (test_coverage.py,
test_hook.py): point BB_DATA_DIR at a temp dir and reload db/registry so each
test gets a clean SQLite store instead of sharing global state.
"""
import importlib
import os

import pytest


@pytest.fixture()
def reg(tmp_path):
    os.environ["BB_DATA_DIR"] = str(tmp_path)
    import db
    importlib.reload(db)
    import registry
    importlib.reload(registry)
    return registry


# ---- defaults ------------------------------------------------------------

def test_default_mode_is_bounty(reg):
    reg.create_target("acme", "hackerone", "public")
    t = reg.active_target()
    assert t["mode"] == "bounty"
    assert t["sandbox_app"] == ""


def test_create_target_return_value_reports_mode(reg):
    out = reg.create_target("acme")
    assert out["mode"] == "bounty"
    assert out["sandbox_app"] == ""


# ---- sandbox mode ----------------------------------------------------------

def test_sandbox_target_reads_back_and_is_sandbox(reg):
    reg.create_target("juice-shop", mode="sandbox", sandbox_app="juice-shop")
    t = reg.active_target()
    assert t["mode"] == "sandbox"
    assert t["sandbox_app"] == "juice-shop"
    assert reg.is_sandbox() is True


def test_is_sandbox_false_after_switching_to_bounty_target(reg):
    reg.create_target("juice-shop", mode="sandbox", sandbox_app="juice-shop")
    assert reg.is_sandbox() is True
    reg.create_target("acme", "hackerone", "public")   # create_target also switches active
    assert reg.is_sandbox() is False


def test_is_sandbox_toggles_with_switch_target(reg):
    reg.create_target("acme", "hackerone", "public")
    reg.create_target("juice-shop", mode="sandbox", sandbox_app="juice-shop")
    assert reg.is_sandbox() is True
    reg.switch_target("acme")
    assert reg.is_sandbox() is False
    reg.switch_target("juice-shop")
    assert reg.is_sandbox() is True


# ---- guarded ALTER idempotency ---------------------------------------------

def test_init_registry_idempotent_across_repeated_calls(reg):
    import db
    db.init_registry()
    db.init_registry()   # must not raise on the second (or later) pass


def test_add_column_if_missing_reraises_non_duplicate_errors(reg):
    import db
    import sqlite3
    conn = db.connect(db.registry_path())
    try:
        with pytest.raises(sqlite3.OperationalError):
            db._add_column_if_missing(conn, "no_such_table", "x TEXT")
    finally:
        conn.close()


# ---- existing (pre-migration) targets are unaffected -----------------------

def test_existing_target_backfilled_with_default_mode(tmp_path):
    """Simulate a target row created before mode/sandbox_app existed: build the
    base schema without the guarded ALTERs, insert a row the old way, then run
    init_registry and confirm it reads back fine with the new columns defaulted."""
    os.environ["BB_DATA_DIR"] = str(tmp_path)
    import db
    importlib.reload(db)

    conn = db.connect(db.registry_path())
    try:
        conn.executescript(db.SCHEMA_REGISTRY)   # base table only, no mode/sandbox_app yet
        conn.execute(
            "INSERT INTO target (handle, platform, confidentiality, db_path, created_at, active) "
            "VALUES (?,?,?,?,?,1)",
            ("legacy", "hackerone", "public", str(db.target_db_path("legacy")),
             "2026-01-01T00:00:00+00:00"),
        )
        conn.commit()
    finally:
        conn.close()

    db.init_target_db(db.target_db_path("legacy"))
    db.init_registry()   # adds mode/sandbox_app via the guarded ALTER, backfilling defaults

    import registry
    importlib.reload(registry)
    t = registry.active_target()
    assert t["handle"] == "legacy"
    assert t["mode"] == "bounty"
    assert t["sandbox_app"] == ""


# ---- sandbox_rules() / check_scope() sandbox branch (Slice 2.2) ------------


def test_sandbox_rules_parses_declared_hostport_patterns(reg):
    reg.create_target("juice-shop", mode="sandbox", sandbox_app="juice-shop")
    reg.set_scope_rules("juice-shop", [
        {"pattern": "127.0.0.1:3000", "in_scope": True},
        {"pattern": "localhost:3000", "in_scope": True},
        {"pattern": "[::1]:3000", "in_scope": True},
    ])
    rules = reg.sandbox_rules()
    pairs = {(r.host, r.port) for r in rules}
    assert pairs == {("127.0.0.1", 3000), ("localhost", 3000), ("::1", 3000)}


def test_sandbox_rules_skips_portless_pattern(reg):
    reg.create_target("juice-shop", mode="sandbox", sandbox_app="juice-shop")
    reg.set_scope_rules("juice-shop", [
        {"pattern": "localhost", "in_scope": True},          # no port: skipped
        {"pattern": "localhost:3000", "in_scope": True},
    ])
    rules = reg.sandbox_rules()
    assert [(r.host, r.port) for r in rules] == [("localhost", 3000)]


def test_sandbox_rules_skips_out_of_scope_rows(reg):
    reg.create_target("juice-shop", mode="sandbox", sandbox_app="juice-shop")
    reg.set_scope_rules("juice-shop", [
        {"pattern": "localhost:3000", "in_scope": True},
        {"pattern": "localhost:9999", "in_scope": False},
    ])
    rules = reg.sandbox_rules()
    assert [(r.host, r.port) for r in rules] == [("localhost", 3000)]


def test_check_scope_sandbox_target_uses_sandbox_allows(reg):
    reg.create_target("juice-shop", mode="sandbox", sandbox_app="juice-shop")
    reg.set_scope_rules("juice-shop", [{"pattern": "localhost:3000", "in_scope": True}])
    assert reg.check_scope("localhost", port=3000)[0] is True
    assert reg.check_scope("localhost", port=9999)[0] is False
    assert reg.check_scope("evil.com", port=3000)[0] is False


def test_check_scope_sandbox_target_ignores_override(reg):
    reg.create_target("juice-shop", mode="sandbox", sandbox_app="juice-shop")
    reg.set_scope_rules("juice-shop", [{"pattern": "localhost:3000", "in_scope": True}])
    reg.add_override("evil.com", "hand-verified")
    assert reg.check_scope("evil.com", port=3000)[0] is False
    # override must still be UNUSED afterwards -- sandbox check_scope never
    # touches take_override, so a bounty target could still consume it later
    import db
    conn = db.connect(db.registry_path())
    try:
        row = conn.execute(
            "SELECT used FROM scope_override WHERE host='evil.com'"
        ).fetchone()
    finally:
        conn.close()
    assert row["used"] == 0


def test_check_scope_bounty_target_still_uses_override_and_is_in_scope(reg):
    """Regression: the non-sandbox path of check_scope must be byte-for-byte
    the same override-then-is_in_scope behavior as before this slice."""
    reg.create_target("acme", "hackerone", "public")
    reg.set_scope_rules("acme", [{"pattern": "*.acme.com", "in_scope": True}])
    assert reg.check_scope("api.acme.com")[0] is True
    assert reg.check_scope("evil.com")[0] is False
    reg.add_override("evil.com", "confirmed authorized by hand")
    assert reg.check_scope("evil.com")[0] is True      # override consumed
    assert reg.check_scope("evil.com")[0] is False      # only once
