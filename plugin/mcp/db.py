"""SQLite storage: data-dir resolution, connections, and schema.

Design rules (from the plan):
  - Case data lives OUTSIDE the repo by default (leakage mitigation). Default
    dir is ~/.bb-bounty, overridable with BB_DATA_DIR. The env is read on every
    call so tests can point it at a temp dir.
  - One registry.db (global list of targets) + one <handle>.db per target.
  - No migration framework: schema is idempotent CREATE-IF-NOT-EXISTS, versioned
    by PRAGMA user_version.
  - No network, no LLM. Just storage.
"""
from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA_REGISTRY = """
CREATE TABLE IF NOT EXISTS target (
  id INTEGER PRIMARY KEY,
  handle TEXT UNIQUE NOT NULL,
  platform TEXT,
  confidentiality TEXT DEFAULT 'public',   -- public | private | nda
  db_path TEXT NOT NULL,
  scope_fetched_at TEXT,
  created_at TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scope_override (
  id INTEGER PRIMARY KEY,
  host TEXT NOT NULL,
  reason TEXT,
  created_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
"""

SCHEMA_TARGET = """
CREATE TABLE IF NOT EXISTS scope_rule (
  id INTEGER PRIMARY KEY,
  pattern TEXT NOT NULL,
  asset_type TEXT DEFAULT '',
  in_scope INTEGER NOT NULL,            -- 1 in-scope, 0 explicitly out
  source TEXT DEFAULT '',
  added_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoint (
  id INTEGER PRIMARY KEY,
  method TEXT, url TEXT, host TEXT, path TEXT,
  params TEXT, auth_hint TEXT, first_seen TEXT, source TEXT,
  UNIQUE(method, url)
);
CREATE TABLE IF NOT EXISTS test_case (
  id TEXT PRIMARY KEY, category TEXT, title TEXT, tier INTEGER, applies_to TEXT,
  -- 'host'     = done once per host/app (TLS config, security headers, .git exposure)
  -- 'endpoint' = done against a specific request (IDOR, XSS in a param, mass assignment)
  -- Pairing host-level tests against every endpoint is noise and inflates coverage math.
  scope_level TEXT NOT NULL DEFAULT 'endpoint',
  -- Optional case-insensitive regex matched against the endpoint path. Used by
  -- FLOW-specific tests (2FA bypass, password reset, email-change ATO) that
  -- apply to a particular feature rather than to an endpoint shape. Without it
  -- they match every authenticated POST and produce confident nonsense.
  path_hint TEXT
);
CREATE TABLE IF NOT EXISTS coverage (
  id INTEGER PRIMARY KEY,
  endpoint_id INTEGER, test_case_id TEXT,
  status TEXT, tested_at TEXT, evidence_id INTEGER, note TEXT,
  UNIQUE(endpoint_id, test_case_id)
);
CREATE TABLE IF NOT EXISTS note (
  id INTEGER PRIMARY KEY, body_md TEXT, endpoint_id INTEGER, created_at TEXT
);
CREATE TABLE IF NOT EXISTS lead (
  id INTEGER PRIMARY KEY, hypothesis TEXT, confidence TEXT, status TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS lead_note (lead_id INTEGER, note_id INTEGER);
CREATE TABLE IF NOT EXISTS primitive (
  id INTEGER PRIMARY KEY, capability TEXT, description TEXT, evidence_id INTEGER, created_at TEXT
);
CREATE TABLE IF NOT EXISTS finding (
  id INTEGER PRIMARY KEY, title TEXT, severity TEXT, status TEXT,
  body_md TEXT, human_confirmed INTEGER DEFAULT 0, created_at TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY, kind TEXT, blob_path TEXT, summary TEXT,
  redacted INTEGER DEFAULT 0, sha256 TEXT, created_at TEXT
);
-- Correlations the user has explicitly rejected. Without this, every session
-- re-proposes the same dead links and the signal drowns in repeat noise.
-- Pair is stored normalised (lower kind:id first) so A-B == B-A.
CREATE TABLE IF NOT EXISTS correlation_dismissed (
  pair_key TEXT PRIMARY KEY, a_ref TEXT, b_ref TEXT, reason TEXT, dismissed_at TEXT
);
"""

_SAFE = re.compile(r"[^a-z0-9._-]+")


def data_dir() -> Path:
    d = Path(os.environ.get("BB_DATA_DIR", Path.home() / ".bb-bounty"))
    d.mkdir(parents=True, exist_ok=True)
    (d / "targets").mkdir(exist_ok=True)
    return d


def registry_path() -> Path:
    return data_dir() / "registry.db"


def safe_handle(handle: str) -> str:
    """Filesystem-safe handle. Fails loud on traversal / path separators rather
    than silently rewriting them, so a bad handle can never resolve to a path
    outside the targets/ dir."""
    raw = (handle or "").strip()
    if not raw or ".." in raw or "/" in raw or "\\" in raw:
        raise ValueError(f"unsafe or empty handle: {handle!r}")
    h = _SAFE.sub("-", raw.lower()).strip("-.")
    if not h:
        raise ValueError(f"unsafe or empty handle: {handle!r}")
    return h


def target_db_path(handle: str) -> Path:
    return data_dir() / "targets" / f"{safe_handle(handle)}.db"


def connect(path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_registry() -> None:
    conn = connect(registry_path())
    try:
        conn.executescript(SCHEMA_REGISTRY)
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        conn.commit()
    finally:
        conn.close()


def init_target_db(path) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA_TARGET)
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    import tempfile
    os.environ["BB_DATA_DIR"] = tempfile.mkdtemp()
    init_registry()
    p = target_db_path("acme-corp")
    init_target_db(p)
    assert registry_path().exists() and p.exists()
    assert safe_handle("ACME Corp!!") == "acme-corp"
    try:
        safe_handle("../etc")
        raise SystemExit("traversal not rejected")
    except ValueError:
        pass
    print("db self-check ok")
