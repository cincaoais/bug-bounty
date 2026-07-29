"""Safety guard tests: the data dir must not be flagged safe when it sits inside a
git repo with a remote (leak risk), and the API-key override must be detected.
"""
import importlib
import os
from pathlib import Path

import pytest


@pytest.fixture()
def saf(tmp_path):
    os.environ["BB_DATA_DIR"] = str(tmp_path)
    import db
    importlib.reload(db)
    import safety
    importlib.reload(safety)
    return safety


def test_clean_dir_is_safe(saf):
    assert saf.gitignore_guard()["safe"] is True


def test_repo_with_remote_is_flagged(tmp_path):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://example.com/x.git\n', encoding="utf-8")
    data = root / "data"
    data.mkdir()
    os.environ["BB_DATA_DIR"] = str(data)
    import db, safety
    importlib.reload(db)
    importlib.reload(safety)
    g = safety.gitignore_guard()
    assert g["safe"] is False and "leak" in g["message"].lower()


def test_repo_without_remote_is_not_flagged(tmp_path):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")
    data = root / "data"
    data.mkdir()
    os.environ["BB_DATA_DIR"] = str(data)
    import db, safety
    importlib.reload(db)
    importlib.reload(safety)
    assert safety.gitignore_guard()["safe"] is True


def test_api_key_override_detected(saf, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert saf.env_guard()["safe"] is False
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert saf.env_guard()["safe"] is True


def test_health_returns_all_sections(saf):
    h = saf.health()
    assert "gitignore" in h and "env" in h and "data_dir" in h
