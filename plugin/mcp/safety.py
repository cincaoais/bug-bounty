"""Local-machine safety checks. Pure, read-only, stdlib. No network, no LLM.

The one that matters: case data (targets, notes, evidence — some NDA-bound) must
not sit inside a git repo that has a remote, or a single `git add .` push could
leak a private program's data. Data defaults to ~/.bb-bounty (outside any repo),
but a user can override BB_DATA_DIR, so this checks where it ACTUALLY landed.
"""
from __future__ import annotations

import os
from pathlib import Path

import db


def _git_dir_with_remote(start: Path) -> Path | None:
    """Nearest ancestor (incl. start) that is a git working tree WITH a remote.
    A repo with no remote can't push, so it isn't a leak risk on its own."""
    for d in [start, *start.parents]:
        gitdir = d / ".git"
        cfg = gitdir / "config" if gitdir.is_dir() else None
        if cfg and cfg.exists():
            try:
                text = cfg.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return None
            if "[remote " in text or "url =" in text:
                return d
            return None            # a repo, but no remote -> stop, not a risk
    return None


def gitignore_guard() -> dict:
    """Check the data dir isn't inside a git repo with a remote. Read-only."""
    data = db.data_dir()
    repo = _git_dir_with_remote(data)
    if repo is None:
        return {"safe": True, "data_dir": str(data),
                "message": "Case data is not inside a git repo with a remote."}
    return {
        "safe": False,
        "data_dir": str(data),
        "repo_root": str(repo),
        "message": (
            f"WARNING: case data at {data} is inside the git repo {repo}, which has a "
            f"remote. A `git add`/push could leak private program data. Move BB_DATA_DIR "
            f"outside the repo (default ~/.bb-bounty), or add the data dir to .gitignore."
        ),
    }


def env_guard() -> dict:
    """Warn if ANTHROPIC_API_KEY is set — it silently overrides the Pro/Max
    subscription and moves Claude Code onto metered API billing."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return {"safe": False, "message": (
            "ANTHROPIC_API_KEY is set in this environment. Claude Code will bill "
            "as pay-as-you-go API usage instead of using your Pro/Max subscription. "
            "Unset it for this project if you intend to use the subscription.")}
    return {"safe": True, "message": "No ANTHROPIC_API_KEY override detected."}


def health() -> dict:
    """One-call setup sanity check for the setup docs / bb-doctor."""
    return {"data_dir": str(db.data_dir()),
            "gitignore": gitignore_guard(),
            "env": env_guard()}


if __name__ == "__main__":
    import tempfile
    # clean case: fresh temp dir, no repo
    os.environ["BB_DATA_DIR"] = tempfile.mkdtemp()
    assert gitignore_guard()["safe"] is True

    # risky case: data dir inside a repo-with-remote
    root = Path(tempfile.mkdtemp())
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://example.com/x.git\n', encoding="utf-8")
    sub = root / "data"
    sub.mkdir()
    os.environ["BB_DATA_DIR"] = str(sub)
    g = gitignore_guard()
    assert g["safe"] is False and "leak" in g["message"], g

    # repo without a remote is not flagged
    root2 = Path(tempfile.mkdtemp())
    (root2 / ".git").mkdir()
    (root2 / ".git" / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")
    os.environ["BB_DATA_DIR"] = str(root2 / "d")
    (root2 / "d").mkdir()
    assert gitignore_guard()["safe"] is True

    # env guard
    os.environ.pop("ANTHROPIC_API_KEY", None)
    assert env_guard()["safe"] is True
    os.environ["ANTHROPIC_API_KEY"] = "sk-test"
    assert env_guard()["safe"] is False
    os.environ.pop("ANTHROPIC_API_KEY", None)
    print("safety self-check ok")
