"""Mission / objective / scoring storage layer (sandbox mode only).

Five tables (created by db.py, not here): mission, objective,
mission_objective_result, mission_attempt, sandbox_audit. This module is pure
storage + scoring math over them. No network, no LLM — same rule as every
other module in plugin/mcp.

Design, mirrored from 01-RND.md Theme 7:
  - The MCP server never makes network calls. Claude polls the sandboxed
    app's own state (e.g. Juice Shop's `/api/Challenges`) and reports what it
    observed; `record_objective_result` only RECORDS that report, gated by a
    mandatory evidence_id when solved=True.
  - `coverage.status='confirmed'` (Claude's working opinion) and
    `mission_objective_result.solved=1` (the app's own state, as polled) are
    deliberately allowed to disagree — that mismatch is a signal, not a bug.
  - Credit is monotonic and baseline-aware: `create_mission` snapshots which
    objectives were ALREADY solved before the run started
    (`baseline_solved`), and `credited = solved AND NOT baseline_solved` so a
    rerun on a never-reset app can't claim someone else's prior work. Once an
    objective is recorded solved=1 with evidence, a later solved=0 report for
    the same (mission, objective) is refused, not silently applied — apps
    misreport state far more often than a genuinely-confirmed solve reverses.
  - `log_attempt` tracks a per-(mission, objective) attempt count and reports
    `over_cap` once it exceeds ATTEMPT_CAP. It does NOT refuse to log the
    attempt — enforcement (moving on to the next objective) is the run
    loop's job (Slice 4.1); this layer only does the accounting so that
    decision is code-backed instead of vibes.
  - `complete_mission` freezes `compute_scorecard()`'s output into
    `scorecard_json` exactly once; `mission_scorecard` serves the frozen
    copy for a completed mission so the score can't drift after the fact.
"""
from __future__ import annotations

import datetime as _dt
import json

import db

POINTS_BY_DIFFICULTY = {1: 10, 2: 25, 3: 50, 4: 100, 5: 200, 6: 400}
SCORING_VERSION = "v1"
ATTEMPT_CAP = 5


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _parse_ts(ts):
    if not ts:
        return None
    try:
        return _dt.datetime.fromisoformat(ts)
    except ValueError:
        return None


# ---- objectives (catalog) ----------------------------------------------------

def seed_objectives(handle: str, objectives: list[dict]) -> dict:
    """Upsert into `objective`, keyed on id. Safe to re-run (mirrors
    coverage.seed_test_cases)."""
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        for o in objectives:
            conn.execute(
                "INSERT OR REPLACE INTO objective "
                "(id, app, native_id, name, category, difficulty, description, wstg_category_hint) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (o["id"], o.get("app", ""), o.get("native_id", ""), o.get("name", ""),
                 o.get("category", ""), int(o.get("difficulty", 1)),
                 o.get("description", ""), o.get("wstg_category_hint", "")),
            )
        conn.commit()
        return {"seeded": len(objectives)}
    finally:
        conn.close()


def list_objectives(handle: str, app: str = "", category: str = "", difficulty: int | None = None,
                     mission_id: int | None = None, unsolved_only: bool = False) -> list[dict]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        if mission_id is not None:
            # LEFT JOIN so an objective with no result row yet for this
            # mission still shows up (solved/polls default to 0).
            sql = (
                "SELECT o.*, "
                "COALESCE(mor.solved, 0) AS solved, "
                "COALESCE(mor.baseline_solved, 0) AS baseline_solved, "
                "mor.solved_at AS solved_at, mor.evidence_id AS evidence_id, "
                "COALESCE(mor.polls, 0) AS polls "
                "FROM objective o "
                "LEFT JOIN mission_objective_result mor "
                "  ON mor.objective_id = o.id AND mor.mission_id = ? "
                "WHERE 1=1"
            )
            args: list = [mission_id]
        else:
            sql = "SELECT o.* FROM objective o WHERE 1=1"
            args = []
        if app:
            sql += " AND o.app=?"
            args.append(app)
        if category:
            sql += " AND o.category=?"
            args.append(category)
        if difficulty is not None:
            sql += " AND o.difficulty=?"
            args.append(int(difficulty))
        if unsolved_only and mission_id is not None:
            sql += " AND COALESCE(mor.solved, 0) = 0"
        sql += " ORDER BY o.id"
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


# ---- missions ------------------------------------------------------------------

def create_mission(handle: str, app: str, base_url: str, baseline: list[str],
                    objective_filter=None, human_ack: bool = False,
                    started_at: str | None = None) -> dict:
    """Start a mission and snapshot the baseline: every catalogued objective
    for `app` gets a mission_objective_result row, baseline_solved=1 (and
    solved=1, since that's the last known true state) iff its id is in
    `baseline`. Everything else starts unsolved."""
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        obj_filter_sql = (
            objective_filter if (objective_filter is None or isinstance(objective_filter, str))
            else json.dumps(objective_filter)
        )
        started = started_at or _now()
        cur = conn.execute(
            "INSERT INTO mission (app, base_url, objective_filter, status, human_ack, started_at) "
            "VALUES (?,?,?,?,?,?)",
            (app, base_url, obj_filter_sql, "running", 1 if human_ack else 0, started),
        )
        mission_id = cur.lastrowid
        baseline_set = set(baseline or [])
        catalog = conn.execute("SELECT id FROM objective WHERE app=?", (app,)).fetchall()
        for row in catalog:
            oid = row["id"]
            is_baseline = 1 if oid in baseline_set else 0
            conn.execute(
                "INSERT INTO mission_objective_result "
                "(mission_id, objective_id, baseline_solved, solved) VALUES (?,?,?,?)",
                (mission_id, oid, is_baseline, is_baseline),
            )
        conn.commit()
        return {
            "id": mission_id, "app": app, "base_url": base_url, "status": "running",
            "human_ack": bool(human_ack), "started_at": started,
            "objectives_seeded": len(catalog),
        }
    finally:
        conn.close()


def list_missions(handle: str, status: str = "", limit: int = 20) -> list[dict]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        sql = "SELECT * FROM mission WHERE 1=1"
        args: list = []
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


# ---- objective results (scoring input) -----------------------------------------

def record_objective_result(handle: str, mission_id: int, objective_id: str, solved: bool,
                             evidence_id: int | None = None, solved_at: str | None = None,
                             source: str = "api", force: bool = False) -> dict:
    """Record what Claude observed by polling the sandboxed app.

    MONOTONIC: once a row is solved=1, a later solved=0 report for the same
    (mission, objective) is refused — the prior credit is kept and
    `refused_downgrade: True` is returned instead. Requires evidence_id
    whenever solved=True; there is no such thing as an unevidenced solve.

    IMMUTABLE AFTER COMPLETION: once the mission's status is 'completed',
    this refuses and returns `{"refused": "mission completed", ...}` WITHOUT
    modifying any row, unless force=True is explicitly passed. This matters
    beyond the frozen scorecard: `assemble_after_action_report` reads
    mission_objective_result LIVE (not the frozen scorecard_json), so without
    this guard a late-arriving "solve" recorded after complete_mission would
    silently change the after-action report's Solved/Missed Objectives
    sections even though the scorecard numbers stayed frozen.
    """
    if solved and evidence_id is None:
        raise ValueError("record_objective_result requires evidence_id when solved=True")
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        mrow = conn.execute("SELECT status FROM mission WHERE id=?", (mission_id,)).fetchone()
        if mrow is not None and mrow["status"] == "completed" and not force:
            return {
                "refused": "mission completed", "mission_id": mission_id,
                "objective_id": objective_id, "solved": None,
            }
        row = conn.execute(
            "SELECT * FROM mission_objective_result WHERE mission_id=? AND objective_id=?",
            (mission_id, objective_id),
        ).fetchone()
        if row is None:
            # Objective wasn't in the baseline snapshot (e.g. seeded after
            # the mission started) — create its result row now, no baseline.
            conn.execute(
                "INSERT INTO mission_objective_result "
                "(mission_id, objective_id, baseline_solved, solved, polls) VALUES (?,?,0,0,0)",
                (mission_id, objective_id),
            )
            row = conn.execute(
                "SELECT * FROM mission_objective_result WHERE mission_id=? AND objective_id=?",
                (mission_id, objective_id),
            ).fetchone()

        refused_downgrade = False
        new_solved = 1 if solved else 0
        if row["solved"] == 1 and new_solved == 0:
            refused_downgrade = True
            new_solved = 1  # keep the credit

        new_solved_at = row["solved_at"]
        if new_solved == 1 and not new_solved_at:
            new_solved_at = solved_at or _now()

        new_evidence_id = evidence_id if evidence_id is not None else row["evidence_id"]

        conn.execute(
            "UPDATE mission_objective_result SET solved=?, solved_at=?, evidence_id=?, polls=polls+1 "
            "WHERE mission_id=? AND objective_id=?",
            (new_solved, new_solved_at, new_evidence_id, mission_id, objective_id),
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM mission_objective_result WHERE mission_id=? AND objective_id=?",
            (mission_id, objective_id),
        ).fetchone()
        return {
            "mission_id": mission_id, "objective_id": objective_id,
            "solved": bool(updated["solved"]), "baseline_solved": bool(updated["baseline_solved"]),
            "solved_at": updated["solved_at"], "evidence_id": updated["evidence_id"],
            "polls": updated["polls"], "refused_downgrade": refused_downgrade, "source": source,
        }
    finally:
        conn.close()


# ---- attempts (append-only narration) -------------------------------------------

def log_attempt(handle: str, mission_id: int, phase: str, action_summary: str,
                 reasoning_md: str = "", objective_id: str | None = None,
                 endpoint_id: int | None = None, test_case_id: str | None = None,
                 tool_used: str = "", outcome: str = "info", evidence_id: int | None = None,
                 created_at: str | None = None) -> dict:
    """Append one attempt row. Assigns `seq` server-side (max+1 per mission)
    and reports the per-(mission, objective) attempt-cap accounting;
    it does not itself refuse to log an over-cap attempt — the caller
    (the run-loop skill) is responsible for moving on."""
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        max_seq = conn.execute(
            "SELECT COALESCE(MAX(seq), 0) m FROM mission_attempt WHERE mission_id=?", (mission_id,)
        ).fetchone()["m"]
        seq = max_seq + 1

        prior_attempts = 0
        if objective_id is not None:
            prior_attempts = conn.execute(
                "SELECT COUNT(*) c FROM mission_attempt WHERE mission_id=? AND objective_id=?",
                (mission_id, objective_id),
            ).fetchone()["c"]

        cur = conn.execute(
            "INSERT INTO mission_attempt "
            "(mission_id, seq, objective_id, endpoint_id, test_case_id, phase, tool_used, "
            "action_summary, reasoning_md, outcome, evidence_id, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (mission_id, seq, objective_id, endpoint_id, test_case_id, phase, tool_used,
             action_summary, reasoning_md, outcome, evidence_id, created_at or _now()),
        )
        conn.commit()

        if objective_id is not None:
            attempts_used = prior_attempts + 1
            attempts_remaining = max(0, ATTEMPT_CAP - attempts_used)
            over_cap = attempts_used > ATTEMPT_CAP
        else:
            attempts_used = 0
            attempts_remaining = None
            over_cap = False

        return {
            "id": cur.lastrowid, "mission_id": mission_id, "seq": seq, "objective_id": objective_id,
            "phase": phase, "outcome": outcome,
            "attempts_used": attempts_used, "attempts_remaining": attempts_remaining,
            "over_cap": over_cap,
        }
    finally:
        conn.close()


def mission_log(handle: str, mission_id: int, objective_id: str | None = None,
                 phase: str = "", outcome: str = "", limit: int = 200) -> list[dict]:
    path = db.target_db_path(handle)
    if not path.exists():
        return []
    conn = db.connect(path)
    try:
        sql = "SELECT * FROM mission_attempt WHERE mission_id=?"
        args: list = [mission_id]
        if objective_id is not None:
            sql += " AND objective_id=?"
            args.append(objective_id)
        if phase:
            sql += " AND phase=?"
            args.append(phase)
        if outcome:
            sql += " AND outcome=?"
            args.append(outcome)
        sql += " ORDER BY seq LIMIT ?"
        args.append(limit)
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


# ---- scoring ---------------------------------------------------------------------

def _empty_scorecard(mission_id: int) -> dict:
    return {
        "mission_id": mission_id, "solved": 0, "total": 0,
        "points_earned": 0, "points_total": 0, "percent": 0.0, "grade": "D",
        "by_category": {}, "by_difficulty": {}, "time_to_first_solve": None,
        "attempts_total": 0, "scoring_version": SCORING_VERSION,
    }


def _grade(percent: float) -> str:
    if percent >= 85:
        return "A"
    if percent >= 60:
        return "B"
    if percent >= 35:
        return "C"
    return "D"


def compute_scorecard(handle: str, mission_id: int) -> dict:
    """Compute the scorecard fresh from current rows. Does NOT store
    anything — `complete_mission` is the only writer of `scorecard_json`."""
    path = db.target_db_path(handle)
    if not path.exists():
        return _empty_scorecard(mission_id)
    conn = db.connect(path)
    try:
        mission = conn.execute("SELECT * FROM mission WHERE id=?", (mission_id,)).fetchone()
        rows = conn.execute(
            "SELECT mor.solved AS solved, mor.baseline_solved AS baseline_solved, "
            "mor.solved_at AS solved_at, o.category AS category, o.difficulty AS difficulty "
            "FROM mission_objective_result mor "
            "JOIN objective o ON o.id = mor.objective_id "
            "WHERE mor.mission_id=?",
            (mission_id,),
        ).fetchall()
        attempts_total = conn.execute(
            "SELECT COUNT(*) c FROM mission_attempt WHERE mission_id=?", (mission_id,)
        ).fetchone()["c"]
    finally:
        conn.close()

    if not rows:
        card = _empty_scorecard(mission_id)
        card["attempts_total"] = attempts_total
        return card

    solved = 0
    points_total = 0
    points_earned = 0
    by_category: dict[str, dict] = {}
    by_difficulty: dict[str, dict] = {}
    first_solve_at = None

    for r in rows:
        difficulty = int(r["difficulty"] or 1)
        pts = POINTS_BY_DIFFICULTY.get(difficulty, 0)
        cat = r["category"] or ""
        diff_key = str(difficulty)
        cat_bucket = by_category.setdefault(
            cat, {"solved": 0, "total": 0, "points_earned": 0, "points_total": 0})
        diff_bucket = by_difficulty.setdefault(
            diff_key, {"solved": 0, "total": 0, "points_earned": 0, "points_total": 0})
        cat_bucket["total"] += 1
        cat_bucket["points_total"] += pts
        diff_bucket["total"] += 1
        diff_bucket["points_total"] += pts
        points_total += pts

        if r["solved"]:
            solved += 1
        credited = bool(r["solved"]) and not bool(r["baseline_solved"])
        if credited:
            points_earned += pts
            cat_bucket["solved"] += 1
            cat_bucket["points_earned"] += pts
            diff_bucket["solved"] += 1
            diff_bucket["points_earned"] += pts
            if r["solved_at"] and (first_solve_at is None or r["solved_at"] < first_solve_at):
                first_solve_at = r["solved_at"]

    percent = (100.0 * points_earned / points_total) if points_total else 0.0

    time_to_first_solve = None
    start_dt = _parse_ts(mission["started_at"]) if mission else None
    solve_dt = _parse_ts(first_solve_at)
    if start_dt and solve_dt:
        time_to_first_solve = (solve_dt - start_dt).total_seconds()

    return {
        "mission_id": mission_id, "solved": solved, "total": len(rows),
        "points_earned": points_earned, "points_total": points_total,
        "percent": percent, "grade": _grade(percent),
        "by_category": by_category, "by_difficulty": by_difficulty,
        "time_to_first_solve": time_to_first_solve,
        "attempts_total": attempts_total, "scoring_version": SCORING_VERSION,
    }


def mission_scorecard(handle: str, mission_id: int) -> dict:
    """Serve the frozen scorecard for a completed mission; otherwise compute
    fresh (a running mission has no frozen copy to serve)."""
    path = db.target_db_path(handle)
    if path.exists():
        conn = db.connect(path)
        try:
            mission = conn.execute(
                "SELECT status, scorecard_json FROM mission WHERE id=?", (mission_id,)
            ).fetchone()
        finally:
            conn.close()
        if mission and mission["status"] == "completed" and mission["scorecard_json"]:
            return json.loads(mission["scorecard_json"])
    return compute_scorecard(handle, mission_id)


def complete_mission(handle: str, mission_id: int, status: str = "completed",
                      force: bool = False, ended_at: str | None = None) -> dict:
    """Freeze compute_scorecard()'s output into scorecard_json exactly once.
    A second call on an already-completed mission returns the frozen copy
    unchanged unless force=True explicitly asks for a recompute."""
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        mission = conn.execute("SELECT * FROM mission WHERE id=?", (mission_id,)).fetchone()
        if mission is None:
            raise ValueError(f"no such mission: {mission_id}")
        if mission["status"] == "completed" and mission["scorecard_json"] and not force:
            return {
                "id": mission_id, "status": mission["status"], "already_completed": True,
                "ended_at": mission["ended_at"], "duration_seconds": mission["duration_seconds"],
                "scoring_version": mission["scoring_version"],
                "scorecard": json.loads(mission["scorecard_json"]),
            }
    finally:
        conn.close()

    scorecard = compute_scorecard(handle, mission_id)

    conn = db.connect(path)
    try:
        ended = ended_at or _now()
        duration = None
        start_dt = _parse_ts(mission["started_at"])
        end_dt = _parse_ts(ended)
        if start_dt and end_dt:
            duration = int((end_dt - start_dt).total_seconds())
        conn.execute(
            "UPDATE mission SET status=?, ended_at=?, duration_seconds=?, scoring_version=?, "
            "scorecard_json=? WHERE id=?",
            (status, ended, duration, SCORING_VERSION, json.dumps(scorecard), mission_id),
        )
        conn.commit()
        return {
            "id": mission_id, "status": status, "already_completed": False,
            "ended_at": ended, "duration_seconds": duration,
            "scoring_version": SCORING_VERSION, "scorecard": scorecard,
        }
    finally:
        conn.close()


def result_solved(handle: str, mission_id: int, objective_id: str) -> bool:
    """True iff (mission_id, objective_id) is currently recorded solved.
    False (not an error) when the target db, mission, or result row don't
    exist — same fail-closed posture as registry.is_sandbox(). Used by
    server.py's promote_to_finding wrapper to independently verify a
    sandbox_auto_confirm claim before synthesizing human_confirmed=True."""
    path = db.target_db_path(handle)
    if not path.exists():
        return False
    conn = db.connect(path)
    try:
        row = conn.execute(
            "SELECT solved FROM mission_objective_result WHERE mission_id=? AND objective_id=?",
            (mission_id, objective_id),
        ).fetchone()
        return bool(row and row["solved"])
    finally:
        conn.close()


# ---- after-action report (assembled from stored data only) ----------------------

def assemble_after_action_report(handle: str, mission_id: int) -> dict:
    """Reassemble a markdown after-action report FROM STORED DATA ONLY: the
    mission row, its scorecard (frozen if completed, else computed live),
    solved objectives with their evidence links, missed objectives, the
    mission_attempt timeline, and a "what to learn next" section grouping
    missed objectives by `objective.wstg_category_hint`.

    Mirrors report.assemble_report's anti-fabrication contract: any section
    with nothing stored behind it becomes a literal `[NO DATA: ...]` marker,
    tracked in the returned `gaps` list, and NOTHING is ever invented to fill
    a gap.
    """
    path = db.target_db_path(handle)
    if not path.exists():
        raise ValueError(f"no such target: {handle!r}")
    conn = db.connect(path)
    try:
        mrow = conn.execute("SELECT * FROM mission WHERE id=?", (mission_id,)).fetchone()
        if mrow is None:
            raise ValueError(f"no such mission: {mission_id}")
        mrow = dict(mrow)
        rows = [
            dict(r) for r in conn.execute(
                "SELECT mor.solved AS solved, mor.baseline_solved AS baseline_solved, "
                "mor.solved_at AS solved_at, mor.evidence_id AS evidence_id, "
                "o.id AS id, o.name AS name, o.category AS category, "
                "o.difficulty AS difficulty, o.native_id AS native_id, "
                "o.wstg_category_hint AS wstg_category_hint "
                "FROM mission_objective_result mor "
                "JOIN objective o ON o.id = mor.objective_id "
                "WHERE mor.mission_id=? ORDER BY o.id",
                (mission_id,),
            ).fetchall()
        ]
        attempts = [
            dict(r) for r in conn.execute(
                "SELECT * FROM mission_attempt WHERE mission_id=? ORDER BY seq", (mission_id,)
            ).fetchall()
        ]
    finally:
        conn.close()

    gaps: list[str] = []

    def _gap(label: str, what: str) -> str:
        gaps.append(label)
        return f"[NO DATA: {what}]"

    # ---- Mission ----
    mission_md = "## Mission\n\n" + "\n".join([
        f"- App: {mrow['app'] or '(unknown)'}",
        f"- Base URL: {mrow['base_url'] or '(unknown)'}",
        f"- Status: {mrow['status']}",
        f"- Human ack: {'yes' if mrow['human_ack'] else 'no'}",
        f"- Started: {mrow['started_at'] or '(unknown)'}",
        f"- Ended: {mrow['ended_at'] or '(mission still running)'}",
        f"- Duration (s): {mrow['duration_seconds'] if mrow['duration_seconds'] is not None else '(unknown)'}",
    ])

    # ---- Scorecard ----
    scorecard = mission_scorecard(handle, mission_id)
    if scorecard["total"] == 0:
        score_md = "## Scorecard\n\n" + _gap(
            "Scorecard", "no objectives are seeded/scored for this mission")
    else:
        cat_lines = "\n".join(
            f"  - {cat}: {v['solved']}/{v['total']} solved, {v['points_earned']}/{v['points_total']} pts"
            for cat, v in sorted(scorecard["by_category"].items())
        ) or "  (none)"
        score_md = (
            "## Scorecard\n\n"
            f"- Solved: {scorecard['solved']} / {scorecard['total']}\n"
            f"- Points: {scorecard['points_earned']} / {scorecard['points_total']} "
            f"({scorecard['percent']:.1f}%) — Grade {scorecard['grade']}\n"
            f"- Time to first solve (s): {scorecard['time_to_first_solve']}\n"
            f"- Attempts total: {scorecard['attempts_total']}\n"
            f"- By category:\n{cat_lines}"
        )

    # ---- Solved objectives ----
    solved_rows = [r for r in rows if r["solved"]]
    if solved_rows:
        lines = []
        for r in solved_rows:
            if r["evidence_id"] is not None:
                ev_text = f"evidence:{r['evidence_id']}"
            else:
                ev_text = _gap(
                    f"Evidence for solved objective {r['id']}",
                    f"objective {r['id']} ({r['name']}) is recorded solved but has no evidence_id linked",
                )
            credit = "credited" if not r["baseline_solved"] else "baseline (not credited)"
            lines.append(
                f"- `{r['id']}` {r['name']} — category: {r['category']}, "
                f"difficulty: {r['difficulty']}, {credit}, "
                f"solved_at: {r['solved_at'] or '(unknown)'}, evidence: {ev_text}"
            )
        solved_md = "## Solved Objectives\n\n" + "\n".join(lines)
    else:
        solved_md = "## Solved Objectives\n\n" + _gap(
            "Solved objectives", "no objectives are recorded solved for this mission")

    # ---- Missed objectives ----
    missed_rows = [r for r in rows if not r["solved"]]
    if missed_rows:
        lines = [
            f"- `{r['id']}` {r['name']} — category: {r['category']}, "
            f"difficulty: {r['difficulty']}, "
            f"wstg_category_hint: {r['wstg_category_hint'] or '(none)'}"
            for r in missed_rows
        ]
        missed_md = "## Missed Objectives\n\n" + "\n".join(lines)
    else:
        missed_md = "## Missed Objectives\n\n(none — every catalogued objective was solved)"

    # ---- Timeline ----
    if attempts:
        lines = []
        for a in attempts:
            obj_part = f", objective: {a['objective_id']}" if a["objective_id"] else ""
            lines.append(
                f"- seq {a['seq']}: [{a['phase']}] {a['tool_used'] or '(tool unspecified)'} — "
                f"{a['action_summary']} (outcome: {a['outcome']}{obj_part})"
            )
        timeline_md = "## Timeline\n\n" + "\n".join(lines)
    else:
        timeline_md = "## Timeline\n\n" + _gap(
            "Timeline", "no attempts were logged for this mission")

    # ---- What to learn next (cross-referencing wstg_category_hint) ----
    hint_names: dict[str, list[str]] = {}
    for r in missed_rows:
        hint = r["wstg_category_hint"]
        if hint:
            hint_names.setdefault(hint, []).append(r["name"])
    if hint_names:
        lines = [
            f"- `{hint}` — {len(names)} unsolved objective(s): {', '.join(names)}"
            for hint, names in sorted(hint_names.items())
        ]
        learn_md = "## What to Learn Next\n\n" + "\n".join(lines)
    elif missed_rows:
        learn_md = "## What to Learn Next\n\n" + _gap(
            "What to learn next", "missed objectives have no wstg_category_hint recorded")
    else:
        learn_md = "## What to Learn Next\n\nNothing outstanding — every catalogued objective was solved."

    title_md = f"# After-Action Report — Mission {mission_id} ({mrow['app'] or 'unknown app'})"
    markdown = "\n\n".join([title_md, mission_md, score_md, solved_md, missed_md, timeline_md, learn_md])

    return {
        "mission_id": mission_id,
        "markdown": markdown,
        "gaps": gaps,
        "scorecard": scorecard,
    }


# ---- sandbox audit (writer for the scope-guard hook, Slice 2.2) ------------------

def log_sandbox_decision(handle: str, tool_name: str, decision: str, host: str, port,
                          reason: str, command_excerpt: str, created_at: str | None = None) -> dict:
    path = db.target_db_path(handle)
    db.init_target_db(path)
    conn = db.connect(path)
    try:
        cur = conn.execute(
            "INSERT INTO sandbox_audit "
            "(tool_name, decision, host, port, reason, command_excerpt, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (tool_name, decision, host, port, reason, command_excerpt, created_at or _now()),
        )
        conn.commit()
        return {
            "id": cur.lastrowid, "tool_name": tool_name, "decision": decision,
            "host": host, "port": port, "reason": reason,
        }
    finally:
        conn.close()


if __name__ == "__main__":  # tiny self-check; real coverage is tests/test_mission.py
    import os
    import tempfile

    os.environ["BB_DATA_DIR"] = tempfile.mkdtemp()
    handle = "selftest"
    db.init_target_db(db.target_db_path(handle))

    seeded = seed_objectives(handle, [
        {"id": "js-1", "app": "juiceshop", "native_id": "1", "name": "Score Board",
         "category": "misc", "difficulty": 1, "description": "Find the score board"},
        {"id": "js-2", "app": "juiceshop", "native_id": "2", "name": "SQL Injection login",
         "category": "injection", "difficulty": 3, "description": "Bypass login via SQLi"},
    ])
    assert seeded == {"seeded": 2}

    mission = create_mission(handle, "juiceshop", "http://localhost:3000",
                              baseline=["js-1"], human_ack=True)
    assert mission["objectives_seeded"] == 2

    downgrade = record_objective_result(handle, mission["id"], "js-1", solved=False,
                                         evidence_id=None)
    assert downgrade["refused_downgrade"] is True and downgrade["solved"] is True

    try:
        record_objective_result(handle, mission["id"], "js-2", solved=True, evidence_id=None)
        raise SystemExit("unevidenced solve not rejected")
    except ValueError:
        pass

    record_objective_result(handle, mission["id"], "js-2", solved=True, evidence_id=1)

    for i in range(6):
        attempt = log_attempt(handle, mission["id"], phase="exploit",
                               action_summary=f"try {i}", objective_id="js-2")
    assert attempt["over_cap"] is True

    card = compute_scorecard(handle, mission["id"])
    assert card["solved"] == 2 and card["total"] == 2
    assert card["points_earned"] == POINTS_BY_DIFFICULTY[3]  # js-1 baseline, not credited
    assert card["points_total"] == POINTS_BY_DIFFICULTY[1] + POINTS_BY_DIFFICULTY[3]

    done = complete_mission(handle, mission["id"])
    assert done["scorecard"]["points_earned"] == POINTS_BY_DIFFICULTY[3]
    record_objective_result(handle, mission["id"], "js-1", solved=True, evidence_id=99)
    frozen = mission_scorecard(handle, mission["id"])
    assert frozen["points_earned"] == POINTS_BY_DIFFICULTY[3], "completed scorecard must stay frozen"

    audit = log_sandbox_decision(handle, "Bash", "allow", "localhost", 3000,
                                  "in-sandbox host+port", "curl localhost:3000")
    assert audit["decision"] == "allow"

    print("mission self-check ok")
