# Phase 2 — Detailed Build Plan

**AI-assisted bug bounty research system · human-in-the-loop · authorized programs only**

Date: 2026-07-28
Status: For your manual review. No code written yet. Phase 3 (build) starts only after you approve this.

Supersedes nothing; builds on `docs/phase-1-rnd-report.md` (approved).

---

## 0. What was decided (so this plan stands alone)

| Decision | Value | Source |
|---|---|---|
| Delivery shape | One Claude Code **plugin**: MCP server + skills + PreToolUse hook + reference data | Phase 1 rec, approved |
| Billing | Interactive Claude Code on **Pro** (Max if needed). No API key. MCP server makes **zero** LLM calls. | Phase 1 §6, approved |
| Tool posture | **Ingest-only** v1. Reads files you produce + Burp proxy history. Generates no traffic. | Phase 1 §7, approved |
| Scope of targets | **Web + API**. Source-reading supported. Mobile/binaries deferred. | Q14 |
| Feature set | **Everything** from Phase 1 + extras, structured so core lands first and features are independently removable | Q17=c, this plan §2 |
| Vuln playbooks | **All**, tiered (Tier 1 deep, Tier 2 lighter), nothing excluded | Q18 |
| Proxy | **Burp Community** for v1; Caido documented as v2 swap | Q19, my call |
| Storage | **SQLite** source of truth, one DB per target, Markdown export | Phase 1 §8 |
| Runtime | Claude Code + MCP server on **Windows** (Python 3.13); recon tools in a **VirtualBox Linux VM**; files cross via shared folder | Q20 |
| Assumptions granted | Burp MCP works on Community; CVP covers Pro/Max | Your instruction (still labelled, not treated as fact) |

**Three assumptions I'm building on, each isolated so a wrong one costs little:**

1. *Burp MCP on Community works* — enters as a **setup step in Milestone 7**, not a design dependency. If it's Pro-only, only that milestone's proxy feature is affected; everything else is untouched.
2. *CVP covers Pro/Max* — v1 is analysis/organization/writing and shouldn't trip exploitation safeguards, so this assumption is load-bearing for **nothing in v1**. It only matters if you later add exploit-dev help.
3. *bounty-targets-data remains available* — public repo, but the scope-intake code has a manual-entry fallback so a fetch failure never blocks you.

---

## 1. Design principles (the rules the code obeys)

These are enforcement rules for Phase 3, not aspirations.

1. **The model proposes; code decides and remembers.** Anything that must be correct (scope, state, redaction) is deterministic Python. Anything that benefits from judgment (methodology, correlation, drafting) is model-driven. The two never swap jobs.
2. **The MCP server never calls an LLM and never makes unsolicited network calls.** Its only outbound calls are to a fixed allowlist (the `bounty-targets-data` host and, optionally, platform scope APIs). This keeps you on the subscription and shrinks attack surface.
3. **Deny-by-default at every trust boundary.** Unknown host → denied. Unparseable input → rejected, not guessed. Missing evidence → gap marker, not filler.
4. **Minimal dependencies.** Python stdlib (`sqlite3`, `json`, `re`, `pathlib`, `urllib`, `hashlib`) plus exactly one runtime dependency: the official `mcp` SDK. One dev dependency: `pytest`. Every added package is justified in writing or not added.
5. **Small blast radius.** One DB file per target. Deleting a program is one `rm`. No cross-target reads without an explicit switch.
6. **Target-derived content is data, never instructions.** Ingested content is delimited and labelled everywhere it enters context.
7. **Each feature is a removable module.** Milestones 3–7 can each be deleted without breaking Milestones 1–2. This is what makes "try it, then cut what doesn't earn its place" real.

**What we deliberately do NOT build** (YAGNI, stated so it's a decision not an oversight):
- No autonomous hunting loop, no scanner, no traffic generation.
- No background/daemon/cron process. Interactive only.
- No web UI, no separate app, no server you log into.
- No ORM, no migration framework (hand-written schema + a tiny version pragma).
- No abstraction with one implementation. No plugin-for-the-plugin.
- No payout estimates anywhere (biases toward severity inflation).
- No mobile/binary/web3 features.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Claude Code (Windows, interactive, Pro subscription)            │
│                                                                  │
│  You ── drive ──►  skills (methodology, workflow, teaching)      │
│                        │ read/write state via                    │
│                        ▼                                          │
│                    MCP tools ────────────►  bb-mcp server        │
│                        │                    (Python, stdio)      │
│                        │                        │                │
│   every tool call      │                        ▼                │
│        │               │                   SQLite case files     │
│        ▼               │                   (one per target)      │
│   PreToolUse hook ◄────┘                        ▲                │
│   (scope-guard.py)                              │                │
│        │  deny / defer                          │                │
│        ▼                                    ingest parsers       │
│   blocks out-of-scope                       (files from VM       │
│   actions before they run                    shared folder)      │
│                                                                  │
│   Burp Community (Windows host) ──MCP──► proxy history (read)    │
└─────────────────────────────────────────────────────────────────┘
```

**Three layers, three jobs (unchanged from Phase 1 §7, Option 3):**

| Layer | Question it answers | Made of | Can it be fooled by a prompt? |
|---|---|---|---|
| PreToolUse hook | "May this happen?" | Python script | No — runs outside the model |
| MCP server | "What is true?" | Python + SQLite | No — no LLM in it |
| Skills | "What should we do, and how?" | Markdown | Yes — so it's never the enforcement layer |

**Data flow for the core loop (`/bb:next`):**
1. Hook loads active target's scope on startup (cheap, cached).
2. You ask "what's next" → skill calls `mcp__bb__next_actions(target)`.
3. MCP server queries coverage ledger: endpoints × test-cases where status = untested, ranked by a simple value heuristic.
4. Returns ~15 rows (not a data dump).
5. Skill presents them with the *why* for each, drawing methodology from the relevant playbook skill.
6. You test one (manually / in the VM). You record the result → `mcp__bb__record_coverage(...)`.
7. Ledger updates. Next `/bb:next` reflects it.

---

## 3. Repository layout

```
bug-bounty/
├─ docs/
│  ├─ phase-1-rnd-report.md          (done)
│  ├─ phase-2-build-plan.md          (this file)
│  └─ setup.md                        (Milestone 8)
├─ plugin/                            (the installable plugin)
│  ├─ .claude-plugin/
│  │  └─ plugin.json                  manifest: name, version, mcp + hook wiring
│  ├─ .mcp.json                       registers the bb-mcp stdio server
│  ├─ mcp/
│  │  ├─ server.py                    FastMCP tool definitions (thin)
│  │  ├─ db.py                        schema, connection, migrations pragma
│  │  ├─ registry.py                  global target registry + active-target state
│  │  ├─ scope.py                     PURE deterministic scope matcher
│  │  ├─ ingest.py                    nuclei/httpx/subfinder/ffuf/katana/burp parsers
│  │  ├─ redact.py                    PURE secret/PII scrubber
│  │  ├─ coverage.py                  ledger queries + next-action ranking
│  │  ├─ correlate.py                 note/lead/primitive graph queries
│  │  ├─ report.py                    grounded draft assembly + gap markers
│  │  └─ scopefetch.py                bounty-targets-data pull (allowlisted host)
│  ├─ hooks/
│  │  └─ scope-guard.py               PreToolUse: deny out-of-scope
│  ├─ skills/
│  │  ├─ bb-target/SKILL.md           create/switch/list targets
│  │  ├─ bb-scope/SKILL.md            intake + parse policy + refresh
│  │  ├─ bb-next/SKILL.md             the core "what should I do next" loop
│  │  ├─ bb-recon/SKILL.md            ingest + triage recon output
│  │  ├─ bb-correlate/SKILL.md        surface links; bank primitives
│  │  ├─ bb-code/SKILL.md             JS + source-available reading
│  │  ├─ bb-report/SKILL.md           draft (full | critique) grounded-only
│  │  ├─ bb-gate/SKILL.md             pre-submission argue-against + checklist
│  │  ├─ bb-learn/SKILL.md            report study + recognition drills + hunt-along
│  │  ├─ bb-review/SKILL.md           post-session retrospective + coverage report
│  │  ├─ bb-hunt/SKILL.md             router → the right playbook
│  │  └─ playbooks/                   one SKILL.md per vuln class (Tier 1 + Tier 2)
│  │     ├─ idor-bola/SKILL.md
│  │     ├─ access-control/SKILL.md
│  │     ├─ ssrf/SKILL.md
│  │     ├─ business-logic/SKILL.md
│  │     └─ … (full list in §8)
│  └─ reference/
│     ├─ wstg-checklist.json          test-case taxonomy backbone
│     ├─ bounty-overlay.json          bounty-specific cases WSTG lacks
│     └─ report-signals.json          "first-noticed signal" per class (teaching)
├─ tests/
│  ├─ test_scope.py                   scope matcher truth table (security-critical)
│  ├─ test_ingest.py                  parser fixtures
│  ├─ test_redact.py                  redaction truth table
│  ├─ test_hook.py                    pipe JSON → assert decision
│  └─ fixtures/                       sample tool outputs
└─ README.md
```

**Dev vs installed:** during Phase 3 the skills/hook also work if dropped in the project's `.claude/`, so we test without formal install. Final packaging (Milestone 8) makes it a proper plugin installable via `/plugin`.

---

## 4. The MCP server

**Transport:** stdio (no listening socket — nothing to portscan, nothing to bind). **Framework:** FastMCP from the official `mcp` package. **Process model:** started by Claude Code from `.mcp.json`; lives only during the session.

### 4.1 Tool catalogue (the full v1 set)

Grouped by feature. Each tool returns narrow, structured data — never a raw dump. Signatures are indicative; Phase 3 finalizes exact params.

**Targets & scope**
- `create_target(handle, platform, confidentiality)` → target_id
- `switch_target(handle)` → sets active target (writes active-target state the hook reads)
- `list_targets()` → rows
- `set_scope_rules(target, rules[])` → count *(rules come parsed from policy by the skill, confirmed by you)*
- `refresh_scope(target)` → pulls latest from bounty-targets-data, diffs, reports changes
- `check_scope(host, path?)` → (in_scope: bool, reason) *(same function the hook uses; exposed so skills can pre-check before proposing anything)*
- `scope_status(target)` → {fetched_at, stale: bool, rule_counts}

**Recon & coverage**
- `ingest_file(target, path, kind)` → {parsed, inserted, skipped} *(kind ∈ nuclei|httpx|subfinder|ffuf|katana|burp-xml)*
- `list_endpoints(target, filter)` → rows (filter by param presence, method, auth, tested status)
- `record_coverage(target, endpoint_id, test_case_id, status, evidence_id?, note?)` → ok *(status ∈ untested|testing|not-vulnerable|suspicious|confirmed|n-a)*
- `coverage_summary(target)` → per-category % tested, untouched surfaces
- `next_actions(target, limit=15)` → ranked untested (endpoint, test_case, why) rows

**Findings graph**
- `add_note(target, body, endpoint_id?)` → note_id
- `add_lead(target, hypothesis, confidence, note_ids[])` → lead_id
- `add_primitive(target, capability, description, evidence_id?)` → primitive_id
- `promote_to_finding(target, lead_id, human_confirmed=true, ...)` → finding_id *(requires human_confirmed; the model cannot create a finding on its own)*
- `list_leads / list_primitives / list_findings(target, ...)` → rows
- `suggest_correlations(target)` → candidate links (item_a, item_b, rationale, confidence) — proposals only

**Evidence**
- `store_evidence(target, kind, content_or_path)` → evidence_id *(runs redaction first; stores file + sha256; DB holds pointer + summary)*
- `get_evidence(target, evidence_id)` → path + redacted body

**Reporting**
- `assemble_report(target, finding_id, platform)` → draft with `[YOU MUST FILL THIS IN]` gap markers where evidence is missing
- `report_checklist(target, finding_id, platform)` → pass/fail per requirement

**Housekeeping**
- `export_markdown(target)` → writes Markdown tree from DB
- `gitignore_guard()` → checks case-file dir isn't in a git repo with a remote; warns

### 4.2 Database schema

One `<handle>.db` per target (SQLite, stdlib). A tiny global `registry.db` lists targets and the active one. Schema versioned by `PRAGMA user_version` — no migration framework.

```sql
-- registry.db (global)
CREATE TABLE target (
  id INTEGER PRIMARY KEY, handle TEXT UNIQUE, platform TEXT,
  confidentiality TEXT,           -- public | private | nda
  db_path TEXT, scope_fetched_at TEXT, created_at TEXT, active INTEGER DEFAULT 0);

-- <handle>.db (per target)
CREATE TABLE scope_rule (
  id INTEGER PRIMARY KEY, pattern TEXT, asset_type TEXT,
  in_scope INTEGER,               -- 1 in, 0 out (out takes precedence at match time)
  source TEXT, added_at TEXT);
CREATE TABLE endpoint (
  id INTEGER PRIMARY KEY, method TEXT, url TEXT, host TEXT, path TEXT,
  params TEXT, auth_hint TEXT, first_seen TEXT, source TEXT,
  UNIQUE(method, url));
CREATE TABLE test_case (               -- seeded from reference JSON per target
  id TEXT PRIMARY KEY, category TEXT, title TEXT, tier INTEGER, applies_to TEXT);
CREATE TABLE coverage (
  id INTEGER PRIMARY KEY, endpoint_id INTEGER, test_case_id TEXT,
  status TEXT, tested_at TEXT, evidence_id INTEGER, note TEXT,
  UNIQUE(endpoint_id, test_case_id));
CREATE TABLE note   (id INTEGER PRIMARY KEY, body_md TEXT, endpoint_id INTEGER, created_at TEXT);
CREATE TABLE lead   (id INTEGER PRIMARY KEY, hypothesis TEXT, confidence TEXT, status TEXT, created_at TEXT);
CREATE TABLE lead_note (lead_id INTEGER, note_id INTEGER);
CREATE TABLE primitive (id INTEGER PRIMARY KEY, capability TEXT, description TEXT, evidence_id INTEGER, created_at TEXT);
CREATE TABLE finding (
  id INTEGER PRIMARY KEY, title TEXT, severity TEXT, status TEXT,
  body_md TEXT, human_confirmed INTEGER, created_at TEXT);
CREATE TABLE evidence (
  id INTEGER PRIMARY KEY, kind TEXT, blob_path TEXT, summary TEXT,
  redacted INTEGER, sha256 TEXT, created_at TEXT);
-- FTS5 over note.body_md and finding.body_md (stdlib) for search
```

The `coverage` table is the asset nothing else in the ecosystem has. `(endpoint, test_case, status)` turns "what haven't I tested" into a `SELECT`.

### 4.3 Scope matcher (`scope.py`) — the security-critical core

Pure function, no I/O, exhaustively unit-tested:

```
is_in_scope(host, path, rules) -> (bool, reason):
  1. Normalize host (lowercase, strip port, punycode).
  2. If host matches ANY in_scope=0 rule  → (False, "explicit out-of-scope: <rule>")
  3. If host matches ANY in_scope=1 rule  → (True,  "matches <rule>")
  4. Otherwise                             → (False, "no matching in-scope rule (deny-by-default)")
```

Rules: exact host, wildcard (`*.example.com` matches sub.example.com, not example.com — matching apex requires its own rule), IPv4/CIDR. Out-of-scope precedence is step-ordering, encoded, not inferred. Truth table lives in `tests/test_scope.py` and is the first thing written (TDD).

### 4.4 Ingest (`ingest.py`)

One parser per tool, each `file → list[dict] → DB`. Input treated as hostile:
- Size cap (reject > N MB).
- `json.loads` per line for JSONL (nuclei/httpx/katana); no `eval`, no `pickle`, no unsafe YAML.
- Burp XML via `xml.etree` with entity expansion disabled (billion-laughs guard).
- Unknown fields ignored, not trusted. Control chars stripped.
- Dedup on `(method, url)`.

### 4.5 Redaction (`redact.py`)

Deterministic, runs before any evidence is stored:
- Known token shapes: `Authorization:` values, `Cookie:`/`Set-Cookie:`, `api[_-]?key`, bearer tokens, JWTs, AWS keys.
- High-entropy string heuristic for the long tail.
- Obvious PII: emails, things shaped like card numbers.
- Redaction is logged (what class was redacted, not the value). Truth table in `tests/test_redact.py`.

---

## 5. The scope-guard hook

`hooks/scope-guard.py`, wired as a `PreToolUse` hook matching `Bash` and any network-capable MCP tools (e.g. a future proxy `send_request`). In ingest-only v1 it mostly guards `Bash`.

**Logic:**
```
read JSON on stdin
if no active target set: defer            (nothing to enforce against)
extract candidate hosts/URLs from tool_input (regex: http(s)://…, bare domains in known flags)
if none found: defer                       (non-network command)
load active target scope (cached)
for each host:
    in_scope, reason = scope.is_in_scope(host, path, rules)
    if not in_scope:
        emit permissionDecision=deny, reason
        exit 0
emit nothing → defer to normal permission flow
```

**Override (for false-denies, which will happen):** a logged escape hatch — you invoke `mcp__bb__scope_override(host, reason)` which writes a timestamped, single-use allowance the hook honors once. No global "disable scope" switch (it would get left on). Every override is recorded in the target DB.

**Stated honestly (from Phase 1 §C3, §9.2):** command parsing is best-effort. `curl $(…)` and base64-encoded hosts can evade extraction. The hook is a strong guard against *drift and mistakes* — the real risk here, since nobody's trying to evade it — not a sandbox. Ingest-only v1 keeps the stakes low; if command-execution is ever added, the hook's parsing coverage gets its own design pass.

**Startup staleness check:** if active target's `scope_fetched_at` is older than 7 days, the hook injects `additionalContext` noting the scope may be stale, so the model surfaces it to you.

---

## 6. Skills — specifications

Each skill: purpose, trigger, MCP tools it uses, and its one firm rule. Progressive disclosure means all of these cost ~nothing until invoked.

| Skill | Purpose | Firm rule |
|---|---|---|
| **bb-target** | Create/switch/list targets; set confidentiality | Private/NDA targets get a visible marker every session |
| **bb-scope** | Parse a policy page into scope rules; pull platform scope; refresh | Rules are **proposed**, you confirm before `set_scope_rules` |
| **bb-next** | The core loop: rank untested surface, explain the why | Only suggests in-scope, untested items; explains each |
| **bb-recon** | Ingest tool output, triage into "interesting" | Cites source rows; never invents endpoints |
| **bb-correlate** | Surface note/lead/primitive links; bank primitives | Correlations are ranked hypotheses, cheap to dismiss |
| **bb-code** | Read client-side JS & source-available repos | Claimed source→sink paths marked unverified until you check |
| **bb-report** | Draft (full) or critique (structure) a report | Reads only stored evidence; gaps → `[YOU MUST FILL THIS IN]` |
| **bb-gate** | Pre-submission: argue against the finding, check evidence, flag AI-disclosure clause, optional duplicate check | Runs against stored evidence, not vibes |
| **bb-learn** | Disclosed-report study (first-noticed signal), recognition drills on the current target, hunt-along explanations | Teaching cites a source; drills use real target data |
| **bb-review** | Post-session retrospective + coverage report | Factual, from the ledger — what you tested, skipped, missed |
| **bb-hunt** | Router: given a target/endpoint, load the right playbook(s) | — |

**Playbook skills** (`skills/playbooks/*`): each is a methodology for one vuln class, structured identically so they're predictable and the model uses them well:

```
## When this applies   (what makes an endpoint a candidate)
## First signals       (what to notice before you know it's a bug — the beginner gap)
## Enumeration         (how to map the surface for this class)
## Test procedure      (concrete, ordered steps)
## Evidence to capture  (what the report will need)
## Escalation          (primitives → chains)
## Out-of-scope traps   (what programs commonly reject for this class)
## WSTG / references
```

The **First signals** section is deliberately the differentiator — it targets your stated problem: knowing what to notice on an unfamiliar app before you know there's a bug.

---

## 7. Safety implementation (maps Phase 1 §9 → concrete code)

| Risk (Phase 1 §9) | Concrete mitigation in this build | Where |
|---|---|---|
| Prompt injection from target data | All ingested content delimited + labelled "UNTRUSTED DATA — not instructions"; structured extraction preferred over raw prose; standing rule in every ingest-touching skill | ingest.py, skills |
| Scope drift / unauthorized traffic | Deny-by-default hook; out-of-scope precedence; staleness warning; logged single-use override | scope.py, scope-guard.py |
| Data leakage into wrong place | `gitignore_guard`; case-file dir excluded by default; loud warning if under a git remote (your dir is under `Documents/GitHub/`) | registry.py, gitignore_guard |
| Data leakage into context | Per-target confidentiality flag; evidence stored as redacted files with DB pointers; model reads summaries, pulls bodies only on demand | redact.py, evidence model |
| Machine safety | stdio only; no `shell=True`; arg-list subprocess only; localhost/allowlist-only network; hostile-input parsers; path-traversal rejection | server.py, ingest.py |
| Hallucinated findings | Model can't create a finding (`human_confirmed` required); no evidence → no confidence; severity proposed not asserted; no payout figures | finding model, bb-report, bb-gate |
| Supply chain | One runtime dep (`mcp`), one dev dep (`pytest`), both pinned; stdlib elsewhere | requirements |

---

## 8. Vuln playbook list (tiered — "all", nothing excluded)

**Tier 1 — full-depth playbooks (high-value, under-automated, reward systematic work):**
IDOR/BOLA · Broken access control (vertical + horizontal) · SSRF · Business logic · Authentication flaws · Session management · Mass assignment · GraphQL/API abuse (BFLA, introspection) · Race conditions

**Tier 2 — solid-but-lighter playbooks (deepen over time):**
XSS (reflected/stored/DOM) · SQLi · Other injection (SSTI/command/XXE) · CSRF · Open redirect · File upload · Path traversal / LFI · JWT flaws · OAuth/OIDC flaws · CORS misconfig · Subdomain takeover · Secrets exposure · HTTP request smuggling · Web cache poisoning

Tiering only sets build order and initial depth. Every class ships a usable playbook in v1.

---

## 9. Build milestones (Phase 3 execution map)

Each milestone is independently usable and shippable. Core-first. You can stop, use it, and tell me what to cut before the rest is built.

| # | Milestone | Delivers | Depends on | Usable on its own? |
|---|---|---|---|---|
| 1 | **Skeleton + scope** | Plugin structure, MCP server boots, DB schema, `scope.py` + hook + their tests | — | Scope enforcement works |
| 2 | **Core loop** | Targets, scope intake, coverage ledger, `bb-next` | 1 | **Yes — solves #7** |
| 3 | **Recon ingest** | All parsers, `bb-recon`, triage | 2 | Yes |
| 4 | **Findings graph** | notes/leads/primitives, `bb-correlate` | 2 | Yes |
| 5 | **Reporting** | `bb-report` (full+critique), `bb-gate`, evidence + redaction | 4 | Yes |
| 6 | **Learning + review** | `bb-learn`, `bb-review`, target selection, `report-signals.json` | 2 | Yes |
| 7 | **Code + proxy + playbooks** | `bb-code`, Burp MCP wiring, full playbook library | 2 | Yes |
| 8 | **Hardening** | Full test pass, `gitignore_guard`, `setup.md`, plugin packaging, security self-review | all | — |

**Milestone 1 & 2 together are the irreducible core** (~40% of the work, per Phase 1). If your appetite changes after using them, Milestones 3–7 are each optional.

---

## 10. Phase 3 orchestration (how the agents build it)

Per your instruction to use multiple agents, and the research cap of **≤3 concurrent** (4+ breaks compaction — Phase 1 §C4).

**Model:** each milestone is planned, then built by 1–3 parallel agents on **independent files**, then reviewed before the next milestone. You approve at milestone boundaries (matches your "review at end of each phase" style, applied at finer grain so a wrong turn is caught early).

**Parallelism rule:** agents only run in parallel when their files don't overlap. Example, Milestone 3: agent A writes `ingest.py` parsers, agent B writes `tests/test_ingest.py` + fixtures, agent C writes `bb-recon/SKILL.md`. No shared file, no collision.

**TDD for the security-critical trio** (scope, redact, hook): tests written first, from the truth tables in this plan, then implementation to green. Non-negotiable — these are the parts that keep you safe and legal.

**Per-milestone loop:**
1. I write a short task spec per agent (files, contract, test to pass).
2. Spawn ≤3 agents.
3. Run the tests. Report actual output (pass/fail), not "should work."
4. Show you the diff summary. You approve → next milestone.

**Verification before any "done" claim:** every milestone ends with the test command and its real output pasted back. No green claim without green output.

---

## 11. Phase 4 (review & safety validation) — planned now so Phase 3 builds toward it

When the build is complete, Phase 4 will:
1. **Run the full test suite**, report real output.
2. **Security self-review** of the MCP server and hook: subprocess calls, path handling, network allowlist, parser hostile-input handling, redaction coverage, no `ANTHROPIC_API_KEY` reliance.
3. **Prompt-injection spot-check**: feed the ingest parsers a fixture containing embedded "instructions" and confirm they're stored as inert data, not acted on.
4. **Scope-guard adversarial pass**: a set of tricky commands (redirects, lookalike hosts, encoded hosts) piped through the hook; document what it catches and — honestly — what it doesn't.
5. **Leakage check**: confirm `gitignore_guard` fires under `Documents/GitHub/`, confirm private-target data path stays local, confirm redaction on stored evidence.
6. **Machine-safety check**: no unexpected listeners, no writes outside the data dir, dependency audit.
7. Written report with verified/assumed labels, same as Phase 1.

---

## 12. Open items carried into Phase 3 (none block starting)

1. **Burp MCP on Community** — verify at Milestone 7 setup. Isolated there.
2. **Exact plugin MCP-registration field** (`plugin.json` vs `.mcp.json`) — confirm against current Claude Code version at Milestone 1. Mechanical.
3. **VirtualBox shared-folder path** for ingest — documented in `setup.md`; you'll set the folder, the MCP reads Windows-side.
4. **WSTG → test_case seeding** — how many cases in v1's `wstg-checklist.json`. I'll seed a practical subset in Milestone 2 and grow it.
5. **Burp on host vs in VM** — `setup.md` covers both; default recommendation is Burp on the Windows host so the MCP connects on localhost.

---

## 13. What "done" looks like for v1

- You can register a program, pull/parse its scope, and the hook blocks out-of-scope commands.
- You point the system at your recon output and Burp history; it builds a coverage ledger.
- `/bb:next` always gives you a ranked, explained next action on the target you're on — no more blank-app paralysis.
- You bank primitives and the system resurfaces relevant ones.
- It drafts or critiques a report from real stored evidence, with gaps marked, never invented.
- Before you submit, it argues against your own finding and checks the program's requirements.
- It teaches from disclosed reports and from the target you're actually on.
- Everything runs on your Pro subscription, no API key, generating zero traffic to any target.

---

**End of Phase 2 plan. Review this, tell me what to change, and on your approval I start Phase 3 at Milestone 1.**
