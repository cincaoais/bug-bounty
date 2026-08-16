# Legal Action-Class Gateway — design

**Date:** 2026-08-10
**Status:** approved, implementing
**Author:** brainstormed with the user (posture: "both now and later"; all four classes hard-gated; deny + logged override; enforce in sandbox; add a brief `bb-legal` skill)

## Problem

The existing `plugin/hooks/scope-guard.py` is a strong **host-scope** gateway: it answers *"is the destination host authorized?"* (CCA 1997 s.3 unauthorised access) with deny-by-default, a fail-closed sandbox path, and escape detection (`$(...)`, decode pipes, proxy redirects). What it does **not** enforce is the *shape of the action* against a host that is otherwise in scope. Several Malaysian statutes bite on action-shape, not destination:

- **CCA 1997 s.5** — unauthorised modification (destructive writes/deletes).
- **CMA 1998 s.233** — improper use of network facilities (DoS-shaped: flooding, brute-force, high-rate scanning). The repo's own field notes name this the top ban/sue risk.
- **CCA 1997 s.6 / s.8** — wrongful communication of access codes; s.8 shifts the burden onto anyone found in possession of credentials.
- **PDPA 2010 (as amended 2024/25)** — bulk extraction/handling of real personal data.
- **Cyber Security Act 2024** — CSSP licence for prescribed penetration-testing services; and **CCA s.9** extraterritorial reach. These are standing legal *status* questions, not per-action shapes.

The user's concern is *accidental* breakout — drift after compaction, a wildcard that matched too much, an autonomous loop that escalates. The methodology skills already say "non-destructive PoC only," but that is model-level discipline, exactly the thing that drifts. The fix must live at the one enforcement point outside the model.

## Approach (chosen)

Add a **legal action-class layer** as a second, independent check inside the existing `scope-guard.py` hook. It mirrors the proven `scope.py` / `sandbox.py` architecture: a pure, deterministic, I/O-free module driven by truth tables, wired into the hook that already matches every traffic-generating tool (Bash, `mcp__burp__send_*`, WebFetch, `mcp__claude-in-chrome__*`, `mcp__hexstrike__*`).

Rejected alternatives:
- **Model-level only** (a skill + expanded `bb-gate` checklist): this is the drift failure mode the user is worried about; not a hard gateway.
- **OS/network-level enforcement** (egress firewall, seccomp): strongest containment but the wrong layer — it cannot tell a destructive HTTP verb from a benign one (both are TCP:443). The sandbox already does egress isolation; that stays as the containment backstop. This gateway is orthogonal and complementary.

## Components

### 1. `plugin/mcp/legalgate.py` (new, pure)

Same posture as `scope.py`/`sandbox.py`: no I/O, no network, no LLM, no imports from `db`/`registry`. One public function:

```python
@dataclass(frozen=True)
class Violation:
    gate_class: str    # "destructive" | "dos" | "credential" | "pii"
    statute: str       # e.g. "CCA 1997 s.5"
    signature: str     # the matched token, for the deny message + audit
    reason: str        # human-readable why-this-is-gated

def classify(tool_name: str, tool_input: dict) -> list[Violation]: ...
```

`classify` scans the searchable text of the call — the **raw command** for Bash, **structured target/body fields plus the stringified input** for Burp/HexStrike/others — and returns every matched violation (a call may hit more than one class). Detection is deliberately **conservative: high-confidence, rarely-legitimate-in-a-PoC shapes only**, because over-blocking trains the user to reflex-override and destroys the gate's value.

**Signature tables (v1):**

| Class | Statute | Matches | Deliberately excluded |
|---|---|---|---|
| `destructive` | CCA s.5 | HTTP mutating verb: `-X DELETE/PUT/PATCH`, `--request DELETE/PUT/PATCH`, an HTTP request-line `^(DELETE\|PUT\|PATCH) … HTTP/`; SQL DDL/DML keywords `DROP TABLE/DATABASE/SCHEMA`, `TRUNCATE`, `DELETE FROM`, `ALTER TABLE`; sqlmap target-mutating flags `--os-shell/--os-cmd/--os-pwn/--file-write/--file-dest/--sql-query`; WebGoat `restartlesson.mvc`; **catastrophic local shell** (machine-safety, adjacent to s.5): `rm -rf` targeting `/`, `~`, `$HOME`, or a bare `*`; `mkfs`; `dd … of=/dev/…`; `> /dev/sd…`; fork bomb | plain `POST`/`GET`/reads; `UPDATE…SET` / `INSERT INTO` (too common in benign bodies → FP risk); ordinary local `rm file`/`rm -rf ./build` |
| `dos` | CMA s.233 | brute-force tools `hydra`/`medusa`/`patator`/`ncrack`; flood/stress tools `ab`/`wrk`/`siege`/`slowloris`/`slowhttptest`/`t50`; `hping3 --flood`; explicit high rate/concurrency flags over threshold — `--rate`/`--min-rate`/`-rl`/`--rate-limit` > 100, `-t`/`-c`/`--threads` > 50; `nmap -T4`/`-T5` | default-concurrency `ffuf`/`nuclei`/`gobuster` recon (no explicit high flag → uses tool default → not flagged) |
| `credential` | CCA s.6/s.8 | offline cracking `hashcat`/`john`; harvest/relay `responder`/`mimikatz`/`secretsdump`/`impacket-secretsdump`/`lsassy`; `crackmapexec`/`nxc` with `--sam`/`--lsa`/`--ntds` | reading a JWT, inspecting a cookie value |
| `pii` | PDPA | `sqlmap --dump`/`--dump-all`; `--dump` combined with `-T (users\|customers\|accounts\|members\|clients\|patients\|profiles)`; a mass `SELECT … FROM (users\|customers\|…)` over a personal-data table | single-record proof reads |

Thresholds apply only to **explicitly passed** flags: a command that omits `-t`/`--rate` runs at the tool default and is never flagged. Numeric flag values are parsed; a non-numeric or absent value is not a match.

Honest limits (documented in the module docstring, same as `scope.py`): a payload encoded past the regex, or a credential the model *writes into a note*, will not be caught here. `$(...)`/decode-pipe escapes are already denied by `sandbox.is_ambiguous` in sandbox mode. Storage-side leakage is covered by `redact.py`, which scrubs every stored evidence/note. The layers compose as defense in depth; none is claimed to be complete alone.

### 2. Enforcement wiring in `scope-guard.py`

`decide()` gains a legal layer that runs **first, in both modes, independent of host candidates** — because `hashcat hash.txt` or `rm -rf /` has no network target but must still be caught:

```
decide(event):
    active = registry.active_target()
    if active is None: return None            # no session → defer (unchanged)
    legal = _legal_decision(event, active)    # NEW
    if legal is not None: return legal        # deny (or None = cleared, continue)
    if registry.is_sandbox(): return _decide_sandbox(event)   # existing
    ... existing real-program scope body ...
```

`_legal_decision`:
1. `violations = legalgate.classify(tool_name, tool_input)`; if none → return None.
2. Distinct violated classes. For each, check `registry.has_legal_override(cls)` (peek).
3. If **all** covered → consume each via `registry.take_legal_override(cls)`, audit the override-allow, return None (cleared; fall through to host/scope logic).
4. Else → `deny` naming class + statute + matched signature + `"run mcp__bb__legal_override('<class>', '<why>') then retry"`.

Runs in **sandbox mode too** (enforce, per the user's call): trains the correct reflex and is defense-in-depth if containment fails. Overrides never weaken host containment — the layers are orthogonal (an overridden destructive call still only reaches the sandbox host:port the existing sandbox path allows). Sandbox legal decisions are written to `sandbox_audit` (reusing `mission.log_sandbox_decision`), like the host decisions already are.

### 3. Standing attestation (CSSP + s.9), one-time not per-action

New guarded columns on `target` (added exactly like `mode`/`sandbox_app`): `jurisdiction`, `tester_location`, `cssp_licensed` (int), `authorization_ref`, `attested_at`. Making "both now and later" concrete: **in bounty mode, the first traffic-generating action (network candidates present) is denied until `attested_at` is set once** for the active target. Sandbox mode never requires attestation (it's local training, no statutory exposure). This is a single conscious gate on going live, not per-action friction. `SessionStart` surfaces cross-border / MY-jurisdiction-without-CSSP as a prominent warning (context, not a block — licensing is a status question).

Order in the bounty body: `candidates = extract_targets(...)`; if none → None; **if not attested → deny(attest)**; then the existing scope loop.

### 4. State — `registry.py` + `db.py`

- `db.py`: bump `SCHEMA_VERSION` to 3. Add to `SCHEMA_REGISTRY` a `legal_override` table mirroring `scope_override` but keyed by class, plus a `used_at` timestamp for the legal audit trail:
  ```sql
  CREATE TABLE IF NOT EXISTS legal_override (
    id INTEGER PRIMARY KEY, gate_class TEXT NOT NULL, reason TEXT,
    created_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, used_at TEXT
  );
  ```
  Add the five attestation columns to `target` via `_add_column_if_missing` in `init_registry`.
- `registry.py`: `add_legal_override(gate_class, reason)`, `has_legal_override(gate_class)` (peek, no consume), `take_legal_override(gate_class)` (consume one unused, stamp `used_at`); `set_attestation(handle, …)`, `get_attestation(handle)`, `is_attested(handle)`.

### 5. MCP tools — `server.py`

- `legal_override(gate_class: str, reason: str)` — one-time, logged allowance for a gated action class; mirrors `scope_override`'s docstring posture ("use only when you have made a deliberate, authorized decision; consumed on next use").
- `legal_attest(jurisdiction, tester_location, cssp_licensed, authorization_ref)` — record the standing legal posture for the active target; required once before live traffic in bounty mode.
- `legal_status(handle="")` — read attestation + count of unused overrides by class.

### 6. Reference — `plugin/reference/legal-gate-map.json`

Machine-readable class → `{statute, cite, signatures[], rationale, forward_map}` where `forward_map` notes the **Cybercrimes Bill 2026** successor (repeals CCA 1997, "computer"→"computer system"; s.5→unauthorised modification maps forward cleanly). This is the auditable source of truth and the file to update when the Bill is gazetted.

### 7. Skill — `plugin/skills/bb-legal/SKILL.md`

Brief, mirroring `bb-scope`/`bb-gate`: what the gate blocks and why (statute per class), that an override is a **deliberate human authorization decision** not a rote unblock, how to attest before going live, and the honest limits.

## Testing (TDD, the security-critical discipline the plan mandates)

- `tests/test_legalgate.py` — truth tables per class, **positive and negative**: `-X DELETE` blocks but plain `POST`/login does not; `ffuf -t 200` blocks but default `ffuf` does not; `hashcat` blocks but reading a JWT does not; `sqlmap --dump` blocks but a single-record `curl` does not; `rm -rf /` blocks but `rm -rf ./build` does not.
- `tests/test_hook.py` extensions — hook denies each class; a matching `legal_override` clears it exactly once then re-denies; sandbox mode enforces + writes an audit row; bounty network action denied until attested; **regression**: every existing scope/sandbox assertion still passes unchanged (the legal layer only adds an early branch).
- `registry`/`db` tests — override peek/consume/`used_at`; attestation round-trip; schema v3 upgrade is idempotent on an existing v2 db.

## Non-goals / documented limits

- Not a substitute for legal advice; surfaces considerations, records attestations, blocks high-signal shapes.
- Does not catch encoded payloads or arbitrary local destructive commands beyond the narrow catastrophic set.
- Copyright/TPM circumvention and OSA duties are out of v1 scope (low bug-bounty relevance); the reference JSON leaves room to add classes later.
