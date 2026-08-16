---
name: bb-legal
description: Understand and work with the legal action-class gateway (Malaysian statute). Use when the scope-guard hook denies an action for a legal-gate reason (destructive/dos/credential/pii or missing attestation), before going live on a real program, or when deciding whether a testing step is lawful.
---

# bb-legal

The legal-gate is the **second enforcement axis** in the PreToolUse hook. `scope.py` answers *"is the destination host authorized?"* (CCA 1997 s.3). The legal-gate answers *"is the shape of this action one that crosses a Malaysian statutory line?"* — independent of the host. It runs below the model, so it cannot be prompt-injected or forgotten after compaction.

It is deny-by-default on four action classes, each mapped to statute (full detail in `plugin/reference/legal-gate-map.json`):

| Class | Statute | Gated action shapes |
|---|---|---|
| `destructive` | CCA 1997 s.5 | HTTP `DELETE`/`PUT`/`PATCH`; SQL `DROP`/`TRUNCATE`/`DELETE FROM`/`ALTER`; sqlmap `--os-shell`/`--file-write`/`--sql-query`; WebGoat `restartlesson.mvc`; catastrophic local shell (`rm -rf /`, `dd of=/dev/…`, `mkfs`, fork bomb) |
| `dos` | CMA 1998 s.233 | brute-force (`hydra`/`medusa`/…), flood/stress (`slowloris`/`wrk`/…), concurrency > 50, rate > 100/s, `nmap -T4/-T5` |
| `credential` | CCA 1997 s.6/s.8 | offline cracking (`hashcat`/`john`), harvest/relay (`responder`/`mimikatz`/`secretsdump`), `crackmapexec --sam/--lsa/--ntds` |
| `pii` | PDPA 2010 | `sqlmap --dump`; mass `SELECT … FROM <personal table>` |

This is **not legal advice** — it surfaces and blocks high-signal shapes. You are still responsible for the program's own rules and the statutes.

## When the hook denies you

The deny message names the class(es), the statute, and the matched signature. Two kinds:

### 1. A gated action class
> `Blocked by bb legal-gate … Gated action class(es) with no override on record: destructive …`

First **stop and think** — the default answer is "don't". A non-destructive proof is almost always enough: prove the vulnerability *exists*, never actually delete the record, dump the users table, crack the password, or flood the host. This is also the correct report posture — a triager rewards a clean PoC, not damage.

If the action is genuinely authorized and necessary (the program's rules explicitly permit this destructive step; you are on a disposable local sandbox; the human has decided to proceed), grant a **one-time, logged override**:

```
mcp__bb__legal_override(gate_class="destructive", reason="<why this is authorized>")
```

Then retry. The override is single-use and its consumption is timestamped as a legal audit trail. An override is a **deliberate human authorization decision, not a rote unblock** — record a real reason. If you find yourself overriding the same class repeatedly, that is a signal the approach is wrong, not that the gate is in the way.

Note both axes still apply after an override: an overridden destructive call must still hit an in-scope host (bounty) or the sandbox allow-list (sandbox).

### 2. Missing attestation (bounty/live mode)
> `… no legal attestation is on record. … via mcp__bb__legal_attest(...)`

Before the first live-traffic action on a real program, record your standing legal posture **once**:

```
mcp__bb__legal_attest(
  jurisdiction="MY",            # where the target is operated/hosted (CCA s.9 extraterritorial)
  tester_location="MY",         # where you are testing from
  cssp_licensed=false,          # Cyber Security Act 2024 CSSP licence, if it applies
  authorization_ref="https://…" # the program/authorization the testing rests on (CCA s.3)
)
```

Surface the considerations to the user before recording: cross-border targets raise CCA s.9 extraterritorial exposure; providing prescribed penetration-testing services in Malaysia may require a CSSP licence under the Cyber Security Act 2024. Sandbox (local training) targets never need attestation.

Check readiness any time with `mcp__bb__legal_status(handle)` — it shows the attestation and any unused overrides by class.

## Honest limits
- Detection is pattern-based: an encoded payload can slip a signature. `$(...)`/decode-pipe escapes are caught separately by the sandbox ambiguity check (sandbox mode only).
- A credential the model writes into a note is not caught here — `redact.py` scrubs that on the storage side. The layers compose; none is complete alone.
- With no active target, the hook does not police local actions at all — the gate is scoped to an active bounty/sandbox session.

## Keeping the map current
- The **Cybercrimes Bill 2026** repeals CCA 1997 on a Minister-gazetted commencement date and replaces "computer" with "computer system". Until the gazette, CCA 1997 is operative. When it commences, update `plugin/reference/legal-gate-map.json` (each class has a `forward_map`) — the enforcement signatures carry forward unchanged.

## Firm rules
- The default for a gated action is **don't** — reach for a non-destructive proof first.
- An override is a deliberate, reasoned, human authorization — never a reflex to clear a block.
- Never send live bounty traffic before attesting the target once.
- The gate advises and blocks; it is not legal advice and does not replace the program's rules or the statutes.
