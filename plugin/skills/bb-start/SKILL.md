---
name: bb-start
description: Onboard a new bug bounty program — interview the user, verify every claim against the program's published page, write enforceable scope and legal posture into the bb ledger, then hand off to the hunt. Use at the very start of any engagement, or when the user says "start a program", "/start", or "onboard this target".
---

# bb-start

## Contract

You onboard ONE program per run and end by (a) writing a verified target + scope + legal posture into the bb ledger, and (b) handing the hunt to the other bb skills. You do NOT find bugs here — you prepare the ground truth the hunt depends on. The hunt (bb-recon -> bb-next -> bb-hunt / pb-*) runs afterwards; reporting (bb-report) runs only after the user approves a finding.

## Iron rule: the user's words are CLAIMS, not facts

1. Everything the user tells you is a claim to verify. The program's published page is ground truth.
2. NEVER fabricate a scope host, a rule, a credential, or a "verified" flag. If you did not read it or the user did not confirm it, it stays 'unverified'.
3. NEVER silently ignore or smooth over a discrepancy. If the user said X and the page says Y, STOP and ask, showing both.
4. If you cannot verify a field (private program, JS-heavy page, no extractable scope), ASK — and mark it 'source: user-claimed, unverified'. Do not pretend.

## Step 0 — what you can use for research

- 'web_fetch' on the program URL (HackerOne public programs render policy + scope server-side; try https://hackerone.com/<handle> and https://hackerone.com/<handle>?type=team).
- 'web_search' for the program's published policy when the direct URL is unknown.
- There is NO browser-automation tool here. Private programs' policy pages are behind HackerOne login, which 'web_fetch' cannot reach — fall back to the user and mark everything unverified.

## Step 1 — seed (two questions, minimal)

Ask only these two first, so you can start research instead of interrogating:
1. Program name and/or HackerOne handle.
2. Primary domain or application URL.

## Step 2 — auto-research (try before asking)

Fetch the program page and extract what you can:
- visibility (public / private) and kind (bug bounty / VDP / pentest)
- in-scope assets — each line's type + identifier + bounty-eligibility + instructions (focus areas, staging host, severity caps)
- out-of-scope — explicit exclusions AND blanket categories (third-party, CDN, physical, social engineering)
- rules of engagement — prohibited activity, automation/rate-limit policy, data-handling limits
- safe harbor and disclosure policy
- rewards — bounty table / minimum bounty (optional, for prioritization)

Record what you actually read, with the URL you read it from. Anything not present on the page goes into the interview below.

## Step 3 — interview (only what is still missing or unverifiable)

Ask in groups. Only ask a question if Step 2 did not already answer it. If the user does not know, mark it 'unknown' and keep it that way — do not invent a default.

Program identity & type
- Public or private program?
- Bug bounty program (BBP) or vulnerability disclosure program (VDP)?
- Industry / product focus (optional).

Asset types
- What asset classes are in scope: web application, API, mobile (iOS/Android), source code (repo), downloadable executable, hardware/IoT, or other?
- Is it black-box (external only) or white-box (source available / credentials provided)?

In scope (exact)
- Exact domains/wildcards (e.g. *.example.com, api.example.com).
- Exact IP ranges / CIDR blocks.
- Exact source repos (owner/repo URLs) if source review is in scope.
- Per-asset instructions if any (staging host, focus areas, severity caps, "no automated scanning").

Out of scope (exact)
- Which subdomains, IPs, or asset types are strictly forbidden to touch?
- Any blanket exclusions (third-party services, CDNs, customer tenants).

Prohibited attack types
- What attacks does the brief explicitly disallow? (DoS/load testing, social engineering, physical access, malware, mass data access, automated scanning, WAF bypass).
- The automation_allowed answer is critical — it decides Step 6.

Authentication
- Does testing require authenticated accounts?
- For each privilege level (admin / user / guest / other), what credentials or session tokens are available, and any MFA note?
- How are accounts provisioned: self-signup, provided test accounts, or none?

Legal posture (needed to go live)
- Jurisdiction where the target is operated/hosted.
- Your tester location.
- Whether you hold a CSSP licence (Cyber Security Act 2024) if applicable to this engagement.
- The authorization reference (the program URL is the right value for HackerOne).

## Step 4 — reconcile (diff and ASK)

Build a table: field | user claimed | program page says | status. For every field where they differ, do not choose — ask the user which is correct and why, because the page can be stale and the user can be wrong. Only after the user resolves a conflict do you record it. Unresolved conflicts block Step 5.

## Step 5 — record into the bb ledger (only VERIFIED data)

mcp__bb__create_target(handle=<handle>, confidentiality=<public|private|nda>, mode=<bounty|sandbox>, platform=<optional>)

- mode="bounty" for ANY real program (BBP or VDP). mode="sandbox" is ONLY for a local training target (Juice Shop / WebGoat), never a real program.

Write scope rules from the VERIFIED in-scope and out-of-scope lists:

mcp__bb__set_scope_rules(handle=<handle>, rules=[
  {"pattern": "*.example.com", "in_scope": true,  "asset_type": "URL",  "source": "<program url>"},
  {"pattern": "203.0.113.0/24", "in_scope": true, "asset_type": "CIDR", "source": "<program url>"},
  {"pattern": "app.staging.example.com", "in_scope": false, "asset_type": "URL", "source": "<program url>"}
])

- Patterns use *.example.com, example.com, example.com/admin, or 10.0.0.0/8. in_scope:false is an EXPLICIT out-of-scope rule that beats any in-scope wildcard.
- The scope-guard enforces HOSTS/IPs. Source-code assets (GitHub repos) do not map to network scope rules — keep them in the brief for bb-code / pb-source-audit later, and do NOT write them as scope patterns.
- If any in-scope/out-of-scope item is unverified, do not write it. Ask first.

If you will send LIVE traffic (real program, mode="bounty"), record legal posture once (this is what unblocks the legal gate):

mcp__bb__legal_attest(jurisdiction=<...>, tester_location=<...>, cssp_licensed=<true|false>, authorization_ref=<program url>)

- Sandbox targets never need attestation. If you cannot attest (missing facts), say so — live traffic stays denied (fail-closed), which is correct.

Then activate the target and load the taxonomy:

mcp__bb__switch_target(handle=<handle>)
mcp__bb__seed_test_cases()

Confirm with mcp__bb__scope_status(handle=<handle>) that the rules are set, and mcp__bb__check_scope(host=<...>) on one in-scope and one out-of-scope host as a sanity check.

## Step 6 — rules gate, then hand off

Read the VERIFIED automation_allowed answer:
- Real program + automation prohibited/unclear -> do NOT run autonomous scanning. Hand off to bb-recon (ingest recon the user runs), then bb-next for ranked, explained next actions. You propose; the user executes.
- Real program + automation explicitly permitted by the brief -> still prefer read-only recon + proposed steps; run active checks only within the verified scope and rate limits.
- Sandbox target (local Juice Shop / WebGoat) -> this is the only case where an autonomous find-exploit-verify loop is appropriate; use bb-sandbox and confirm network isolation (mcp__bb__sandbox_preflight) first.

End your onboarding reply with a one-paragraph summary of the recorded target, the scope the guard now enforces, and the exact next action (bb-recon or bb-next).

## Step 7 — the findings contract (state it to the user)

Tell the user, before hunting starts:
1. Findings are PROPOSED with: where the bug is (host + endpoint), why it matters, and exact manual repro steps.
2. The user approves or rejects each one.
3. bb-report runs ONLY after the user approves a finding — never on the model's own initiative.

## Hard failure modes (never do these)

- Never write an unverified scope rule or invent a host to "complete" the scope.
- Never auto-run traffic against a real program whose rules you have not verified as permitting it.
- Never mark a finding confirmed or run reporting without the user's explicit approval.
- Never put real production credentials/session tokens into scope or notes; if the user provides test creds, record them with the confidentiality they carry and redact anything sensitive.
