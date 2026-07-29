---
name: bb-scope
description: Turn a program's published scope into enforceable in-scope/out-of-scope rules. Use when onboarding a new target, when the program's scope has changed, or when scope_status reports stale data before testing continues.
---

# bb-scope

## When to use this
- A target exists but has no scope rules yet.
- The program's scope page has changed since rules were last set.
- `scope_status` reports `stale: true`.
- Before recommending or running any test — scope rules are what the enforcement hook checks against.

## Sources, in preference order
1. **Platform structured scope** — HackerOne/Bugcrowd/Intigriti/YesWeHack's own structured scope tables. Most authoritative and current.
2. **`arkadiyt/bounty-targets-data`** — a maintained daily dump of platform scopes in structured JSON. Use as a fallback when the platform UI is awkward to parse, or as a cross-check against it.
3. **The program's written policy page** — for VDP-style programs whose scope is prose, or where structured scope is incomplete.
4. **Manual entry** — for private programs, NDA programs, or VDPs with no structured scope at all. Ask the user to paste or describe the relevant scope section.

## Parsing is a proposal, never a silent action
Never call `set_scope_rules` straight from parsed text.

1. Parse the source into a candidate rule list: `{pattern, in_scope, asset_type, source}`.
2. Show the full list to the user as a table before submitting anything.
3. Get explicit confirmation. If the user edits the list, apply the edits and re-show before calling `set_scope_rules`.

This applies even to structured platform scope — it can still be stale, mid-edit, or include assets the program has quietly dropped. There is no source trustworthy enough to skip confirmation.

## Out-of-scope is the important half
- Out-of-scope entries use `in_scope: false`. At match time, an out-of-scope rule **takes precedence** over an in-scope rule that would otherwise cover the same asset.
- The out-of-scope list is the one people skim past on the policy page. Read it as carefully as the in-scope list — missing one entry there is a scope violation, not a missed asset.
- When proposing rules, surface the out-of-scope table distinctly (e.g. list it first) so it doesn't get rubber-stamped along with the usually-longer in-scope list.

## What scope rules can't express — capture as notes
Scope rules only encode host/path patterns and in/out status. When the policy also mentions any of the following, record it as a plain note tied to the target (not as a scope rule), and resurface it at report time:
- No automated scanning
- A required identifying header (e.g. a bounty-specific user-agent or header)
- Test accounts only / no real user data
- Rate limits
- Excluded vulnerability classes (e.g. "no self-XSS", "no clickjacking reports")

## Wildcard semantics
- `*.example.com` matches subdomains only. It does **not** match the bare apex `example.com` — if the apex itself is in scope, add a separate rule for it.
- `example.com/admin` scopes a path prefix on that host, not the whole domain.
- Don't let a broad subdomain wildcard lull you into assuming the root domain is covered — check the policy for an explicit apex mention.

## Keeping scope current
- Call `mcp__bb__scope_status(handle)` before relying on existing rules for a session. Check `fetched_at` and `stale`.
- `stale: true` means more than 7 days since the last fetch. Programs add and remove assets continuously — re-pull from the preferred source and re-propose rules (with confirmation) before continuing to test.

## scope_override — one-time escape hatch
- `mcp__bb__scope_override(host, reason)` is for a host that's clearly in-scope by evidence you've personally verified (e.g. named explicitly in the policy text in front of you right now) but not yet captured in scope rules.
- Hand-verify authorization first. Don't reach for this just to route around a hook block you haven't actually checked against the policy.
- It's a one-time, logged allowance — not a way to permanently broaden scope. If the same host keeps needing an override, fix the underlying scope rules instead of overriding repeatedly.

## Firm rules
- Never call `set_scope_rules` without first showing the user the parsed rule list and getting explicit confirmation.
- Always capture out-of-scope assets as `in_scope: false` — never omit them because they seem obvious or redundant.
- Never assume `*.example.com` covers `example.com` — add the apex explicitly when it's in scope.
- Check `scope_status` and refresh when stale (>7 days) before trusting existing rules.
- Use `scope_override` only after hand-verifying authorization yourself, and never as a repeated substitute for fixing scope rules.
