---
name: bb-target
description: Create, switch, or list bug bounty targets. Use when starting work on a new program, resuming an existing one, or before running any other bb-* skill to confirm which target is currently active.
---

# bb-target

## When to use this
- Starting work on a bug bounty program not yet tracked.
- Resuming work on a program already created.
- Session start, or before any other bb-* skill — the scope hook enforces against whichever target is ACTIVE, so confirm it first.

## Creating a target
1. Ask for whatever isn't already stated: program name, platform (hackerone, bugcrowd, intigriti, yeswehack, self-hosted/VDP, etc.), confidentiality (`public` | `private` | `nda`).
2. Derive a short kebab-case handle from the program name if the user hasn't given one (e.g. "Acme Corp Public Program" -> `acme-corp`). Keep it short — it gets typed in every subsequent command.
3. Confirm platform and confidentiality explicitly before creating. Confidentiality can't be safely guessed — never default to `public`.
4. Call `mcp__bb__create_target(handle, platform, confidentiality)`.

## Handle rules
- kebab-case, short, ASCII, no spaces or underscores.
- One handle per program engagement. If the user re-engages a program later, reuse the existing handle — check `list_targets` first rather than creating a duplicate.

## Confidentiality — private/nda handling
Confidentiality is sticky state the user's memory won't reliably retain across a multi-week gap between sessions. Treat it as something that must resurface every time, not a one-time setting.

- At the start of every session touching a private or nda target, state the flag visibly first, before anything else: e.g. `Active target: acme-corp (PRIVATE)`.
- Never paste a private/nda target's program name, hostnames, endpoint paths, or any other identifying detail into a web search, external tool call, or any lookup outside this project's own tools. Check the active target's confidentiality before every external lookup — don't assume it's safe because the last one was.
- Public targets carry no such restriction, but re-check confidentiality before assuming that, especially right after a switch.

## Switching targets
- Switching is a safety-relevant action: the scope hook checks commands against the ACTIVE target, not whatever the user last mentioned in conversation. A stale active target means the hook silently checks the wrong scope.
- Call `mcp__bb__switch_target(handle)`, then immediately state which target is now active and its confidentiality level so a wrong switch is caught right away.
- If unsure what's active, call `mcp__bb__list_targets()` rather than guessing.

## Listing targets
`mcp__bb__list_targets()` — use when the user asks what's being tracked, or to check for an existing handle before creating a new one.

## Firm rules
- Never guess confidentiality — ask, and treat unconfirmed cases as private until the user says otherwise.
- Always surface the active target and its confidentiality flag at session start and immediately after every switch.
- Never include private/nda target details (name, hosts, paths) in any external search, web fetch, or third-party tool call.
- Never create a duplicate handle for a program that already has one — check `list_targets` first.
