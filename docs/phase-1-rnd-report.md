# Phase 1 — R&D Report

**AI-assisted bug bounty research system, human-in-the-loop, authorized programs only**

Date: 2026-07-28
Status: For your review. No code written. No design locked in.

---

## 0. What this report is and how to read it

You asked me to research how AI can assist a bug bounty workflow across six areas — recon summarization, findings correlation, code reading, report drafting, scope tracking, and learning bug classes — explore multiple approaches, compare them, and stop.

This report does that. It ends with a recommendation, but the recommendation is a proposal for you to accept, reject, or modify. Phase 2 (detailed plan) starts only after you approve.

**Epistemic labels used throughout:**

- **[V]** — Verified. I read the doc, ran the command, or fetched the page. The source is cited.
- **[A]** — Assumed. Reasoning from evidence but not directly confirmed. I say what I didn't check.
- **[U]** — Unknown. I could not determine this and it needs to be resolved before it matters.

I have flagged every place where I am reasoning rather than reporting. Where I disagree with a direction, I say so.

**Your inputs that shaped this (from our Q&A):**

| # | Question | Your answer |
|---|---|---|
| 1 | Experience level | Infosec student. Solid theory on OWASP Top 10 and common vuln classes. Few/no valid findings on live programs. Skip 101-level definitions; teach *how to find them in the wild*. |
| 2 | Target types | Web, API, source-available, mobile/binaries/infra — later cut to web + API + source-reading for v1 (you agreed, Q14) |
| 3 | Platforms | HackerOne, Bugcrowd/Intigriti/YWH, self-hosted VDPs, private engagements |
| 4 | Tool posture | Undecided — compare in R&D and recommend |
| 5 | Data sensitivity | Needs care. Some programs have NDAs / private scope that must never leave the machine. |
| 6 | Existing workflow | Burp Community. nuclei + ffuf used in labs. No notes system. Open to recommendation. |
| 7 | Biggest pain | *"I know the vuln classes in theory but I don't know how to systematically find them on a real target — I don't have a repeatable process, so I stare at an app and don't know where to start."* |
| 8 | Core of the system | A methodology engine. Everything else supports it. |
| 9 | Time available | A few hours per week. |
| 10 | Target selection help | Yes, but sometimes you'll pick the target yourself. Both modes. |
| 11 | Report drafting | Both full drafts and structure-plus-critique, depending on the finding. |
| 12 | API cost | Fine. |
| 13 | Storage | Open — decide in R&D. |
| 14 | v1 scope cut | Accepted: web + API primary, source-reading supporting, mobile/binaries deferred. |
| 15 | Report depth | Detailed. Longer is fine. |
| 16 | Web research | Approved. Also: **include a Claude Pro subscription implementation path so no API key is needed.** |

**Verified environment** [V] — I ran these:

```
WSL2 Ubuntu (installed, currently Stopped)
docker-desktop WSL distro (Stopped)
Python 3.13.14
Node v22.14.0 / npm 10.9.2
Docker 29.1.2
git 2.51.0.windows.1
Go: not present on the Windows side
```

Relevance: the Go-based recon stack (nuclei, ffuf, subfinder, httpx, katana) is not installed on Windows and would live in WSL or Docker. Any design that shells out to those tools crosses a Windows↔WSL boundary, which has real path-translation friction. Noted for Phase 2.

---

## 1. Executive summary

**The recommendation: build a Claude Code plugin containing (a) a small local MCP server that owns a SQLite case file, (b) a set of skills that encode methodology, and (c) a PreToolUse hook that enforces scope. Ingest-only for network traffic in v1. It runs entirely on your existing Claude Pro subscription with no API key.**

Five findings drove that:

**Finding 1 — The gap in the ecosystem is memory, not prompts.**
Two mature Claude Code bug bounty bundles already exist (82 skills / 681 report patterns, and 26 slash commands with an autonomous `/autopilot` loop) [V]. Both are *content* — prompt libraries. Neither maintains persistent, queryable state across sessions. That means neither can answer "what have I already tested on this target, and what haven't I?" — which is exactly your problem #7. Building another prompt bundle would reproduce the gap. The differentiating asset is a **coverage ledger**: durable state that survives context compaction, session restarts, and weeks between hunting sessions.

**Finding 2 — Your Pro subscription works, but only for the interactive path.**
As of 2026-06-15 Anthropic split billing: interactive Claude Code on Pro/Max draws from the subscription pool, while the Agent SDK, `claude -p` headless mode, GitHub Actions, and third-party apps authenticating through the Agent SDK draw from a separate metered Agent SDK credit at API rates [V]. Setting `ANTHROPIC_API_KEY` overrides the subscription entirely [V]. **Design consequence: the system must be driven by you interactively inside Claude Code, and must never call the Anthropic API itself.** Any "background agent that hunts while you sleep" design silently moves you onto metered billing. This aligns with your human-in-the-loop requirement anyway — the constraint and the safety goal point the same direction, which is a good sign.

**Finding 3 — AI is strong at discovery and weak at the last mile, consistently.**
Independent sources converge. YesWeHack ran Claude Code against PortSwigger labs: it identified vulnerable client-side JS "within seconds" and built the payload, but on another lab "assumed that a POST request was enough and burned over half an hour on a redirect it never followed," and when stuck it repeats failed approaches without reconsidering assumptions [V]. Stanford's December 2025 benchmark found the best autonomous agent missed a critical RCE that 80% of humans found [V]. The system should therefore *aggressively* automate mapping, hypothesis generation, correlation, and drafting — and *refuse* to claim a finding is real. Validation stays yours.

**Finding 4 — Scope enforcement can be mechanical, not advisory.**
Both existing bundles handle scope with disclaimers in documentation. One explicitly has "no runtime verification that endpoints remain in-scope during autonomous hunting" [V]. Claude Code's PreToolUse hook can return `permissionDecision: "deny"` and hard-block a tool call before it executes [V]. That turns scope from a prompt instruction the model might drift from into a deterministic check outside the model. This is the single highest-value safety mechanism available and nobody in the surveyed ecosystem uses it.

**Finding 5 — Prompt injection from target data is a live, under-addressed risk in this exact use case.**
You are pointing an LLM at output from systems whose owners are, by construction, being probed. Target-controlled content (HTTP response bodies, error messages, HTML, JSON, JS source) enters your context. Palo Alto Unit 42 documented indirect prompt injection against web-browsing agents in the wild [V]; the CAI paper is literally titled "Hacking the AI Hackers via Prompt Injection" [V]. Combined with an agent that has filesystem and shell access, this is the "lethal trifecta" — privileged access + untrusted input + exfiltration channel. Mitigations are in §9.1 and are a first-class design requirement, not an afterthought.

**What I recommend you do not build:** an autonomous hunting loop, a scanner, anything that fires traffic without your explicit action, and any feature for mobile/binary targets in v1.

---

## 2. Reading your profile

Your situation is specific and it changes the design meaningfully. Three things stand out.

**You have theory but no live-target reps.** This is the most common place people stall out, and it is not a knowledge problem. You know what an IDOR is. What you lack is the *procedural* layer: given an unfamiliar app, which of the 40 things you know how to test do you do first, how do you enumerate the app's objects and roles so you know where IDORs could even exist, and how do you know when you've exhausted a surface. That layer is normally acquired by watching someone hunt or by hundreds of hours of trial and error. A system can compress it, but only if it is opinionated about process and keeps score.

**A few hours a week means state is everything.** If you hunt Tuesday evening and again the following Sunday, five days of forgetting sit in between. Without external state you re-derive the app's structure every session, and re-derivation eats most of a short session. The value of persistent state is roughly proportional to how *fragmented* your time is — and yours is very fragmented. This is why I weight the coverage ledger so heavily.

**"Needs care" on data sensitivity, with no notes system yet.** You are in the fortunate position of choosing a storage model before you have a decade of notes in the wrong format. Since some programs are NDA-bound, the storage design needs a mechanism for "this program's data never goes into a prompt" from day one — retrofitting that is painful.

**One thing I want to flag as a risk to you, not to the code.** Systems like this can become a substitute for hunting. Building the tool is intellectually satisfying in a way that staring at an unfamiliar app is not. The measure of Phase 3's success is not lines of code; it is whether you spend more hours actually testing targets afterward. I would suggest a deliberately small v1 so you get back to hunting quickly, and let real use dictate v2. I raise this now because it should shape how ambitious Phase 2's plan is.

---

## 3. Part A — What AI actually does well and badly, per workflow area

This section grades each of your six areas. The grade is about *current, honest capability under human supervision*, not marketing.

### A1. Recon summarization

**What it means:** you run subfinder/httpx/ffuf/katana/nuclei (or just browse with a proxy), and end up with thousands of lines of output. Turning that into "here is the shape of this application and here are the five interesting things" is the task.

**Verdict: strong. Among the best uses.** [A — reasoning from YesWeHack's assessment plus general LLM capability]

YesWeHack's evaluation says Claude Code is "fast and thorough at recon, fingerprinting and mapping attack surfaces" [V]. This matches the underlying capability: it is a large-scale pattern-recognition and summarization problem over semi-structured text, which is what LLMs are actually good at.

Specifically it does well at:

- Clustering endpoints by function ("these 40 URLs are all the admin panel; these 12 are the payments flow")
- Spotting the odd one out — the endpoint on a different framework, the subdomain with a different TLS cert issuer, the one host still on an old version
- Naming the technology stack from headers, cookie names, JS bundle fingerprints, and error page formats
- Inferring the object model from URL structure (`/api/v2/orgs/{id}/projects/{id}/members/{id}` tells you a lot about what IDOR targets exist)
- Translating between formats — Burp export to a structured endpoint list, for example

**The failure mode that matters: context cost.** A raw nuclei run or a full katana crawl can be tens of thousands of tokens. Dumping that into an interactive Claude Code session on a Pro plan will chew through your 5-hour window fast [V — Pro shares the rolling window with Claude chat], and it degrades quality because the signal is buried.

**Design consequence:** recon data must be *stored and queried*, not *pasted*. The right pattern is: a normalizer parses tool output into a database, and the model queries it with narrow questions ("show me endpoints with `id` parameters that I haven't tested"). This one decision drives a lot of the architecture in §7.

**Second failure mode: fabricated detail.** Asked to summarize a large dump, models will occasionally assert an endpoint or header that isn't in the data. Mitigation is to make summaries cite the source row, so you can spot-check.

### A2. Organizing and correlating findings

**What it means:** you noticed a weird `X-Original-URL` header on Tuesday and an internal-looking hostname in a JS bundle on Sunday. Those two facts together are an SSRF lead. Nothing in your current workflow connects them.

**Verdict: high value, but the value comes from the data structure, not the model.** [A]

This is the area where I think most existing tooling is weakest, and where a modest amount of engineering pays off most.

The Critical Thinking podcast practitioners describe a hierarchical note structure specifically to survive context compaction [V]:

```
Notes → Leads → Primitives/Gadgets → Findings → Reports
```

That is a genuinely good model and I would adopt it more or less directly. The distinction that matters:

- **Note** — raw observation. "This endpoint returns 403 with a JSON error body."
- **Lead** — an observation with a hypothesis attached. "403 body leaks the internal service name; maybe a header-based bypass works."
- **Primitive / gadget** — a confirmed capability that isn't a bug by itself. "I can control the `Host` header and it reaches the backend." Primitives are the raw material of chains and are what beginners most consistently fail to record.
- **Finding** — a confirmed, reproducible security issue.
- **Report** — a finding written up for a specific program's format.

The model is good at *proposing* links between items ("your Host-header primitive plus this internal hostname suggests trying X"). It is bad at *maintaining* the graph — it forgets, duplicates, and drifts. So the graph should live in a database with explicit relations, and the model should read and propose against it.

**The specific thing that will help you most:** primitives. Beginners find a half-bug, can't escalate it, and discard it. Experienced hunters bank it and combine it three weeks later. A system that makes recording primitives cheap and resurfaces them contextually is doing something a notebook doesn't.

**Failure mode: over-correlation.** Ask a model "what connects these 30 notes?" and it will always find something, because it is a pattern-matcher and there is always a pattern. Correlation output must be presented as hypotheses with confidence, ranked, and cheap for you to dismiss — not as conclusions. If every session generates 15 "promising leads" you will stop reading them by week three.

### A3. Reading and explaining code

**Verdict: strong — arguably the strongest area, and the most under-exploited by beginners.** [V for the capability claim; A for the strategic emphasis]

YesWeHack: Claude Code "reasons through code logic well enough to direct researchers towards vulnerable components" [V], and in a DOM XSS lab "identified the vulnerable client-side JavaScript" within seconds [V].

Concretely useful jobs:

1. **Client-side JS analysis.** Every web target ships its source to you. Modern bundles are hundreds of KB of minified JS containing route tables, API client definitions, feature flags, role checks, and occasionally keys. Reading these by hand is miserable and most beginners skip it. This is a large, consistent, mostly-unexploited edge, and it is pure text analysis with zero network interaction — which also makes it perfectly safe.
2. **Source-available targets.** Programs whose product is on GitHub, or built on a known open-source core. Sink-to-source tracing, authorization-check auditing, and diffing versions for silently-patched bugs are all things the model does competently.
3. **Dependency review.** Identifying the versions in use and mapping to known CVEs. (Note: version-based CVE claims without demonstrated exploitation are a classic report rejection — see §A4.)
4. **Explaining a bug class as it appears *in this code*.** This is where the teaching goal and the code-reading capability meet, and it's much more useful to you than a generic explanation of the class.

**Failure modes:**

- **Confident wrong tracing.** It will assert a data path from source to sink that doesn't exist, especially across framework boundaries, DI containers, and dynamic dispatch. Every claimed path needs verification.
- **Missing the security-relevant question.** Asked "is this code vulnerable," it audits for the classes it expects rather than the ones that matter for this app's threat model. Better to ask specific questions: "which endpoints in this router lack the `requireAuth` middleware that the others have?"
- **Context limits on large repos.** Needs a search-then-read strategy, not whole-repo ingestion.

### A4. Drafting reports

**Verdict: strong, with a hard boundary — it must never invent the technical content.** [A, well-supported]

Reports get rejected for: duplicates, insufficient evidence, out-of-scope, low/unproven impact, and incomplete reproduction steps [V]. Of these, an AI can directly help with three:

- **Evidence completeness.** A checklist pass against the program's actual requirements catches "you didn't include the request/response pair" before triage does.
- **Impact articulation.** This is genuinely hard for beginners, and it is the difference between "Informative" and a bounty. The skill is translating a technical primitive into a business consequence in the target's own terms. "IDOR on `/api/orders/{id}`" is a technical fact; "any authenticated user can enumerate every customer's order history including shipping addresses and partial payment details, at ~200 records/sec" is an impact statement. The model is good at this translation *given the facts*.
- **Reproduction step clarity.** Rewriting your shorthand into steps a triager can follow without asking you a question. Every round-trip with triage costs days.

You said you want **both** full drafts and structure-plus-critique (Q11). Correct call — they suit different situations. A clean XSS with an obvious payload wants a fast full draft. A subtle business-logic chain wants you to write the technical narrative (because only you understand it) and the AI to attack the draft as a hostile triager would.

**The hard boundary:** the model must not generate steps to reproduce that it did not observe, must not invent request/response pairs, and must not assign severity independently. Report fabrication is the fastest way to destroy a researcher reputation, and platforms are actively penalizing AI-generated slop. **Design consequence: report drafting reads only from stored, verified evidence, and any gap is rendered as an explicit `[YOU MUST FILL THIS IN]` marker rather than plausible filler.**

**Duplicate risk** deserves a note: checking Hacktivity for prior similar reports on the same program is genuinely useful pre-submission and is a legitimate API use [V — the Hacktivity endpoint supports filtering by team, CWE, severity, and disclosure date].

### A5. Tracking authorized program scope and rules

**Verdict: high value, and the one area where correctness matters more than intelligence.** [V on mechanisms]

Scope has structure, so treat it structurally:

- **In-scope assets** — domains, wildcards, IPs, mobile apps, repos, with asset types.
- **Out-of-scope assets** — often the more important list, and the one people skim.
- **Out-of-scope vulnerability classes** — self-XSS, missing headers, rate limiting, CSV injection, clickjacking on non-sensitive pages. Programs vary enormously here.
- **Testing rules** — no automated scanning, no DoS/load testing, test accounts only, required `X-Bug-Bounty` header, no social engineering, no testing against production data.
- **Safe harbor terms.**

Sources available:

| Source | Coverage | Notes |
|---|---|---|
| `arkadiyt/bounty-targets-data` | H1, Bugcrowd, Intigriti, YWH, Federacy | Public repo, refreshed ~every 30 min. Structured JSON. No auth needed. [V] |
| HackerOne Hacker API | H1 only | `GET /v1/hackers/programs/{handle}/structured_scopes`. Requires your API token. Returns typed assets with CIA requirements. [V] |
| Program policy page | All | Prose. The rules that actually matter usually live here, not in the structured data. Needs a human or an LLM to parse, and needs your review. |
| `security.txt` / self-hosted VDPs | Non-platform programs | Ad hoc. Manual entry. |
| Private engagements | — | PDF/email. Manual entry, and the data is confidential. |

**The key insight: the "am I allowed to touch this host" question should be answered by deterministic code, not by the model.** A domain-matching function with wildcard handling, an explicit deny list that takes precedence, and a default of *deny when unknown*. The model is fine for *parsing* prose policy into structured rules (with your confirmation), and completely wrong as the *enforcement* mechanism, because it can be talked out of a rule by a persuasive context — including an injected one.

The subtle trap: scope changes. Programs add and remove assets. A cached scope from three weeks ago can be wrong in the direction that gets you in trouble. Staleness needs to be visible and the refresh needs to be cheap.

### A6. Helping you learn specific bug classes

**Verdict: high value, and specifically for your gap — but only if it's grounded in real targets and real reports.** [A]

You explicitly asked to skip 101-level definitions. Good, because generic explanations are the least valuable thing here and the most likely thing an unopinionated system would produce.

What is actually useful for the "theory but no reps" problem:

1. **Disclosed report study, structured.** ~700 patterns extracted from HackerOne reports exist in one bundle already [V], and the Hacktivity API supports filtered queries by CWE, program, and date [V]. The valuable framing is not "here's an IDOR report" but **"here is what the hunter noticed *first*, before they knew it was a bug."** That first-noticing moment is the skill you're missing. Most write-ups skip it; a model reading the report can often reconstruct it.
2. **Recognition drills against the target you're actually on.** "Here are six endpoints from your current target. Which two are the most plausible IDOR candidates and why?" You answer, then compare. This beats abstract quizzing because it builds the specific judgment you need, on data you care about.
3. **Post-session retrospectives.** After a session: what did you test, what did you skip, what would an experienced hunter have looked at that you didn't. This is where the coverage ledger pays a second dividend — it makes the retrospective factual instead of vibes.
4. **Hunt-along explanation.** When the system proposes a test, it explains *why this test on this endpoint*. Learning as a side effect of working, rather than a separate study mode. This is the highest-leverage version and it costs almost nothing extra to build.

**Failure mode: plausible-but-wrong methodology.** A model asked "how do I find IDORs" will produce a confident, generic, mediocre answer. Grounding in disclosed reports and in real target data is what separates this from a blog post. Where the system teaches, it should cite.

### A7. Summary table

| Area | Verdict | Main risk | Design implication |
|---|---|---|---|
| Recon summarization | Strong | Context cost; fabricated detail | Store and query, don't paste. Cite source rows. |
| Findings correlation | High value | Over-correlation noise | Explicit graph in DB; model proposes, ranked, dismissible |
| Code reading | Strong | Confident wrong tracing | Verify claimed paths; ask specific questions |
| Report drafting | Strong | Fabricated evidence | Read only from stored evidence; explicit gap markers |
| Scope tracking | High value | Model drift; stale data | Deterministic enforcement in code; staleness visible |
| Learning | High value | Generic slop | Ground in disclosed reports + current target; cite |

---

## 4. Part B — Ecosystem survey

### B1. Fully autonomous platforms

XBOW: founded 2024, coordinates hundreds of autonomous agents, reached #1 on HackerOne's US leaderboard in June 2025, submitted 1,060+ vulnerabilities including a 48-step chain escalating blind SSRF to full compromise, raised $237M total [V]. Others in the category: Escape, Terra Security, Hadrian, Penti, HexStrike AI [V].

**Relevance to you: essentially none, and that's worth being clear about.** These are venture-funded platforms with proprietary agent orchestration, dedicated infrastructure, and enterprise contracts. You are not going to build one on a Pro subscription, and if you tried, the result would be a worse scanner that gets you banned.

The genuinely useful data point from this space is the counter-evidence: Stanford's December 2025 benchmark found the best autonomous agent missed a critical RCE that 80% of humans found, and the effective model is hybrid — agentic depth plus human validation [V]. Even the well-funded autonomous efforts don't fully replace human judgment. Your human-in-the-loop constraint is the state of the art, not a limitation.

There's also a strategic argument for your position: as automated submission volume rises, programs increasingly value researchers who submit *few, high-quality, well-reasoned* reports. Competing on volume against XBOW is a losing game. Competing on depth of understanding of one target is not.

### B2. Existing Claude Code bug bounty bundles

These are your closest prior art, and the most important part of this survey.

**`elementalsouls/Claude-BugHunter`** [V]

- 82 skills across 11 categories, 15 slash commands, 681 disclosed-report patterns across 24 vuln classes
- Attack matrices for M365/Entra, Okta, vCenter, SharePoint, SSL VPN appliances
- Six-phase non-linear workflow: recon → map & rank → hunt → validate → report
- Auto-routes findings to relevant skills based on context
- A `triage-validation` skill with a "7-Question Gate" that asks whether the target is in scope and on the accepted-impact list before submission
- Explicitly excludes internal AD attacks, C2, post-exploitation, binary exploitation — external surfaces only
- Documents that Anthropic's runtime safeguards block offensive tooling by default and points at CVP

**What it gets right:** the scope of exclusion is disciplined, the 7-Question Gate before submission is a good idea, the disclosed-report pattern corpus is a real asset, and the "different operational risk profile" reasoning for excluding internal tradecraft shows judgment.

**What it doesn't solve for you:** it is a prompt library. There is no persistent state. Every session starts cold. The 7-Question Gate is a *prompt* the model is asked to follow — it can be skipped, forgotten after compaction, or reasoned around. And 82 skills is a lot of surface area for a system whose job is to make you *less* overwhelmed.

**`shuvonsec/claude-bug-bounty`** [V]

- Nine agent components: recon-agent, validator, report-writer, web3-auditor, chain-builder, autopilot, ranker, token-auditor, credential-hunter
- 26 slash commands across recon / hunting / validation / reporting
- Wraps subfinder, httpx, nuclei, katana, ffuf
- `/scope-aggregate` pulls in-scope assets across H1, Bugcrowd, Intigriti, YWH, Immunefi
- `/autopilot target.com` — "full loop, autonomous — scope → recon → hunt → validate → report" with claimed safety checkpoints
- Hunt memory persisting across sessions via `/remember` and `/memory-gc`
- Seven mandatory rules including "Only test what the program authorizes" and "Never go out of scope"

**What it gets right:** `/scope-aggregate` is the right instinct. The persistent hunt memory is the right instinct. Report templates targeting "not N/A'd" shows understanding of the real failure mode.

**What's wrong with it for your purposes:**

- `/autopilot` is precisely the thing you said you don't want. Autonomous scope → recon → hunt → report is unsupervised traffic against a live target.
- The fetched analysis is explicit: *"no runtime verification that endpoints remain in-scope during autonomous hunting — a potential authorization drift risk"* and *"'For authorized security testing only' appears as a footer disclaimer, not enforced at runtime"* [V]. Scope lives in prompts, not in code.
- Payout figures in report templates ("$500–$5K for XSS") encourage severity inflation, which is how you get reports downgraded and reputation damaged.
- Web3/token/credential modules are scope sprawl for a web+API researcher.

**The synthesis — and this is the central finding of the survey.** Both bundles are large, well-researched *content* libraries with weak or absent *state* and *enforcement*. The gap is not "more prompts about IDOR." Every prompt about IDOR that will ever be needed already exists, in these repos and in HackTricks and PayloadsAllTheThings. The gap is:

1. **Durable coverage state** — what has been tested on this target, by whom, with what result, when. Nothing tracks this.
2. **Mechanical scope enforcement** — a deny that the model cannot talk itself past.
3. **A next-action engine** — given current coverage state, what is the highest-value untested thing right now.

Item 3 is your problem #7 restated. Items 1 and 2 are what make item 3 possible and safe.

### B3. Proxy MCP servers

This matters because you have Burp Community.

**PortSwigger official MCP Server** (BApp Store) [V] — first-party, official extension. Search results indicate compatibility with **both Community and Professional** editions [V, medium confidence — this came from search result summarization, not from reading the BApp Store compatibility field directly; **needs confirmation in Phase 2**]. The GitHub README doesn't document a tool list or edition matrix [V — I fetched it]. It has a config-editing capability gated behind an explicit "Enable tools that can edit your config" checkbox, and runs on localhost.

**`Den-Sec/burp-mcp`** [V] — 61 tools, explicitly targeting Claude Code, described as Burp Suite **Professional**. Can search proxy history, run scans, drive Repeater/Intruder, poll Collaborator. Scanner and Collaborator are Pro-only features, so this is not fully usable on Community [A — reasoning from Burp's own edition split, which I did not re-verify].

**`swgee/BurpMCP`** [V] — Burp extension exposing save/send/modify requests, Collaborator payload generation, debug logs. SSE on localhost:8181.

**Caido MCP server** (`c0tton-fluff/caido-mcp-server`, plus official Caido docs) [V] — view request history, send via Replay, HTTPQL filtering, list/create findings and scope presets, sitemap endpoint discovery, project switching. Caido has a documented plugin/workflow API and official MCP tutorial.

**Assessment.** The proxy-MCP layer is the single highest-leverage integration available, because your proxy history *is* the ground truth of what the application does, and it is already on your machine. Reading proxy history is also inherently safe — no new traffic is generated.

But note the asymmetry: these servers expose both *read* tools (history, sitemap) and *write* tools (send request, run scan, Intruder). **The read half is a gift; the write half is where the human-in-the-loop question actually gets decided.** Any of these can be added later without redesign, which is an argument for not committing in v1.

Practical note for you: Caido is worth evaluating. Its MCP integration is first-party and documented, its scope presets and HTTPQL give structured querying that Burp Community lacks, and its free tier is more capable than Burp Community for this kind of automation. I'm not recommending you switch — just flagging it as a real option, since you said you're still building your workflow and aren't invested in Burp yet.

### B4. Scope data sources

`arkadiyt/bounty-targets-data` is the standard: hourly (actually ~30-minute) dumps of H1/Bugcrowd/Intigriti/YWH/Federacy scopes as JSON, public, no auth [V]. Companion repo `bounty-targets` does the crawling.

This is a solved problem and there is no reason to build a crawler. Pull the JSON, cache it, diff it. It gives you (a) scope for any program without API tokens, and (b) as a bonus, program *discovery* data for your Q10 target-selection interest.

Limits: it captures structured assets, not policy prose. The "no automated scanning" rule, the required identifying header, the out-of-scope vulnerability classes — those live in the policy page and need separate handling.

### B5. Note-taking and methodology tooling

The community has largely converged on Obsidian + Markdown [V — multiple practitioner sources]. There is a Burp↔Obsidian integration extension [V]. Bugcrowd's own methodology content emphasizes note and session tracking [V]. The Critical Thinking practitioners describe local folders, Obsidian, or a custom API, with the hierarchical structure noted in §A2 [V].

OWASP WSTG provides a structured test-case taxonomy with stable identifiers (`WSTG-<CATEGORY>-<NN>`, e.g. `WSTG-INFO-02`) and published checklists [V]. This is directly usable as the backbone of a coverage ledger — you need *some* stable vocabulary for "what has been tested," and inventing one is wasted effort. WSTG is comprehensive but pentest-shaped rather than bounty-shaped, so it needs a bounty overlay (WSTG has no test case for "check for subdomain takeover" or "look for a race condition in the coupon redemption flow"). [A — the mapping work is real but modest.]

**Nothing in the surveyed tooling closes the loop between the checklist and the notes.** Checklists are static documents; notes are freeform. Nobody joins "test case X" to "on endpoint Y, on date Z, result: not vulnerable, evidence: request #443." That join is the coverage ledger.

### B6. The gap, stated plainly

```
EXISTS ALREADY                          MISSING
─────────────────────────────────────────────────────────────────
Prompt libraries for every vuln class   Coverage state across sessions
Recon tool wrappers                     Mechanical scope enforcement
Scope data feeds                        Checklist↔evidence join
Proxy MCP servers (read + write)        "What should I do next" engine
Disclosed-report corpora                Primitive/gadget banking
Report templates                        Grounded-only report drafting
Autonomous hunt loops (unwanted)        Session continuity for part-time hunters
```

Build the right column. Consume the left column.

---

## 5. Part C — Delivery mechanisms available

Before comparing architectures, here is what the platform actually offers. All verified against current Claude Code docs [V].

### C1. Skills

A `SKILL.md` file with YAML frontmatter plus optional bundled files. Key properties:

- **Progressive disclosure.** Only the `description` (plus `when_to_use`) sits in context, capped at 1,536 characters combined; the body loads only when invoked. Long reference material costs nothing until used. This is the critical property for a methodology library — you can have 30 detailed playbooks without paying for them every turn.
- **Locations:** `~/.claude/skills/` (personal), `.claude/skills/` (project), `<plugin>/skills/` (plugin, namespaced `plugin:skill`). Nested `.claude/skills/` below cwd also load.
- **Invocation control:** `disable-model-invocation: true` for manual-only, `user-invocable: false` for background knowledge.
- **`allowed-tools`** pre-approves tools for the invoking turn only; the grant clears on your next message.
- **`disallowed-tools`** removes tools from the pool while active.
- **`context: fork`** runs the skill in a subagent; `background: false` waits for the result inline.
- **`hooks`** — skills can carry their own lifecycle hooks.
- **`model` / `effort`** per-skill overrides.
- **`${CLAUDE_SKILL_DIR}`** substitutes in both body and `allowed-tools` Bash rules, so a skill can run a bundled script without prompting.

**Good for:** methodology, checklists, procedures, teaching content, report templates. Anything that is *instructions*.
**Bad for:** anything requiring computation, state, or determinism. A skill is text the model reads; it cannot enforce.

### C2. MCP servers

A local process exposing typed tools over stdio or HTTP. Runs as real code — Python or Node here.

**Good for:** state (the SQLite case file), deterministic computation (scope matching), parsing (tool output normalization), and structured queries that avoid dumping data into context.
**Bad for:** methodology. Encoding a checklist as MCP tools is awkward; it's text, and skills handle text better.

**The key architectural property:** an MCP tool returns *only what it returns*. `list_untested_endpoints(target, limit=20)` puts 20 rows in context, not 4,000. This is how you keep a Pro subscription viable against large recon datasets.

### C3. Hooks

`PreToolUse` fires before every tool call. Configured in settings files or in skill/agent frontmatter. Receives JSON on stdin including `tool_name`, `tool_input`, `cwd`, `permission_mode`. Returns:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Host not in scope for program <x>"
  }
}
```

`permissionDecision` accepts `deny` (block, reason shown to Claude), `allow` (skip permission checks), `ask` (escalate to you), `defer` (normal flow). Exit 2 is also a blocking error with stderr fed back. Matchers filter by tool name (`"Bash"`, `"Edit|Write"`, `"mcp__memory__.*"`), and an optional `if` field narrows by permission-rule syntax — though the docs note `if` is best-effort and the permission system is the hard enforcement layer [V]. [V — all of this from the hooks doc.]

**This is the enforcement primitive.** A hook is code, outside the model, that sees every tool call. It cannot be prompt-injected, cannot be forgotten after compaction, and cannot be reasoned around. For scope enforcement this is categorically better than any instruction.

**Caveat I want to state honestly:** a hook that parses shell commands to extract target hosts is doing adversarial parsing of a very flexible language. `curl https://a.com` is easy; `curl $(echo aHR0cHM6Ly9ldmlsLmNvbQo= | base64 -d)` is not. A hook is a strong guardrail against *drift and mistakes* — which is the actual risk here, since neither you nor the model is trying to evade it. It is not a sandbox against a determined adversary. §9.2 covers what to do about that.

### C4. Subagents

Fresh context, own tool set, returns a summary. Useful for bounded research tasks whose intermediate output you don't want in main context.

**Critical constraint** [V — from the Critical Thinking practitioners]: autonomous sessions with 4+ subagents cause compaction to "fail catastrophically." They recommend 2–3 maximum. This directly bounds Phase 3 — your instruction was "use multiple agents to develop the code," and I'll plan around that ceiling.

### C5. Plugins

A plugin bundles skills, subagents, hooks, and MCP servers into one installable unit, distributed via a git repo marketplace [V]. "Skills are the unit of capability and plugins are the unit of distribution."

Since the recommended design uses all four component types, a plugin is the natural container. It also gives clean install/uninstall and namespacing (`bb:hunt` rather than a bare `/hunt` colliding with something else).

### C6. Standalone application

A Python/TypeScript app calling the Anthropic API directly.

**Ruled out by your Q16 constraint, and I'd rule it out anyway.** It requires an API key, moves you to metered billing, and means rebuilding the entire agent loop, tool dispatch, permission system, and TUI that Claude Code already provides. You'd write thousands of lines to get a worse Claude Code.

A *headless CLI* (`claude -p`) is likewise ruled out: as of 2026-06-15 it draws from the metered Agent SDK credit rather than your subscription [V].

### C7. Mechanism-to-job mapping

| Job | Mechanism | Why |
|---|---|---|
| Methodology playbooks | Skill | Text; progressive disclosure keeps cost at zero until used |
| Teaching content | Skill | Same |
| Report templates | Skill | Same |
| Case file state | MCP server | Needs a database and typed access |
| Scope matching | MCP server | Deterministic computation |
| Recon output parsing | MCP server (or script) | Parsing, not reasoning |
| Coverage queries | MCP server | Narrow results, not data dumps |
| Scope *enforcement* | PreToolUse hook | Must be outside the model |
| Redaction before storage | Script + hook | Must be deterministic |
| Bounded research | Subagent | Context isolation, max 2–3 |
| Distribution | Plugin | Bundles all of the above |

The mapping is unusually clean — each job has one obviously-right mechanism. That's a good sign the architecture is falling out of the constraints rather than being imposed.

---

## 6. Part D — The Claude Pro subscription path

You asked for this explicitly. It is a genuine design constraint, not a footnote.

### D1. What the billing actually does [V]

| Path | Billing | API key needed |
|---|---|---|
| Interactive Claude Code, signed in with Pro/Max | Subscription pool: 5-hour rolling window shared with Claude chat, plus a weekly cap | No |
| `claude -p` headless | Separate metered Agent SDK credit at API rates (since 2026-06-15) | Effectively yes |
| Claude Agent SDK | Same metered credit | Yes |
| GitHub Actions integration | Same metered credit | Yes |
| Any app with `ANTHROPIC_API_KEY` set | Pay-as-you-go API, **overrides subscription entirely** | Yes |

Pro is $20/mo. Max 5x is $100/mo and Max 20x is $200/mo, each raising both the 5-hour window and the weekly cap proportionally [V].

### D2. What this means for the design

**Three hard rules fall out:**

1. **The system is driven by you, interactively, inside Claude Code.** Not a daemon, not a cron job, not a background hunter. This is also what you asked for on safety grounds — the billing model and the safety model agree.

2. **The system never calls the Anthropic API itself.** The MCP server does storage, parsing, and matching. It contains no LLM calls. If it did, it would need a key and would bill separately.

3. **Do not set `ANTHROPIC_API_KEY` in your environment for this project.** It silently overrides the subscription. Worth putting in the setup docs as an explicit warning.

**And one soft rule that shapes the whole data design:**

4. **Context frugality is a cost constraint, not just good practice.** The 5-hour window is shared with your Claude chat usage. A single careless "summarize this 40k-line nuclei output" can eat a meaningful chunk of a session. The store-and-query architecture (§7) is the direct response: raw data lands in SQLite via a parser, and the model pulls narrow slices.

Concretely, the difference:

```
BAD:   Read(nuclei-output.json)          → ~35,000 tokens
GOOD:  mcp__bb__list_findings(
         target="x", severity=">=medium",
         status="untriaged", limit=20)   → ~800 tokens
```

That's roughly a 40× difference on one call, and it repeats every session.

### D3. Anthropic's cyber safeguards — an honest unknown

Anthropic applies runtime safeguards that block "vulnerability exploitation or offensive security tooling development" by default [V — documented in the Claude-BugHunter README and corroborated by CVP coverage]. The Cyber Verification Program lifts this for verified parties.

**But:** CVP is described as *"org-scoped and API-key scoped, exercised through the Console Workbench or via direct API calls using the organization's key"* and *"not a consumer-account feature"* [V]. Every public acceptance announcement I found is a company (Cycode, Mitiga, Tamnoon, Mondoo, Zafran) [V].

**[U] — I could not determine whether an individual researcher on a Pro subscription can obtain CVP coverage, or whether CVP even applies to subscription-authenticated Claude Code as opposed to API keys.** The sources point toward "no" on both, but I did not find an authoritative statement either way.

**Practical implications:**

- The recommended v1 is mostly *analysis, organization, and writing* — reading proxy history, correlating notes, drafting reports, explaining code. That is unlikely to trip exploitation-focused safeguards. [A]
- If you later want help *developing working exploit code*, you may hit refusals, and CVP may not be available to you as an individual. That is a real ceiling on this project and you should know about it now rather than in Phase 3.
- This is worth checking directly with Anthropic before Phase 2 finalizes anything that depends on it. It's a five-minute question to support and it removes a `[U]` from the plan.

I'd rather flag this as unresolved than design around a guess.

---

## 7. Part E — Three candidate architectures

### Option 1 — Pure skill bundle

Skills only. Methodology, checklists, teaching content, report templates. Notes in Markdown files that Claude reads and writes with the normal file tools.

**Structure:**
```
bb-skills/
  skills/
    scope-intake/        parse a policy into a scope file
    recon-triage/        read tool output, summarize
    hunt-idor/           IDOR methodology
    hunt-authz/          ...
    (~20 more)
    write-report/
  templates/
```

**Pros**
- Simplest possible thing. Could be usable in days.
- Nothing to install beyond dropping files in `~/.claude/skills/`.
- Zero new attack surface — no server process, no database.
- Trivially portable; skills follow an open standard that works across tools.
- You could write it yourself and modify it freely.

**Cons**
- **State is Markdown files the model manages.** After compaction it forgets what it wrote. It will duplicate entries, contradict earlier notes, and lose track. This is not a hypothetical — it's the standard failure mode of model-managed files across sessions.
- **No way to answer coverage questions reliably.** "What haven't I tested on this target" requires reading all the files into context — expensive and increasingly infeasible as notes grow.
- **No mechanical scope enforcement.** Back to prompt-based rules — the exact weakness of the existing bundles.
- **Context cost scales badly.** Every session re-reads the notes.

**Verdict: this is what already exists, twice.** It would be fast to build and would not solve your problem #7, because #7 is fundamentally a state problem. Rejected as the primary architecture — though the skills *layer* of it is retained in Option 3.

### Option 2 — MCP server plus thin skills

A local MCP server owns a SQLite case file and exposes typed tools. A handful of skills tell the model how to use them.

**Structure:**
```
bb-mcp/          Python MCP server
  db.py          SQLite schema + migrations
  scope.py       deterministic scope matching
  ingest.py      parse nuclei/ffuf/httpx/Burp output
  tools.py       MCP tool definitions
skills/
  hunt/          how to drive the tools
  report/
```

**Pros**
- Real, durable state. Survives compaction, restarts, and weeks off.
- Coverage queries are cheap and exact.
- Correlation is a SQL join, not a model guess.
- Context-frugal — narrow results instead of data dumps.
- Deterministic scope matching lives in code.

**Cons**
- **Scope matching exists but nothing enforces it.** The model *can* call `check_scope()` — and can also just not call it. A tool the model may skip is not a control.
- Methodology has to live somewhere; putting it in MCP tool descriptions is awkward and wastes context (tool descriptions are always loaded, unlike skill bodies).
- More to build than Option 1.
- New process on your machine — a small but real security surface (§9.4).

**Verdict: right foundation, missing the enforcement layer.** The gap between "the model should check scope" and "scope is checked" is exactly the gap I criticized in §B2.

### Option 3 — Plugin: skills + MCP server + PreToolUse hook (RECOMMENDED)

Option 2 plus a hook that mechanically blocks out-of-scope actions, all bundled as one installable plugin.

**Structure:**
```
bb/                              (Claude Code plugin)
  .claude-plugin/plugin.json
  mcp/                           local MCP server (Python)
    server.py
    db.py                        SQLite: targets, endpoints, coverage,
                                 notes, leads, primitives, findings, evidence
    scope.py                     deterministic matcher, deny-by-default
    ingest.py                    normalizers for nuclei/ffuf/httpx/katana/Burp
    redact.py                    strip secrets/PII before storage
  hooks/
    scope-guard.py               PreToolUse: deny out-of-scope
  skills/
    bb-target/                   set up / switch active target
    bb-next/                     "what should I do next" — the core loop
    bb-recon/                    ingest and triage recon output
    bb-hunt-*/                   per-class methodology playbooks
    bb-correlate/                surface links between notes/primitives
    bb-report/                   draft or critique a report
    bb-review/                   post-session retrospective + coverage report
  reference/
    wstg-checklist.json          test-case taxonomy backbone
    bounty-overlay.json          bounty-specific cases WSTG lacks
```

**How the three layers divide responsibility:**

| Layer | Owns | Property |
|---|---|---|
| Hook | "May this action happen?" | Deterministic, outside the model, unbypassable by prompt |
| MCP server | "What is true?" | Durable, queryable, no LLM involved |
| Skills | "What should we do and how?" | Flexible, progressive-disclosure, model-driven |

This separation is the whole idea. Each layer does what it is actually good at, and the layer that must not be fooled is the one that isn't made of prompts.

**Pros**
- Solves #7 directly: the coverage ledger plus `/bb:next` means you always have a next action, grounded in what you've actually done.
- Scope enforcement is mechanical.
- Runs entirely on Pro, no API key.
- Context-frugal by construction.
- Clean install/uninstall; namespaced commands.
- Each layer independently testable — the scope matcher is a pure function with a table of test cases; the ingest parsers are pure functions; the hook is a script you can pipe JSON into.
- Grows well: adding a proxy MCP later, or a new vuln playbook, doesn't touch the rest.

**Cons**
- Most to build. Realistically the largest of the three by 2–3×.
- The hook can annoy you when it's wrong. A false-deny mid-session is disruptive, so it needs a clean, auditable override path (§9.2).
- Three components means three places a bug can live.
- Shell-command parsing in the hook is inherently imperfect (§C3).

**Verdict: recommended.**

### Comparison

| | Opt 1: Skills | Opt 2: MCP + skills | Opt 3: Plugin (rec.) |
|---|---|---|---|
| Solves problem #7 | No | Partly | Yes |
| Durable state | Weak | Yes | Yes |
| Coverage queries | No | Yes | Yes |
| Scope enforcement | Prompt only | Advisory | Mechanical |
| Context cost | High, grows | Low | Low |
| Runs on Pro, no key | Yes | Yes | Yes |
| Build effort | Low | Medium | Medium-high |
| New attack surface | None | Small | Small |
| Differentiated vs existing | No | Yes | Yes |

### The tool-posture recommendation (your Q4)

You deferred this to R&D. My recommendation: **ingest-only for v1, with proxy-history reading, and command-proposal as a fast follow.**

Reasoning:

- **Ingest-only has zero unauthorized-traffic risk by construction.** Nothing to get wrong. For a student building a first system, starting where the blast radius is zero is correct.
- **Your proxy history is already the richest data source you have,** and reading it generates no traffic. Most of the value of "AI-assisted recon" is available without the AI ever touching the network. This surprised me somewhat but it holds up: the model's edge is in *interpretation*, and interpretation doesn't need network access.
- **A few hours a week means the bottleneck is your thinking time, not your scanning throughput.** Automating scan execution optimizes something that isn't your constraint.
- **Command-proposal (Q4b) is a cheap addition later** — the model drafts, the scope hook validates, you run it. It slots in without redesign.
- **Execution-with-approval (Q4c) I'd defer indefinitely.** Approval fatigue is real: after the fortieth prompt you start clicking yes without reading, and the control becomes theatre. If it goes in at all, it should be after you've used the system for a month and know exactly which commands you'd want automated.

The scope hook should be built in v1 regardless, even though ingest-only mode barely needs it. Building enforcement before you need it means you never ship a version that needs it and doesn't have it.

---

## 8. Part F — Storage

Options considered for the case file:

**Markdown files only.** Human-readable, greppable, git-friendly, Obsidian-compatible, zero dependencies. But: no queries, model-managed consistency (which fails), and unbounded context cost. The community defaults to this [V] and the community also doesn't have coverage tracking — I don't think that's a coincidence.

**SQLite only.** Queryable, transactional, consistent, tiny, in the Python standard library (`sqlite3` — no dependency). But: not human-readable without a tool, and bad for the prose parts (a methodology note or a draft report is not a row).

**Obsidian vault.** Nice UI, graph view, plugin ecosystem, community precedent. But it's Markdown underneath, so it inherits the query problem, and it adds a dependency on an app for programmatic access.

**Full app with a real database.** Overkill by a wide margin for a single user with a few hours a week.

**Recommendation: SQLite as the source of truth, with Markdown export.**

- SQLite holds the structured entities: targets, scope rules, endpoints, coverage records, notes, leads, primitives, findings, evidence pointers. `sqlite3` ships with Python, so this adds no dependency.
- Prose bodies (report drafts, detailed notes) are Markdown *stored in* SQLite columns — you get FTS5 full-text search for free, also stdlib.
- An export command writes a Markdown tree. That gives you readability, git history, Obsidian compatibility, and portability, without making Markdown the thing that has to stay consistent.
- One database file per target keeps blast radius small and makes "delete everything about this program" a single `rm`. That matters for your NDA constraint (§9.3).

Rough entity sketch (Phase 2 will specify this properly):

```
target        program, platform, scope_fetched_at, confidentiality
scope_rule    target_id, pattern, asset_type, in_scope(bool), source
endpoint      target_id, method, url, params, first_seen, source
coverage      target_id, endpoint_id, test_case_id, status, tested_at, evidence_id
note          target_id, body_md, created_at
lead          target_id, hypothesis, confidence, status
primitive     target_id, capability, description, evidence_id   ← the underused one
finding       target_id, title, severity, status, body_md
evidence      target_id, kind, blob_path, redacted(bool), sha256
```

The `coverage` table is the heart of it. `(endpoint, test_case, status)` is what nothing else has, and it's what makes "what's untested" a query instead of a guess.

---

## 9. Part G — Safety analysis and failure modes

Your Phase 4 asks for machine and data safety validation. Designing for it starts now.

### 9.1 Prompt injection from target data — the highest risk

**The threat.** Content you ingest is controlled by the target. HTTP response bodies, error messages, HTML comments, JS source, JSON fields, HTTP headers, filenames. Any of it can contain text crafted to be read as instructions by an LLM. Unit 42 has documented indirect prompt injection against web-browsing agents in the wild [V]. There is published work specifically on injecting AI security agents [V].

**Why it's worse here than in normal agent use.** You are, by definition, interacting with systems whose operators may be adversarial toward automated tooling — and some targets deliberately deploy anti-bot and anti-agent measures. You also hold the "lethal trifecta": privileged local access (filesystem, shell), untrusted input (target data), and an exfiltration channel (network tools). A successful injection could exfiltrate your notes on *other* programs, your API tokens, or your SSH keys.

**Mitigations for the design:**

1. **Delimit and label all target-derived content.** Anything ingested gets wrapped and explicitly marked as untrusted data, never as instructions. The guidance from the literature is to "clearly tag and isolate external content from system-generated data" [V].
2. **Prefer structured extraction over raw text.** Parsers pull fields into typed columns rather than passing prose through. A URL in a `url` column is data; a URL in a paragraph the model reads is an instruction vector.
3. **Never auto-execute anything derived from target content.** The scope hook already blocks network actions; the same principle extends to file writes and shell commands.
4. **Standing instruction in every relevant skill:** content retrieved from a target is evidence, never direction. If ingested content appears to contain instructions, that is itself a finding to report to you, not something to follow.
5. **Cap ingest size and sanitize control characters** before storage.
6. **Keep the blast radius small:** per-target databases, no cross-target reads without an explicit switch.

I want to be straight with you: **these mitigations reduce risk, they do not eliminate it.** There is no known complete defense against indirect prompt injection. The realistic posture is defense in depth plus a small blast radius, and knowing this is a live risk rather than assuming it's handled.

### 9.2 Scope drift and unauthorized traffic

**The threat.** Testing something you're not authorized to test. Consequences range from a report rejection to a legal problem. Ways it happens without malice: scope changed since you cached it, a wildcard matched something unexpected, a redirect took a request to a different host, a subdomain resolves to a third-party SaaS you're not authorized against, or the model simply confused two similar hostnames.

**Mitigations:**

1. **PreToolUse hook, deny-by-default.** Unknown host → deny. Not "warn."
2. **Explicit out-of-scope list takes precedence over wildcard in-scope matches.** `*.example.com` in scope plus `internal.example.com` out of scope means `internal.example.com` is denied, and the ordering must be encoded, not inferred.
3. **Scope staleness visible.** If the cached scope is older than N days, say so before the session starts.
4. **Redirect awareness.** If a proposed command follows redirects, flag it — the destination is not knowable in advance. (Relevant given YesWeHack's finding that the model already mishandles redirects [V].)
5. **Auditable override.** When the hook is wrong — and it will be — you need a clean way past it that leaves a record. An override that requires you to type the host and a reason, logged with a timestamp. Not a global "disable scope checking" flag, which would inevitably get left on.
6. **Honest limit:** as noted in §C3, shell-command parsing is imperfect. The hook is a strong guard against mistakes and drift, not a sandbox. Ingest-only v1 keeps this from mattering much; if you later add command execution, the hook's parsing coverage becomes a real design question deserving its own analysis.

### 9.3 Data leakage

**The threat.** You said some programs have NDAs and private scope that must never leave the machine. Three leakage paths:

1. **Into the model's context** — anything the model reads goes to Anthropic's API. Unavoidable for anything you want help with; the control is *choosing* what goes.
2. **Into the wrong place on disk** — a private program's notes written into a directory synced to GitHub or OneDrive. Your working directory is under `Documents/GitHub/`, which is a real risk if any of it ends up in a pushed repo.
3. **Via injection** — §9.1.

**Mitigations:**

1. **Per-target confidentiality flag.** Set at target creation. Private/NDA targets get different handling.
2. **Redaction before storage.** Deterministic scrubbing of session tokens, cookies, API keys, and obvious PII from stored evidence. Deterministic — regex and entropy heuristics, not a model call.
3. **Evidence stored as files with pointers in the DB**, so the model reads a path and a summary rather than a full request/response by default. It pulls the body only when it needs it.
4. **A `.gitignore` that excludes the case-file directory by default,** plus a loud warning if the case-file path is inside a git repo with a remote. Given your `Documents/GitHub/` working directory, this is not theoretical.
5. **Named exclusion mechanism** — a per-target setting that hard-blocks certain data classes from ever entering a prompt.

### 9.4 Local machine safety

**The threat.** The system itself damaging or exposing your machine.

**Mitigations:**

1. **MCP server is read/write only within its own data directory.** No arbitrary filesystem access. Path traversal explicitly rejected.
2. **Minimal dependencies.** Python stdlib where possible (`sqlite3`, `json`, `re`, `pathlib`). Every third-party package is supply-chain surface — and the Caido guide's warning about version-pinning applies directly [V]. Fewer dependencies also means less to audit in Phase 4.
3. **No `shell=True`, no string-interpolated commands.** Anywhere a subprocess is spawned, argument lists only.
4. **Server binds localhost only,** or stdio transport (preferable — no listening socket at all).
5. **No network calls from the MCP server** except explicitly-allowed scope-data fetches (the `bounty-targets-data` JSON, platform APIs), each to a fixed allowlisted host.
6. **Ingest parsers treat input as hostile.** They're parsing attacker-influenced data. Size caps, no `eval`, no pickle, no YAML `load` without `SafeLoader`, defensive JSON parsing.
7. **Credentials via environment or a file outside the repo,** never in the database, never in the case file, never committed.

### 9.5 Hallucinated findings and false confidence

**The threat.** The model says "this is an IDOR" and it isn't. You submit. Program marks it N/A. Reputation drops. Repeat a few times and you're getting less access, not more. This is a slow, quiet failure and it's the one most likely to actually happen to you.

**Mitigations:**

1. **A finding is never created by the model.** It proposes a *lead*; only you promote a lead to a finding. The state machine enforces this — the MCP tool to create a finding requires a human-confirmation field.
2. **Every claim carries evidence or is marked unverified.** No evidence pointer, no confidence.
3. **Report drafting reads only from stored evidence.** Gaps become `[YOU MUST FILL THIS IN]`, never plausible filler.
4. **A skill whose job is to argue against a finding** before you submit. Cheap to build, high value — it's the 7-Question Gate idea from Claude-BugHunter but grounded in the stored evidence rather than asked as freeform questions.
5. **Severity is proposed with reasoning, never asserted.** And no payout estimates anywhere — that's the shuvonsec mistake and it biases toward inflation.

### 9.6 Anthropic safeguards and CVP

Covered in §6.3. Summary: refusals are possible on exploitation-heavy tasks; CVP appears to be org-scoped and may not be available to you as an individual [U]; the recommended v1 is analysis-and-writing shaped and unlikely to be heavily affected [A]. Worth confirming with Anthropic before Phase 2 locks anything down.

### 9.7 Platform terms regarding AI

**[U] — I did not research each platform's current policy on AI-assisted submissions, and it's changing fast.** Platforms have been tightening rules in response to low-quality AI-generated report volume. Some now require disclosure of AI assistance; some restrict automated tooling.

This should be checked per-program before you submit, and the system should surface any AI-usage clause from the program policy at report time. Adding it to the pre-submission checklist is cheap. I'm flagging it as unresolved rather than guessing.

---

## 10. Part H — Open questions for Phase 2

Resolve these before or during planning:

1. **Burp Community + MCP.** Search results say the PortSwigger MCP extension supports Community [V, medium confidence], but I did not confirm from the BApp Store compatibility field. Which tools work without Pro? **This determines whether proxy integration lands in v1 or waits.**
2. **CVP availability for individuals** [U]. §6.3. A direct question to Anthropic support resolves it.
3. **Caido vs Burp Community.** Caido's MCP integration is first-party and more capable, and you're not invested in Burp yet. Worth 30 minutes of evaluation before we build against either.
4. **Windows vs WSL.** The Go recon stack isn't on Windows [V]. Where does the case file live, where does the MCP server run, and how do paths translate? Matters even for ingest-only, since you'll be feeding it WSL-produced files.
5. **Scope for the first playbook set.** Which vulnerability classes get real methodology playbooks in v1? I'd suggest starting with 4–6, not 20 — IDOR/BOLA, access control, SSRF, and business logic would be my picks for a web+API researcher, since they're high-value, under-automated, and reward exactly the systematic approach you're missing. XSS and SQLi are more contested and more automated by others.
6. **Test-case taxonomy.** WSTG as the backbone plus a bounty overlay [A — I believe this is right but haven't mapped it in detail]. How many test cases in v1?
7. **Platform AI-disclosure policies** [U]. §9.7.
8. **Target selection (your Q10).** You want both modes. Does target-selection guidance ship in v1 or v2? My instinct is v2 — it's a separate problem from "work the target I'm on," and v1 should stay focused on #7.

---

## 11. Recommendation summary

**Build:** a Claude Code plugin — SQLite-backed MCP server for state, skills for methodology, PreToolUse hook for scope enforcement.

**Posture:** ingest-only in v1. The model reads output you produce and proxy history you've already collected. It generates no traffic. Command-proposal as a fast follow if you want it.

**Billing:** interactive Claude Code on your existing Pro subscription. No API key. No headless mode, no Agent SDK, no background agents.

**Storage:** SQLite source of truth, per target, with Markdown export.

**Scope for v1:** web + API. Source-reading supported as an analysis capability. Mobile, binaries, and infra deferred.

**The one-sentence justification:** every existing tool in this space is a prompt library, your actual problem is that you can't remember or reason about what you've already covered, and that's a state problem — so build the state, borrow the prompts.

**What I'd cut if you want it smaller:** the teaching skills and the correlation engine can both be v2. The irreducible core is: scope intake → coverage ledger → `/bb:next` → report drafting. That alone addresses problem #7, and it's maybe 40% of the work.

---

## Sources

Ecosystem and tooling:
- [Best Agentic Pentesting Tools in 2026 — Security Boulevard](https://securityboulevard.com/2025/12/best-agentic-pentesting-tools-in-2026/)
- [AI Pentesting Agents 2026: The Rise of 39+ Tools Tested](https://appsecsanta.com/research/ai-pentesting-agents-2026)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
- [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)
- [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) · [MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [Den-Sec/burp-mcp](https://github.com/Den-Sec/burp-mcp) · [swgee/BurpMCP](https://github.com/swgee/BurpMCP)
- [c0tton-fluff/caido-mcp-server](https://github.com/c0tton-fluff/caido-mcp-server) · [Caido MCP docs](https://docs.caido.io/app/tutorials/mcp)
- [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data)

Practitioner assessments:
- [YesWeHack — How to use Claude Code for Bug Bounty: find fast, validate manually](https://www.yeswehack.com/learn-bug-bounty/llm-series-claude)
- [Critical Thinking HackerNotes Ep. 166 — Claude Code Skills for Bug Bounty](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-166-claude-code-skills-for-bug-bounty-when-why-and-how-to-build-them)
- [Caido — The Practitioner's Guide to AI-Enhanced Hacking](https://www.caido.io/blog/2026-03-24-ai-enhanced-hacking/)
- [TrustedSec — MCP in Burp Suite: From Enumeration to Targeted Exploitation](https://trustedsec.com/blog/mcp-in-burp-suite-from-enumeration-to-targeted-exploitation)

Methodology and reporting:
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) · [WSTG checklist](https://github.com/OWASP/wstg/blob/master/checklists/checklist.md)
- [Bugcrowd — The Importance of Notes & Session Tracking](https://www.bugcrowd.com/blog/the-importance-of-notes-session-tracking-bug-bounty-hunter-methodology/)
- [Why Bug Bounty Reports Get Rejected](https://www.comolho.com/post/why-bug-bounty-reports-get-rejected)
- [Intigriti Triage Standards](https://kb.intigriti.com/en/articles/10335710-intigriti-triage-standards)
- [HackerOne Hacker API](https://api.hackerone.com/hacker-resources/)

Platform, billing, and safety:
- [Claude Code skills documentation](https://code.claude.com/docs/en/skills) · [Claude Code hooks documentation](https://code.claude.com/docs/en/hooks)
- [Claude Code Billing in 2026: Subscription Usage vs the Agent Credit Pool](https://tygartmedia.com/claude-code-billing-credit-pool-2026/)
- [Claude Code Rate Limits & Usage Quotas Explained (2026)](https://www.truefoundry.com/blog/claude-code-limits-explained)
- [Anthropic's Cyber Verification Program in Practice](https://bregg.com/blog/cvp-cyber-verification-program-defensive-security-2026-07-08)
- [Unit 42 — Web-Based Indirect Prompt Injection Observed in the Wild](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)
- [Cybersecurity AI: Hacking the AI Hackers via Prompt Injection (arXiv)](https://arxiv.org/pdf/2508.21669)
- [OpenAI — Understanding prompt injections: a frontier security challenge](https://openai.com/index/prompt-injections/)
- [Claude Code Plugins: bundling skills, hooks, agents, and MCP servers](https://hidekazu-konishi.com/entry/claude_code_plugins_complete_guide.html)

---

**End of Phase 1. Awaiting your review before Phase 2 planning.**
