---
name: pb-xss
description: Methodology playbook for finding reflected, stored, and DOM XSS on a real target. Load when testing input reflection/rendering contexts or when bb-next surfaces an XSS test case.
---

# pb-xss

## When this applies
Any point where attacker-influenced input might later be parsed as HTML/JS/CSS by a browser: URL params/path segments/fragment, form fields, headers reflected into pages (User-Agent, Referer, X-Forwarded-*), stored content (profile fields, comments, filenames, uploaded SVG, support tickets a different role later views), `postMessage` handlers, and client-side routing that reads `location.hash`/`search`. Covers WSTG-INPV-01 (reflected), WSTG-INPV-02 (stored), and WSTG-CLNT-01 (DOM-based) for the purely client-side variant.

## First signals
Notice these before forming any hypothesis about a bug:
- WHERE input reappears, not whether it "looks dangerous": HTML text node, HTML attribute (quoted/unquoted), inside a `<script>` block, inside a URL (href/src), inside CSS, inside JSON later parsed client-side, inside an HTML comment.
- The same input reflected in two different spots on one page, encoded differently in each — a context-mismatch is often the actual gap, not a total absence of encoding.
- A client-side sink fed by attacker-reachable input: `innerHTML`/`outerHTML`, `document.write`, `eval`/`Function`, code reading `location.hash`/`search` into the DOM, a templating "raw"/"unescaped" helper, `dangerouslySetInnerHTML` (React), `[innerHTML]` (Angular), `v-html` (Vue).
- A stored field a *different* privilege level later views (an admin dashboard rendering a user-submitted display name, a support panel rendering a ticket subject) — stored XSS often lands in the viewer's session, not the submitter's.
- File upload accepting SVG, HTML, or a MIME type a browser renders directly when linked to, rather than downloading.
- A filter or WAF that visibly transforms your marker (strips a tag, encodes one character but not another) — the transform itself tells you what's sanitized, worth noting even before finding a gap in it.
- `postMessage` listeners with no origin check, consuming attacker-influenceable data from another window/frame.

## Enumeration
Map every input-to-context pairing before testing any single one.
1. Walk the app enumerating every parameter/field/header that ends up somewhere on a page: reflected in the response, stored and displayed later, or consumed purely client-side.
2. For each, note the render context: HTML text, HTML attribute, `<script>` context, URL context (href/src), CSS context, or a specific DOM sink. The same parameter reflected in two contexts needs testing in both — each has its own escaping rules.
3. Separate reflected (comes back this response) from stored (comes back in a LATER response, possibly to a different viewer) from DOM-based (never leaves the browser; the server never sees the value that ends up executing).
4. For stored candidates, list every surface where the stored value is later rendered — a display name might appear on a profile page, a comment list, an admin table, and a notification email, each with independent escaping.
5. For DOM candidates, trace the actual sink the value reaches by reading the bundled JS where available (cross-reference `bb-code`) rather than inferring from behavior alone.
6. Coverage is exhausted once every distinct input-x-context pair has a recorded result — not once a handful of "reflective-looking" fields have been tried. A field safe in one context still needs checking in every other context it also reaches.

## Test procedure
1. Baseline: submit a unique, harmless marker string (short random alphanumeric, no HTML metacharacters) and locate exactly where and how many times it reappears.
2. From that location, add standard HTML metacharacters (`< > " ' &`) one context at a time and observe encoding: returned literally, HTML-entity-encoded, backslash-escaped, or stripped. This single observation tells you whether the sink is safe, context-mismatched, or genuinely unescaped, before trying to prove anything more.
3. HTML-text-node context: confirm whether `<`/`>` survive unescaped. If they do, the standard next step is one inert, harmless tag that only proves the parser treated your input as markup (something you can visually confirm rendered) — not a payload that runs script.
4. Attribute context: confirm whether a quote breaks out of the attribute, and whether the attribute is script-bearing (an event handler, `href="javascript:..."`) versus a plain data attribute — that distinction decides whether escape-and-break-out is meaningful on its own.
5. `<script>`-block or JSON-in-`<script>` context: confirm only whether the marker can terminate the surrounding string/script context. Stop at confirming termination — don't add a functional script body beyond what shows the parser is now outside your intended string.
6. DOM sink: confirm the value reaches the sink unmodified by reading the rendered DOM or the relevant JS, rather than assuming from URL shape alone.
7. Stored XSS: submit the marker once, then check every render surface identified during enumeration for the same encoding behavior — a value safely escaped on one surface can be unescaped on a sibling one.
8. Where a context is genuinely unescaped, the standard confirmation is a single benign, visually or DOM-observably distinct proof of execution, fired once in your own browser/session — never anything that reads cookies or tokens, targets another user, or persists beyond what's needed for evidence.
9. Note any `Content-Security-Policy` or output encoding that blocks the sink you found — a strong CSP can make an unescaped sink non-exploitable in practice; record that distinction instead of treating "unescaped" and "exploitable" as the same finding.

### Worked example of a context-encoding sweep
```
Marker: xssprobe7k2

?q=xssprobe7k2  ->  HTML body:      <p>Results for xssprobe7k2</p>            (verbatim, no metachar test yet)
?q=xssprobe7k2"><b>  ->  same field: <p>Results for xssprobe7k2&quot;&gt;&lt;b&gt;</p>   (entity-encoded — safe here)

?name=xssprobe7k2"><b>  ->  attribute context on profile page:
    <input value="xssprobe7k2"><b>">                                          (quote NOT encoded — breaks attribute)
```
The second field is the finding-in-progress: the same class of character that was safely encoded in the body context reaches the page unescaped in an attribute context. That's the signal to move to step 4 on that specific field, not on the first one.

## Evidence to capture
- The exact input, the exact landing context, and a screenshot or raw response/DOM snippet showing the encoding (or absence of it).
- For confirmed execution: a screenshot or console log showing the harmless proof firing in your own browser/session — never a payload reading cookies, tokens, or another user's data.
- The full request/response pair (or DOM state for client-side-only cases) via `mcp__bb__store_evidence`.
- For stored XSS: evidence from both the submission point and every render surface it was confirmed on.
- Relevant response headers: `Content-Security-Policy`, `X-Content-Type-Options`, cookie flags if session theft is part of the impact story.
- Browser and version used — encoding/sink behavior can differ on older or WebView-embedded browsers.

## Escalation
- Reflected XSS on a pre-auth page reachable via a constructible link is generally more impactful than one needing hard-to-deliver interaction — name the realistic delivery path, don't assert "an attacker could" without it.
- Stored XSS rendered to a higher-privilege viewer (support agent, admin) is materially bigger than the same payload rendering only back to the submitter — name the viewing role explicitly.
- DOM XSS reachable via a URL fragment needs no server round-trip to deliver, often a stronger delivery story than a reflected querystring parameter.
- Where CSP exists, state precisely what it blocks and doesn't (inline vs. externally loaded, directive gaps) — a bypassable or partial CSP is its own secondary finding, not a reason to fold everything into "lower severity."
- If the context also grants access to a CSRF token embedded in the page, or lets you make authenticated same-origin requests, name that primitive specifically (session/token theft, arbitrary action as the victim) instead of leaving impact at "script execution."
- Bank a confirmed-but-limited context (harmless tag renders, no clean path to a scriptable one yet) via `add_primitive` rather than dropping it — a filter gap or sink found elsewhere may complete the chain.

## Out-of-scope traps
- Self-XSS: a payload that only fires because you pasted it into your own console/devtools, or into a field that never round-trips through the server or another user's session, has no victim delivery path. Confirm a path a victim could actually be steered into hitting.
- A field that stores your marker but never renders as HTML/JS (a `SELECT` filter, an internal log, a PDF's plain-text field) is not XSS regardless of round-tripping — confirm the rendering context, not just persistence.
- Input landing inside a `<textarea>`, an HTML comment, or a genuinely attribute-escaped context a browser will never treat as an active boundary is not a finding just because the marker "shows up" — verify the parser context actually breaks.
- A `Content-Type` forcing download or non-HTML handling (`application/json`, `text/plain` with `X-Content-Type-Options: nosniff`) neutralizes an otherwise-reflective parameter — check actual response headers before assuming reflection equals rendering.
- A sanitizing rich-text renderer that strips dangerous characters but preserves plain text is working as designed — confirm the specific sanitizer is actually bypassed, not just that some unrelated tag passes through elsewhere.
- Read program exclusions: most explicitly exclude self-XSS, XSS requiring MITM/physical device access, or XSS confined to a local-only context (`window.name`) with no realistic delivery.

## Integration
- Record every input-context pair with `mcp__bb__record_coverage(handle, endpoint_id, test_case_id, status, note?, evidence_id?)`, one record per context (`xss-reflected-html-body`, `xss-reflected-attr`, `xss-stored-admin-view`) rather than one blanket result per endpoint.
- Bank a confirmed-but-not-yet-scriptable observation (marker reflects unescaped in an attribute, but no event-handler attribute is reachable here) via `mcp__bb__add_primitive` — it may combine with a filter gap found on a sibling context.
- The assistant proposes which inputs, contexts, and probe sequence to try next; the human sends every request and observes the actual rendered DOM/console before anything counts as confirmed.
- Never assert XSS is confirmed from a description of behavior alone — that's `record_coverage(status="confirmed")` or `promote_to_finding(..., human_confirmed=True)` only after the human has seen it fire themselves.
