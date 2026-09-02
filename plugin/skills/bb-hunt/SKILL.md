---
name: bb-hunt
description: Router to the right vulnerability-class methodology playbook. Use when about to test a specific class, or when bb-next surfaces a test case and you need the detailed how-to for it. Loads one focused playbook instead of guessing.
---

# bb-hunt

Routes from "I'm about to test X" to the one detailed playbook for X. The playbooks
(`pb-*` skills) hold the systematic method for each class; this skill picks the right
one so you load focused guidance instead of improvising.

## When to use this
- `bb-next` surfaced a test case and you want the full method before testing it.
- The user names a class ("let's look for IDORs here").
- You are unsure which class a candidate endpoint most rewards — map its shape to a playbook below.

## How to route
1. Take the test case's `category` (from `next_actions`) or the class the user named.
2. Match it to a playbook below and load that `pb-*` skill.
3. Follow the playbook's 8 sections. Record the result with `mcp__bb__record_coverage`
   and bank any half-finding as a primitive with `mcp__bb__add_primitive`.

If two playbooks plausibly apply (an admin API endpoint is both access-control and
IDOR/BOLA), load both — they overlap on purpose. Do not force a single choice.

## Category / signal → playbook

| If the coverage category or signal is… | Load |
|---|---|
| Authorization, object id, ownership, tenant | `pb-idor-bola` |
| Authorization, admin function, role/vertical, forced browsing | `pb-broken-access-control` |
| A parameter the server fetches (url/webhook/import/preview) | `pb-ssrf` |
| Business Logic, multi-step flow, price/quantity/state trust | `pb-business-logic` |
| Authentication, login/register/reset/MFA | `pb-authentication-flaws` |
| Session Management, cookies, token lifecycle | `pb-session-management` |
| Extra writable fields (role/is_admin/owner) on a write endpoint | `pb-mass-assignment` |
| API, a /graphql endpoint, introspection | `pb-graphql-abuse` |
| A check-then-act on a limited resource (coupon/balance/limit) | `pb-race-condition` |
| Reflected/stored user input in a rendered context | `pb-xss` |
| A parameter reaching a database query | `pb-sql-injection` |
| Input reaching a template/command/XML parser | `pb-injection` |
| A state-changing request with no anti-CSRF protection | `pb-csrf` |
| A url/next/return/redirect parameter | `pb-open-redirect` |
| A file upload / import / avatar feature | `pb-file-upload` |
| A filename/path parameter | `pb-path-traversal` |
| A JWT in use (auth header/cookie) | `pb-jwt-flaws` |
| OAuth/OIDC/SSO login, redirect_uri | `pb-oauth-flaws` |
| CORS headers reflecting origin with credentials | `pb-cors-misconfig` |
| A CNAME to a deprovisioned third-party service | `pb-subdomain-takeover` |
| Exposed .git/.env/backup, keys in JS, cloud buckets | `pb-secrets-exposure` |
| Front-end/back-end request parsing differences | `pb-request-smuggling` |
| A cache in front of the app, unkeyed inputs reflected | `pb-cache-poisoning` |
| A WAF/filter blocking a payload, 403s, sanitized echoes | `pb-waf-bypass` |
| A chatbot / AI feature / agent / RAG / model endpoint | `pb-llm-security` |
| Cloud assets, ops panels, middleware, CI/CD, supply chain | `pb-cloud-infra` |
| Source code or decompiled artifacts to audit statically | `pb-source-audit` |
| Serialized data, deep-merge objects, yaml/XML parsers | `pb-deserialization` |
| A WeChat/Alipay miniprogram or WeChat Cloud surface | `pb-miniprogram` |
| An Android APK — exported components, deep links, keys | `pb-android` |
| An APK that decompiles to stubs — packed, needs unpacking | `pb-apk-reversing` |
| The REST/protocol surface — docs, versions, methods, WebSocket | `pb-api-security` |
| A Windows EXE/DLL/SYS or .NET binary to analyze | `pb-windows-binary` |
| Unauthenticated surface — path not in main-site JS, standalone/migrated H5, sibling or same-IP host, gateway 405/empty-array, front-end crypto used as auth | `pb-unauth-surface` |
| A verification code / OTP / CAPTCHA that may be reusable, unbound to the recipient, or decided client-side | `pb-authentication-flaws` |

If nothing matches cleanly, describe the endpoint's shape and pick the closest — then
say what you're unsure about rather than forcing a bad fit.

## Firm rules
- Load the specific playbook; do not improvise a method when one exists.
- The assistant proposes tests; the human runs them. This system sends no traffic.
- Only suggest tests for in-scope, untested (or `suspicious`) items.
- Never claim a finding is real — that is the user's call after they verify and record it.
- If two classes apply, load both rather than guessing at one.
