---
name: pb-miniprogram
description: Methodology playbook for WeChat/Alipay/Douyin/Baidu miniprogram targets, including WeChat Cloud Development. Load when the target ships a miniprogram package, its backend API, login chain, or cloud functions are in scope, or when bb-next surfaces a miniprogram test case.
---

# pb-miniprogram

## When this applies
- The target is a miniprogram (WeChat, Alipay, Douyin, Baidu, QQ) or embeds one.
- You have or can obtain the miniprogram package (`.wxapkg` / subpackages / decompiled output).
- The interesting surface is the miniprogram's backend: `wx.request` endpoints, the login chain (wx.login code → session), payment flows, or WeChat Cloud (cloud functions / database / storage).
- Frontend rendering points exist: web-view, rich-text, JSBridge, share/card jumps.

Division of labor: Android APK component security is `pb-android`; the two share backends constantly — extract the domain from one and test the surface on both. Backend endpoints found here flow into the standard API/auth playbooks.

## First signals
- A miniprogram ID (appid) visible in share links, QR codes, or the package metadata — the identifier you need to locate the package.
- PC WeChat cache directories (`WeChat Files/Applet/<appid>/`) containing `.wxapkg` files after the miniprogram has been opened once.
- In the decompiled source: `appsecret` (a frontend config error by definition — the backend should hold it), cloud env IDs, cloud-provider keys (SecretId/SecretKey), or internal/back-office domain names.
- `wx.login()` → code → token flows where the request body carries an `openid` field the client supplies — the single most common fatal mistake in this ecosystem.
- `wx.cloud.callFunction({name: ...})` calls with no visible identity check inside the function.
- web-view `src` or rich-text `nodes` fed by user or AI-generated content.

## Enumeration
1. Obtain the package: PC WeChat cache, developer-tools projects, proxied package downloads, or platform-specific archives. Note the appid and version; record how you obtained it.
2. Unpack and decompile (unpacker tools of the wxappUnpacker/unveilr generation; Alipay/Douyin/Baidu have equivalent formats and tools). Verify completeness — the decompiled page list should match the live miniprogram's pages before you trust the artifact.
3. Extract the high-value material first:
   - Sensitive strings: appid/appsecret/keys, cloud env IDs, cloud-provider credentials, internal domains.
   - The endpoint list: every `wx.request`/`request(` URL, every `wx.cloud.callFunction` name, with their parameter structures and auth headers.
   - The login chain: how code becomes a token, what the client sends, what the server returns (does it return `session_key` to the client?).
   - Rendering points: web-view src sources, rich-text nodes sources, JSBridge/message handlers, share/`navigateToMiniProgram` parameters.
4. Feed every extracted domain and endpoint into the coverage ledger (bb-recon) — the backend API is the same surface the web app uses, and it usually has weaker controls than the miniprogram frontend suggests.
5. You've covered the package when the extracted endpoint list is complete and cross-checked against a proxy capture of the live miniprogram (things in traffic but not in code are dynamic-loaded; things in code but never called are dead).

## Test procedure
Work the classic chains in priority order — the login chain first, because everything else hangs off it.

1. Login-chain tests (the ecosystem's classic):
   - **openid/client-supplied identity**: if the token exchange accepts an `openid` (or user id) parameter from the client, substituting another user's value is arbitrary login — the highest-impact bug in this class. Confirm by obtaining B's data/session with your own code/token flow.
   - **code replay**: the same `code` exchanged twice → two tokens; code not bound to session/device.
   - **session_key disclosure**: the backend returning `session_key` to the frontend (it exists to stay server-side; it decrypts phone numbers).
   - **token tampering**: custom tokens containing plaintext openid/user_id, or JWT-family tokens with weak/none signing (route to pb-jwt-flaws when it's a JWT).
   - **register-as-login**: a registration call that returns a logged-in session, letting you claim existing identifiers.
2. Payment/order logic: order-amount parameters honored from the client, callback signature verification missing (a forged notify accepted), duplicate callbacks re-triggering fulfillment, refund amount/count trust. The confirmation is a real state change on a test resource the program provides — route deeper logic hunts to pb-business-logic.
3. Authz on backend endpoints: no-token, forged-token, and other-user-token differentials on every extracted endpoint — the miniprogram backend is where BOLA/IDOR findings concentrate (hand off to pb-idor-bola for full methodology).
4. WeChat Cloud checks:
   - Cloud functions: callable with arbitrary names, and inside the function no `getWXContext()` identity check → an unauthenticated caller driving privileged logic. Confirm with a function that reads/writes data you shouldn't reach.
   - Cloud database: default (all-users) permissions, `where` conditions built from client input → cross-user reads/writes.
   - Cloud storage: publicly readable buckets, enumerable objects.
   - Environment switching: an env ID taken from the client allowing access to another environment (staging/admin).
5. Rendering checks:
   - web-view `src` controllable → arbitrary URL load; test the whitelist for parse-difference bypasses (this is pb-xss/pb-open-redirect territory once the load is confirmed).
   - rich-text `nodes` rendering HTML without sanitization, especially when the content is AI output or chat content — stored-XSS with the miniprogram's webview as the execution context (route to pb-xss; LLM-origin content routes to pb-llm-security).
   - JSBridge/message handlers without a sender whitelist; `navigateToMiniProgram`/share parameters injected into paths that drive internal navigation.
6. Local storage: `wx.setStorage` of plaintext tokens/keys/phone numbers — a note unless it combines with something that reads it back (another app component, a webview bridge).

### Worked example of tiering a result
```
Observe: token exchange accepts {"openid": "oXXXX-A"} from the client body
Test:   request with your code + openid of account B → response contains B-scoped token
Confirm: calling /api/user/profile with that token returns B's profile
         -> arbitrary user login confirmed (not just "parameter accepted")
```
Report the tier reached — "the parameter is accepted" is a lead; only B's data in your session is the finding.

## Evidence to capture
- The package (or its hash), appid, version, and how it was obtained.
- The decompiled fragments backing each claim (file paths in the unpacked tree).
- For login findings: your code/token request, the substituted identity, and the other-user data returned.
- For payment findings: the forged callback/order and the state change observed on a test resource.
- For cloud-function findings: the function name, the request without valid identity, and the privileged result.
- For rendering findings: the injected content and the rendered/executed proof (screenshot of the webview behavior).
- Extracted credentials/domains as separate notes — they are findings and recon fuel at once.

## Escalation
- An accepted `openid` parameter escalates to arbitrary login only with B's data shown — the differential is the finding, not the parameter.
- code replay alone is medium at best; it escalates when a replay grants a *persistent* session or defeats a 2FA/device binding.
- `session_key` disclosure escalates by what it decrypts (phone numbers are PII; that's the impact).
- Cloud-function auth gaps escalate by what the function does — a read of public data is low; an admin write or cross-tenant read is high.
- Payment forgery escalates with the real-world effect (fulfillment, credit) — demonstrate on the smallest test resource, never a real transaction.
- Extracted appsecret/cloud keys escalate by what the key is authorized for — verify the key's permissions before claiming impact (pb-cloud-infra owns that follow-up).
- A miniprogram XSS often has a wider blast radius than web XSS in the same app — the webview context can bridge into the app's JSBridge; note the bridge capabilities when reporting.

## Out-of-scope traps
- Only test miniprograms the program owns — a miniprogram is a separate product from the web app and may not be in scope; check the program's asset list.
- Decompiled code is a map, not proof: every finding still needs live confirmation on the backend; "the code does X" is not "X happens".
- Self-inflicted data (your own openid, your own orders) is not a finding — the cross-user differential is mandatory.
- appsecret presence in the frontend package is a configuration finding, not a license to use it — report it; don't drive unauthenticated backend calls with a leaked production secret beyond confirming validity.
- Payment testing needs the program's explicit test environment and their rules about amounts/refunds — real-money manipulation is out of bounds everywhere.
- Local-storage notes are Informative by themselves — don't inflate them.
- Package acquisition must stay within the program's terms (caches and published packages are fine; breaking DRM or attacking distribution infra is not).

## Integration
- Record every extracted endpoint and each chain tested with `mcp__bb__record_coverage` — the miniprogram backend joins the same ledger as the web surface.
- Bank primitives with `mcp__bb__add_primitive`: accepted-but-unverified parameters, session_key in responses, cloud env IDs, unauthed-but-harmless cloud functions.
- Extracted domains/keys go to bb-recon; login/IDOR findings hand off to pb-authentication-flaws / pb-idor-bola; rendering findings to pb-xss; cloud follow-ups to pb-cloud-infra.
- The assistant proposes which chain to test next and the exact differential to run; the human executes every request and confirms what came back.
