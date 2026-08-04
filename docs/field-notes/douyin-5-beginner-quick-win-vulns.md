---
title: "新手第一天就能出成果的5种漏洞，手把手教你挖（全带实战教程）"
source: "https://v.douyin.com/9iAkL4ksp4s/ (video id 7654895323810221331)"
platform: douyin
creator: "网络安全黑卡 (抖音号 60860301060)"
duration: "06:22"
language: zh
analyzed: 2026-07-30
content_type: tutorial
tags: [bug-bounty, beginner, broken-access-control, sqli, info-disclosure, unauth-access, password-reset, china-platforms]
---

# 5 "Day-One" Beginner Bug Classes (Douyin field note)

> Analysis method note: **no Whisper variant was installed on this machine**, so
> there is no machine transcript. The video is a mind-map-driven tutorial with
> **burned-in Chinese subtitles**, so these notes were reconstructed from the
> extracted frames — the 思维导图 (mind maps) carry the full methodology and the
> subtitles carry the narration. Exact dork/path strings were read off the frames
> (image text); sanity-check any string before pasting it. See **Caveats**.

## 摘要 / Summary
A Chinese-platform (抖音/Douyin) beginner recruitment-style tutorial by "网络安全黑卡"
arguing that a newcomer can get a *first accepted bug* on day one by focusing on 5
low-skill vulnerability classes, each presented as a mind map plus a short demo
against the creator's own practice range (智慧样官方靶场) and DVWA. The core pitch:
"不是你不行，是你不知道该从哪下手" — *it's not that you can't, you just don't know where
to start.* The 5 classes and the "prove-existence-only, use authorized ranges"
ethic are legitimate; the "无脑上手 / 当天出结果" (brainless / same-day results) framing
is marketing and should be read skeptically (see Caveats).

## 核心要点 / Key Takeaways
- The beginner's edge is **class selection and sequencing**, not tooling: pick the
  handful of classes with the lowest skill floor and highest acceptance rate, and
  test only those first instead of staring at the whole app.
- **Broken access control (越权) is pitched as the single best beginner class** — the
  creator claims it is >35% of accepted reports on the Chinese platform 补天 (Butian).
  Split it into 水平越权 (horizontal: reach another *peer* user's data) and 垂直越权
  (vertical: reach *admin* data/actions).
- The IDOR/越权 detection move is mechanical: find a request carrying a numeric ID /
  username / order-number (`?id=2`), then decrement/increment it (`id=1` peer, `id=4`
  higher-privilege) and see whether you get back someone else's data.
- **Information disclosure via search-engine dorks needs zero access to the target**:
  `site:TARGET inurl:backup`, `filetype:sql`, `filetype:zip`, `intext:password` surface
  backups, DB dumps, and credentials the site published by accident. FOFA is used the
  same way to find *more targets* running a given stack.
- **Unauthorized access = forced browsing**: append common privileged paths
  (`/admin`, `/manage`, `/api/user/list`, `/upload`, `/console`) to the target and see
  if the back-office opens with no login. The creator claims ~60% of their unauth
  findings came from that short path list.
- **Entry-level SQLi is one character**: put a single quote `'` into an input and watch
  for a database error. A raw DB/SQL error is the first signal that input reaches an
  unparameterized query.
- **Arbitrary password reset (任意用户密码重置) is the highest-impact beginner class**:
  intercept a "change/forgot password" request in Burp and swap the `username`/`phone`
  parameter to a victim's — if the reset succeeds, that is full account takeover.
- Repeated legal framing throughout: **only prove the vulnerability exists; never
  actually reset a real user's password or exfiltrate real data; practise on
  authorized ranges (靶场).** This matches how a report should read (existence + impact,
  not exploitation).

## 内容分解 / Timestamped Breakdown

### [00:00] Hook — "you're not incapable, you just don't know where to start"
On-screen: "不是你不行" / "是你不知道该从哪下手" / "一步到位". Frames the video as a fix
for the beginner's blank-page problem and promises 5 classes that are "无脑上手，当天出
结果" (easy to start, same-day results). Creator watermark 抖音号 60860301060 / 网络安全黑卡
persists on every frame.

### [00:40] Vuln 1 — 越权访问漏洞 (Broken Access Control / IDOR)
Mind map (`越权访问漏洞`):
- **漏洞占比与价值 (share & value):** 补天平台占比超 35%; 新手易获赏金. *(creator claim)*
- **类型划分 (types):**
  - **水平越权 (horizontal):** 普通用户访问其他普通用户数据. 示例: 查看同事工资条 (view a
    colleague's salary slip).
  - **垂直越权 (vertical):** 普通用户访问/操作管理员数据. 示例: 查看或篡改老板工资条 (view or
    tamper the boss's salary slip).
- **目标参数特征 (target params):** URL 或数据包中含数字 ID、用户名、订单号等编号型参数.
- **测试方法 (test):** 登录靶场，进入个人中心 (如 `/id=2`).
- **复现步骤 (repro):** 改 `id` 为相邻值 (如 `id=1`) → 若看到他人信息即水平越权; 改 `id` 为高
  权限值 (如 `id=4`) → 若看到管理员信息即垂直越权.

### [01:30] Vuln 1 demo — salary system, id=2 → id=4, ¥5000 bounty
Live demo against `123.199.70.32/salary?id=2` (智慧样企业管理系统, an "employee management
system" range). Changing the `id` in the URL shows other employees' salary panels
(¥5700 / ¥2375 for one id; ¥12000 / ¥5000 for another) — "相当于你可以看到老板的工资条".
Then a "漏洞状态通知" screenshot: **漏洞状态: 已确认，漏洞等级: 严重，并获得赏金 5000 元** —
presented as the reward for that submission. *(creator claim — a screenshot, unverifiable.)*

### [02:00] Vuln 2 — 目录遍历与信息泄露漏洞 (Info disclosure via search dorks)
Mind map (`目录遍历与信息泄露漏洞`, labelled 大漏洞):
- **漏洞特征:** 无需技术基础，依赖搜索引擎高级语法.
- **漏洞原理:** 非法访问服务器公开文件.
- **信息泄露:** 网页直接暴露密码、手机号等敏感数据.
- **常用搜索语法 (dorks):**
  - `site:目标网站 inurl:backup` → 查找备份文件 (backup files)
  - `site:目标网站 filetype:sql` → 查找 SQL 数据文件 (DB dumps)
  - `site:目标网站 filetype:zip` → 查找压缩包文件 (archives)
  - `site:目标网站 intext:password` → 查找含密码文本的网页 (pages containing passwords)
- **类比示例:** `site:baidu.com filetype:pdf` → find Baidu-hosted PDFs (shown live in a
  Baidu search bar at ~[03:00]).
- **复现实战:** 掌握语法即可，举一反三.
- At ~[02:50] a **FOFA** query (`app="thinkphp"`) is shown as the way to enumerate *more*
  targets running the same framework.

### [03:10] Vuln 3 — 未授权访问漏洞 (Unauthorized access / forced browsing)
Mind map (`未授权访问漏洞`):
- **漏洞定义:** 游客用户绕过认证直接访问需授权资源; 后台页面/接口缺乏权限校验.
- **高危路径 (high-value paths):** `/admin`、`/manage`、`/api/user/list`、`/upload`、`/console`
  ("这五个"). 其他常用路径见学习笔记; **claim: 60% 漏洞由上述路径发现.**
- **复现实战:** 在目标域名后逐个拼接路径 (如 `/domain/dashboard`); 若无需登录/验证码即可访问
  后台页面 → 存在漏洞.
- Demo: an 员工登录 (employee login) page exists, but browsing directly to
  `123.199.70.33:9017/dashboard` opens the data dashboard (and elsewhere an
  `Internal Server Error`) with no auth — "就能直接打开数据看板页面". Claimed result:
  未授权访问所有业主号与联系方式, plus a bounty screenshot.

### [04:10] Vuln 4 — SQL 注入漏洞（入门级）(Entry-level SQL injection)
Mind map (`SQL注入漏洞（入门级）`):
- **技术门槛:** 无需掌握 SQL 语法; 仅需英文单引号 `'` 即可初步探测.
- **检测方法:** 在输入框输入数字/一组值点 Submit; 用 DVWA 的 `SQL Injection` 模块练习.
- **复现实战:** 观察是否返回数据库错误提示; 出现英文/数据库报错常暗示 ~90% 可能存在 SQL 注入.
  *(creator's rough heuristic, not a real probability.)*
- Demo in DVWA `SQL Injection`: enter `1` (or a single quote) in the User ID box, Submit,
  read the returned row / error ("或者错误的提示了").

### [04:50] Vuln 5 — 任意用户密码重置漏洞 (Arbitrary user password reset / ATO)
Mind map (`任意用户密码重置漏洞`):
- **危害等级:** 账号接管类漏洞中最致命的一种; 可绕过全部身份验证机制重置任意用户密码;
  验证码可暴力破解.
- **常见成因:** 抓包修改 `username`/`phone` 等参数即可重置他人密码 (新手最易复现).
- **测试范围:** 所有 "忘记密码"/"找回密码" 重置功能点; 覆盖网页、APP、小程序等全端场景.
- **复现实战:** 正常登录 → 进入密码修改页 → 输入新密码 → 点击确认前用 **BurpSuite 抓包** →
  修改数据包 `username` 为目标他人用户名 → 放行后若提示成功 → 用该用户名 + 新密码登录验证.
- **靶场推荐:** 智慧样官方授权靶场对应模块 (demo shows a 张三 user, 修改密码 packet edited).
- **法律提醒:** 仅验证漏洞存在性; **严禁真实重置他人密码.**

### [06:00] 总结 / Summary
- 五大漏洞均属 "无脑上手，当天出结果" 类型. *(marketing claim)*
- **新手友好特性:** 无需编程能力，无需理解深层原理.
- **成功路径:** 严格按实战步骤操作 → 结合学习笔记系统实践 → 快速产出漏洞并获取赏金.
- Closing legal line: "你挖洞时只要证明漏洞存在就可以" — when hunting you only need to
  *prove the vuln exists*. Call to action to follow the account / DM for the 学习笔记.

## 视觉信息 / Visual-Only Information
- The entire methodology lives in **5 mind maps** (思维导图), one per class — these are the
  real payload of the video and were read in full from the frames.
- **Demo target hosts (illustrative, the creator's own ranges — do NOT touch):**
  `123.199.70.32/salary?id=2` (salary/越权 demo), `123.199.70.33:9017/dashboard` (unauth
  demo). These are the presenter's authorized practice ranges, not your scope.
- **Bounty screenshots** shown as social proof: 越权 → "已确认…严重…赏金 5000 元"; 未授权 →
  a second reward screenshot. Both are images with no verifiable provenance.
- **Tools shown on screen:** Baidu (dork demo), **FOFA** (`app="thinkphp"` target discovery),
  **BurpSuite** (intercept for the password-reset demo), **DVWA** (SQLi module).
- The `/admin, /manage, /api/user/list, /upload, /console` path list and the four
  `site:` dorks appear as on-screen text and are the most directly reusable artifacts.

## 知识点提取 / Extracted Knowledge
- Broken access control splits into horizontal (reach a peer user's data) and vertical
  (reach an admin's data/actions).
- An IDOR test is: find a request with a numeric/username/order-id parameter, change it to
  a neighbouring or higher-privilege value, and check whether another user's data returns.
- Reaching a higher-privileged user's data by changing an id in the URL is a vertical
  access-control break; reaching a peer's is horizontal.
- Public search dorks find data a site leaked without any access to the target:
  `site:TARGET inurl:backup`, `site:TARGET filetype:sql`, `site:TARGET filetype:zip`,
  `site:TARGET intext:password`.
- FOFA (and similar) find additional hosts running a given stack via fingerprints like
  `app="thinkphp"`.
- Forced browsing means appending known privileged paths to a host and seeing if they open
  without authentication; a high-yield starter list is `/admin`, `/manage`, `/api/user/list`,
  `/upload`, `/console`.
- A single quote `'` in an input is the minimum SQL-injection detection probe; a raw
  database/SQL error in the response is the first signal.
- Arbitrary password reset is caused by trusting a client-supplied `username`/`phone`
  parameter in a reset flow; swapping it to a victim's identifier resets their password.
- Password-reset/account-takeover flaws exist across all "forgot/reset password" functions
  and across web, app, and mini-program front-ends.
- Ethical rule for reporting: prove the vulnerability exists; do not actually reset a real
  user's password or exfiltrate real records. (This is also the correct report posture.)
- 补天 (Butian) is a Chinese bug bounty platform; broken access control is claimed to be
  >35% of its accepted reports. (claim)
- The classes with the lowest skill floor for a beginner (per this creator) are, in order:
  broken access control / IDOR, info disclosure via dorks, unauthorized access, entry-level
  SQLi, and arbitrary password reset. (claim about ordering)

## 金句引用 / Notable Quotes
- [00:05] "不是你不行，是你不知道该从哪下手" — names the exact beginner problem this repo's
  coverage ledger and bb-next are built to solve.
- [05:55] "你挖洞时只要证明漏洞存在就可以" — the prove-existence-not-exploit ethic, which is
  also the right severity posture for a report.

## 疑点与局限 / Caveats
- **This is a lead-generation / training-recruitment account** (repeated "学习笔记" / follow-me
  calls to action). The "无脑上手 / 当天出结果" (brainless / same-day results) framing is
  marketing. In reality these are the *first* classes every beginner tries, so on real public
  programs they are the most picked-over and most likely to return duplicates — the opposite of
  an easy win. Treat "day-one results" as aspirational, not typical.
- The **¥5000 bounty and ">35% of 补天" figures are unverifiable creator claims** (a screenshot
  and a spoken number). Do not repeat them as fact.
- The **"~90% chance of SQLi if you see an error" heuristic is not a real probability** — a DB
  error means input *reached* the query and warrants a proper check, nothing more. This repo's
  `pb-sql-injection` states the disciplined version.
- **Analysis gap:** built from frames only (no Whisper transcript). The mind maps are captured
  in full and are stable across many frames, but narration between the 10-second frame samples
  may contain minor points not captured here. Dork/path strings were OCR-read from images —
  verify exact spelling before use.
- The demo hosts (`123.199.70.32`, `123.199.70.33`) are the presenter's own authorized ranges.
  They are **out of scope for you** and appear here only to document the demo; never send them
  traffic.
- Methodology depth is beginner-level and is a strict subset of this repo's playbooks
  (`pb-broken-access-control`, `pb-idor-bola`, `pb-path-traversal`, `pb-secrets-exposure`,
  `pb-sql-injection`, `pb-authentication-flaws`), which cover the same probes plus enumeration,
  escalation, out-of-scope traps, and evidence discipline. Use the playbooks for the actual work;
  use this note only for the *beginner sequencing* and the *China-platform (补天/FOFA) context*.

## Prompt-Ready Distillation

    Beginner "quick-win" bug-hunting sequence — 5 low-skill-floor web classes to test
    FIRST on an authorized target, in order of skill floor (methodology only; prove
    existence, never exploit real data; practise on authorized ranges):

    1. Broken access control / IDOR (highest beginner value).
       - Horizontal = reach a peer user's data; vertical = reach admin data/actions.
       - Target any request carrying a numeric id, username, or order number (e.g. ?id=2).
       - Change it to a neighbouring value (id=1) or a higher-privilege value (id=4) and
         check whether another user's / an admin's data returns. Returned foreign data = break.

    2. Information disclosure via search dorks (no target access needed).
       - site:TARGET inurl:backup      -> backup files
       - site:TARGET filetype:sql      -> database dumps
       - site:TARGET filetype:zip      -> archives
       - site:TARGET intext:password   -> pages exposing credentials
       - Use FOFA-style fingerprint queries (e.g. app="thinkphp") to enumerate more hosts.

    3. Unauthorized access (forced browsing).
       - Append privileged paths to the host and see if the back-office opens with no login:
         /admin, /manage, /api/user/list, /upload, /console (highest-yield starter list).
       - "Page renders without auth AND exposes data/actions" = finding; "URL merely resolves"
         is not.

    4. Entry-level SQL injection.
       - Minimum probe is a single quote ' in one input.
       - A raw DB/SQL error (or a true/false-shaped response difference) is the first signal
         that input reaches an unparameterized query. Confirm with one true/false pair; do not
         extract data.

    5. Arbitrary user password reset (account takeover — highest impact of the five).
       - In any forgot/reset-password flow, intercept the request (Burp) and change the
         client-supplied username/phone parameter to a victim identifier.
       - If the reset succeeds, that is full ATO. Demonstrate on an account you control; never
         reset a real user's password.

    Ethic and reality check: only prove the vulnerability exists (existence + impact), never
    exploit real users' data or reset real passwords. These five are the classes every beginner
    tries first, so on mature public programs they are heavily picked over and duplicate-prone —
    the "same-day results" promise is marketing. The durable edge is systematic coverage of a
    target across these classes, not the class list itself.
