---
title: "一文讲透新手如何上手AI漏洞挖掘"
source: "https://v.douyin.com/mdHmnvFAnAE/ (video id 7656328725268679988)"
platform: douyin
creator: "洺熙-AI安全 (抖音号 40282896511)"
duration: "18:57"
language: zh
analyzed: 2026-08-02
content_type: tutorial
tags: [ai-assisted-hunting, claude-code, claude-md, skills, mcp, playwright, hallucination-control, bug-bounty, methodology]
---

# Getting Started with AI-Assisted Vulnerability Hunting (Douyin field note)

> **Analysis method note:** full pipeline ran — 138 frames + 13 montage grids, plus
> 17 full-resolution slide captures, and a machine transcript from `faster-whisper`
> (`small`, language forced to `zh`; the `medium` model crashed natively on this
> machine). The deck is the real payload here: it carries structured tables,
> templates, and file paths that the narration only gestures at. Whisper garbled
> nearly every product name (`Claude Code` → "clad code / crow的code / cloud code",
> `Skill` → "secure / sql", `IDOR` → "乐学"); every name below was cross-checked
> against the slides. Names that appear **only** in audio are flagged in Caveats.

## 摘要 / Summary

A Chinese-language (抖音/Douyin) tutorial by AI-security researcher 洺熙 arguing that
beginners fail at AI-assisted bug hunting because they treat the model like a wishing
lamp rather than an amplifier. The video's thesis: AI multiplies whatever skill you
already have, so the setup that matters is not a bigger model but a *system* — a
`CLAUDE.md` project memory card, one browser MCP, narrow single-vulnerability Skills,
and above all a verification gate that assumes every finding is a hallucination until
proven. It is explicitly **not** a guide to autonomous hunting; the stated frame is
"人主导，AI辅助" (human-led, AI-assisted). Structurally it is a slide deck walkthrough:
tool choice → model choice → `CLAUDE.md` → MCP → Skills → workflows → anti-hallucination
→ division of labour → collaboration modes.

## 核心要点 / Key Takeaways

- **The failure mode has a signature.** Someone pointed AI at an open-source project
  and asked it to "find the vulnerabilities": it reported **17 高危 (high-severity)
  findings; 16 were false positives and the 1 real one was an already-public CVE**
  [00:28]. Same toolchain, opposite outcome from people who first know how data flows
  through the app and roughly which endpoint yields which bug class.
- **Web-chat AI is the wrong tool shape, not just a weaker one.** Hunting is a
  long-running engagement (长线程) you may return to next year, requiring script
  execution, code reading and verification — none of which survives a chat box that
  "聊完就忘" (forgets when the conversation ends) [03:34]. Use Claude Code or Codex.
- **Less configuration beats more.** Installing many MCPs and Skills crowds out the
  model's reasoning space: "你的这些思考的空间都给这些 MCP、给这些 Skill 了，那么模型
  真正干活的空间就剩下很少了" [04:43]. One browser MCP is the recommended total.
- **There is no strongest model, only the most suitable one** [05:25]. Pick per task
  rather than seeking a universal best; having two models challenge each other reduces
  single-model blind spots [06:33].
- **`CLAUDE.md` is a memory card, and the most valuable field is the negative one.**
  Recording *what you excluded and why* is worth as much as recording findings —
  "排除原因和发现一样值钱，三天后你会感谢自己写下来了" [slide, 09:20].
- **One Skill handles exactly one vulnerability class.** The observed failure is
  stuffing dozens of checkpoints into a single file until the model gets lost [10:43].
- **Prohibitions constrain better than aspirations**: "你禁止他做什么，比希望他做什么
  来的约束更好一点" [12:27] — tell the Skill what it may *not* do.
- **AI's biggest risk is not missing a bug, it's confidently reporting a fake one**
  [slide, 15:11]. The countermeasure is a four-gate verification ladder (G0–G3) and a
  quarantine directory: new findings land in `hallucinations/` and are promoted to
  `findings/` only after passing every gate.
- **Ask the model to admit ignorance.** "让 AI 承认不知道，比硬编靠谱" — letting it say
  "I don't know" is more reliable than letting it fabricate [13:37].
- **The division of labour is the whole point**: AI does 体力活 (grunt work) and
  information processing; the human does 思考判断 (judgement) and 决策验证 (decision
  verification). "AI 能帮你挖洞，但是它不能替你坐牢，也不能给你背锅" [17:08].

## 内容分解 / Timestamped Breakdown

### [00:00] Why this video exists — the 17-findings cautionary tale
Made in response to feedback that earlier videos explained how to *build* an AI system
but not how a beginner actually hunts with one. The anchoring anecdote [00:28]: a viewer
pointed AI at an open-source project with the instruction "this project is open source,
find me the vulnerabilities in it." The model returned **17 high-severity findings**;
on review **16 were false positives** and the remaining one was a **publicly known CVE**.
Meanwhile other viewers using the same system found real bugs. The difference [00:57]:
successful hunters "本身就知道这个数据怎么流转，这个功能点、这个接口大概哪里会出现什么样的
漏洞" — they already know the data flow and where a given endpoint tends to break, and
use AI to amplify that. The failure mode is treating AI as Aladdin's lamp: "神灯神灯，
我要一个洞" (lamp, lamp, give me a bug).

### [01:26] Scope of the video, and the results screenshot
Explicit framing: this is about AI **amplifying a beginner**, not automating hunting
end-to-end. Shows a (heavily redacted) bounty screenshot captioned **单洞 2.6W 严重**
— a single critical bug paying ~26,000 RMB at a core major vendor, plus multiple 高危
findings at large companies [01:26–01:56]. Stated precondition: that hunter already had
基本功 (fundamentals), business understanding, and attack-surface familiarity; AI scaled
what was already there.

### [02:26] The beginner's actual mistake
Not that they can't attack, but that they treat AI as a slot machine — "给我一个 payload，
帮我把这个项目所有的洞全部找出来." The missing pieces are stated as three questions
[02:36]: **when** to use it, **on what**, and **how to verify afterwards**. Without
answers, there's no system.

### [02:54] Drop web-chat AI, adopt an agentic CLI
Advice: stop hunting through web-based chat models (豆包 and similar). Real project work
is a long-running thread — you might still be on the same project next year — and requires
running scripts, reading code, and verifying. Web chat makes you the courier: "你就像一个
搬运工" [03:49]. An agent instead gives the model a tool-calling, repeatedly-verifying
environment — "相当于是你有了一个替你打工的人" (like having someone working for you)
[04:03]. Recommendation: **Claude Code or Codex** [04:28].

### [04:35] Configure minimally — less is more
Many people immediately install assorted MCPs and Skills. Argued unnecessary: they
consume the model's thinking budget. Stated principle [05:02]: "配置的原则就是尽可能精简，
少即是多" — keep configuration as lean as possible. (The sentence that follows is
misspoken in the audio; see Caveats.)

### [05:12] Model selection — no strongest, only most suitable
"没有最强的模型，只有最适合的模型" [05:25]. Different vendors train differently, so
capabilities differ. The right question is not "which model is best for hunting" but
"which model fits *this task*" [05:43]. Rough assignments given: Claude for code work,
GPT for searching/research material, various domestic Chinese models for automatable
tasks. Two models can be set to challenge each other to reduce a single model's blind
spots [06:33]; a practitioner example cited is Claude for vulnerability analysis with
GPT doing cross-validation [06:41]. A budget recommendation for students is given at
[06:49] (name uncertain in transcript — see Caveats).

### [07:00] STEP 3 — write `CLAUDE.md`, the project memory card
`CLAUDE.md` sits in the project root and is auto-read by Claude Code at every launch;
without it you re-explain the project on every reopen. Contents to write: the testing
scope, where the red lines are, which bug classes you intend to test, what you have
found, **what you have not found**, what you have already ruled out, and your
understanding of the business/application [07:36–07:54]. With it, the agent "知道你当前
在干什么" and becomes a real assistant rather than something that "瞎指导、瞎忽悠"
(gives useless direction) [08:08].

### [08:23] Install one browser MCP
A `CLAUDE.md` alone is not enough because the goal is for AI to *act*. Install **one**
browser MCP — "这个 MCP 一个就够了" [08:31]. Rationale: rather than describing in prose
how to log in, let it drive the browser itself [08:39]. It can then visit pages, submit
forms, and test buttons; paired with the `CLAUDE.md` rules this forms the **minimal
viable structure** [09:04].

### [09:15] Worked example — the `CLAUDE.md` template
Walks the template (transcribed in full under Visual-Only Information). Scenario used
[09:33]: a community site's **user module** — have the agent read the front-end
interfaces, extract the corresponding **API endpoints**, check whether you can access
other users' resources, generate PoCs to test with, and organise the results. The
detailed version is offered via the creator's fan group.

### [10:14] Writing Skills — teaching the audit methodology
A Skill auto-loads when a task matches, so you don't re-type the procedure; it encodes
"你针对某类漏洞的审计思路" and makes the model follow your playbook [10:28]. The common
failure he sees [10:43]: "他们把几十个检查点全部塞进一个 md 文件里面了" — dozens of
checkpoints in one file, and the model gets lost reading it. Recommended shape: define
role and domain, then the system/business context and constraints, supply examples and
decision routing, give step-by-step instructions, and specify the output format [11:04].
Important nuance [11:29]: give constraints and routing but **don't over-specify**, because
excessive detail "反而会限制模型的一个发散能力" (suppresses the model's divergent thinking).

### [11:44] Worked example — IDOR Skill and the generic template
Walks an IDOR audit Skill plus a generic Skill template side by side (both transcribed
below). The emphasised point [12:18]: "一定要加上约束，禁止他测什么" — always add
constraints about what it must not test, because "你禁止他做什么，比希望他做什么来的
约束更好一点." Notes that beyond special business scenarios, a generic Skill covers most
cases [12:41], and that as models improve, Skills will compress further [12:46].

### [12:52] Practical workflows
Three workflows plus tips (full slide below). **JS auditing** [12:58]: many people now
have AI audit JavaScript because it's laborious for humans, and the model quickly
extracts endpoints, parameters, and call relationships. **Brainstorming/lead ranking**
[13:16]: give the model context on what you've already tried and the problems you hit,
ask what might be useful, then have it **rank** the leads and surface the few most worth
digging into. Tip [13:37]: "让 AI 承认自己不知道比它硬编一个要靠谱的很多."
**Negative recording** [13:47]: models tend to record only what was found, but what was
*not* found matters — recording why something was excluded tells you where to improve
the system and saves re-spending tokens next round [14:00–14:19].

### [14:20] Multi-session strategy and mandatory review
Run several parallel sessions, each owning one area — one for IDOR, one for
authentication, others for free exploration — kept independent and non-interfering
[14:24–14:37]; this sometimes surfaces unexpected findings. Interrogate every output
[14:40]: are you sure it's exploitable, what's the false-positive scenario, how would you
manually confirm it. Every finding must be verified to guard against AI false positives
and hallucination [14:52]. Reports written by AI **must be reviewed before submission**,
never submitted directly [14:58].

### [15:11] Anti-hallucination — the verification gate
Framed as the beginner's trap: AI will "一本正经地胡说八道" (talk nonsense with a
completely straight face). The answer is two characters — **验证** (verify) [15:30].
Mechanism: whatever the AI finds goes into a first-tier directory and is verified there
— does the PoC exist and compile, does it reproduce, does it have real exploitation
value, does it trigger stably in the current business environment [15:41–15:58]. Only
after verification is it promoted to the second-tier directory [16:12]. This
"先怀疑，再验证" (doubt first, then verify) mechanism drives the false-positive rate down
[16:18]. Reinforced: use two models, or the same model forced to argue opposite
positions, to analyse the same question [16:23].

### [16:36] Division of labour
"你的分工一定是明确的" — AI handles physical/repetitive work and information processing;
you handle judgement and decisions [16:40]. JS extraction, payload generation, document
organisation → give to AI. Which target is most worth digging, the business logic behind
it, whether two findings combine into something severe, hands-on reproduction, report
review, and what may be submitted → yours [16:52–17:05]. The line [17:08]:
**"AI 能帮你挖洞，但是它不能替你坐牢，也不能给你背锅"** — AI can help you find bugs, but
it can't go to jail for you and can't take the blame for you. The end state is 人机互补
(human-machine complementarity).

### [17:21] Progression and closing
Start by using AI to assist analysis, get today's configuration in place, write your own
Skills, and practise on authorised targets. "它是来增强我们的，而不是让我们去依赖它的"
[17:44] — it exists to augment you, not to be depended on; know when to use it and when
to do it yourself. Final points [17:52–18:17]: fundamentals matter, vulnerability theory
still has to be learned, AI is an amplifier, **verification matters more than discovery**,
don't trust AI's findings — verify them. Closing contrast: treat AI as a **crutch** and
you get no growth; treat it as an **accelerator** and you'll outpace most people. Slides
are offered via the creator's fan group; viewers are urged to do hands-on practice.

## 视觉信息 / Visual-Only Information

The deck carries the actionable content. Everything below was read off full-resolution
frames and is *not* fully spoken in the audio.

### [03:00] 安装 Claude Code，告别网页端 — the comparison table
| 网页端 AI 的 4 个局限 | Claude Code 的 4 个能力 |
|---|---|
| 聊完就忘，没法连续跟踪一个假设 | 读本地代码和文件结构，持续记忆 |
| 大项目只能一段一段喂，全局关系被切断 | 执行命令和脚本，自动验证 |
| 不能调用你的工具，不能跑 `grep`、读文件树 | 调用浏览器等外部工具，操作页面 |
| 所有中间结果都要手动复制粘贴 | 自动加载项目背景，断点续挖 |

### [07:50] STEP 3 — 写 CLAUDE.md，让 AI 记住项目
Header: *"CLAUDE.md 是放在项目根目录的『记忆卡』，Claude Code 每次启动自动读取。没有它，
每次 reopen 都要重新交代项目背景。"* Six cards:

| 卡片 | 内容 |
|---|---|
| 测试范围 | 在测范围、排除范围、项目限制（速率/规则）。越界测试可能惹麻烦。 |
| 技术栈与账号 | 前端/后端技术栈、认证方式、测试账号与角色权限。 |
| 赏金表与 SLA | 赏金直接影响投入策略。高危 2000 元和 8000 元的测试深度完全不同。 |
| 已测绘攻击面 | 值得关注的接口、JS 中发现的功能开关、异常观察记录。 |
| 发现与排除 | 当前发现（含置信度）、已排除的发现。排除原因和发现一样值钱。 |
| 对应用的认知 | 架构假设、异常行为、业务逻辑观察。值钱的洞见从这里长出来。 |

**关键原则** (footer): 隔几天回来也能接着干。**跨租户 IDOR 测试至少需要两个不同组织的账号。**
文件位置: `项目根目录 / CLAUDE.md`

### [08:25] 安装 MCP — Playwright
Points at `https://github.com/microsoft/playwright` with the upstream "Get Started" table:

| Path | Best for | Install |
|---|---|---|
| Playwright Test | End-to-end testing | `npm init playwright@latest` |
| Playwright CLI | Coding agents (Claude Code, Copilot) | `npm i -g @playwright/cli@latest` |
| **Playwright MCP** | **AI agents and LLM-driven automation** | `npx @playwright/mcp@latest` |
| Playwright Library | Browser automation scripts | `npm i playwright` |
| VS Code Extension | Test authoring and debugging in VS Code | Install from Marketplace |

### [09:20] 举个栗子 — CLAUDE.md 模板参考
```markdown
# [项目名称] — 测试上下文

## 测试范围
### 在测范围
- `app.example.com`
- `api.example.com`
- `*.example.com` （下列除外）
### 排除范围
- `blog.example.com`
- `status.example.com`
- 第三方集成（支付、短信、邮件、埋点等）
### 项目限制
- 自动化扫描速率不超过 5 req/s
- 禁止社会工程学
- 禁止接触真实用户数据
- 禁止将发现的漏洞用于超出 PoC 的任何用途

## 项目信息
- 平台：补天 / 漏洞盒子 / 360 SRC / 京东安全 / 蚂蚁安全 / 企业…
- 首次响应 SLA：3 个工作日
- 企业自评：是 / 否
```
Accompanying **字段解析** panel:
- **范围与限制**: SRC 有法律和平台规则
- **赏金表与 SLA**: 同样是高危，2000 和 8000 的投入策略完全不同
- **测试账号与角色**: 只有一个账号，很多越权漏洞根本测不出来
- **已测绘攻击面**: 把 AI 或手工发现的线索结构化，避免反复从零开始
- **当前发现与已排除**: 排除原因和发现一样值钱，三天后你会感谢自己写下来了
- **对应用的认知**: 自由记录，很多真正值钱的洞见是从这里长出来的

### [11:40] 写 Skill，教 AI 审计思路
Header: *"Skill 放在 `~/.claude/skills/` 下的 `SKILL.md`，任务匹配时自动加载，把审计思路
『教』给 Claude。"*

**五段式结构**: `01 PERSONA` (定义角色和专业领域) → `02 CONTEXT` (系统、业务、约束) →
`03 EXAMPLES` (3–5 个带推理的示例) → `04 INSTRUCTIONS` (分步骤检查指令) →
`05 OUTPUT` (结构化输出)

**六大设计原则**:
1. 一个 Skill 只处理一种漏洞
2. 步骤要具体到能执行
3. 输出必须结构化
4. 写明停止条件
5. 加反幻觉规则
6. 长内容放附件

Footer: *"**Skill 要迭代**：建议放 Git 加版本号（如 `idor-hunt-v1.1.md`），误报变多或技术栈
变化时及时更新。"*

### [12:25] 举个栗子 — IDOR 审计 Skill，保存为 `~/.claude/skills/idor-hunt/SKILL.md`
```markdown
# IDOR 审计 Skill

## 角色
你是专注于访问控制缺陷的安全工程师，擅长通过对比不同账号的响应来识别 IDOR。

## 目标
在授权范围内，从目标应用的 API 端点中找出 IDOR 和越权访问漏洞。

## 触发条件
用户提到以下任一关键词：idor、越权、访问控制、角色权限、tenant、organization、
user_id、order_id。

## 工具约束
- 使用 Read/Grep/Glob 读取代码和请求文件。
- 禁止对外发包，除非用户明确授权并指定目标。
- 禁止猜测文件路径。

## 执行步骤
1. 枚举所有包含 ID 参数、用户 ID、组织 ID 的端点。
2. 识别响应中包含敏感数据的字段（email、phone、address、amount、status 等）。
3. 请求用户用两个不同账号（A 和 B）访问同一端点，对比响应。
4. 如果响应相同，或账号 A 能访问账号 B 的数据，则标记为 IDOR 候选。
5. 对候选端点，尝试以下变体：递增/递减 ID …
```
*(the step-5 variant list is cut off by the slide frame)*

**通用 Skill 模板** (shown alongside):
```markdown
# [攻击面名称] 审计 Skill

## 角色
你是专注于 [领域] 的安全工程师

## 目标
在授权范围内，从 [代码类型] 中找出 [漏洞类型]

## 工具约束
- 使用 Read/Grep/Glob 读取代码
- 禁止 Bash 的 grep/find
- 禁止对外发包

## 执行步骤
1. 枚举 [入口点/敏感函数]
2. 向上追溯 3 层数据流
3. 检查是否有 [具体缓解措施]
4. 对可疑点设计验证测试
5. 输出结构化报告并停止

## 输出格式
输出必须是 JSON，包含：
- vulnerable: true/false
- severity: high/medium/low
- attack chain: 数据流描述
```

### [14:20] 实战工作流：从线索到报告
| 工作流 | 步骤 | 说明 |
|---|---|---|
| **1. JS 审计** | 下载 JS → AI 分析 → 发现 | 让 AI 提取 API 端点、硬编码密钥、前端逻辑漏洞 |
| **2. 线索挖掘** | 问对问题 → 排序验证 → 深挖 | **"给我 10 个最值得深挖的线索"**，按可利用可能性排序 |
| **3. 负向记录** | 测试排除 → 记录原因 → 省 Token | 记录排除的端点和原因，避免重复浪费 Token |

**实用技巧**:
- 多开会话，各自负责一块：**A 会话 (IDOR) / B 会话 (认证) / C 会话 (SSRF) / D 会话 (自由探索)**
- 对输出追问：你确定能利用吗？
- 假阳性可能是什么？
- 怎么手动确认？
- 验证分级：**已确认 / 待验证 / 已排除**
- 让 AI 承认不知道，比硬编靠谱

**报告写作** (footer): *"用 Claude 写初稿后必须人工重写，删掉 AI 味。复现步骤精确到复制粘贴
就能跑，影响要结合业务讲清楚。"*

### [15:45] 防幻觉：验证比发现更重要
Warning banner: *"**AI 最大的风险**：不是找不到洞，而是自信地告诉你一个假洞。防幻觉的核心
就两个字 —— 验证"*

**四级验证门**:
| Gate | 条件 | 判据 |
|---|---|---|
| **G0** | PoC 能编译 | 验证代码是否存在且可运行 |
| **G1** | 干净环境复现 | 在 VM 快照中复现崩溃 |
| **G2** | 真实可利用 | 不是空指针或优雅退出 |
| **G3** | 普通权限触发 | 非 SYSTEM/Admin 权限 |

**辅助防幻觉手段**:
- 建 `negative_findings.md`，把排除的点全记下来
- 高置信度发现用**第二个模型独立复核**
- 让不同模型从**相反立场**分析同一个问题

**参考案例** (footer): *"`zsec.uk` 的做法 —— 所有新发现先放进 `hallucinations/` 目录，
只有通过全部验证门后才晋升到 `findings/`。先怀疑再验证，误报率接近为零。"*

### [17:30] AI 能做什么 vs 不能做什么
| ✅ AI 适合干的 | ❌ 人类必须干的 |
|---|---|
| **重复性分析**: 子域名枚举、端口扫描、技术栈识别 | **策略判断**: 这个程序最值得挖哪里 |
| **代码解析**: JS 分析、端点提取、模式识别 | **业务理解**: API 调用链背后的业务意图 |
| **Payload 生成**: PoC 编写、验证脚本、文档整理 | **组合创新**: 把两个无关问题组合成严重漏洞 |
| **知识检索**: 报告初稿、历史漏洞关联分析 | **亲手复现**: 一步一步验证漏洞真实性 |
| **自动化验证**: 在隔离环境中跑 PoC 确认漏洞 | **边界判断**: 哪些目标能测，哪些数据不能碰 |

Footer: *"记住这个分工：AI 负责『体力活』和『信息处理』，你负责『思考判断』和『决策验证』"*

### [18:10] 新手的四种人机协作模式
| 阶段 | 模式 | 说明 |
|---|---|---|
| **入门推荐** | 人主导，AI 辅助 | 你制定策略，AI 执行重复任务。大多数 SRC 场景的默认选择。 |
| **进阶** | AI 主导，人监督 | AI 提出候选漏洞，你做最终判断。适合大规模初筛。 |
| **高级** | 多 AI 对抗，人仲裁 | 多个模型独立分析，你整合结论。适合复杂根因分析。 |
| **仅限隔离环境** | 全自动 Agent | 设定目标后完全放手。**仅限授权、隔离、可回滚环境。** |

**进阶路径**: 学会用 AI 辅助分析 → 掌握 Claude Code 配置 → 编写自定义 Skill → 多模型协作挖洞

Footer: *"AI 增强安全研究员，不是更依赖 AI，而是更清楚什么时候该用它，什么时候该自己上"*

### [18:35] 收尾卡片 — GET STARTED
> **基本功决定下限 / 判断力决定上限**
> AI 只是放大你已有的东西
> `开始你的第一次 AI 辅助挖洞 →`
>
> AI 适合干的：子域名枚举 / JS 解析 / 端点提取 / PoC 编写 / 报告初稿
> 人类必须干的：判断挖哪里 / 理解业务意图 / 亲手复现 / 决定边界
> **用 AI 作为加速器，你会跑得比任何人都快**

## 知识点提取 / Extracted Knowledge

- Pointing a model at a codebase with "find the vulnerabilities" produces mostly false
  positives; one reported run gave 17 high-severity findings of which 16 were false and
  1 was an already-public CVE. (claim)
- AI amplifies existing skill rather than substituting for it; hunters who succeed
  already know the app's data flow and which endpoint classes yield which bugs.
- Bug hunting is a long-running engagement, not a chat session; tooling must persist
  context across days and support code reading, script execution, and verification.
- Web-chat models cannot call local tools, cannot run `grep` or read a file tree, lose
  global project structure when fed piecemeal, and force manual copy-paste of every
  intermediate result.
- An agentic CLI (Claude Code, Codex) can read local code and file structure, execute
  commands and scripts for automatic verification, drive external tools such as a
  browser, and resume a project from where it stopped.
- Every additional MCP and Skill consumes model reasoning capacity; minimal
  configuration is a deliberate performance choice, not laziness.
- One browser MCP is sufficient for web application hunting; Playwright MCP installs
  with `npx @playwright/mcp@latest`.
- Letting an agent drive a browser directly is more reliable than describing a login
  flow in prose.
- No model is universally strongest; select per task — code work, research/search, and
  automatable bulk tasks favour different models.
- Running two models against each other, or forcing one model to argue opposite
  positions, reduces single-model blind spots.
- `CLAUDE.md` lives in the project root and is auto-loaded by Claude Code at every
  launch; without it, project background must be re-supplied on each reopen.
- A testing `CLAUDE.md` should record: in-scope and out-of-scope assets, project limits
  (rate caps, prohibited techniques), tech stack, auth method, test accounts and role
  permissions, the bounty table and SLA, mapped attack surface, current findings with
  confidence levels, excluded findings with reasons, and free-form application insight.
- Recording *why* a lead was excluded is as valuable as recording a finding: it prevents
  re-testing the same dead end and re-spending tokens.
- Bounty size should change testing depth — a program paying 2,000 for a high-severity
  finding warrants different investment than one paying 8,000.
- Cross-tenant IDOR testing requires accounts in at least two different organisations;
  with a single account most authorisation bugs are undetectable.
- A Skill is a `SKILL.md` under `~/.claude/skills/` that auto-loads on task match and
  encodes an audit methodology.
- A Skill should follow a five-part structure: PERSONA (role and domain), CONTEXT
  (system, business, constraints), EXAMPLES (3–5 worked examples with reasoning),
  INSTRUCTIONS (step-by-step checks), OUTPUT (structured format).
- Six Skill design rules: one Skill per vulnerability class; steps concrete enough to
  execute; structured output; explicit stop conditions; anti-hallucination rules; long
  content moved to attachments.
- Cramming dozens of checkpoints into a single Skill file causes the model to lose track.
- Negative constraints ("you may not do X") bind model behaviour more effectively than
  positive aspirations ("please do Y").
- Over-specifying a Skill suppresses the model's divergent thinking; supply constraints
  and routing without scripting every detail.
- Skills should be version-controlled in Git with version numbers (e.g.
  `idor-hunt-v1.1.md`) and updated when false positives rise or the tech stack changes.
- A Skill's output format can be pinned to JSON containing `vulnerable`, `severity`, and
  an attack-chain data-flow description.
- Restricting a Skill to `Read`/`Grep`/`Glob` while forbidding Bash `grep`/`find` and
  outbound packets keeps an audit passive and inside authorisation.
- The IDOR detection procedure is: enumerate endpoints carrying ID parameters, identify
  responses containing sensitive fields (email, phone, address, amount, status), have two
  accounts request the same endpoint, and compare — identical responses or A reading B's
  data marks an IDOR candidate.
- Parallel sessions scoped to one attack class each (IDOR / authentication / SSRF / free
  exploration), kept independent, surface findings a single session misses.
- Asking a model to rank leads — "give me the 10 most worth digging into" ordered by
  exploitability — converts unstructured output into a work queue.
- Explicitly permitting a model to say "I don't know" yields more reliable output than
  forcing an answer.
- The dominant AI risk in security work is a confidently-asserted false vulnerability,
  not a missed one.
- A four-gate verification ladder filters hallucinated findings: G0 the PoC compiles;
  G1 it reproduces in a clean VM snapshot; G2 it is genuinely exploitable rather than a
  null-pointer or graceful exit; G3 it triggers under ordinary user privileges rather
  than SYSTEM/Admin.
- Quarantining unverified findings in a `hallucinations/` directory and promoting them to
  `findings/` only after all gates pass drives the false-positive rate toward zero — the
  practice is attributed to `zsec.uk`. (claim)
- A `negative_findings.md` file recording every excluded lead is a standard
  anti-hallucination aid.
- High-confidence findings warrant independent re-review by a second model.
- Findings must be graded by verification state: 已确认 (confirmed) / 待验证 (pending) /
  已排除 (excluded).
- AI-drafted vulnerability reports must be manually rewritten before submission to remove
  AI phrasing, with reproduction steps precise enough to copy-paste and run, and impact
  explained in business terms.
- Tasks appropriate for AI: subdomain enumeration, port scanning, tech-stack
  fingerprinting, JS analysis, endpoint extraction, pattern recognition, PoC and
  verification-script writing, documentation, report drafts, historical-vulnerability
  correlation, and running PoCs in isolated environments.
- Tasks reserved for humans: deciding where a program is most worth attacking,
  understanding business intent behind API call chains, combining two unrelated issues
  into one severe finding, hands-on reproduction, and deciding which targets may be
  tested and which data must not be touched.
- Four human-AI collaboration modes scale with experience: human-led with AI assist
  (beginner default for SRC work); AI-led with human supervision (large-scale triage);
  multiple AIs in opposition with human arbitration (complex root-cause analysis); fully
  autonomous agent (authorised, isolated, rollback-capable environments only).
- The progression path is: use AI for assisted analysis → master agentic CLI
  configuration → write custom Skills → hunt with multiple models in collaboration.
- Accountability does not transfer to the model: it cannot bear legal consequences or
  take blame for an out-of-scope test.

## 金句引用 / Notable Quotes

- [00:57] "把 AI 当做那种阿拉丁的神灯许愿式的挖洞 —— 神灯神灯，我要一个洞" — names the
  exact anti-pattern the whole video is built against.
- [04:03] "相当于是你有了一个替你打工的人，你就不用在中间当各种的搬运工" — the case for an
  agent over a chat box, in one image.
- [05:25] "没有最强的模型，只有最适合的模型" — reframes model choice from ranking to fit.
- [12:27] "你禁止他做什么，比希望他做什么来的约束更好一点" — the single most portable
  prompt-engineering rule in the video.
- [15:11 slide] "AI 最大的风险：不是找不到洞，而是自信地告诉你一个假洞" — why verification
  outranks discovery.
- [17:08] "AI 能帮你挖洞，但是它不能替你坐牢，也不能给你背锅" — accountability stays human.
- [18:35 slide] "基本功决定下限，判断力决定上限。AI 只是放大你已有的东西" — the thesis.
- [18:08] "如果你把 AI 作为拐杖，基本上没有什么成长空间；但如果你把 AI 作为加速器，你可能
  会跑得比很多人都快" — crutch vs accelerator (see Caveats: audio misspeaks, slide confirms).

## 疑点与局限 / Caveats

- **Whisper garbled most product names.** Corrections applied throughout, verified
  against slides: "clad code / crow的code / cloud code / 克拉的" → **Claude Code**;
  "crow.md / cloud.md" → **CLAUDE.md**; "code x / code是" → **Codex**;
  "secure / sql / sq" → **Skill**; "乐学 / 乐学室" → **IDOR**; "绘话/绘画" → **会话**
  (session); "杰斯 / 节奢" → **JS**; "破壳 / poke / pog" → **PoC**; "排楼" → **Payload**;
  "互发率" → **误报率**; "一本针接" → **一本正经**.
- **Three model names could not be resolved and are deliberately omitted above.** At
  [06:18] the transcript reads "gbt5.5 … 现在应该出到 5.6 了" and "考则406"; at [06:49]
  the student-budget recommendation transcribes as "tipsaker" (plausibly DeepSeek, but I
  did not verify); at [03:01] a web-chat product transcribes as "Debatec". The slide at
  that point is a bare title card with no model names, so **there is no visual
  cross-check** — treat any specific model recommendation from this video as unconfirmed.
- **A key sentence is misspoken in the audio.** At [05:02] the transcript reads
  "你配的越多，模型推理被约束的越**少**" — which inverts the argument he has just made and
  contradicts the surrounding sentences. The intended meaning is clearly "the more you
  configure, the **more** the model's reasoning is constrained." I've rendered the
  intended sense above.
- **The closing line is repeated wrongly in the audio.** At [18:08] the transcript says
  "把 AI 作为拐杖" (crutch) in *both* halves of the contrast. The closing slide resolves it:
  拐杖 (crutch) vs **加速器** (accelerator).
- **Step numbering is only partly visible.** Only the `CLAUDE.md` slide carries a badge
  ("STEP 3"); the MCP and Skill slides show no step number in the captured frames, so the
  deck's full numbering could not be reconstructed.
- **The earnings screenshot is unverifiable.** The 单洞 2.6W claim at [01:26] is shown as a
  heavily blurred/redacted panel — no program, date, or platform is legible. Standard for
  this genre; treat as marketing, not evidence.
- **Lead-generation framing.** The detailed `CLAUDE.md` template, the Skill examples, and
  the full PPT are all gated behind the creator's 粉丝群 (fan group), mentioned three times
  [09:24, 11:44, 18:45]. The slides transcribed above are what was actually shown on
  screen; the "detailed versions" were not.
- **`zsec.uk` hallucinations/findings practice is cited but not demonstrated** — I have
  not independently verified that attribution or the "误报率接近为零" claim.
- **Title inconsistency**: the Douyin description says 新**手**, the on-screen title card
  says 新**人**. Same meaning (beginner/newcomer).
- **Scope note for your use**: the whole methodology assumes an authorised SRC/bounty
  target. The G0–G3 gate language (VM snapshots, crash reproduction, SYSTEM/Admin
  privileges) reads like it was adapted from binary/memory-safety research rather than
  web hunting — G1's "复现崩溃" doesn't map cleanly onto a web IDOR.

## Prompt-Ready Distillation

```
AI-ASSISTED VULNERABILITY HUNTING — OPERATING METHODOLOGY

CORE PREMISE
AI amplifies existing skill; it does not substitute for it. A model pointed at a
codebase with "find the vulnerabilities" typically returns mostly false positives.
Effective hunters already know the application's data flow and which endpoint
classes yield which bug types, and use the model to scale that judgement.
Fundamentals set your floor; judgement sets your ceiling.

TOOLING
Use an agentic CLI (Claude Code, Codex), not a web chat interface. Hunting is a
long-running engagement requiring persistent context, local code reading, script
execution, and verification. Web chat loses conversational context, cannot call
local tools or run grep, fragments large projects when fed piecemeal, and forces
manual copy-paste of intermediate results.

Configure minimally. Every MCP server and Skill consumes reasoning capacity.
Install exactly one browser MCP (Playwright MCP: `npx @playwright/mcp@latest`);
letting the agent drive a browser beats describing a login flow in prose.

MODEL SELECTION
No model is universally strongest — select per task. Assign code analysis,
research/search, and bulk automation to different models by their strengths. Run
two models against each other, or force one model to argue opposite positions, to
reduce single-model blind spots. Have a second model independently re-review any
high-confidence finding.

PROJECT MEMORY: CLAUDE.md
Place CLAUDE.md in the project root; the agent auto-loads it every launch. Record:
- Scope: in-scope hosts, excluded hosts, excluded third-party integrations
  (payment, SMS, email, analytics)
- Limits: scan rate cap (e.g. no more than 5 req/s), no social engineering, no
  contact with real user data, no use of findings beyond PoC
- Program info: platform, first-response SLA, self-assessment status
- Tech stack, auth method, test accounts and role permissions
- Bounty table and SLA — payout size dictates testing depth; a high-severity
  paying 2,000 warrants different investment than one paying 8,000
- Mapped attack surface: notable endpoints, feature flags found in JS, anomalies
- Current findings with confidence levels, and excluded findings with reasons
- Free-form application understanding: architecture assumptions, odd behaviours,
  business-logic observations
Two rules: the file must let you resume cold after days away, and cross-tenant
IDOR testing requires accounts in at least two different organisations — with one
account most authorisation bugs are undetectable.
Recording why a lead was excluded is worth as much as recording a finding: it
prevents re-testing dead ends and re-spending tokens.

SKILLS: ENCODING AUDIT METHODOLOGY
A Skill is a SKILL.md under ~/.claude/skills/ that auto-loads on task match.
Five-part structure:
  01 PERSONA      — role and domain of expertise
  02 CONTEXT      — system, business, constraints
  03 EXAMPLES     — 3-5 worked examples including reasoning
  04 INSTRUCTIONS — step-by-step check procedure
  05 OUTPUT       — structured output format
Six design rules:
  1. One Skill handles exactly one vulnerability class
  2. Steps concrete enough to execute
  3. Output must be structured (pin it to JSON: vulnerable true/false, severity
     high/medium/low, attack chain as a data-flow description)
  4. State explicit stop conditions
  5. Include anti-hallucination rules
  6. Move long content to attachments
Negative constraints bind better than positive ones: specify what the model may
NOT do. Restrict tools to Read/Grep/Glob; forbid Bash grep/find, outbound packets
without explicit authorisation, and guessing file paths. But do not over-specify —
excessive detail suppresses divergent thinking. Do not cram dozens of checkpoints
into one file; the model loses track. Version Skills in Git (idor-hunt-v1.1.md)
and update them when false positives rise or the stack changes.

IDOR skill procedure: enumerate endpoints carrying ID / user-ID / org-ID
parameters; identify responses containing sensitive fields (email, phone, address,
amount, status); have two accounts (A and B) request the same endpoint and compare
responses; identical responses, or A reading B's data, marks an IDOR candidate;
then try ID increment/decrement and related variants.

WORKFLOWS
1. JS audit: download JS -> AI extracts API endpoints, hardcoded secrets,
   front-end logic flaws -> triage findings.
2. Lead mining: ask the right question -> "give me the 10 leads most worth deep
   investigation, ranked by exploitability" -> verify ranking -> dig.
3. Negative recording: test and exclude -> record the endpoint and the reason ->
   save tokens on future runs.
Run parallel sessions scoped one attack class each — session A on IDOR, B on
authentication, C on SSRF, D on free exploration — kept independent.
Interrogate every output: Are you certain this is exploitable? What would a false
positive look like here? How would I manually confirm it? Grade every finding as
confirmed / pending verification / excluded. Explicitly allow the model to answer
"I don't know" — it is more reliable than a forced answer.

ANTI-HALLUCINATION: VERIFICATION OUTRANKS DISCOVERY
The dominant risk is a confidently-asserted fake vulnerability, not a missed one.
Doubt first, then verify. Apply four gates in order:
  G0 — PoC compiles; the code exists and runs
  G1 — reproduces in a clean VM snapshot
  G2 — genuinely exploitable, not a null-pointer or graceful exit
  G3 — triggers under ordinary user privileges, not SYSTEM/Admin
Quarantine every new finding in a hallucinations/ directory; promote to findings/
only after all gates pass. Maintain negative_findings.md listing every excluded
lead with its reason. Re-review high-confidence findings with a second model, and
have different models analyse the same question from opposing positions.

REPORTING
An AI draft must be manually rewritten before submission — remove AI phrasing,
make reproduction steps precise enough to copy-paste and run, and explain impact
in concrete business terms. Never submit a model's output directly.

DIVISION OF LABOUR
Give to AI: subdomain enumeration, port scanning, tech-stack fingerprinting, JS
analysis, endpoint extraction, pattern recognition, PoC and verification-script
writing, documentation, report drafts, historical-vulnerability correlation, and
running PoCs inside isolated environments.
Keep for the human: deciding where a program is most worth attacking, reading
business intent behind API call chains, combining two unrelated issues into one
severe finding, hands-on reproduction, and deciding which targets may be tested
and which data must never be touched.
AI handles labour and information processing; the human handles judgement and
decision verification. Accountability never transfers to the model — it cannot
face legal consequences and cannot take the blame for an out-of-scope test.

COLLABORATION MODES — pick by experience level
  Beginner (default for SRC work) — Human-led, AI-assisted: you set strategy, AI
    executes repetitive tasks.
  Intermediate — AI-led, human-supervised: AI proposes candidates, you make the
    final call. Suits large-scale triage.
  Advanced — Multiple AIs in opposition, human arbitrates: models analyse
    independently, you integrate. Suits complex root-cause analysis.
  Isolated environments only — Fully autonomous agent: set a goal and release
    control. Restricted to authorised, isolated, rollback-capable environments.
Progression: assisted analysis -> agentic CLI configuration -> custom Skills ->
multi-model collaborative hunting.

CLOSING RULES
Learn vulnerability theory regardless; AI is an amplifier, not a replacement.
Verification matters more than discovery. Do not believe a finding — verify it.
Used as a crutch, AI stops your growth; used as an accelerator, it outpaces
everyone. Practise on authorised, small-scope targets first.
```
