// Verification suite for the 11 ported skills (run with: node --test tools/verify-ported-skills.test.js)
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const skillsRoot = path.join(__dirname, "..", "plugin", "skills");
const newSkills = [
  "pb-waf-bypass", "pb-llm-security", "pb-cloud-infra", "pb-source-audit",
  "pb-deserialization", "pb-miniprogram", "pb-android", "pb-apk-reversing",
  "pb-api-security", "pb-windows-binary", "pb-unauth-surface",
];
const sections = [
  "## When this applies", "## First signals", "## Enumeration", "## Test procedure",
  "## Evidence to capture", "## Escalation", "## Out-of-scope traps", "## Integration",
];

test("each ported skill has valid frontmatter and 8 sections in order", () => {
  for (const name of newSkills) {
    const file = path.join(skillsRoot, name, "SKILL.md");
    assert.ok(fs.existsSync(file), `${name}: SKILL.md missing`);
    const text = fs.readFileSync(file, "utf8");
    const m = text.match(/^---\r?\nname: ([^\r\n]+)\r?\ndescription: ([^\r\n]+)\r?\n---\r?\n/);
    assert.ok(m, `${name}: bad frontmatter`);
    assert.strictEqual(m[1], name, `${name}: frontmatter name != dir name`);
    assert.ok(m[2].trim().length > 0, `${name}: empty description`);
    let lastIdx = -1;
    for (const s of sections) {
      const idx = text.indexOf(s);
      assert.ok(idx !== -1, `${name}: missing section ${s}`);
      assert.ok(idx > lastIdx, `${name}: section order wrong at ${s}`);
      lastIdx = idx;
    }
    const lines = text.split("\n").length;
    assert.ok(lines >= 60 && lines <= 320, `${name}: suspicious length ${lines}`);
    assert.ok(!/[\u4e00-\u9fff]/.test(text), `${name}: contains CJK characters`);
  }
});

test("bb-hunt routes every playbook it names and covers all 10 new skills", () => {
  const hunt = fs.readFileSync(path.join(skillsRoot, "bb-hunt", "SKILL.md"), "utf8");
  const routes = [...hunt.matchAll(/\|\s+`(pb-[a-z0-9-]+)`\s*\|/g)].map((m) => m[1]);
  for (const r of routes) {
    assert.ok(fs.existsSync(path.join(skillsRoot, r)), `bb-hunt routes to missing skill ${r}`);
  }
  for (const n of newSkills) {
    assert.ok(routes.includes(n), `bb-hunt has no route row for ${n}`);
  }
});

test("bounty-overlay.json parses with unique ids and legal scope_level", () => {
  const overlay = JSON.parse(
    fs.readFileSync(path.join(__dirname, "..", "plugin", "reference", "bounty-overlay.json"), "utf8")
  );
  const ids = new Set();
  for (const c of overlay) {
    assert.ok(!ids.has(c.id), `duplicate id ${c.id}`);
    ids.add(c.id);
    assert.ok(["host", "endpoint"].includes(c.scope_level), `${c.id}: bad scope_level`);
  }
  const newIds = ["BB-LLM-01","BB-LLM-02","BB-CLOUD-02","BB-DESER-01","BB-API-01","BB-MP-01","BB-MP-02","BB-AND-01","BB-WIN-01","BB-WAF-01","BB-SRC-01","BB-UNAUTH-01","BB-CAPTCHA-01"];
  for (const id of newIds) assert.ok(ids.has(id), `missing new taxonomy id ${id}`);
});

test("skill directory totals match README (50 = 16 bb-* + 34 pb-*)", () => {
  const dirs = fs.readdirSync(skillsRoot, { withFileTypes: true })
    .filter((d) => d.isDirectory()).map((d) => d.name);
  const bb = dirs.filter((d) => d.startsWith("bb-")).length;
  const pb = dirs.filter((d) => d.startsWith("pb-")).length;
  assert.strictEqual(dirs.length, 50);
  assert.strictEqual(bb, 16);
  assert.strictEqual(pb, 34);
});
