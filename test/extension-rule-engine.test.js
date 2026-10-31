const test = require("node:test");
const assert = require("node:assert/strict");
const {
  ALLOW_RULE_START,
  BLOCK_RULE_START,
  MAX_ALLOW_RULES,
  MAX_BLOCK_RULES,
  buildRules,
  calculateChanges,
  isOwnedRule,
  normalizeDomain,
} = require("../extension/rule-engine");

test("normalizes bare IDNs and rejects URLs, ports, IPs, and malformed domains", () => {
  assert.equal(normalizeDomain("Exämple.com"), "xn--exmple-cua.com");
  assert.equal(normalizeDomain("example.com."), "example.com");
  assert.equal(normalizeDomain("https://example.com/path"), null);
  assert.equal(normalizeDomain("example.com:443"), null);
  assert.equal(normalizeDomain("127.0.0.1"), null);
  assert.equal(normalizeDomain("bad..example.com"), null);
});

test("creates bounded main-frame allow and block rules with allow precedence", () => {
  const rules = buildRules({
    enabled: true,
    blockedDomains: [{ domain: "phish.example", lastSeen: 10 }],
    trustedDomains: ["trusted.example"],
  });

  assert.equal(rules.length, 2);
  const allow = rules.find((rule) => rule.action.type === "allow");
  const block = rules.find((rule) => rule.action.type === "block");
  assert.ok(allow.id >= ALLOW_RULE_START && allow.id < ALLOW_RULE_START + MAX_ALLOW_RULES);
  assert.equal(allow.priority, 2);
  assert.deepEqual(allow.condition, {
    urlFilter: "||trusted.example^",
    resourceTypes: ["main_frame"],
  });
  assert.ok(block.id >= BLOCK_RULE_START && block.id < BLOCK_RULE_START + MAX_BLOCK_RULES);
  assert.equal(block.priority, 1);
  assert.deepEqual(block.condition, {
    urlFilter: "||phish.example^",
    resourceTypes: ["main_frame"],
  });
  const rebuilt = buildRules({
    enabled: true,
    blockedDomains: [{ domain: "phish.example", lastSeen: 10 }],
    trustedDomains: ["trusted.example"],
  });
  assert.deepEqual(rebuilt.map(({ id }) => id), rules.map(({ id }) => id));
});

test("caps rule counts and clears managed rules while protection is disabled", () => {
  const blockedDomains = Array.from({ length: MAX_BLOCK_RULES + 2 }, (_, index) => `d${index}.example`);
  const trustedDomains = Array.from({ length: MAX_ALLOW_RULES + 2 }, (_, index) => `t${index}.example`);
  const rules = buildRules({ enabled: true, blockedDomains, trustedDomains });

  assert.equal(rules.filter((rule) => rule.action.type === "block").length, MAX_BLOCK_RULES);
  assert.equal(rules.filter((rule) => rule.action.type === "allow").length, MAX_ALLOW_RULES);
  assert.equal(buildRules({ enabled: false, blockedDomains, trustedDomains }).length, 0);
  assert.equal(isOwnedRule(BLOCK_RULE_START), true);
  assert.equal(isOwnedRule(ALLOW_RULE_START + MAX_ALLOW_RULES), false);
});

test("keeps rule identifiers stable and changes only managed rules that differ", () => {
  const prior = buildRules({
    enabled: true,
    blockedDomains: ["phish.example"],
    trustedDomains: [],
  });
  const next = buildRules({
    enabled: true,
    blockedDomains: ["phish.example", "new-phish.example"],
    trustedDomains: [],
  });
  const unrelated = {
    id: 7,
    priority: 1,
    action: { type: "block" },
    condition: { urlFilter: "||other.example^", resourceTypes: ["main_frame"] },
  };
  const changes = calculateChanges([...prior, unrelated], next, isOwnedRule);

  assert.deepEqual(changes.removeRuleIds, []);
  assert.equal(changes.addRules.length, 1);
  assert.equal(changes.addRules[0].condition.urlFilter, "||new-phish.example^");
});
