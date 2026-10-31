(function (root, factory) {
  const engine = factory();
  if (typeof module === "object" && module.exports) module.exports = engine;
  root.ClearSignalRuleEngine = engine;
})(globalThis, function () {
  const BLOCK_RULE_START = 10_000;
  const ALLOW_RULE_START = 20_000;
  const MAX_BLOCK_RULES = 4_000;
  const MAX_ALLOW_RULES = 500;

  function normalizeDomain(input) {
    if (typeof input !== "string") return null;
    const candidate = input.trim().toLowerCase().replace(/\.$/, "");
    if (!candidate || candidate.includes("/") || candidate.includes("@") ||
        candidate.includes(":") || candidate.includes("*") || candidate.includes("?") ||
        candidate.includes("#")) return null;
    let hostname;
    try {
      hostname = new URL(`https://${candidate}`).hostname.toLowerCase().replace(/\.$/, "");
    } catch {
      return null;
    }
    if (hostname.length > 253) return null;
    const labels = hostname.split(".");
    if (labels.length < 2 || labels.some((label) =>
      label.length < 1 || label.length > 63 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    )) return null;
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return null;
    return hostname;
  }

  function normalizeEntries(entries, limit) {
    const unique = new Map();
    for (const entry of Array.isArray(entries) ? entries : []) {
      const domain = normalizeDomain(typeof entry === "string" ? entry : entry?.domain);
      if (!domain) continue;
      const timestamp = Number(entry?.lastSeen || entry?.addedAt || 0);
      const existing = unique.get(domain);
      if (!existing || timestamp >= existing.timestamp) unique.set(domain, { domain, timestamp });
    }
    return [...unique.values()]
      .sort((left, right) => right.timestamp - left.timestamp || left.domain.localeCompare(right.domain))
      .slice(0, limit)
      .map((entry) => entry.domain);
  }

  function stableIds(domains, rangeStart, rangeSize) {
    const assigned = new Set();
    return new Map(domains.map((domain) => {
      let hash = 0x811c9dc5;
      for (let index = 0; index < domain.length; index += 1) {
        hash = Math.imul(hash ^ domain.charCodeAt(index), 0x01000193) >>> 0;
      }
      let offset = hash % rangeSize;
      while (assigned.has(rangeStart + offset)) offset = (offset + 1) % rangeSize;
      const id = rangeStart + offset;
      assigned.add(id);
      return [domain, id];
    }));
  }

  function buildRules({ enabled, blockedDomains, trustedDomains }) {
    if (!enabled) return [];
    const blocked = normalizeEntries(blockedDomains, MAX_BLOCK_RULES);
    const trusted = normalizeEntries(trustedDomains, MAX_ALLOW_RULES);
    const rules = [];
    const trustedIds = stableIds(trusted, ALLOW_RULE_START, MAX_ALLOW_RULES);
    const blockedIds = stableIds(blocked, BLOCK_RULE_START, MAX_BLOCK_RULES);

    trusted.forEach((domain) => {
      rules.push({
        id: trustedIds.get(domain),
        priority: 2,
        action: { type: "allow" },
        condition: { urlFilter: `||${domain}^`, resourceTypes: ["main_frame"] },
      });
    });
    blocked.forEach((domain) => {
      rules.push({
        id: blockedIds.get(domain),
        priority: 1,
        action: { type: "block" },
        condition: { urlFilter: `||${domain}^`, resourceTypes: ["main_frame"] },
      });
    });
    return rules;
  }

  function isOwnedRule(ruleId) {
    return (ruleId >= BLOCK_RULE_START && ruleId < BLOCK_RULE_START + MAX_BLOCK_RULES) ||
      (ruleId >= ALLOW_RULE_START && ruleId < ALLOW_RULE_START + MAX_ALLOW_RULES);
  }

  function rulesEqual(left, right) {
    const leftCondition = left.condition || {};
    const rightCondition = right.condition || {};
    return left.id === right.id &&
      left.priority === right.priority &&
      left.action?.type === right.action?.type &&
      leftCondition.urlFilter === rightCondition.urlFilter &&
      JSON.stringify(leftCondition.resourceTypes || []) === JSON.stringify(rightCondition.resourceTypes || []) &&
      JSON.stringify(leftCondition.requestDomains || []) === JSON.stringify(rightCondition.requestDomains || []) &&
      JSON.stringify(leftCondition.tabIds || []) === JSON.stringify(rightCondition.tabIds || []);
  }

  function calculateChanges(existingRules, desiredRules, isManagedId) {
    const existingById = new Map(existingRules.map((rule) => [rule.id, rule]));
    const desiredById = new Map(desiredRules.map((rule) => [rule.id, rule]));
    const removeRuleIds = existingRules
      .filter((rule) => isManagedId(rule.id) &&
        (!desiredById.has(rule.id) || !rulesEqual(rule, desiredById.get(rule.id))))
      .map((rule) => rule.id);
    const addRules = desiredRules.filter((rule) => {
      const existing = existingById.get(rule.id);
      return !existing || !rulesEqual(existing, rule);
    });
    return { removeRuleIds, addRules };
  }

  return {
    ALLOW_RULE_START,
    BLOCK_RULE_START,
    MAX_ALLOW_RULES,
    MAX_BLOCK_RULES,
    buildRules,
    calculateChanges,
    isOwnedRule,
    normalizeDomain,
  };
});
