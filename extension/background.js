importScripts("rule-engine.js");

const API_URL = "http://127.0.0.1:5000/api/scan";
const CACHE_MAX = 500;
const MAX_PENDING_SCANS = 64;
const CACHE_TTL_MS = 10 * 60 * 1000;
const WHITELIST_TTL_MS = 5 * 60 * 1000;
const MAX_TEMPORARY_ALLOW_RULES = 500;
const MAX_STORED_BLOCKED_DOMAINS = 5_000;
const MAX_STORED_TRUSTED_DOMAINS = 500;
const WHITELIST_ALARM = "clearsignal-temporary-allow-expiry";
const MAX_BADGE_REASONS = 8;
const pendingScans = new Map();
const safeCache = new Map();
const temporaryWhitelist = new Map();
const tabBlockedCounts = new Map();
const recentBlockedEvents = new Map();
let localMutationQueue = Promise.resolve();
let sessionMutationQueue = Promise.resolve();
let ruleSyncQueue = Promise.resolve();
let ruleSyncRequested = false;
let ruleSyncError = "";

const sessionStateReady = chrome.storage.session.get([
  "safeCacheEntries",
  "temporaryWhitelistEntries",
  "tabBlockedCounts",
  "recentBlockedEvents",
]).then((state) => {
  for (const [url, entry] of state.safeCacheEntries || []) {
    if (typeof url === "string" && Number.isFinite(entry?.timestamp) && entry.result?.verdict === "SAFE") {
      safeCache.set(url, entry);
    }
  }
  for (const [key, expiresAt] of state.temporaryWhitelistEntries || []) {
    if (typeof key === "string" && Number.isFinite(expiresAt)) temporaryWhitelist.set(key, expiresAt);
  }
  for (const [tabId, count] of state.tabBlockedCounts || []) {
    if (Number.isInteger(tabId) && Number.isInteger(count) && count >= 0) tabBlockedCounts.set(tabId, count);
  }
  for (const [key, timestamp] of state.recentBlockedEvents || []) {
    if (typeof key === "string" && Number.isFinite(timestamp)) recentBlockedEvents.set(key, timestamp);
  }
  pruneSessionState();
}).catch((error) => {
  console.warn("Could not restore this session's scan state.", error);
});

function persistSessionState() {
  const write = sessionMutationQueue.then(() => chrome.storage.session.set({
    safeCacheEntries: [...safeCache.entries()],
    temporaryWhitelistEntries: [...temporaryWhitelist.entries()],
    tabBlockedCounts: [...tabBlockedCounts.entries()],
    recentBlockedEvents: [...recentBlockedEvents.entries()],
  }));
  sessionMutationQueue = write.catch((error) => {
    console.warn("Could not persist this session's scan state.", error);
  });
  return write;
}

function updateLocalState(mutator) {
  const write = localMutationQueue.then(async () => {
    const current = await chrome.storage.local.get({
      enabled: true,
      blockedDomains: [],
      trustedDomains: [],
      globalBlockedCount: 0,
    });
    const next = await mutator(current);
    await chrome.storage.local.set(next);
    return next;
  });
  localMutationQueue = write.catch((error) => {
    console.error("Could not update ClearSignal settings.", error);
  });
  return write;
}

function queueRuleSync() {
  if (ruleSyncRequested) return ruleSyncQueue;
  ruleSyncRequested = true;
  const sync = ruleSyncQueue.then(async () => {
    ruleSyncRequested = false;
    await Promise.all([sessionStateReady, localMutationQueue]);
    const settings = await chrome.storage.local.get({
      enabled: true,
      blockedDomains: [],
      trustedDomains: [],
    });
    const desiredDynamic = ClearSignalRuleEngine.buildRules(settings);
    const desiredSession = buildTemporaryAllowRules();
    const dynamicRules = await chrome.declarativeNetRequest.getDynamicRules();
    const sessionRules = await chrome.declarativeNetRequest.getSessionRules();
    const dynamicChanges = ClearSignalRuleEngine.calculateChanges(
      dynamicRules,
      desiredDynamic,
      ClearSignalRuleEngine.isOwnedRule,
    );
    const sessionChanges = ClearSignalRuleEngine.calculateChanges(
      sessionRules,
      desiredSession,
      (id) => id >= 30_000 && id < 30_000 + MAX_TEMPORARY_ALLOW_RULES,
    );
    if (dynamicChanges.removeRuleIds.length || dynamicChanges.addRules.length) {
      await chrome.declarativeNetRequest.updateDynamicRules(dynamicChanges);
    }
    if (sessionChanges.removeRuleIds.length || sessionChanges.addRules.length) {
      await chrome.declarativeNetRequest.updateSessionRules(sessionChanges);
    }
    ruleSyncError = "";
    scheduleWhitelistExpiry();
    return { dynamicRuleCount: desiredDynamic.length, sessionRuleCount: desiredSession.length };
  });
  ruleSyncQueue = sync.catch((error) => {
    ruleSyncError = "Dynamic block rules could not be synchronized.";
    console.error("ClearSignal DNR synchronization failed.", error);
  });
  return sync;
}

function buildTemporaryAllowRules() {
  const rules = [];
  for (const [key, expiresAt] of temporaryWhitelist) {
    const separator = key.indexOf(":");
    const tabId = Number(key.slice(0, separator));
    const domain = ClearSignalRuleEngine.normalizeDomain(key.slice(separator + 1));
    if (!Number.isInteger(tabId) || !domain || expiresAt <= Date.now()) continue;
    rules.push({ tabId, domain, expiresAt });
  }
  rules.sort((left, right) => left.expiresAt - right.expiresAt || left.tabId - right.tabId);
  return rules.slice(0, MAX_TEMPORARY_ALLOW_RULES).map(({ tabId, domain }, index) => ({
    id: 30_000 + index,
    priority: 3,
    action: { type: "allow" },
    condition: {
      requestDomains: [domain],
      tabIds: [tabId],
      resourceTypes: ["main_frame"],
    },
  }));
}

function scheduleWhitelistExpiry() {
  const nextExpiry = Math.min(...temporaryWhitelist.values());
  if (!Number.isFinite(nextExpiry)) {
    void chrome.alarms.clear(WHITELIST_ALARM);
    return;
  }
  chrome.alarms.create(WHITELIST_ALARM, { when: Math.max(Date.now() + 1000, nextExpiry) });
}

function pruneSessionState() {
  const now = Date.now();
  let changed = false;
  for (const [url, entry] of safeCache) {
    if (now - entry.timestamp > CACHE_TTL_MS) {
      safeCache.delete(url);
      changed = true;
    }
  }
  while (safeCache.size > CACHE_MAX) {
    safeCache.delete(safeCache.keys().next().value);
    changed = true;
  }
  for (const [key, expiresAt] of temporaryWhitelist) {
    if (expiresAt <= now) {
      temporaryWhitelist.delete(key);
      changed = true;
    }
  }
  while (temporaryWhitelist.size > MAX_TEMPORARY_ALLOW_RULES) {
    let earliestKey = null;
    let earliestExpiry = Infinity;
    for (const [key, expiresAt] of temporaryWhitelist) {
      if (expiresAt < earliestExpiry) {
        earliestKey = key;
        earliestExpiry = expiresAt;
      }
    }
    if (earliestKey === null) break;
    temporaryWhitelist.delete(earliestKey);
    changed = true;
  }
  for (const [key, timestamp] of recentBlockedEvents) {
    if (now - timestamp > 30 * 60 * 1000) {
      recentBlockedEvents.delete(key);
      changed = true;
    }
  }
  while (recentBlockedEvents.size > 1_000) {
    recentBlockedEvents.delete(recentBlockedEvents.keys().next().value);
    changed = true;
  }
  if (changed) persistSessionState();
}

function normalizeUrl(raw) {
  try {
    let value = String(raw).trim().replace(/[\u200B-\u200D\u2060\uFEFF]/g, "");
    for (let index = 0; index < 3; index += 1) {
      try {
        const decoded = decodeURIComponent(value);
        if (decoded === value) break;
        value = decoded;
      } catch {
        break;
      }
    }
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    url.hash = "";
    return url;
  } catch {
    return null;
  }
}

function getDomain(hostname) {
  const labels = hostname.toLowerCase().replace(/\.$/, "").split(".");
  return labels.length > 1 ? labels.slice(-2).join(".") : hostname.toLowerCase();
}

function editDistance(left, right) {
  const previous = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let row = 1; row <= left.length; row += 1) {
    let diagonal = previous[0];
    previous[0] = row;
    for (let column = 1; column <= right.length; column += 1) {
      const above = previous[column];
      previous[column] = Math.min(
        previous[column] + 1,
        previous[column - 1] + 1,
        diagonal + (left[row - 1] === right[column - 1] ? 0 : 1)
      );
      diagonal = above;
    }
  }
  return previous[right.length];
}

function fallbackScan(raw) {
  const url = normalizeUrl(raw);
  if (!url) return { url: String(raw), score: 60, verdict: "SUSPICIOUS", reasons: ["URL could not be safely normalized."] };
  const host = url.hostname.toLowerCase();
  const registrable = getDomain(host);
  const reasons = [];
  let score = 0;
  const add = (points, reason) => {
    score = Math.min(100, score + points);
    reasons.push(reason);
  };
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.startsWith("[")) add(30, "The address uses a raw IP instead of a domain.");
  if (host.split(".").some((label) => label.startsWith("xn--"))) add(35, "The domain contains Punycode encoding.");
  if (String(raw).includes("@")) add(25, "The URL contains an @ symbol that may disguise its destination.");
  const brand = TARGETS.find((domain) => {
    const token = domain.split(".")[0];
    return registrable !== domain &&
      host.split(".").some((label) =>
        label.includes(token) ||
        (label.length >= 5 && editDistance(label.replace(/[01]/g, (character) => character === "0" ? "o" : "i"), token) === 1)
      );
  });
  if (brand) add(45, `The domain imitates the ${brand.split(".")[0]} brand.`);
  if (["xyz", "top", "zip", "tk", "buzz"].includes(host.split(".").at(-1))) add(12, "The domain uses a higher-risk TLD.");
  if (url.protocol !== "https:") add(10, "The connection does not use HTTPS.");
  const verdict = score >= 70 ? "BLOCKED" : score >= 8 ? "SUSPICIOUS" : "SAFE";
  return { url: url.toString(), score, verdict, reasons };
}

function cacheSafe(url, result) {
  safeCache.delete(url);
  safeCache.set(url, { timestamp: Date.now(), result });
  pruneSessionState();
  void persistSessionState();
}

function whitelistKey(tabId, domain) {
  return `${tabId}:${domain}`;
}

function isWhitelisted(url, tabId) {
  if (!Number.isInteger(tabId)) return false;
  pruneSessionState();
  const prefix = `${tabId}:`;
  for (const [key, expiresAt] of temporaryWhitelist) {
    if (!key.startsWith(prefix) || expiresAt <= Date.now()) continue;
    const domain = key.slice(prefix.length);
    if (url.hostname === domain || url.hostname.endsWith(`.${domain}`)) return true;
  }
  return false;
}

async function scan(raw, options = {}) {
  await sessionStateReady;
  const url = normalizeUrl(raw);
  if (!url) return fallbackScan(raw);
  const key = url.toString();
  const cached = safeCache.get(key);
  if (!options.force && cached && Date.now() - cached.timestamp <= CACHE_TTL_MS) {
    safeCache.delete(key);
    safeCache.set(key, cached);
    return cached.result;
  }
  if (pendingScans.has(key)) return pendingScans.get(key);
  if (pendingScans.size >= MAX_PENDING_SCANS) {
    return {
      url: key,
      score: 60,
      verdict: "SUSPICIOUS",
      reasons: ["The local scanner is busy; review before proceeding."],
    };
  }

  const promise = (async () => {
    let result;
    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: key, checkNetwork: true }),
        signal: AbortSignal.timeout(12_000),
      });
      if (!response.ok) throw new Error(`Scanner returned HTTP ${response.status}`);
      const body = await response.json();
      if (!Number.isFinite(body.score) ||
          !["SAFE", "SUSPICIOUS", "BLOCKED"].includes(body.verdict) ||
          !Array.isArray(body.reasons)) {
        throw new Error("Scanner response did not match the expected schema.");
      }
      result = body;
    } catch {
      result = fallbackScan(key);
      result.backendOffline = true;
    }
    if (result.verdict === "SAFE") cacheSafe(key, result);
    return result;
  })();
  pendingScans.set(key, promise);
  try {
    return await promise;
  } finally {
    pendingScans.delete(key);
  }
}

function shouldBlock(result) {
  return result.verdict === "BLOCKED" || Number(result.score) >= 70;
}

function blockedPageUrl(result) {
  const query = new URLSearchParams({
    url: result.url,
    score: String(result.score),
    reasons: JSON.stringify((result.reasons || []).slice(0, MAX_BADGE_REASONS)),
  });
  return `${chrome.runtime.getURL("blocked.html")}?${query}`;
}

function isExtensionPage(sender, page) {
  if (sender.id !== chrome.runtime.id || typeof sender.url !== "string") return false;
  try {
    const actual = new URL(sender.url);
    const expected = new URL(chrome.runtime.getURL(page));
    return actual.origin === expected.origin && actual.pathname === expected.pathname;
  } catch {
    return false;
  }
}

function updateBadge(tabId) {
  if (!Number.isInteger(tabId)) return;
  const count = tabBlockedCounts.get(tabId) || 0;
  void chrome.action.setBadgeText({ tabId, text: count ? String(count) : "" });
  void chrome.action.setBadgeBackgroundColor({ tabId, color: "#b52c2c" });
}

async function recordBlocked(result, tabId) {
  await sessionStateReady;
  const url = normalizeUrl(result.url);
  const domain = ClearSignalRuleEngine.normalizeDomain(result.blocked_domain || url?.hostname);
  if (!domain) return;
  const now = Date.now();
  const eventKey = Number.isInteger(tabId) ? `${tabId}:${url?.href || domain}` : null;

  await updateLocalState((state) => {
    const existing = Array.isArray(state.blockedDomains) ? state.blockedDomains : [];
    const prior = existing.find((entry) => entry?.domain === domain);
    const blockedDomains = [
      { domain, score: Number(result.score) || 0, addedAt: prior?.addedAt || now, lastSeen: now },
      ...existing.filter((entry) => entry?.domain !== domain),
    ].slice(0, MAX_STORED_BLOCKED_DOMAINS);
    const isNewEvent = eventKey && !recentBlockedEvents.has(eventKey);
    if (isNewEvent) {
      recentBlockedEvents.set(eventKey, now);
      tabBlockedCounts.set(tabId, (tabBlockedCounts.get(tabId) || 0) + 1);
      pruneSessionState();
      void persistSessionState();
    }
    return {
      blockedDomains,
      globalBlockedCount: Math.max(0, Number(state.globalBlockedCount) || 0) + (isNewEvent ? 1 : 0),
      lastBlockedAt: isNewEvent ? new Date(now).toISOString() : state.lastBlockedAt || null,
    };
  });
  updateBadge(tabId);
  await queueRuleSync();
}

async function syncBackendBlocklist() {
  const response = await fetch("http://127.0.0.1:5000/api/blocklist", {
    signal: AbortSignal.timeout(2500),
  });
  if (!response.ok) throw new Error(`Blocklist sync returned HTTP ${response.status}`);
  const body = await response.json();
  if (!Array.isArray(body.entries)) throw new Error("Blocklist response is invalid.");

  const imported = body.entries.flatMap((entry) => {
    const domain = ClearSignalRuleEngine.normalizeDomain(entry?.domain);
    const score = Number(entry?.score);
    if (!domain || !Number.isFinite(score) || score < 70) return [];
    return [{
      domain,
      score: Math.min(100, Math.round(score)),
      addedAt: entry.addedAt || new Date().toISOString(),
      lastSeen: Date.parse(entry.lastSeenAt || entry.addedAt) || 0,
    }];
  });
  if (!imported.length) return;

  await updateLocalState((state) => {
    const merged = new Map((Array.isArray(state.blockedDomains) ? state.blockedDomains : [])
      .filter((entry) => ClearSignalRuleEngine.normalizeDomain(entry?.domain))
      .map((entry) => [entry.domain, entry]));
    for (const entry of imported) {
      const current = merged.get(entry.domain);
      if (!current || entry.lastSeen >= (Number(current.lastSeen) || 0)) merged.set(entry.domain, entry);
    }
    return {
      blockedDomains: [...merged.values()]
        .sort((left, right) => (Number(right.lastSeen) || 0) - (Number(left.lastSeen) || 0))
        .slice(0, MAX_STORED_BLOCKED_DOMAINS),
    };
  });
}

async function showBlocked(tabId, result, expectedTabUrl = null) {
  if (!Number.isInteger(tabId) || !shouldBlock(result)) return;
  try {
    const tab = await chrome.tabs.get(tabId);
    if (expectedTabUrl) {
      const current = normalizeUrl(tab.pendingUrl || tab.url || "");
      const expected = normalizeUrl(expectedTabUrl);
      if (!current || !expected || current.href !== expected.href) return;
    }
    if (tab.url?.startsWith(chrome.runtime.getURL("blocked.html"))) return;
    await chrome.tabs.update(tabId, { url: blockedPageUrl(result) });
  } catch {
    // The tab may have closed while its scan was in progress.
  }
}

async function isProtectionEnabled() {
  const settings = await chrome.storage.local.get({ enabled: true });
  return settings.enabled !== false;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object") return false;

  if (message.type === "SCAN_LINK" && typeof message.url === "string" && Number.isInteger(sender.tab?.id)) {
    void (async () => {
      if (!(await isProtectionEnabled())) {
        return { url: message.url, score: 0, verdict: "SAFE", reasons: ["Real-time protection is disabled."] };
      }
      await sessionStateReady;
      const url = normalizeUrl(message.url);
      const settings = await chrome.storage.local.get({ trustedDomains: [] });
      if (url && (isWhitelisted(url, sender.tab.id) ||
          settings.trustedDomains.some((domain) => url.hostname === domain || url.hostname.endsWith(`.${domain}`)))) {
        return { url: url.href, score: 0, verdict: "SAFE", reasons: ["This domain is trusted for this browser session."] };
      }
      const result = await scan(message.url);
      if (shouldBlock(result)) {
        try {
          await recordBlocked(result, sender.tab.id);
        } catch (error) {
          console.error("Could not persist a detected threat.", error);
        }
      }
      return result;
    })().then((result) => {
      sendResponse(result);
    }).catch(() => sendResponse(fallbackScan(message.url)));
    return true;
  }

  if (message.type === "DISPLAY_BLOCKED" && message.result && shouldBlock(message.result) &&
      Number.isFinite(message.result.score) && Number.isInteger(sender.tab?.id)) {
    const result = {
      ...message.result,
      url: normalizeUrl(message.result.url)?.href,
      reasons: Array.isArray(message.result.reasons)
        ? message.result.reasons.filter((reason) => typeof reason === "string").slice(0, MAX_BADGE_REASONS)
        : [],
    };
    if (!result.url) {
      sendResponse({ ok: false });
      return false;
    }
    if (message.openInNewTab === true) {
      void chrome.tabs.create({ url: blockedPageUrl(result), openerTabId: sender.tab.id })
        .then(() => sendResponse({ ok: true }))
        .catch(() => sendResponse({ ok: false }));
      return true;
    }
    void showBlocked(sender.tab.id, result, sender.tab.url)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message.type === "OPEN_SCANNED_TAB" && typeof message.url === "string" && Number.isInteger(sender.tab?.id)) {
    const url = normalizeUrl(message.url);
    if (url) void chrome.tabs.create({ url: url.toString(), openerTabId: sender.tab.id });
    sendResponse({ ok: Boolean(url) });
    return false;
  }

  if (message.type === "WHITELIST_ONCE" && typeof message.url === "string" &&
      isExtensionPage(sender, "blocked.html")) {
    const url = normalizeUrl(message.url);
    const tabId = Number.isInteger(sender.tab?.id) ? sender.tab.id : message.tabId;
    if (!url || !Number.isInteger(tabId)) {
      sendResponse({ ok: false });
      return false;
    }
    void (async () => {
      const warningTab = await chrome.tabs.get(tabId);
      if (!warningTab.url?.startsWith(chrome.runtime.getURL("blocked.html"))) return false;
      await sessionStateReady;
      const key = whitelistKey(tabId, url.hostname);
      temporaryWhitelist.set(key, Date.now() + WHITELIST_TTL_MS);
      pruneSessionState();
      await persistSessionState();
      await queueRuleSync();
      await chrome.tabs.update(tabId, { url: url.href });
      return true;
    })().then((ok) => sendResponse({ ok, expiresInSeconds: WHITELIST_TTL_MS / 1000 }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message.type === "GET_STATUS" && isExtensionPage(sender, "popup.html")) {
    void (async () => {
      await Promise.all([sessionStateReady, ruleSyncQueue]);
      pruneSessionState();
      const settings = await chrome.storage.local.get({
        enabled: true,
        globalBlockedCount: 0,
        trustedDomains: [],
      });
      const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      return {
        enabled: settings.enabled !== false,
        cachedSafe: safeCache.size,
        blockedOnCurrentPage: Number.isInteger(tabBlockedCounts.get(tab?.id)) ? tabBlockedCounts.get(tab.id) : 0,
        globalBlockedTotal: Number(settings.globalBlockedCount) || 0,
        trustedDomains: settings.trustedDomains,
        ruleSyncError,
      };
    })().then(sendResponse).catch(() => sendResponse({ error: "Could not read extension status." }));
    return true;
  }

  if (message.type === "SET_ENABLED" && typeof message.enabled === "boolean" &&
      isExtensionPage(sender, "popup.html")) {
    void updateLocalState(() => ({ enabled: message.enabled }))
      .then(() => queueRuleSync())
      .then(() => sendResponse({ ok: true, enabled: message.enabled }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message.type === "ADD_TRUSTED_DOMAIN" && typeof message.domain === "string" &&
      isExtensionPage(sender, "popup.html")) {
    const domain = ClearSignalRuleEngine.normalizeDomain(message.domain);
    if (!domain) {
      sendResponse({ ok: false, error: "Enter a domain only, such as example.com." });
      return false;
    }
    void updateLocalState((state) => ({
      trustedDomains: [...new Set([...(Array.isArray(state.trustedDomains) ? state.trustedDomains : []), domain])]
        .slice(-MAX_STORED_TRUSTED_DOMAINS),
    })).then(() => queueRuleSync())
      .then(() => sendResponse({ ok: true, domain }))
      .catch(() => sendResponse({ ok: false, error: "Could not update trusted domains." }));
    return true;
  }

  if (message.type === "REMOVE_TRUSTED_DOMAIN" && typeof message.domain === "string" &&
      isExtensionPage(sender, "popup.html")) {
    const domain = ClearSignalRuleEngine.normalizeDomain(message.domain);
    if (!domain) {
      sendResponse({ ok: false });
      return false;
    }
    void updateLocalState((state) => ({
      trustedDomains: (Array.isArray(state.trustedDomains) ? state.trustedDomains : [])
        .filter((entry) => entry !== domain),
    })).then(() => queueRuleSync())
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  return false;
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0 || details.tabId < 0) return;
  const url = normalizeUrl(details.url);
  if (!url || url.hostname === "127.0.0.1" || url.hostname === "localhost" ||
      url.hostname.endsWith(".localhost") || url.href.startsWith(chrome.runtime.getURL("blocked.html"))) return;

  void (async () => {
    await sessionStateReady;
    pruneSessionState();
    if (!(await isProtectionEnabled()) || isWhitelisted(url, details.tabId)) return;
    const settings = await chrome.storage.local.get({ trustedDomains: [] });
    if (settings.trustedDomains.some((domain) => url.hostname === domain || url.hostname.endsWith(`.${domain}`))) return;
    // This is a fallback for direct navigations: MV3 cannot cancel this event.
    const result = await scan(url.href);
    if (shouldBlock(result)) {
      try {
        await recordBlocked(result, details.tabId);
      } catch (error) {
        console.error("Could not persist a detected threat.", error);
      }
      await showBlocked(details.tabId, result, details.url);
    }
  })().catch(() => {
    const fallback = fallbackScan(url.href);
    if (shouldBlock(fallback)) void showBlocked(details.tabId, fallback, details.url);
  });
});

chrome.tabs.onActivated.addListener(({ tabId }) => updateBadge(tabId));

chrome.tabs.onRemoved.addListener((tabId) => {
  tabBlockedCounts.delete(tabId);
  const prefix = `${tabId}:`;
  for (const key of temporaryWhitelist.keys()) {
    if (key.startsWith(prefix)) temporaryWhitelist.delete(key);
  }
  for (const key of recentBlockedEvents.keys()) {
    if (key.startsWith(prefix)) recentBlockedEvents.delete(key);
  }
  void persistSessionState().then(() => queueRuleSync());
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && ["enabled", "blockedDomains", "trustedDomains"].some((key) => key in changes)) {
    void queueRuleSync();
  }
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== WHITELIST_ALARM) return;
  pruneSessionState();
  void persistSessionState().then(() => queueRuleSync());
});

chrome.runtime.onInstalled.addListener(() => {
  void updateLocalState((state) => ({
    enabled: state.enabled !== false,
    blockedDomains: Array.isArray(state.blockedDomains) ? state.blockedDomains : [],
    trustedDomains: Array.isArray(state.trustedDomains) ? state.trustedDomains : [],
    globalBlockedCount: Number(state.globalBlockedCount) || 0,
  })).then(() => syncBackendBlocklist())
    .then(() => queueRuleSync())
    .catch((error) => {
      console.warn("Could not import the backend blocklist.", error);
      void queueRuleSync();
    });
});

chrome.runtime.onStartup.addListener(() => {
  void sessionStateReady.then(() => {
    pruneSessionState();
    return persistSessionState();
  }).then(() => syncBackendBlocklist())
    .then(() => queueRuleSync())
    .catch((error) => {
      console.warn("Could not import the backend blocklist.", error);
      void queueRuleSync();
    });
});

void queueRuleSync();
