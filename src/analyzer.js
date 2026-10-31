const net = require("node:net");
const { canonicalizeUrl } = require("./url-normalizer");

const BRANDS = [
  { name: "Amazon", host: "amazon.com", token: "amazon" },
  { name: "Apple", host: "apple.com", token: "apple" },
  { name: "Bank of America", host: "bankofamerica.com", token: "bankofamerica" },
  { name: "Barclays", host: "barclays.co.uk", token: "barclays" },
  { name: "Chase", host: "chase.com", token: "chase" },
  { name: "Citi", host: "citi.com", token: "citi" },
  { name: "Facebook", host: "facebook.com", token: "facebook" },
  { name: "Google", host: "google.com", token: "google" },
  { name: "GitHub", host: "github.com", token: "github" },
  { name: "HDFC Bank", host: "hdfcbank.com", token: "hdfc" },
  { name: "HSBC", host: "hsbc.com", token: "hsbc" },
  { name: "ICICI Bank", host: "icicibank.com", token: "icici" },
  { name: "Instagram", host: "instagram.com", token: "instagram" },
  { name: "Microsoft", host: "microsoft.com", token: "microsoft" },
  { name: "Netflix", host: "netflix.com", token: "netflix" },
  { name: "PayPal", host: "paypal.com", token: "paypal" },
  { name: "State Bank of India", host: "sbi.co.in", token: "sbi" },
  { name: "WhatsApp", host: "whatsapp.com", token: "whatsapp" },
  { name: "Wells Fargo", host: "wellsfargo.com", token: "wellsfargo" },
];

const TARGETED_DOMAINS = [...new Set(BRANDS.map((brand) => brand.token))];
const OFFICIAL_GOV_SUFFIXES = new Set(["gov", "gov.in", "gov.uk", "gov.au", "gc.ca"]);
const SHORTENERS = new Set([
  "bit.ly",
  "cutt.ly",
  "is.gd",
  "rebrand.ly",
  "shorturl.at",
  "tinyurl.com",
  "t.ly",
]);

const URGENCY_WORDS = /\b(login|log-in|signin|sign-in|verify|verification|secure|account|update|password|wallet|billing|support)\b/i;
const SENSITIVE_WORDS = /\b(login|log-in|signin|sign-in|verify|verification|secure|account|update|banking)\b/i;
const FINANCIAL_OR_GOVERNMENT_WORDS = /\b(bank|banking|government|govt?|tax|revenue|treasury|payroll)\b/i;
const MULTI_LABEL_SUFFIXES = new Set([
  "ac.in",
  "co.in",
  "co.jp",
  "co.nz",
  "co.uk",
  "com.au",
  "com.br",
  "com.cn",
  "com.sg",
  "gov.in",
  "org.uk",
]);

function getRegisteredLabel(hostname) {
  const domain = getRegistrableDomain(hostname);
  if (net.isIP(domain)) return domain;
  const labels = domain.split(".");
  return labels.length > 1 ? labels[labels.length - 2] : domain;
}

function getRegistrableDomain(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (net.isIP(host)) return host;

  const labels = host.split(".");
  if (labels.length < 2) return host;
  const suffix = labels.slice(-2).join(".");
  return MULTI_LABEL_SUFFIXES.has(suffix) && labels.length >= 3
    ? labels.slice(-3).join(".")
    : labels.slice(-2).join(".");
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
        diagonal + (left[row - 1] === right[column - 1] ? 0 : 1),
      );
      diagonal = above;
    }
  }
  return previous[right.length];
}

function shannonEntropy(value) {
  if (!value) return 0;
  const frequencies = new Map();
  for (const character of value) frequencies.set(character, (frequencies.get(character) || 0) + 1);
  let entropy = 0;
  for (const frequency of frequencies.values()) {
    const probability = frequency / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function normalizeLookalikeLabel(label) {
  return label
    .toLowerCase()
    .replace(/rn/g, "m")
    .replace(/[0]/g, "o")
    .replace(/[1!]/g, "i")
    .replace(/[3]/g, "e")
    .replace(/[5]/g, "s")
    .replace(/[7]/g, "t");
}

function classifyRisk(score, knownPhishing) {
  if (knownPhishing || score >= 60) return { riskLevel: "high", status: "Malicious" };
  if (score >= 8) return { riskLevel: "medium", status: "Suspicious" };
  return { riskLevel: "low", status: "Safe" };
}

function toWarningFlags(checks) {
  return checks
    .filter((check) => check.status !== "good")
    .map((check) => ({
      code: check.code || "url_signal",
      severity: check.status === "danger" ? "high" : "medium",
      title: check.title,
      detail: check.detail,
    }));
}

function analyzeUrl(input, feed = { urls: new Set(), available: false }) {
  const normalized = canonicalizeUrl(input);
  const { url, hostname } = normalized;
  const trimmed = normalized.cleaned;

  const checks = [];
  let score = 0;
  let knownPhishing = false;
  const addCheck = (title, detail, points = 0, status = "warning", code = "url_signal", category = "URL & Lexical") => {
    checks.push({ title, detail, status, code, points, category });
    score += points;
  };

  let officialBrand = null;
  let lookalikeBrand = null;
  for (const brand of BRANDS) {
    if (hostname === brand.host || hostname.endsWith(`.${brand.host}`)) {
      officialBrand = brand;
      break;
    }
    const labels = hostname.split(".");
    const registeredLabel = getRegisteredLabel(hostname);
    const distanceLimit = brand.token.length >= 8 ? 2 : 1;
    if (
      labels.some((label) => label.includes(brand.token)) ||
      labels.some((label) => {
        const normalizedLabel = normalizeLookalikeLabel(label);
        const candidates = [
          normalizedLabel,
          ...normalizedLabel.split(/[-_]+/),
          normalizedLabel.replace(/[-_]/g, ""),
        ];
        return candidates.some((candidate) =>
          candidate.length >= 4 && editDistance(candidate, brand.token) <= distanceLimit
        );
      })
    ) {
      lookalikeBrand = brand;
      break;
    }
  }

  if (lookalikeBrand) {
    addCheck(
      `${lookalikeBrand.name} name on an unrelated domain`,
      `The address contains “${lookalikeBrand.token}”, but it is not on ${lookalikeBrand.host}. Brand names in a URL are easy to copy.`,
      45,
      "danger",
      "brand_lookalike",
      "Typosquatting & Lookalikes",
    );
  } else if (officialBrand) {
    addCheck(
      `Recognized ${officialBrand.name} domain`,
      `The hostname belongs to ${officialBrand.host}. This does not independently verify the page or its content.`,
      0,
      "good",
    );
  }

  const suffix = hostname.split(".").slice(-2).join(".");
  const registeredLabel = getRegisteredLabel(hostname);
  if (
    !officialBrand &&
    !OFFICIAL_GOV_SUFFIXES.has(suffix) &&
    FINANCIAL_OR_GOVERNMENT_WORDS.test(registeredLabel)
  ) {
    addCheck(
      "Banking or government wording on an unverified domain",
      "The registered domain uses banking or government-related terms, but it does not match a recognized organization domain. Verify it using an official bookmark or document.",
      30,
      "warning",
      "unverified_financial_or_government_domain",
      "Deceptive Keywords",
    );
  }

  const feedUrls = feed.urls instanceof Set ? feed.urls : new Set(feed.urls || []);
  const normalizedUrl = normalized.normalizedUrl;
  const feedHit = feedUrls.has(normalizedUrl) || feedUrls.has(`${normalizedUrl.replace(/\/$/, "")}/`);
  const hostHit = [...feedUrls].some((entry) => {
    try {
      return new URL(entry).hostname.toLowerCase() === hostname;
    } catch {
      return false;
    }
  });
  if (feedHit || hostHit) {
    knownPhishing = true;
    addCheck(
      "Listed in the OpenPhish community feed",
      "This address or its hostname appears in a public phishing feed. Do not enter information or continue to the site.",
      100,
      "danger",
      "known_phishing_feed_match",
      "Threat Intelligence",
    );
  } else if (feed.available) {
    addCheck("OpenPhish feed checked", "No matching address was found in the current community feed.", 0, "good");
  } else {
    addCheck("Threat feed unavailable", "The live phishing feed could not be checked; this result uses URL clues only.", 0);
  }

  const ipAddress = net.isIP(hostname);
  if (ipAddress) {
    addCheck("Website uses an IP address", "A numeric address instead of a domain can make the site harder to identify.", 30, "warning", "ip_address_host");
  }
  if (normalized.nonCanonicalIp) {
    addCheck(
      "Obfuscated numeric IP address",
      "The address used a shortened, integer, hexadecimal, or octal IP form that was normalized to a dotted address before inspection.",
      18,
      "warning",
      "noncanonical_ip_address",
      "Lexical & Obfuscation",
    );
  }

  if (trimmed.includes("@")) {
    addCheck("Address contains an @ symbol", "An @ symbol can make text before it look like the destination even though the browser treats it as login information.", 25, "danger", "at_symbol");
  }

  if (hostname.startsWith("xn--") || hostname.split(".").some((label) => label.startsWith("xn--"))) {
    addCheck("Internationalized domain encoding", "The hostname contains punycode (xn--), which can disguise look-alike characters.", 35, "danger", "punycode_hostname");
  }

  if (url.href.length > 75) {
    addCheck("Unusually long web address", `This address is ${url.href.length} characters long. Long links can hide the actual destination.`, 8, "warning", "long_url");
  }

  const domainEntropy = shannonEntropy(getRegisteredLabel(hostname));
  if (getRegisteredLabel(hostname).length >= 14 && domainEntropy >= 3.5) {
    addCheck(
      "High-entropy registered domain",
      `The registered domain has Shannon entropy ${domainEntropy.toFixed(2)} bits per character, an unusually varied label sometimes seen in generated domains.`,
      12,
      "warning",
      "high_domain_entropy",
      "Lexical & Obfuscation",
    );
  }

  if (normalized.encodedAuthority || normalized.nestedEncoding || normalized.encodedSequences >= 4) {
    addCheck(
      "Repeated or excessive URL encoding",
      "The address contains recursively encoded characters or many percent-encoded sequences, which can hide the apparent destination.",
      18,
      "warning",
      "encoded_url_abuse",
      "Lexical & Obfuscation",
    );
  }

  const labels = hostname.split(".");
  const dotCount = (hostname.match(/\./g) || []).length;
  if (dotCount > 3) {
    addCheck("Many subdomains", `The hostname has ${dotCount} dots. Multiple subdomains can hide the registered domain.`, 12, "warning", "many_subdomains");
  }

  const hyphenCount = (registeredLabel.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    addCheck("Several hyphens in the registered domain", "Long, hyphen-heavy domains can imitate the wording of a trusted organization. Check the actual domain carefully.", 10, "warning", "excessive_domain_hyphens");
  }

  const tld = hostname.split(".").at(-1);
  if (["xyz", "top", "zip", "tk", "buzz"].includes(tld)) {
    addCheck("Domain uses a higher-risk domain ending", `The .${tld} ending has appeared in suspicious links. A domain ending alone does not prove fraud.`, 15, "warning", "suspicious_tld");
  }

  if (SHORTENERS.has(hostname)) {
    addCheck("Shortened link", "This service hides the final destination. Check the destination through a trusted channel before opening it.", 10, "warning", "shortened_url");
  }

  const sensitiveCandidate = `${labels.slice(0, -2).join(".")}${url.pathname}`.match(SENSITIVE_WORDS);
  const sensitiveMatch = sensitiveCandidate &&
    !new RegExp(`\\b${sensitiveCandidate[0]}\\b`, "i").test(registeredLabel)
    ? sensitiveCandidate
    : null;
  if (sensitiveMatch) {
    addCheck(
      "Sensitive keyword outside the registered domain",
      `The word “${sensitiveMatch[0]}” appears in a subdomain or path, not as proof of the organization that owns this address.`,
      12,
      "warning",
      "deceptive_sensitive_keyword",
    );
  }

  if (URGENCY_WORDS.test(`${hostname}${url.pathname}${url.search}`) && !sensitiveMatch) {
    addCheck("Urgent or account-related wording", "Words like “verify” or “login” can create pressure and are common in phishing links.", 8, "warning", "urgent_url_wording");
  }

  if (url.protocol !== "https:") {
    addCheck("Connection does not use HTTPS", "Information sent over this connection may not be encrypted. HTTPS alone would not prove legitimacy.", 10, "warning", "https_not_used");
  } else {
    addCheck("HTTPS connection requested", "The address uses HTTPS; this encrypts traffic but does not prove the site is genuine.", 0, "good", "https_requested");
  }

  if (url.port && !["80", "443"].includes(url.port)) {
    addCheck("Unusual port number", `The address uses port ${url.port}, which is uncommon for a public website.`, 10, "warning", "unusual_port");
  }

  if (checks.length === 0 || checks.every((check) => check.status === "good")) {
    checks.push({
      title: "No obvious URL warning signs",
      detail: "Automated checks found no strong warning signs. This is not proof that the site or its content is safe.",
      status: "good",
    });
  }

  const { riskLevel, status } = classifyRisk(Math.min(score, 100), knownPhishing);
  const finalChecks = checks;

  return {
    input: trimmed,
    normalizedUrl,
    hostname,
    domainEntropy: Number(domainEntropy.toFixed(2)),
    score: Math.min(score, 100),
    riskLevel,
    status,
    knownPhishing,
    checks: finalChecks,
    warningFlags: toWarningFlags(checks),
    checkedAt: new Date().toISOString(),
    disclaimer: "A URL check cannot guarantee safety. Do not share passwords, verification codes, or payment details with a site you do not trust.",
  };
}

module.exports = { analyzeUrl, classifyRisk, getRegistrableDomain, getRegisteredLabel, shannonEntropy, TARGETED_DOMAINS };
