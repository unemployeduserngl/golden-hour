const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeUrl } = require("../src/analyzer");

test("flags a brand name used on an unrelated domain", () => {
  const result = analyzeUrl("https://paypal-login.example.net/signin", { urls: new Set(), available: true });

  assert.equal(result.status, "Suspicious");
  assert.ok(result.checks.some((check) => check.title.includes("PayPal") && check.status === "danger"));
  assert.ok(result.warningFlags.some((flag) => flag.code === "brand_lookalike"));
});

test("flags common character substitutions in a copied brand domain", () => {
  const result = analyzeUrl("https://paypa1-secure.example/login", { urls: new Set(), available: true });

  assert.equal(result.status, "Suspicious");
  assert.ok(result.checks.some((check) => check.title.includes("PayPal")));
});

test("flags a sensitive path word even when a different word appears in the registered domain", () => {
  const result = analyzeUrl("https://paypa1-login.example/verify", { urls: new Set(), available: true });

  assert.ok(result.warningFlags.some((flag) => flag.code === "deceptive_sensitive_keyword"));
});

test("warns about unverified banking domains even when the feed has no match", () => {
  const result = analyzeUrl("https://secure-online-banking.example/login", { urls: new Set(), available: true });

  assert.equal(result.status, "Malicious");
  assert.ok(result.checks.some((check) => check.title.includes("Banking or government")));
});

test("flags bank impersonation on common look-alike top-level domains", () => {
  const result = analyzeUrl("http://bank-login-verification.xyz", { urls: new Set(), available: false });

  assert.equal(result.status, "Malicious");
  assert.ok(result.checks.some((check) => check.title.includes("Banking or government")));
});

test("matches the OpenPhish feed by hostname", () => {
  const result = analyzeUrl("https://phishing.example/other-page", {
    urls: new Set(["https://phishing.example/login"]),
    available: true,
  });

  assert.equal(result.knownPhishing, true);
  assert.equal(result.status, "Malicious");
  assert.ok(result.warningFlags.some((flag) => flag.code === "known_phishing_feed_match"));
});

test("flags lexical URL patterns and keywords outside the registered domain", () => {
  const result = analyzeUrl(
    "https://login.verify.example.xyz/secure/account/update?next=one-two-three-four-five-six-seven-eight-nine",
    { urls: new Set(), available: true },
  );
  const codes = new Set(result.warningFlags.map((flag) => flag.code));

  assert.ok(codes.has("long_url"));
  assert.ok(codes.has("deceptive_sensitive_keyword"));
  assert.ok(codes.has("suspicious_tld"));
  assert.ok(result.warningFlags.every((flag) => flag.title && flag.detail && flag.severity));
});

test("flags @ symbols and high subdomain counts", () => {
  const atResult = analyzeUrl("https://trusted.example@evil.example/path", { urls: new Set(), available: true });
  const subdomainResult = analyzeUrl("https://one.two.three.four.example.com", { urls: new Set(), available: true });

  assert.ok(atResult.warningFlags.some((flag) => flag.code === "at_symbol"));
  assert.ok(subdomainResult.warningFlags.some((flag) => flag.code === "many_subdomains"));
});

test("flags numeric IP hosts and GitHub typo domains", () => {
  const ipResult = analyzeUrl("http://8.8.8.8/login", { urls: new Set(), available: true });
  const typoResult = analyzeUrl("https://githud.example/login", { urls: new Set(), available: true });

  assert.ok(ipResult.warningFlags.some((flag) => flag.code === "ip_address_host"));
  assert.ok(typoResult.warningFlags.some((flag) => flag.code === "brand_lookalike"));
});

test("does not call an HTTPS site safe just because it uses HTTPS", () => {
  const result = analyzeUrl("https://example.com", { urls: new Set(), available: true });

  assert.equal(result.status, "Safe");
  assert.match(result.disclaimer, /cannot guarantee safety/i);
  assert.ok(result.checks.some((check) => check.title === "HTTPS connection requested"));
});

test("normalizes bare domains and strips fragments", () => {
  const result = analyzeUrl("Example.com/path#section", { urls: new Set(), available: true });

  assert.equal(result.normalizedUrl, "https://example.com/path");
});

test("rejects unsupported schemes and malformed addresses", () => {
  assert.throws(() => analyzeUrl("javascript:alert(1)"), /Only HTTP and HTTPS/);
  assert.throws(() => analyzeUrl("not a url"), /valid website address/);
});
