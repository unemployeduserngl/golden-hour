const test = require("node:test");
const assert = require("node:assert/strict");
const { canonicalizeUrl, decodeRepeatedly } = require("../src/url-normalizer");
const { analyzeUrl, shannonEntropy } = require("../src/analyzer");

test("removes zero-width characters and recursively decodes URL input", () => {
  const result = canonicalizeUrl("https%253A%252F%252Fexample.com%252Flogin\u200b");

  assert.equal(result.hostname, "example.com");
  assert.equal(result.decodingChangedInput, true);
  assert.equal(decodeRepeatedly("%252541", 4), "A");
});

test("canonicalizes integer and octal IPv4 host forms", () => {
  const integer = canonicalizeUrl("http://2130706433/");
  const octal = canonicalizeUrl("http://0177.0.0.1/");
  assert.equal(integer.hostname, "127.0.0.1");
  assert.equal(octal.hostname, "127.0.0.1");
  assert.equal(integer.nonCanonicalIp, true);
  assert.equal(octal.nonCanonicalIp, true);
});

test("computes Shannon entropy", () => {
  assert.equal(shannonEntropy("aaaa"), 0);
  assert.equal(shannonEntropy("abcd"), 2);
});

test("does not over-penalize ordinary encoded path characters", () => {
  const normal = analyzeUrl("https://example.com/search%20term", { urls: new Set(), available: true });
  const obfuscated = analyzeUrl("https://example.com/%252Fadmin", { urls: new Set(), available: true });

  assert.equal(normal.warningFlags.some((flag) => flag.code === "encoded_url_abuse"), false);
  assert.equal(obfuscated.warningFlags.some((flag) => flag.code === "encoded_url_abuse"), true);
});
