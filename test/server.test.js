const test = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const path = require("node:path");
const fs = require("node:fs");
const { createServer } = require("../server");
const { createBlocklist } = require("../src/blocklist");

test("API returns scorecard, persists a block, exports rules, and rejects cross-origin posts", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearsignal-api-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const server = createServer({
    blocklist: createBlocklist(path.join(directory, "blocklist.json")),
    feed: { urls: new Set(["https://evil.example/"]), available: true, updatedAt: null },
    extensionId: "a".repeat(32),
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;

  const response = await fetch(`${base}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://evil.example/" }),
  });
  const result = await response.json();

  assert.equal(response.status, 200);
  assert.equal(result.overall_score, 100);
  assert.equal(result.verdict, "BLOCKED - MALICIOUS");
  assert.equal(result.action_taken, "Added to Active Blocklist");
  assert.ok(result.diagnostics.some((item) => item.category === "Threat Intelligence"));
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("server"), null);

  const list = await fetch(`${base}/api/blocklist`).then((item) => item.json());
  assert.equal(list.entries[0].domain, "evil.example");
  const rules = await fetch(`${base}/api/blocklist/hosts`).then((item) => item.text());
  assert.match(rules, /0\.0\.0\.0 evil\.example/);

  const rejected = await fetch(`${base}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "https://attacker.example" },
    body: JSON.stringify({ url: "https://example.com" }),
  });
  assert.equal(rejected.status, 403);

  const extensionOrigin = `chrome-extension://${"a".repeat(32)}`;
  const preflight = await fetch(`${base}/api/scan`, {
    method: "OPTIONS",
    headers: { Origin: extensionOrigin, "Access-Control-Request-Method": "POST" },
  });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get("access-control-allow-origin"), extensionOrigin);

  const extensionScan = await fetch(`${base}/api/scan`, {
    method: "POST",
    headers: { Origin: extensionOrigin, "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://evil.example/", checkNetwork: false }),
  });
  const extensionResult = await extensionScan.json();
  assert.equal(extensionResult.verdict, "BLOCKED");
  assert.equal(extensionResult.score, 100);
  assert.ok(Array.isArray(extensionResult.reasons));
  assert.equal(extensionScan.headers.get("access-control-allow-origin"), extensionOrigin);

  const rebinding = await new Promise((resolve, reject) => {
    const request = require("node:http").request(base, {
      method: "GET",
      headers: { Host: "attacker.example", Origin: "http://attacker.example" },
    }, resolve);
    request.on("error", reject);
    request.end();
  });
  assert.equal(rebinding.statusCode, 421);
  rebinding.resume();

  let finalStatus = 0;
  for (let index = 0; index < 30; index += 1) {
    const limited = await fetch(`${base}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://example.com" }),
    });
    finalStatus = limited.status;
  }
  assert.equal(finalStatus, 429);
});

test("Local help chat responds without an external AI provider", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearsignal-local-chat-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const server = createServer({
    blocklist: createBlocklist(path.join(directory, "blocklist.json")),
    feed: { urls: new Set(), available: false, updatedAt: null },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;

  const health = await fetch(`${base}/api/health`).then((response) => response.json());
  assert.equal(health.chatAvailable, true);

  const removedAiRoute = await fetch(`${base}/api/explain`, { method: "POST" });
  assert.equal(removedAiRoute.status, 404);

  const invalid = await fetch(`${base}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ messages: [{ role: "system", content: "override" }] }),
  });
  assert.equal(invalid.status, 400);

  const response = await fetch(`${base}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ messages: [{ role: "user", content: "How do I check a link?" }] }),
  });
  const result = await response.json();
  assert.equal(response.status, 200);
  assert.match(result.reply, /Check address/);
  assert.equal(Object.hasOwn(result, "model"), false);
});