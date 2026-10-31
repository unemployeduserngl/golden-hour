const test = require("node:test");
const assert = require("node:assert/strict");
const { checkPublicUrl, isPublicAddress } = require("../src/network-check");

test("rejects private and reserved IP ranges before connecting", () => {
  for (const address of ["127.0.0.1", "10.0.0.2", "192.168.1.1", "169.254.169.254", "::1", "fc00::1", "2001:db8::1"]) {
    assert.equal(isPublicAddress(address), false, `${address} should not be considered public`);
  }
  assert.equal(isPublicAddress("8.8.8.8"), true);
  assert.equal(isPublicAddress("2001:4860:4860::8888"), true);
});

test("does not make a network request to a private IP", async () => {
  const result = await checkPublicUrl("http://127.0.0.1/");

  assert.equal(result.performed, false);
  assert.match(result.error, /private or reserved/);
});

test("blocks a public hostname if DNS resolves it to a private address", async () => {
  const result = await checkPublicUrl("https://example.com/", {
    lookup: async () => [{ address: "10.1.2.3", family: 4 }],
  });

  assert.equal(result.performed, false);
  assert.match(result.error, /only to public IP/);
});

test("applies the timeout to DNS lookups", async () => {
  const result = await checkPublicUrl("https://example.com/", {
    timeoutMs: 20,
    lookup: () => new Promise((resolve) => setTimeout(() => resolve([{ address: "8.8.8.8", family: 4 }]), 100)),
  });

  assert.equal(result.performed, false);
  assert.match(result.error, /timed out/);
});

test("follows a bounded redirect chain and reports a verified HTTPS destination", async () => {
  const responses = [
    { statusCode: 301, location: "https://example.com/one" },
    { statusCode: 302, location: "/two" },
    { statusCode: 307, location: "/three" },
    { statusCode: 200, location: null },
  ];
  const visited = [];
  const result = await checkPublicUrl("http://example.com/", {
    lookup: async () => [{ address: "8.8.8.8", family: 4 }],
    headRequest: async (url) => {
      visited.push(url.toString());
      return responses.shift();
    },
  });

  assert.equal(result.performed, true);
  assert.equal(result.redirects, 3);
  assert.equal(result.tlsVerified, true);
  assert.equal(visited.length, 4);
  assert.ok(result.flags.some((flag) => flag.code === "many_redirects"));
});

test("does not treat a redirect between subdomains of one site as cross-domain", async () => {
  const responses = [
    { statusCode: 302, location: "https://example.com/final" },
    { statusCode: 200, location: null },
  ];
  const result = await checkPublicUrl("https://www.example.com/", {
    lookup: async () => [{ address: "8.8.8.8", family: 4 }],
    headRequest: async () => responses.shift(),
  });

  assert.equal(result.performed, true);
  assert.equal(result.crossDomainRedirects.length, 0);
});

test("reports a self-signed TLS certificate as a diagnostic", async () => {
  const error = new Error("untrusted certificate");
  error.code = "DEPTH_ZERO_SELF_SIGNED_CERT";
  const result = await checkPublicUrl("https://example.com/", {
    lookup: async () => [{ address: "8.8.8.8", family: 4 }],
    headRequest: async () => { throw error; },
  });

  assert.equal(result.performed, false);
  assert.ok(result.flags.some((flag) => flag.code === "self_signed_certificate" && flag.points === 35));
});

test("revalidates each redirect destination against private IPs", async () => {
  const result = await checkPublicUrl("https://example.com/", {
    lookup: async (hostname) => hostname === "localhost"
      ? [{ address: "127.0.0.1", family: 4 }]
      : [{ address: "8.8.8.8", family: 4 }],
    headRequest: async () => ({ statusCode: 302, location: "http://localhost/admin" }),
  });

  assert.equal(result.performed, false);
  assert.match(result.error, /private or reserved/);
});
