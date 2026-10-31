const dns = require("node:dns").promises;
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const { resolvePublicAddress } = require("./network-check");
const { getRegistrableDomain } = require("./analyzer");

const PAGE_TIMEOUT_MS = 2500;
const MAX_HTML_BYTES = 512 * 1024;
const MAX_REDIRECTS = 3;
const TARGET_BRANDS = ["amazon", "apple", "bankofamerica", "chase", "facebook", "github", "google", "hdfc", "hsbc", "icici", "instagram", "microsoft", "netflix", "paypal", "sbi", "wellsfargo", "whatsapp"];
const EPHEMERAL_HOSTING = [
  "ngrok-free.app", "trycloudflare.com", "pages.dev", "vercel.app",
  "web.app", "surge.sh", "netlify.app", "workers.dev",
];

function withTimeout(promise, timeoutMs) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("DNS lookup timed out.")), timeoutMs);
    }),
  ]).finally(() => clearTimeout(timer));
}

function requestHtml(url, address, timeoutMs) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === "https:" ? https : http;
    const plainHostname = url.hostname.replace(/^\[|\]$/g, "");
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      callback(value);
    };

    const request = transport.request(url, {
      method: "GET",
      headers: {
        "User-Agent": "ClearSignal-Safe-Inspector/1.0",
        Accept: "text/html,application/xhtml+xml;q=0.9",
        "Accept-Encoding": "identity",
      },
      lookup: (_hostname, options, callback) => {
        if (options && options.all) callback(null, [{ address: address.address, family: address.family }]);
        else callback(null, address.address, address.family);
      },
      servername: net.isIP(plainHostname) ? undefined : plainHostname,
      rejectUnauthorized: true,
    }, (response) => {
      const chunks = [];
      let totalBytes = 0;
      response.on("data", (chunk) => {
        if (settled) return;
        const remaining = MAX_HTML_BYTES - totalBytes;
        if (remaining > 0) {
          const portion = chunk.subarray(0, remaining);
          chunks.push(portion);
          totalBytes += portion.length;
        }
        if (totalBytes >= MAX_HTML_BYTES) {
          response.destroy();
          finish(resolve, {
            statusCode: response.statusCode || 0,
            location: response.headers.location || null,
            contentType: response.headers["content-type"] || "",
            body: Buffer.concat(chunks).toString("utf8"),
            truncated: true,
          });
        }
      });
      response.on("end", () => finish(resolve, {
        statusCode: response.statusCode || 0,
        location: response.headers.location || null,
        contentType: response.headers["content-type"] || "",
        body: Buffer.concat(chunks).toString("utf8"),
        truncated: false,
      }));
      response.on("error", (error) => finish(reject, error));
    });

    const deadline = setTimeout(() => request.destroy(new Error("HTML fetch timed out.")), timeoutMs);
    request.setTimeout(timeoutMs, () => request.destroy(new Error("HTML fetch timed out.")));
    request.on("error", (error) => finish(reject, error));
    request.end();
  });
}

async function fetchPublicHtml(input, options = {}) {
  const startedAt = Date.now();
  const lookup = options.lookup || dns.lookup;
  const getHtml = options.getHtml || requestHtml;
  const timeoutMs = options.timeoutMs || PAGE_TIMEOUT_MS;
  let url;
  let redirects = 0;

  try {
    url = new URL(input);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
      throw new Error("HTML inspection supports public HTTP(S) URLs without embedded credentials.");
    }
    while (true) {
      const timeLeft = timeoutMs - (Date.now() - startedAt);
      if (timeLeft <= 0) throw new Error("HTML fetch timed out.");
      const address = await resolvePublicAddress(url.hostname, lookup, timeLeft);
      const response = await getHtml(url, address, timeLeft);
      if (![301, 302, 303, 307, 308].includes(response.statusCode) || !response.location) {
        return { ...response, finalUrl: url.toString(), redirects };
      }
      if (redirects >= MAX_REDIRECTS) throw new Error("HTML fetch exceeded the redirect limit.");
      const redirectedUrl = new URL(response.location, url);
      if (!["http:", "https:"].includes(redirectedUrl.protocol) || redirectedUrl.username || redirectedUrl.password) {
        throw new Error("HTML redirect uses an unsupported URL.");
      }
      url = redirectedUrl;
      redirects += 1;
    }
  } catch (error) {
    return { error: error.message, finalUrl: url?.toString() || "", redirects };
  }
}

function parseAttributes(tag) {
  const attributes = {};
  const pattern = /([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;
  let match;
  while ((match = pattern.exec(tag))) {
    attributes[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? "";
  }
  return attributes;
}

function analyzeHtml(html, pageUrl) {
  const diagnostics = [];
  const add = (code, severity, issue, penalty, detail) => {
    diagnostics.push({ code, category: "Page Content", severity, issue, penalty, detail });
  };
  const base = new URL(pageUrl);
  const pageDomain = getRegistrableDomain(base.hostname);

  for (const match of html.matchAll(/<iframe\b[^>]*>/gi)) {
    const tag = match[0];
    const attrs = parseAttributes(tag);
    const style = (attrs.style || "").replace(/\s/g, "").toLowerCase();
    const isHidden = "hidden" in attrs ||
      /display:none|visibility:hidden|opacity:0/.test(style) ||
      attrs.width === "0" || attrs.height === "0";
    if (isHidden) {
      add("hidden_iframe", "HIGH", "Hidden iframe detected", 18, "The page contains an iframe hidden with CSS or zero dimensions.");
      break;
    }
  }

  if (/<[^>]+\boncontextmenu\s*=/i.test(html) ||
      /addEventListener\s*\(\s*['"]contextmenu['"][\s\S]{0,300}?preventDefault\s*\(/i.test(html) ||
      /oncontextmenu\s*=\s*['"][^'"]*return\s+false/i.test(html)) {
    add("disabled_context_menu", "LOW", "Right-click menu is disabled", 5, "Scripts or handlers appear to disable the browser context menu.");
  }

  const forms = [...html.matchAll(/<form\b[^>]*>[\s\S]*?<\/form\s*>/gi)];
  for (const formMatch of forms) {
    const formTag = formMatch[0].match(/^<form\b[^>]*>/i)?.[0] || "";
    const formAttrs = parseAttributes(formTag);
    const passwordInput = /<input\b[^>]*\btype\s*=\s*(?:"password"|'password'|password\b)[^>]*>/i.test(formMatch[0]);
    if (!passwordInput) continue;

    const action = formAttrs.action || pageUrl;
    try {
      const actionUrl = new URL(action, pageUrl);
      if (actionUrl.protocol !== "https:") {
        add("password_form_http", "CRITICAL", "Password form submits over HTTP", 35, "A password form submits to an unencrypted HTTP address.");
      }
      if (getRegistrableDomain(actionUrl.hostname) !== pageDomain) {
        add("password_form_external", "CRITICAL", "Password form submits to another domain", 35, `A password form submits to ${actionUrl.hostname}, outside the page's registered domain.`);
      }
    } catch {
      add("password_form_invalid_action", "HIGH", "Password form has an invalid destination", 20, "A password form's destination could not be safely interpreted.");
    }
  }

  const title = html.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i)?.[1]
    ?.replace(/<[^>]+>/g, " ")
    .replace(/&(?:amp|lt|gt|quot|#39);/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase() || "";
  const faviconMatches = [...html.matchAll(/<link\b[^>]*>/gi)]
    .map((match) => parseAttributes(match[0]))
    .filter((attrs) => /icon/i.test(attrs.rel || ""))
    .map((attrs) => `${attrs.href || ""} ${attrs.title || ""}`.toLowerCase());
  const brandingText = `${title} ${faviconMatches.join(" ")}`;
  const brand = TARGET_BRANDS.find((name) =>
    brandingText.includes(name) && !pageDomain.includes(name)
  );
  if (brand) {
    add("branding_domain_mismatch", "CRITICAL", "Zero-day brand clone detected", 45, `The page title or favicon references “${brand}”, but the registered domain is “${pageDomain}”. This can indicate a previously unreported impersonation page.`);
  }

  return { diagnostics, title: title || null };
}

function inspectHostname(hostname) {
  const domain = getRegistrableDomain(hostname).toLowerCase();
  const host = hostname.toLowerCase();
  const suffix = EPHEMERAL_HOSTING.find((item) => host === item || host.endsWith(`.${item}`));
  if (!suffix) return [];
  return [{
    code: "ephemeral_hosting",
    category: "Hosting",
    severity: "HIGH",
    issue: "Hosted on an ephemeral or shared deployment platform",
    penalty: 20,
    detail: `The address uses ${suffix}, a shared platform that can host legitimate projects as well as short-lived phishing pages. Hosting alone does not prove malicious intent.`,
  }];
}

async function checkDomainAge(hostname, options = {}) {
  const domain = getRegistrableDomain(hostname).toLowerCase();
  const resolver = options.fetch || fetch;
  if (!/^[a-z0-9.-]{1,253}$/.test(domain) || !domain.includes(".")) {
    return { performed: false, error: "Domain name is not eligible for an RDAP lookup." };
  }
  try {
    const response = await resolver(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: "application/rdap+json, application/json" },
      signal: AbortSignal.timeout(options.timeoutMs || 1800),
      redirect: "error",
    });
    if (!response.ok) return { performed: false, error: `RDAP returned HTTP ${response.status}.` };
    const record = await response.json();
    const event = (record.events || []).find((item) =>
      /registration|registered/i.test(item.eventAction || "")
    );
    if (!event?.eventDate) return { performed: false, error: "RDAP did not provide a registration date." };
    const createdAt = Date.parse(event.eventDate);
    if (!Number.isFinite(createdAt)) return { performed: false, error: "RDAP returned an invalid registration date." };
    const ageDays = Math.max(0, Math.floor((Date.now() - createdAt) / 86400000));
    return { performed: true, domain, createdAt: new Date(createdAt).toISOString(), ageDays };
  } catch {
    return { performed: false, error: "RDAP lookup unavailable or timed out." };
  }
}

async function inspectDns(hostname, options = {}) {
  const resolver = options.resolver || dns;
  const timeoutMs = options.timeoutMs || 1800;
  const diagnostics = [];
  const query = (promise) => withTimeout(promise, timeoutMs);
  const domain = getRegistrableDomain(hostname);

  try {
    const mx = await query(resolver.resolveMx(domain));
    if (!mx.length) diagnostics.push({
      code: "missing_mx",
      category: "DNS",
      severity: "INFO",
      issue: "No mail exchanger record found",
      penalty: 0,
      detail: "No MX record was found for this domain. Many legitimate websites do not receive email.",
    });
  } catch (error) {
    if (error.code === "ENODATA" || error.code === "ENOTFOUND") diagnostics.push({
      code: "missing_mx",
      category: "DNS",
      severity: "INFO",
      issue: "No mail exchanger record found",
      penalty: 0,
      detail: "No MX record was found for this domain. Many legitimate websites do not receive email.",
    });
  }

  let txtRecords = [];
  try {
    txtRecords = await query(resolver.resolveTxt(domain));
  } catch (error) {
    if (error.code === "ENODATA" || error.code === "ENOTFOUND") txtRecords = [];
  }
  if (!txtRecords.some((record) => record.join("").toLowerCase().startsWith("v=spf1"))) {
    diagnostics.push({
      code: "missing_spf",
      category: "DNS",
      severity: "INFO",
      issue: "No SPF policy found",
      penalty: 0,
      detail: "No SPF TXT record was found. This is an email-security signal, not proof that the website is malicious.",
    });
  }

  try {
    const dmarc = await query(resolver.resolveTxt(`_dmarc.${domain}`));
    if (!dmarc.some((record) => record.join("").toLowerCase().startsWith("v=dmarc1"))) {
      diagnostics.push({
        code: "missing_dmarc",
        category: "DNS",
        severity: "INFO",
        issue: "No DMARC policy found",
        penalty: 0,
        detail: "No DMARC policy was found. This email-security signal does not establish that the website is malicious.",
      });
    }
  } catch (error) {
    if (error.code === "ENODATA" || error.code === "ENOTFOUND") diagnostics.push({
      code: "missing_dmarc",
      category: "DNS",
      severity: "INFO",
      issue: "No DMARC policy found",
      penalty: 0,
      detail: "No DMARC policy was found. This email-security signal does not establish that the website is malicious.",
    });
  }
  return diagnostics;
}

module.exports = { analyzeHtml, checkDomainAge, fetchPublicHtml, inspectDns, inspectHostname, MAX_HTML_BYTES };
