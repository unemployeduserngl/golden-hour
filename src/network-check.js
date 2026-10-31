const dns = require("node:dns").promises;
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const { getRegistrableDomain } = require("./analyzer");

const MAX_REDIRECTS = 3;
const DEFAULT_TIMEOUT_MS = 5000;

function isPublicAddress(address) {
  const version = net.isIP(address);
  if (version === 4) {
    const octets = address.split(".").map(Number);
    const [first, second] = octets;
    if (
      first === 0 || first === 10 || first === 127 || first >= 224 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && (second === 0 || second === 168)) ||
      (first === 198 && (second === 18 || second === 19 || second === 51)) ||
      (first === 203 && second === 0)
    ) return false;
    return true;
  }

  if (version === 6) {
    const normalized = address.toLowerCase();
    if (normalized.includes(".")) return false;
    const segments = normalized.split(":");
    const firstHextet = Number.parseInt(segments[0] || "0", 16);
    const secondHextet = Number.parseInt(segments[1] || "0", 16);
    return firstHextet >= 0x2000 && firstHextet <= 0x3fff &&
      !(firstHextet === 0x2001 && secondHextet <= 0x01ff) &&
      !(firstHextet === 0x2001 && secondHextet === 0x0db8) &&
      !(firstHextet === 0x3fff && secondHextet <= 0x000f) &&
      firstHextet !== 0x2002;
  }

  return false;
}

function withTimeout(promise, timeoutMs, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    }),
  ]).finally(() => clearTimeout(timer));
}

async function resolvePublicAddress(hostname, lookup = dns.lookup, timeoutMs = 2000) {
  const plainHostname = hostname.replace(/^\[|\]$/g, "");
  const version = net.isIP(plainHostname);
  if (version) {
    if (!isPublicAddress(plainHostname)) throw new Error("Network checks are blocked for private or reserved IP addresses.");
    return { address: plainHostname, family: version };
  }

  const addresses = await withTimeout(
    lookup(plainHostname, { all: true, verbatim: true }),
    Math.min(2000, timeoutMs),
    "DNS lookup timed out.",
  );
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new Error("Network checks require a hostname resolving only to public IP addresses; private or reserved results are blocked.");
  }
  return addresses[0];
}

function requestHead(url, address, timeoutMs) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === "https:" ? https : http;
    const plainHostname = url.hostname.replace(/^\[|\]$/g, "");
    const request = transport.request(url, {
      method: "HEAD",
      headers: { "User-Agent": "ClearSignal-Link-Checker/1.0", Accept: "*/*" },
      lookup: (_hostname, options, callback) => {
        if (options && options.all) {
          callback(null, [{ address: address.address, family: address.family }]);
        } else {
          callback(null, address.address, address.family);
        }
      },
      servername: net.isIP(plainHostname) ? undefined : plainHostname,
      rejectUnauthorized: true,
    }, (response) => {
      response.resume();
      const peerCertificate = url.protocol === "https:" &&
        typeof response.socket.getPeerCertificate === "function"
        ? response.socket.getPeerCertificate()
        : {};
      const validFrom = peerCertificate.valid_from || null;
      const validTo = peerCertificate.valid_to || null;
      const issuer = peerCertificate.issuer ? Object.values(peerCertificate.issuer).join(", ") : null;
      resolve({
        statusCode: response.statusCode || 0,
        location: response.headers.location || null,
        tls: url.protocol === "https:" ? {
          issuer,
          validFrom,
          validTo,
          ageDays: validFrom ? Math.max(0, Math.floor((Date.now() - Date.parse(validFrom)) / 86400000)) : null,
          daysUntilExpiry: validTo ? Math.floor((Date.parse(validTo) - Date.now()) / 86400000) : null,
          subject: peerCertificate.subject?.CN || null,
        } : null,
      });
    });

    request.setTimeout(timeoutMs, () => request.destroy(new Error("Connection timed out.")));
    request.on("error", reject);
    request.end();
  });
}

async function checkPublicUrl(input, options = {}) {
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const lookup = options.lookup || dns.lookup;
  const headRequest = options.headRequest || requestHead;
  let currentUrl;

  try {
    currentUrl = new URL(input);
  } catch {
    return { performed: false, error: "A valid absolute URL is required for a live network check.", redirects: 0, flags: [] };
  }

  if (!["http:", "https:"].includes(currentUrl.protocol) || currentUrl.username || currentUrl.password) {
    return { performed: false, error: "Live checks support HTTP(S) addresses without embedded credentials.", redirects: 0, flags: [] };
  }

  const startedAt = Date.now();
  let redirects = 0;
  let finalStatusCode = null;
  let tlsVerified = false;
  let tls = null;
  const crossDomainRedirects = [];

  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      const timeLeft = timeoutMs - (Date.now() - startedAt);
      if (timeLeft <= 0) throw new Error("Live network check timed out.");
      const address = await resolvePublicAddress(currentUrl.hostname, lookup, timeLeft);
      const responseTimeLeft = timeoutMs - (Date.now() - startedAt);
      if (responseTimeLeft <= 0) throw new Error("Live network check timed out.");
      const response = await headRequest(currentUrl, address, responseTimeLeft);
      finalStatusCode = response.statusCode;
      if (currentUrl.protocol === "https:") {
        tlsVerified = true;
        tls = response.tls || null;
      }

      if (![301, 302, 303, 307, 308].includes(response.statusCode) || !response.location) break;
      if (hop === MAX_REDIRECTS) throw new Error(`The URL redirected more than ${MAX_REDIRECTS} times.`);

      const nextUrl = new URL(response.location, currentUrl);
      if (!["http:", "https:"].includes(nextUrl.protocol) || nextUrl.username || nextUrl.password) {
        throw new Error("The redirect points to an unsupported or credential-containing URL.");
      }
      redirects += 1;
      if (getRegistrableDomain(nextUrl.hostname) !== getRegistrableDomain(currentUrl.hostname)) {
        crossDomainRedirects.push({
          from: currentUrl.hostname,
          to: nextUrl.hostname,
        });
      }
      currentUrl = nextUrl;
    }

    const flags = [];
    if (currentUrl.protocol !== "https:") {
      flags.push({
        code: "network_https_unavailable",
        severity: "medium",
        points: 10,
        title: "Final page does not use HTTPS",
        detail: "The live check ended on an HTTP address, so the connection is not encrypted.",
      });
    } else {
      flags.push({
        code: "network_tls_verified",
        severity: "info",
        points: 0,
        title: "HTTPS certificate verified",
        detail: "The final HTTPS connection presented a certificate accepted by the system trust store. This does not prove the site is legitimate.",
      });
    }
    if (redirects >= 3) {
      flags.push({
        code: "many_redirects",
        severity: "medium",
        points: 10,
        title: "Several redirects before reaching the page",
        detail: `The live check followed ${redirects} redirects. Long redirect chains can obscure a link's destination.`,
      });
    }
    if (crossDomainRedirects.length > 0) {
      flags.push({
        code: "cross_domain_redirect",
        severity: "medium",
        points: 12,
        title: "Redirect crosses to another domain",
        detail: `The address redirected to ${crossDomainRedirects.map((redirect) => redirect.to).join(", ")}, which is a different hostname from the submitted address.`,
      });
    }
    if (tls?.daysUntilExpiry !== null && tls?.daysUntilExpiry <= 0) {
      flags.push({
        code: "tls_certificate_expired",
        severity: "high",
        points: 35,
        title: "HTTPS certificate is expired",
        detail: "The HTTPS certificate validity period has ended.",
      });
    }
    return {
      performed: true,
      redirects,
      finalUrl: currentUrl.toString(),
      finalStatusCode,
      tlsVerified: tlsVerified && currentUrl.protocol === "https:",
      tls,
      crossDomainRedirects,
      flags,
    };
  } catch (error) {
    const flags = [];
    if (["DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN"].includes(error.code)) {
      flags.push({
        code: "self_signed_certificate",
        severity: "critical",
        points: 35,
        title: "Self-signed HTTPS certificate",
        detail: "The server presented a certificate that is not trusted by the system certificate store.",
      });
    }
    if (error.code === "CERT_HAS_EXPIRED") {
      flags.push({
        code: "tls_certificate_expired",
        severity: "critical",
        points: 35,
        title: "HTTPS certificate is expired",
        detail: "The server's TLS certificate has expired and cannot be trusted for a secure connection.",
      });
    }
    if (error.code === "ERR_TLS_CERT_ALTNAME_INVALID") {
      flags.push({
        code: "tls_certificate_name_mismatch",
        severity: "critical",
        points: 35,
        title: "HTTPS certificate name mismatch",
        detail: "The HTTPS certificate is not valid for the hostname being checked.",
      });
    }
    if (error.message.startsWith("The URL redirected more than")) {
      flags.push({
        code: "many_redirects",
        severity: "medium",
        points: 10,
        title: "Too many redirects",
        detail: `The address redirected more than ${MAX_REDIRECTS} times, so the final destination could not be verified.`,
      });
    }
    flags.push({
      code: "network_check_failed",
      severity: "info",
      points: 0,
      title: "Live network check could not complete",
      detail: `${error.message} This is not by itself evidence that the site is malicious.`,
    });
    return {
      performed: false,
      error: error.message,
      redirects,
      flags,
    };
  }
}

module.exports = { checkPublicUrl, isPublicAddress, resolvePublicAddress };
