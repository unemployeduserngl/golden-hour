const net = require("node:net");

const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/g;

function decodeRepeatedly(value, rounds = 4) {
  let decoded = value;
  for (let index = 0; index < rounds; index += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded;
}

function canonicalizeUrl(input) {
  if (typeof input !== "string" || input.length === 0 || input.length > 2048) {
    throw new TypeError("Enter a URL between 1 and 2,048 characters.");
  }

  const cleaned = input.trim().replace(ZERO_WIDTH, "");
  const decoded = decodeRepeatedly(cleaned).replace(ZERO_WIDTH, "");
  const hasScheme = /^[a-z][a-z\d+.-]*:/i.test(decoded);
  const hasWebScheme = /^https?:\/\//i.test(decoded);
  if (hasScheme && !hasWebScheme && !/^[\w.-]+:\d+(?:[/?#]|$)/.test(decoded)) {
    throw new TypeError("Only HTTP and HTTPS website addresses can be checked.");
  }
  const candidate = hasWebScheme ? decoded : `https://${decoded}`;
  let url;
  try {
    url = new URL(candidate);
  } catch {
    throw new TypeError("That does not look like a valid website address.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new TypeError("Only HTTP and HTTPS website addresses can be checked.");
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!hostname || (!hostname.includes(".") && !net.isIP(hostname))) {
    throw new TypeError("Enter a complete website address, such as example.com.");
  }

  const authority = candidate.match(/^[a-z][a-z\d+.-]*:\/\/([^/?#]*)/i)?.[1] || "";
  const rawHost = authority.slice(authority.lastIndexOf("@") + 1)
    .replace(/^\[|\]$/g, "")
    .replace(/:\d+$/, "")
    .toLowerCase();
  url.hash = "";
  url.hostname = hostname;
  return {
    cleaned,
    decoded,
    url,
    hostname,
    normalizedUrl: url.toString(),
    nonCanonicalIp: Boolean(net.isIP(hostname) && rawHost && rawHost !== hostname),
    decodingChangedInput: decoded !== cleaned,
    encodedSequences: (cleaned.match(/%[0-9a-f]{2}/gi) || []).length,
    encodedAuthority: /^(?:https?:\/\/)?[^/?#]*%[0-9a-f]{2}/i.test(cleaned),
    nestedEncoding: /%25(?:25)?(?:2f|3a|40|2e)/i.test(cleaned),
  };
}

module.exports = { canonicalizeUrl, decodeRepeatedly };
