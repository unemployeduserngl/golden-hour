const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const net = require("node:net");
const { scanUrl } = require("./src/scanner");
const { createBlocklist } = require("./src/blocklist");
const { buildLocalHelpReply } = require("./src/help-assistant");

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "127.0.0.1";
const PUBLIC_DIR = path.join(__dirname, "public");
const FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";
const FEED_TTL_MS = 15 * 60 * 1000;
const MAX_BODY_BYTES = 4096;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const ALLOWED_EXTENSION_ID = process.env.ALLOWED_EXTENSION_ID || "";
const CONFIGURED_HOST = HOST.replace(/^\[|\]$/g, "").toLowerCase();
const HOST_IS_LOOPBACK = CONFIGURED_HOST === "localhost" ||
  CONFIGURED_HOST === "::1" ||
  (net.isIPv4(CONFIGURED_HOST) && CONFIGURED_HOST.startsWith("127."));

const feedState = {
  urls: new Set(),
  available: false,
  updatedAt: null,
  attemptedAt: 0,
  error: null,
};
let feedRefresh = null;

async function refreshFeed() {
  if (feedRefresh) return feedRefresh;
  if (Date.now() - feedState.attemptedAt < FEED_TTL_MS) return;

  feedState.attemptedAt = Date.now();
  feedRefresh = (async () => {
    try {
      const response = await fetch(FEED_URL, { signal: AbortSignal.timeout(6000) });
      if (!response.ok) throw new Error(`OpenPhish returned HTTP ${response.status}`);
      const body = await response.text();
      const urls = new Set(
        body
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter((line) => /^https?:\/\//i.test(line))
          .map((line) => {
            try {
              const parsed = new URL(line);
              parsed.hash = "";
              parsed.hostname = parsed.hostname.toLowerCase();
              return parsed.toString();
            } catch {
              return null;
            }
          })
          .filter(Boolean),
      );
      if (urls.size === 0) throw new Error("OpenPhish returned an empty feed.");
      feedState.urls = urls;
      feedState.available = true;
      feedState.updatedAt = new Date().toISOString();
      feedState.error = null;
    } catch (error) {
      feedState.error = error.message;
      if (!feedState.available) console.warn(`OpenPhish feed unavailable: ${error.message}`);
    } finally {
      feedRefresh = null;
    }
  })();
  return feedRefresh;
}

function publicFeedStatus(source = feedState) {
  return {
    available: source.available,
    updatedAt: source.updatedAt,
    message: source.available
      ? "OpenPhish community feed"
      : "OpenPhish feed unavailable; URL heuristics remain active.",
  };
}

function sendJson(response, status, payload) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-origin",
  });
  response.end(JSON.stringify(payload));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    let tooLarge = false;
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      if (!tooLarge) {
        body += chunk;
        if (Buffer.byteLength(body) > MAX_BODY_BYTES) {
          tooLarge = true;
          body = "";
        }
      }
    });
    request.on("end", () => {
      if (tooLarge) {
        reject(Object.assign(new Error("Request body is too large."), { status: 413 }));
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(Object.assign(new Error("Request body must be valid JSON."), { status: 400 }));
      }
    });
    request.on("error", reject);
  });
}

const CONTENT_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
};

function serveStatic(request, response, pathname) {
  let requestedPath;
  try {
    requestedPath = decodeURIComponent(pathname);
  } catch {
    sendJson(response, 400, { error: "Invalid URL path." });
    return;
  }

  const relativePath = requestedPath === "/" ? "index.html" : requestedPath.replace(/^\/+/, "");
  const filePath = path.resolve(PUBLIC_DIR, relativePath);
  if (!filePath.startsWith(`${PUBLIC_DIR}${path.sep}`)) {
    sendJson(response, 404, { error: "Not found." });
    return;
  }

  fs.readFile(filePath, (error, contents) => {
    if (error) {
      sendJson(response, 404, { error: "Not found." });
      return;
    }
    response.writeHead(200, {
      "Content-Type": CONTENT_TYPES[path.extname(filePath)] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Content-Security-Policy": "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
      "Referrer-Policy": "no-referrer",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
      "Cross-Origin-Resource-Policy": "same-origin",
    });
    response.end(contents);
  });
}

function createServer(options = {}) {
  const blocklist = options.blocklist || createBlocklist();
  const serverFeed = options.feed || feedState;
  const extensionId = options.extensionId ?? ALLOWED_EXTENSION_ID;
  const requestCounts = new Map();
  const allowedLocalHosts = new Set(["localhost", "127.0.0.1", "::1"]);
  if (HOST_IS_LOOPBACK) {
    allowedLocalHosts.add(CONFIGURED_HOST);
  }
  const server = http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url, "http://localhost");
    const pathname = requestUrl.pathname;
    let requestHostname;
    try {
      requestHostname = new URL(`http://${request.headers.host}`).hostname.replace(/^\[|\]$/g, "").toLowerCase();
    } catch {
      sendJson(response, 421, { error: "Request rejected." });
      return;
    }
    if (!allowedLocalHosts.has(requestHostname)) {
      sendJson(response, 421, { error: "Request rejected." });
      return;
    }
    const origin = request.headers.origin;
    if (origin) {
      let originHost;
      try {
        originHost = new URL(origin).host;
      } catch {
        sendJson(response, 403, { error: "Request rejected." });
        return;
      }
      const extensionOriginAllowed = /^chrome-extension:\/\/[a-p]{32}$/i.test(origin) &&
        extensionId && origin === `chrome-extension://${extensionId}`;
      if (originHost.toLowerCase() !== request.headers.host.toLowerCase() && !extensionOriginAllowed) {
        sendJson(response, 403, { error: "Request rejected." });
        return;
      }
      if (extensionOriginAllowed || originHost.toLowerCase() === request.headers.host.toLowerCase()) {
        response.setHeader("Access-Control-Allow-Origin", origin);
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");
        response.setHeader("Vary", "Origin");
      }
    }

    if (request.method === "OPTIONS" &&
        (pathname === "/api/scan" || pathname === "/api/analyze" || pathname === "/api/chat")) {
      if (!origin || !response.hasHeader("Access-Control-Allow-Origin")) {
        sendJson(response, 403, { error: "Request rejected." });
        return;
      }
      response.writeHead(204, {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "600",
        "Vary": "Origin",
        "X-Content-Type-Options": "nosniff",
      });
      response.end();
      return;
    }

    const now = Date.now();
    for (const [ip, record] of requestCounts) {
      if (now - record.startedAt >= RATE_LIMIT_WINDOW_MS) requestCounts.delete(ip);
    }
    const ip = request.socket.remoteAddress || "unknown";
    let count = requestCounts.get(ip);
    if (!count || now - count.startedAt >= RATE_LIMIT_WINDOW_MS) {
      count = { startedAt: now, requests: 0 };
      requestCounts.set(ip, count);
    }

    if (request.method === "GET" && pathname === "/api/health") {
      sendJson(response, 200, {
        ok: true,
        feed: publicFeedStatus(serverFeed),
        chatAvailable: true,
      });
      return;
    }

    if (request.method === "GET" && pathname === "/api/blocklist") {
      sendJson(response, 200, { entries: blocklist.list() });
      return;
    }

    if (request.method === "GET" && pathname === "/api/blocklist/hosts") {
      response.writeHead(200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=\"clearsignal-blocklist-hosts.txt\"",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
      });
      response.end(blocklist.hostsFile());
      return;
    }

    if (request.method === "POST" && pathname === "/api/chat") {
      count.requests += 1;
      if (count.requests > RATE_LIMIT_MAX_REQUESTS) {
        sendJson(response, 429, { error: "Too many requests. Wait a minute and try again." });
        return;
      }
      try {
        if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] || "")) {
          sendJson(response, 415, { error: "Send a JSON request." });
          return;
        }
        const body = await readJson(request);
        const keys = body && typeof body === "object" && !Array.isArray(body) ? Object.keys(body) : [];
        const validMessages = Array.isArray(body?.messages) &&
          body.messages.length > 0 &&
          body.messages.length <= 6 &&
          body.messages.every((message) =>
            message && typeof message === "object" && !Array.isArray(message) &&
            ["user", "assistant"].includes(message.role) &&
            typeof message.content === "string" &&
            message.content.trim().length > 0 &&
            message.content.length <= 600
          ) &&
          body.messages[body.messages.length - 1].role === "user" &&
          body.messages.reduce((total, message) => total + message.content.length, 0) <= 3000;
        if (keys.length !== 1 || keys[0] !== "messages" || !validMessages) {
          sendJson(response, 400, { error: "Send up to six recent chat messages, ending with your question." });
          return;
        }
        const reply = buildLocalHelpReply(body.messages);
        sendJson(response, 200, { reply });
      } catch (error) {
        const status = error.status || (error.name === "TimeoutError" ? 504 : 502);
        sendJson(response, status, {
          error: status === 413 ? "Request body is too large." :
            status === 504 ? "The assistant timed out. Try again." :
              error.status ? error.message : "The assistant could not reply. Try again.",
        });
      }
      return;
    }

    if (request.method === "POST" && ["/api/analyze", "/api/scan"].includes(pathname)) {
      count.requests += 1;
      if (count.requests > RATE_LIMIT_MAX_REQUESTS) {
        sendJson(response, 429, { error: "Too many checks. Wait a minute and try again." });
        return;
      }
      try {
        if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] || "")) {
          sendJson(response, 415, { error: "Send a JSON request." });
          return;
        }
        const body = await readJson(request);
        if (!body || typeof body !== "object" || Array.isArray(body) ||
            Object.keys(body).some((key) => !["url", "checkNetwork"].includes(key)) ||
            typeof body.url !== "string" ||
            (body.checkNetwork !== undefined && typeof body.checkNetwork !== "boolean")) {
          sendJson(response, 400, { error: "Invalid request. Provide a URL and optional boolean checkNetwork." });
          return;
        }
        if (!options.feed) await refreshFeed();
        const result = await scanUrl(body.url, {
          feed: serverFeed,
          blocklist,
          checkNetwork: body.checkNetwork === true,
        });
        result.feed = publicFeedStatus(serverFeed);
        if (pathname === "/api/scan") {
          sendJson(response, 200, {
            url: result.normalizedUrl,
            score: result.overall_score,
            verdict: result.verdict === "BLOCKED - MALICIOUS"
              ? "BLOCKED"
              : result.verdict,
            reasons: result.diagnostics.map((diagnostic) =>
              `${diagnostic.category}: ${diagnostic.issue} (${diagnostic.penalty})`
            ),
            diagnostics: result.diagnostics,
            action_taken: result.action_taken,
            tls: result.networkCheck.tls || null,
            domain_age: result.domainAge,
            redirects: result.networkCheck.redirects || 0,
          });
          return;
        }
        sendJson(response, 200, result);
      } catch (error) {
        const status = error.status || (error instanceof TypeError ? 400 : 500);
        if (status >= 500) console.error("URL analysis failed.");
        sendJson(response, status, {
          error: status === 413 ? "Request body is too large." :
            status === 400 ? "Invalid request. Enter a valid HTTP(S) URL." :
              "The analysis request could not be completed.",
        });
      }
      return;
    }

    if (request.method === "GET" && !pathname.startsWith("/api/")) {
      serveStatic(request, response, pathname);
      return;
    }

    sendJson(response, 404, { error: "Not found." });
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 12_000;
  server.keepAliveTimeout = 5_000;
  return server;
}

if (require.main === module) {
  if (!HOST_IS_LOOPBACK) {
    throw new Error("ClearSignal only binds to loopback addresses.");
  }
  const server = createServer();
  server.listen(PORT, HOST, () => {
    console.log(`ClearSignal is running at http://${HOST}:${PORT}`);
    void refreshFeed();
  });
}

module.exports = { createServer };
