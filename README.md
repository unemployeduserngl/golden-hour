# ClearSignal — Look-Alike Website Detector

ClearSignal is a dependency-free Node.js 20+ localhost app for explaining URL and optional live-site warning signals. It does not execute target JavaScript.

## Run locally

```powershell
cd C:\golden\golden-hour
npm start
```

Open [http://localhost:3000](http://localhost:3000). Run the tests with `npm test`. The server binds to `127.0.0.1` by default. `HOST` may be set to another loopback address, and `PORT` can be changed.

## Detection modules

- `src/url-normalizer.js` removes zero-width characters, recursively decodes up to four encoding layers for analysis, and relies on WHATWG URL parsing to canonicalize integer/octal IPv4 forms and IDNs.
- `src/analyzer.js` checks OpenPhish, brand look-alikes, Punycode, raw IP hosts, entropy, suspicious TLDs, excessive subdomains/hyphens, sensitive words, and URL encoding.
- `src/network-check.js` optionally performs public-only DNS-pinned HTTPS/HEAD probes, checks TLS certificate issuer and validity, detects redirect chains, and blocks private/reserved destinations at every hop.
- `src/live-inspection.js` optionally fetches at most 512 KiB of HTML with a 2.5-second timeout and a non-executing inspection for hidden iframes, disabled context menus, password forms, and mismatched branding. It also checks for shared/ephemeral hosting, performs a bounded RDAP domain-age lookup, and reports DNS MX/SPF/DMARC observations as informational only.
- `src/scanner.js` combines checks into `overall_score`, `verdict`, `action_taken`, and categorized `diagnostics`.
- `src/blocklist.js` persists a local JSON blocklist at `data/blocklist.json`. Scores of 70 or higher add the registered domain to it. `/api/blocklist` lists entries and `/api/blocklist/hosts` downloads a hosts-file ruleset for manual review.

The app does **not** modify the OS hosts file, browser settings, firewall, or network. A localhost web app cannot transparently block a user's browsing; the downloadable rules require deliberate installation, and should be reviewed before use. Domains already in this app's local blocklist are marked blocked by subsequent scans. Remove an entry manually from `data/blocklist.json` to undo that local action.

Live page inspection is off by default in the web UI. Check the consent box before use: the server contacts the entered public site, follows at most three redirects, and fetches a bounded HTML response. DNS answers must all be public IPs, requests pin the connection to a checked address, credentials and non-HTTP schemes are rejected, and TLS certificates must validate. The optional scan also uses `https://rdap.org` for a bounded domain registration-age lookup. Network/registry errors are not treated as malicious by themselves. The registered-domain parser uses a small suffix list, not the full Public Suffix List.

The client uses same-origin requests; API writes validate JSON schema and `Origin`, cap request bodies, and apply per-IP rate limits. The server binds to loopback by default and sets security headers. A browser-embedded HMAC secret would be publicly extractable and would not protect this localhost app, so no fake client-side signing scheme is used. Do not expose this development service to an untrusted network without adding real authentication and deployment-specific controls.

## Local help chat

The **Need help?** chat provides basic ClearSignal navigation and safe-browsing guidance locally. It does not use a remote AI provider, browse websites, or perform scans.

## Optional Chrome, Brave, or Edge extension

The Manifest V3 extension is in `extension\`. It scans HTTP(S) link clicks before opening them, prompts on suspicious results, and installs bounded `declarativeNetRequest` main-frame rules for confirmed high-risk domains. Its `webNavigation` listener can only observe direct address-bar navigation after it starts; Manifest V3 does not let this listener cancel the initial request, so unknown direct navigations are best-effort. The extension requests broad HTTP(S) page access to inspect links; install it only if you understand and accept that permission.

1. Open the browser's extensions page (`chrome://extensions`, `brave://extensions`, or `edge://extensions`), enable **Developer mode**, choose **Load unpacked**, and select `C:\golden\golden-hour\extension`. Copy the extension ID shown by the browser.
2. Start the backend on port `5000` and allow that exact extension ID in PowerShell:

   ```powershell
   cd C:\golden\golden-hour
   $env:ALLOWED_EXTENSION_ID = "paste-the-32-character-extension-id-here"
   $env:PORT = "5000"
   npm start
   ```

   Keep this terminal open while using the extension. The extension calls `http://127.0.0.1:5000/api/scan`; the API only allows the configured extension origin. If you reload or reinstall the extension and its ID changes, restart the server with the new ID.
3. Use the popup toggle to enable/disable protection, or add/remove a trusted domain. Safe links proceed, suspicious links require confirmation, and blocked links open the ClearSignal interstitial. The session cache and per-tab five-minute allowlist survive service-worker suspension and expire automatically. DNR retains at most 4,000 blocked domains and 500 trusted domains, leaving headroom below Chrome's 5,000 dynamic-rule limit. The popup counters reflect scanner-detected blocked events; DNR does not expose production rule-match counts without its developer-only feedback permission.

The Node backend already implements an exact-extension-origin CORS allowlist. For a separate Node HTTP backend, the minimal equivalent is:

```js
const extensionId = process.env.ALLOWED_EXTENSION_ID;
const allowedOrigin = `chrome-extension://${extensionId}`;
const origin = request.headers.origin;

if (origin === allowedOrigin) {
  response.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  response.setHeader("Vary", "Origin");
}
if (request.method === "OPTIONS" && origin === allowedOrigin) {
  response.writeHead(204);
  response.end();
  return;
}
```

Do not use `Access-Control-Allow-Origin: *` for this local API. CORS is not authentication; keep the server bound to loopback and validate request data.

`/api/scan` accepts the same JSON input as `/api/analyze` and returns `url`, numeric `score`, `verdict` (`SAFE`, `SUSPICIOUS`, or `BLOCKED`), `reasons`, categorized `diagnostics`, blocklist action, TLS details, domain age, and redirect count. The extension requests live checks for each uncached URL; this contacts the public destination and RDAP service.

All scoring is heuristic and can produce false positives or miss threats. A low score does not guarantee safety. HTTPS certificates establish an encrypted connection to a host, not that the host is trustworthy. MX/SPF/DMARC absence is not evidence that a site is malicious.

## API

`POST /api/analyze` accepts:

```json
{
  "url": "https://paypa1-login.example/verify",
  "checkNetwork": false
}
```

Set `checkNetwork` to `true` only with consent to live checks. Response includes the legacy `score`, `status`, and `checks` fields as well as:

```json
{
  "overall_score": 100,
  "verdict": "BLOCKED - MALICIOUS",
  "action_taken": "Added to Active Blocklist",
  "diagnostics": [
    {
      "category": "Threat Intelligence",
      "severity": "CRITICAL",
      "issue": "Listed in the OpenPhish community feed",
      "penalty": "+100",
      "detail": "The address or hostname appears in the feed.",
      "code": "known_phishing_feed_match"
    }
  ]
}
```

Possible verdicts are `SAFE`, `SUSPICIOUS`, and `BLOCKED - MALICIOUS`. Scores from 8 to 69 are suspicious; scores of 70 or more are added to the app-local blocklist. Known threat-feed matches score 100.

## Open references

- [OpenPhish community feed](https://openphish.com/feed.txt)
- [OpenPhish](https://openphish.com/)
- [URLhaus by abuse.ch](https://urlhaus.abuse.ch/)
- [Google Safe Browsing](https://safebrowsing.google.com/)

ClearSignal is not affiliated with or endorsed by those services.
