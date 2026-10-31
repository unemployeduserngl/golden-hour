const { analyzeUrl, getRegistrableDomain } = require("./analyzer");
const { checkPublicUrl } = require("./network-check");
const { analyzeHtml, checkDomainAge, fetchPublicHtml, inspectDns, inspectHostname } = require("./live-inspection");
const { BLOCK_THRESHOLD } = require("./blocklist");

function severityForCheck(check) {
  if (check.status === "danger") return check.points >= 35 ? "CRITICAL" : "HIGH";
  if (check.points >= 15) return "MEDIUM";
  return "LOW";
}

function asDiagnostic(check) {
  const penalty = Number(check.points) || 0;
  return {
    category: check.category || "URL & Lexical",
    severity: severityForCheck(check),
    issue: check.title,
    penalty: `+${penalty}`,
    detail: check.detail,
    code: check.code || "url_signal",
  };
}

async function scanUrl(input, options = {}) {
  const blocklist = options.blocklist;
  const base = analyzeUrl(input, options.feed || { urls: new Set(), available: false });
  let score = base.score;
  const diagnostics = base.checks
    .filter((check) => check.status !== "good")
    .map(asDiagnostic);
  for (const diagnostic of inspectHostname(base.hostname)) {
    score = Math.min(100, score + diagnostic.penalty);
    diagnostics.push({ ...diagnostic, penalty: `+${diagnostic.penalty}` });
  }
  let networkCheck = { performed: false, reason: "Live inspection was not requested." };
  let pageInspection = { performed: false, reason: "Live inspection was not requested." };
  let domainAge = { performed: false, reason: "Live inspection was not requested." };

  if (options.checkNetwork === true) {
    networkCheck = await (options.checkPublicUrl || checkPublicUrl)(base.normalizedUrl);
    for (const flag of networkCheck.flags || []) {
      if (flag.points > 0) score = Math.min(100, score + flag.points);
      if (flag.severity !== "info") diagnostics.push({
        category: "SSL / Network",
        severity: flag.severity === "critical" ? "CRITICAL" : flag.severity === "high" ? "HIGH" : "MEDIUM",
        issue: flag.title,
        penalty: `+${flag.points || 0}`,
        detail: flag.detail,
        code: flag.code,
      });
    }

    if (networkCheck.performed) {
      if (networkCheck.tls?.ageDays !== null && networkCheck.tls?.ageDays !== undefined &&
          networkCheck.tls.ageDays < 3) {
        score = Math.min(100, score + 20);
        diagnostics.push({
          code: "new_tls_certificate",
          category: "SSL / Network",
          severity: "MEDIUM",
          issue: "TLS certificate was issued within the last 72 hours",
          penalty: "+20",
          detail: `The verified certificate is ${networkCheck.tls.ageDays} days old. New certificates are common for legitimate sites too; this is only one risk signal.`,
        });
      }

      domainAge = await (options.checkDomainAge || checkDomainAge)(base.hostname);
      if (domainAge.performed && domainAge.ageDays < 30) {
        score = Math.min(100, score + 35);
        diagnostics.push({
          code: "newly_registered_domain",
          category: "Domain Age",
          severity: "HIGH",
          issue: "Domain registered within the last 30 days",
          penalty: "+35",
          detail: `RDAP reports registration on ${domainAge.createdAt} (${domainAge.ageDays} days ago). Newly registered domains deserve extra scrutiny.`,
        });
      }

      const finalUrl = networkCheck.finalUrl || base.normalizedUrl;
      const page = await (options.fetchPublicHtml || fetchPublicHtml)(finalUrl);
      const htmlContentType = (page.contentType || "").toLowerCase();
      if (page.error) {
        pageInspection = { performed: false, error: page.error };
      } else if (htmlContentType && !htmlContentType.includes("text/html") && !htmlContentType.includes("xhtml")) {
        pageInspection = { performed: false, error: "The public response was not HTML." };
      } else {
        pageInspection = { performed: true, truncated: page.truncated, title: null };
        if (page.redirects >= 3) {
          score = Math.min(100, score + 10);
          diagnostics.push({
            category: "SSL / Network",
            severity: "MEDIUM",
            issue: "Several redirects before the HTML page",
            penalty: "+10",
            detail: `The page fetch followed ${page.redirects} redirects.`,
            code: "html_redirect_chain",
          });
        }
        try {
          if (getRegistrableDomain(new URL(page.finalUrl || finalUrl).hostname) !==
              getRegistrableDomain(new URL(base.normalizedUrl).hostname) &&
              !(networkCheck.flags || []).some((flag) => flag.code === "cross_domain_redirect")) {
            score = Math.min(100, score + 12);
            diagnostics.push({
              category: "SSL / Network",
              severity: "MEDIUM",
              issue: "HTML request redirected to another domain",
              penalty: "+12",
              detail: "The public page redirected to a different hostname.",
              code: "html_cross_domain_redirect",
            });
          }
        } catch {
          pageInspection.error = "The final page address could not be verified.";
        }
        const content = analyzeHtml(page.body || "", page.finalUrl || finalUrl);
        pageInspection.title = content.title;
        for (const diagnostic of content.diagnostics) {
          score = Math.min(100, score + diagnostic.penalty);
          diagnostics.push({
            ...diagnostic,
            penalty: `+${diagnostic.penalty}`,
          });
        }
      }

      try {
        const dnsDiagnostics = await (options.inspectDns || inspectDns)(new URL(finalUrl).hostname);
        diagnostics.push(...dnsDiagnostics.map((diagnostic) => ({
          ...diagnostic,
          penalty: `+${diagnostic.penalty}`,
        })));
      } catch {
        diagnostics.push({
          code: "dns_forensics_unavailable",
          category: "DNS",
          severity: "INFO",
          issue: "DNS forensics unavailable",
          penalty: "+0",
          detail: "DNS record checks could not complete; this does not increase the threat score.",
        });
      }
    }
  }

  score = Math.min(100, score);
  const alreadyBlocked = blocklist?.find(base.hostname) || null;
  let verdict = alreadyBlocked
    ? "BLOCKED - MALICIOUS"
    : score >= BLOCK_THRESHOLD
      ? "BLOCKED - MALICIOUS"
      : score >= 8
        ? "SUSPICIOUS"
        : "SAFE";
  let actionTaken = alreadyBlocked ? "Already on Active Blocklist" : "Allowed";
  if (!alreadyBlocked && score >= BLOCK_THRESHOLD && blocklist) {
    blocklist.add(getRegistrableDomain(base.hostname), score, diagnostics.map((item) => item.code).join(", "));
    actionTaken = "Added to Active Blocklist";
  }

  if (alreadyBlocked) {
    diagnostics.push({
      category: "Active Blocklist",
      severity: "CRITICAL",
      issue: "Domain is on the local active blocklist",
      penalty: "+0",
      detail: `This domain was added to the local blocklist on ${alreadyBlocked.addedAt}.`,
      code: "active_blocklist_match",
    });
  }

  return {
    ...base,
    overall_score: score,
    status: verdict === "BLOCKED - MALICIOUS" ? "Malicious" : verdict === "SUSPICIOUS" ? "Suspicious" : "Safe",
    riskLevel: verdict === "BLOCKED - MALICIOUS" ? "high" : verdict === "SUSPICIOUS" ? "medium" : "low",
    verdict,
    action_taken: actionTaken,
    diagnostics,
    blocked_domain: verdict === "BLOCKED - MALICIOUS" ? getRegistrableDomain(base.hostname) : null,
    networkCheck,
    pageInspection,
    domainAge,
  };
}

module.exports = { scanUrl, asDiagnostic, BLOCK_THRESHOLD };
