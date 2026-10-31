(() => {
  let enabled = true;
  const toast = document.createElement("div");
  toast.id = "clearsignal-scan-toast";
  toast.setAttribute("role", "status");
  toast.setAttribute("aria-live", "polite");
  toast.textContent = "Scanning link…";
  Object.assign(toast.style, {
    position: "fixed",
    zIndex: "2147483647",
    display: "none",
    right: "18px",
    bottom: "18px",
    padding: "10px 14px",
    borderRadius: "999px",
    background: "#152432",
    color: "#fff",
    boxShadow: "0 5px 22px #0004",
    font: "12px/1.4 system-ui, sans-serif",
    fontWeight: "600",
    pointerEvents: "none",
  });
  if (document.documentElement) document.documentElement.appendChild(toast);
  else document.addEventListener("DOMContentLoaded", () => document.documentElement.appendChild(toast), { once: true });

  chrome.storage.local.get({ enabled: true }, (settings) => {
    enabled = settings.enabled !== false;
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.enabled) enabled = changes.enabled.newValue !== false;
  });

  function anchorFor(target) {
    return target instanceof Element ? target.closest("a[href]") : null;
  }

  function eligible(anchor) {
    if (!anchor || anchor.hasAttribute("download")) return null;
    const raw = anchor.href;
    try {
      const url = new URL(raw, location.href);
      if (!["http:", "https:"].includes(url.protocol)) return null;
      return url.href;
    } catch {
      return null;
    }
  }

  function askBackground(url, openInNewTab = false) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "SCAN_LINK", url, openInNewTab }, (result) => {
        if (chrome.runtime.lastError) {
          resolve({ verdict: "SUSPICIOUS", score: 60, reasons: ["Local scanner is unavailable; use caution."] });
          return;
        }
        resolve(result || { verdict: "SUSPICIOUS", score: 60, reasons: ["No scanner response; use caution."] });
      });
    });
  }

  let latestClick = 0;

  async function interceptLink(event) {
    if (!enabled || !event.isTrusted || event.defaultPrevented ||
        (event.type === "click" && event.button !== 0) ||
        (event.type === "auxclick" && event.button !== 1)) return;
    const anchor = anchorFor(event.target);
    const url = eligible(anchor);
    if (!url) return;

    event.preventDefault();
    event.stopImmediatePropagation();
    const clickNumber = ++latestClick;
    const openInNewTab = (anchor.target && anchor.target !== "_self") || event.button === 1 ||
      event.metaKey || event.ctrlKey || event.shiftKey;
    toast.style.display = "block";
    const verdict = await askBackground(url, openInNewTab);
    if (clickNumber !== latestClick) return;
    toast.style.display = "none";
    if (verdict.verdict === "BLOCKED" || verdict.score >= 70) {
      chrome.runtime.sendMessage({ type: "DISPLAY_BLOCKED", result: verdict, openInNewTab });
      return;
    }
    if (verdict.verdict === "SUSPICIOUS") {
      const proceed = window.confirm(
        `ClearSignal warning: this link looks suspicious (score ${verdict.score}/100).\n\n${(verdict.reasons || []).slice(0, 3).join("\n")}\n\nOpen it anyway?`
      );
      if (!proceed) return;
    }
    if (openInNewTab) {
      chrome.runtime.sendMessage({ type: "OPEN_SCANNED_TAB", url });
      return;
    }
    location.assign(url);
  }

  document.addEventListener("click", interceptLink, true);
  document.addEventListener("auxclick", interceptLink, true);
})();
