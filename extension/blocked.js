const params = new URLSearchParams(location.search);
const target = params.get("url") || "";
const score = Math.max(0, Math.min(100, Number(params.get("score")) || 0));
let reasons = [];
try {
  const parsed = JSON.parse(params.get("reasons") || "[]");
  if (Array.isArray(parsed)) reasons = parsed.filter((item) => typeof item === "string").slice(0, 8);
} catch {
  reasons = ["The scanner returned a risk signal."];
}

document.querySelector("#score").textContent = String(score);
document.querySelector("#blocked-url").textContent = target || "Unknown URL";
const list = document.querySelector("#reasons");
if (reasons.length) {
  for (const reason of reasons) {
    const item = document.createElement("li");
    item.textContent = reason;
    list.append(item);
  }
} else {
  const item = document.createElement("li");
  item.className = "empty";
  item.textContent = "The URL was blocked by the score threshold.";
  list.append(item);
}

document.querySelector("#back-button").addEventListener("click", () => {
  if (history.length > 1) history.back();
  else location.replace("about:blank");
});

document.querySelector("#proceed-button").addEventListener("click", () => {
  if (!target || !/^https?:\/\//i.test(target)) {
    document.querySelector("#error").textContent = "This destination cannot be opened.";
    document.querySelector("#error").hidden = false;
    return;
  }
  chrome.tabs.getCurrent((tab) => {
    chrome.runtime.sendMessage({ type: "WHITELIST_ONCE", url: target, tabId: tab?.id }, (response) => {
      if (chrome.runtime.lastError || !response?.ok) {
        document.querySelector("#error").textContent = "Could not temporarily allow this site.";
        document.querySelector("#error").hidden = false;
      }
    });
  });
});
