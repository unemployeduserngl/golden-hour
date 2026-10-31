const statusDot = document.querySelector("#status-dot");
const statusTitle = document.querySelector("#status-title");
const statusDetail = document.querySelector("#status-detail");
const cacheCount = document.querySelector("#cache-count");
const protectionToggle = document.querySelector("#protection-toggle");
const tabBlockedCount = document.querySelector("#tab-blocked-count");
const globalBlockedCount = document.querySelector("#global-blocked-count");
const trustedForm = document.querySelector("#trusted-form");
const trustedInput = document.querySelector("#trusted-domain");
const trustedList = document.querySelector("#trusted-domains");
const trustedError = document.querySelector("#trusted-error");
const ruleError = document.querySelector("#rule-error");

function sendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (result) => {
      if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
      else resolve(result);
    });
  });
}

async function refreshStatus() {
  try {
    const response = await fetch("http://127.0.0.1:5000/api/health", { signal: AbortSignal.timeout(1800) });
    if (!response.ok) throw new Error("Backend unavailable");
    statusDot.className = "online";
    statusTitle.textContent = "Local scanner connected";
    statusDetail.textContent = "DNR blocking and click scanning active";
  } catch {
    statusDot.className = "offline";
    statusTitle.textContent = "Fallback protection active";
    statusDetail.textContent = "Local scanner is offline";
  }
  try {
    const state = await sendMessage({ type: "GET_STATUS" });
    if (state.error) throw new Error(state.error);
    cacheCount.textContent = String(state.cachedSafe);
    tabBlockedCount.textContent = String(state.blockedOnCurrentPage);
    globalBlockedCount.textContent = String(state.globalBlockedTotal);
    protectionToggle.checked = state.enabled;
    ruleError.hidden = !state.ruleSyncError;
    ruleError.textContent = state.ruleSyncError || "";
    renderTrustedDomains(state.trustedDomains || []);
  } catch {
    statusTitle.textContent = "Extension status unavailable";
  }
}

protectionToggle.addEventListener("change", () => {
  const requested = protectionToggle.checked;
  void sendMessage({ type: "SET_ENABLED", enabled: requested }).then((result) => {
    if (!result?.ok) throw new Error("Could not update protection.");
  }).catch(() => { protectionToggle.checked = !requested; });
});

function renderTrustedDomains(domains) {
  trustedList.replaceChildren();
  for (const domain of domains) {
    const item = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = domain;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => {
      void sendMessage({ type: "REMOVE_TRUSTED_DOMAIN", domain }).then((result) => {
        if (result?.ok) return refreshStatus();
        return undefined;
      }).catch(() => { statusTitle.textContent = "Could not update trusted domains"; });
    });
    item.append(name, remove);
    trustedList.append(item);
  }
}

trustedForm.addEventListener("submit", (event) => {
  event.preventDefault();
  trustedError.hidden = true;
  void sendMessage({ type: "ADD_TRUSTED_DOMAIN", domain: trustedInput.value }).then((result) => {
    if (!result?.ok) throw new Error(result?.error || "Could not add that domain.");
    trustedInput.value = "";
    return refreshStatus();
  }).catch((error) => {
    trustedError.textContent = error.message || "Could not add that domain.";
    trustedError.hidden = false;
  });
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.enabled) protectionToggle.checked = changes.enabled.newValue !== false;
  if (changes.trustedDomains) renderTrustedDomains(changes.trustedDomains.newValue || []);
});

document.querySelector("#refresh").addEventListener("click", () => void refreshStatus());
void refreshStatus();
