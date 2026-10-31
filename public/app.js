const form = document.querySelector("#check-form");
const input = document.querySelector("#website-url");
const button = form.querySelector("button[type=submit]");
const buttonLabel = button.querySelector(".button-label");
const networkCheckInput = document.querySelector("#network-check");
const clearButton = document.querySelector(".clear-input");
const errorBox = document.querySelector("#form-error");
const resultBox = document.querySelector("#result");
const chatToggle = document.querySelector("#help-chat-toggle");
const chatPanel = document.querySelector("#help-chat-panel");
const chatClose = document.querySelector("#help-chat-close");
const chatForm = document.querySelector("#help-chat-form");
const chatInput = document.querySelector("#help-chat-input");
const chatMessagesBox = document.querySelector("#help-chat-messages");
const chatStatus = document.querySelector("#help-chat-status");
const chatSuggestions = document.querySelector(".help-chat-suggestions");
const t = window.clearsignalT;
let chatAvailable = false;
let chatStatusChecked = false;
let lastResult = null;
let chatHistory = [];

function appendChatMessage(role, content) {
  const message = document.createElement("p");
  message.className = `chat-message ${role}`;
  message.textContent = content;
  chatMessagesBox.append(message);
  chatMessagesBox.scrollTop = chatMessagesBox.scrollHeight;
}

function setChatOpen(open) {
  chatPanel.hidden = !open;
  chatToggle.setAttribute("aria-expanded", String(open));
  if (open) chatInput.focus();
  else chatToggle.focus();
}

chatToggle.addEventListener("click", () => setChatOpen(chatPanel.hidden));
chatClose.addEventListener("click", () => setChatOpen(false));
chatPanel.addEventListener("keydown", (event) => {
  if (event.key === "Escape") setChatOpen(false);
});

chatSuggestions.addEventListener("click", (event) => {
  const suggestion = event.target.closest("[data-chat-question]");
  if (!suggestion) return;
  chatInput.value = suggestion.dataset.chatQuestion;
  chatForm.requestSubmit();
});

chatForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const question = chatInput.value.trim();
  if (!question) return;
  if (!chatAvailable) {
    chatStatus.textContent = chatStatusChecked ? t("unavailable") : t("checkingAvailability");
    return;
  }

  chatHistory.push({ role: "user", content: question });
  chatHistory = chatHistory.slice(-6);
  appendChatMessage("user", question);
  chatInput.value = "";
  chatInput.disabled = true;
  chatForm.querySelector("button[type=submit]").disabled = true;
  chatSuggestions.querySelectorAll("button").forEach((suggestion) => { suggestion.disabled = true; });
  chatStatus.textContent = t("replying");

  try {
    const response = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages: chatHistory }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || "The assistant could not reply.");
    const reply = window.clearsignalLanguage() === "en" ? body.reply : t("localReply");
    chatHistory.push({ role: "assistant", content: reply });
    chatHistory = chatHistory.slice(-6);
    appendChatMessage("assistant", reply);
    chatStatus.textContent = t("localAnswered");
  } catch (error) {
    chatStatus.textContent = error.message || "Could not reach the assistant. Please try again.";
  } finally {
    chatInput.disabled = false;
    chatForm.querySelector("button[type=submit]").disabled = false;
    chatSuggestions.querySelectorAll("button").forEach((suggestion) => { suggestion.disabled = false; });
    chatInput.focus();
  }
});

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function renderResult(result) {
  lastResult = result;
  const score = Math.max(0, Math.min(100, Number(result.overall_score ?? result.score) || 0));
  const verdict = result.verdict || result.status || "SAFE";
  const blocked = verdict === "BLOCKED - MALICIOUS";
  const stateClass = blocked ? "blocked" : verdict === "SUSPICIOUS" || result.riskLevel === "medium" ? "suspicious" : "safe";
  const diagnostics = Array.isArray(result.diagnostics)
    ? result.diagnostics
    : (result.checks || []).filter((check) => check.status !== "good").map((check) => ({
      category: "URL & Lexical",
      severity: check.status === "danger" ? "HIGH" : "LOW",
      issue: check.title,
      penalty: `+${check.points || 0}`,
      detail: check.detail,
    }));
  const rows = diagnostics.length
    ? diagnostics.map((item) => `<tr>
        <td data-label="${t("category")}">${escapeHtml(item.category)}</td>
        <td data-label="${t("severity")}"><span class="severity-badge severity-${escapeHtml(String(item.severity).toLowerCase())}">${escapeHtml(item.severity)}</span></td>
        <td data-label="${t("finding")}"><strong>${escapeHtml(item.issue)}</strong><small>${escapeHtml(item.detail || "")}</small></td>
        <td data-label="${t("penalty")}" class="penalty-cell">${escapeHtml(item.penalty)}</td>
      </tr>`).join("")
    : `<tr><td colspan="4" class="no-diagnostics">${t("noFlags")}</td></tr>`;
  const network = result.networkCheck || {};
  const tls = network.tls || {};
  const blockedBanner = blocked
    ? `<div class="blocked-banner" role="alert"><span aria-hidden="true">⛔</span><div><strong>${t("blockedBanner")}</strong><small>${t("blockedInfo")}</small></div></div>`
    : "";
  const blockActions = blocked
    ? `<div class="block-actions"><a href="/api/blocklist">${t("viewBlocklist")}</a><a href="/api/blocklist/hosts">${t("downloadRules")}</a></div>`
    : "";
  const tlsLine = network.performed && tls.issuer
    ? `<p class="network-summary">${t("tlsIssuer")} ${escapeHtml(tls.issuer)}${tls.daysUntilExpiry !== null && tls.daysUntilExpiry !== undefined ? ` · ${t("certExpires")} ${escapeHtml(tls.daysUntilExpiry)} days` : ""}${tls.ageDays !== null && tls.ageDays !== undefined ? ` · ${t("certAge")} ${escapeHtml(tls.ageDays)} days` : ""}</p>`
    : "";
  const explanation = blocked
    ? t("blockedExplain")
    : stateClass === "suspicious"
      ? t("suspiciousExplain")
      : t("safeExplain");

  resultBox.innerHTML = `${blockedBanner}
    <div class="threat-scorecard state-${stateClass}">
      <div class="scorecard-copy">
        <span class="score-kicker">${t("score")}</span>
        <h2>${blocked ? t("blockedHeading") : stateClass === "suspicious" ? t("suspiciousHeading") : t("safeHeading")}</h2>
        <p>${explanation}</p>
        <div class="score-verdict">${escapeHtml(verdict)}</div>
      </div>
      <div class="score-gauge" role="img" aria-label="${t("scoreAria", { score })}">
        <svg viewBox="0 0 120 120" aria-hidden="true"><circle class="gauge-track" cx="60" cy="60" r="48" pathLength="100"/><circle class="gauge-value" cx="60" cy="60" r="48" pathLength="100" stroke-dasharray="${score} 100"/></svg>
        <div class="gauge-label"><strong>${score}</strong><span>/ 100</span></div>
      </div>
    </div>
    ${blockActions}
    <div class="checked-address">${escapeHtml(result.normalizedUrl || result.hostname || "")}</div>
    <div class="diagnostic-heading"><div><span class="section-kicker">${t("analysis")}</span><h2>${t("reportHeading")}</h2></div><span class="finding-count">${diagnostics.length} ${diagnostics.length === 1 ? t("finding") : t("findings")}</span></div>
    <div class="diagnostic-table-wrap"><table class="diagnostic-table"><thead><tr><th>${t("category")}</th><th>${t("severity")}</th><th>${t("finding")}</th><th>${t("penalty")}</th></tr></thead><tbody>${rows}</tbody></table></div>
    ${tlsLine}
    ${result.pageInspection?.error ? `<p class="network-summary">${t("pageUnavailable")} ${escapeHtml(result.pageInspection.error)}</p>` : ""}
    ${result.networkCheck?.error ? `<p class="network-summary">${t("liveUnavailable")} ${escapeHtml(result.networkCheck.error)}</p>` : ""}
    <p class="result-disclaimer">${t("disclaimer")}</p>
    <div class="feed-source">${t("action")} ${escapeHtml(result.action_taken || "Allowed")} · ${t("threatIntel")} ${escapeHtml(result.feed?.message || t("urlHeuristics"))} · <a href="https://openphish.com/" target="_blank" rel="noreferrer">${t("aboutOpenPhish")}</a></div>`;
  resultBox.hidden = false;
  resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

fetch("/api/health")
  .then(async (response) => {
    if (!response.ok) throw new Error(t("healthFailed"));
    return response.json();
  })
  .then((health) => {
    chatAvailable = health.chatAvailable === true;
    chatStatusChecked = true;
    chatStatus.textContent = chatAvailable
      ? t("localReady")
      : t("chatUnavailable");
  })
  .catch(() => {
    chatStatusChecked = true;
    chatStatus.textContent = t("healthFailed");
  });

input.addEventListener("input", () => {
  clearButton.hidden = input.value.length === 0;
  errorBox.hidden = true;
});

clearButton.addEventListener("click", () => {
  input.value = "";
  clearButton.hidden = true;
  resultBox.hidden = true;
  errorBox.hidden = true;
  input.focus();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = input.value.trim();
  if (!url) {
    errorBox.textContent = t("pasteAddress");
    errorBox.hidden = false;
    input.focus();
    return;
  }

  button.disabled = true;
  buttonLabel.textContent = t("checking");
  errorBox.hidden = true;
  resultBox.hidden = true;

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, checkNetwork: networkCheckInput.checked }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(t("formInvalid"));
    renderResult(body);
  } catch (error) {
    errorBox.textContent = error.message || t("checkerFailed");
    errorBox.hidden = false;
  } finally {
    button.disabled = false;
    buttonLabel.textContent = t("check");
  }
});

window.addEventListener("clearsignal-language-change", () => {
  if (!resultBox.hidden && lastResult) renderResult(lastResult);
  if (chatStatusChecked) {
    chatStatus.textContent = chatAvailable
      ? t("localReady")
      : t("chatUnavailable");
  }
});
