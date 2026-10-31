function buildLocalHelpReply(messages = []) {
  const latestQuestion = [...messages].reverse().find((message) => message && message.role === "user")?.content || "";
  const prompt = String(latestQuestion || "").toLowerCase();

  if (/check.*(link|website|address)|how do i check|check address/.test(prompt)) {
    return "Paste the full address into the box and click Check address. If you want a deeper review, turn on live inspection first. The tool checks the address and explains any suspicious clues before you visit it.";
  }

  if (/score|what does.*score|verdict/.test(prompt)) {
    return "Higher scores mean more suspicious signals. ClearSignal labels low scores as safe, medium values as suspicious, and high scores as blocked. A score is a helpful signal, not a guarantee, so review the findings before you act.";
  }

  if (/live.*inspection|network|tls|redirect|dns/.test(prompt)) {
    return "Live inspection is optional and off by default. It checks the public site's TLS, redirects, DNS, and limited HTML, without executing the site’s JavaScript. You can enable it with the opt-in checkbox before running the scan.";
  }

  if (/safe|phish|fake|look-alike|copycat|brand/.test(prompt)) {
    return "ClearSignal looks for copycat domains, suspicious URL patterns, known phishing reports, and other look-alike signals. It does not visit the site and does not guarantee a site is safe, but it helps you spot warning signs early.";
  }

  return "I can help with ClearSignal basics: checking an address, explaining the score, or describing live inspection. Paste the link into the main box and click Check address to begin.";
}

module.exports = { buildLocalHelpReply };
