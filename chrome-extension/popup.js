const backendInput = document.getElementById("backend-url");
const scanButton = document.getElementById("scan");
const statusElement = document.getElementById("status");

chrome.storage.local.get(["phishguardBackendUrl"], (saved) => {
  if (saved.phishguardBackendUrl) backendInput.value = saved.phishguardBackendUrl;
});

function escapeHTML(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

scanButton.addEventListener("click", async () => {
  scanButton.disabled = true;
  statusElement.className = "";
  statusElement.textContent = "Scanning...";
  const backend = backendInput.value.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(backend)) {
    statusElement.className = "error";
    statusElement.textContent = "Enter a valid HTTP or HTTPS backend URL.";
    scanButton.disabled = false;
    return;
  }
  chrome.storage.local.set({ phishguardBackendUrl: backend });

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) throw new Error("Could not read the active tab URL.");
    if (!/^https?:\/\//i.test(tab.url)) throw new Error("Only HTTP and HTTPS tab URLs can be scanned.");
    const response = await fetch(`${backend}/api/v1/analyze/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ url: tab.url })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || "The backend rejected the URL.");
    const reasons = (data.evidence || []).slice(0, 5).map((item) => item.description || item.indicator).filter(Boolean);
    statusElement.className = "result";
    statusElement.innerHTML = `
      <strong>${escapeHTML(String(data.classification).replaceAll("_", " "))}</strong>
      <div>Risk score: ${Number(data.risk_score || 0)} / 100</div>
      ${reasons.length ? `<div>${reasons.map((reason) => escapeHTML(reason)).join("<br>")}</div>` : "<div>No heuristic evidence triggered.</div>"}
    `;
  } catch (error) {
    statusElement.className = "error";
    statusElement.textContent = error.message || "Cannot connect to PhishGuard.";
  } finally {
    scanButton.disabled = false;
  }
});
