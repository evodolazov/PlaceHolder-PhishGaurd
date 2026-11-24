const backendInput = document.getElementById("backend-url");
const scanButton = document.getElementById("scan");
const statusElement = document.getElementById("status");
const VALID_CLASSIFICATIONS = new Set([
  "low_risk",
  "moderate_risk",
  "high_risk",
  "critical_risk"
]);

chrome.storage.local.get(["phishguardBackendUrl", "phishguardPendingBackendOrigin"], (saved) => {
  if (saved.phishguardBackendUrl) backendInput.value = saved.phishguardBackendUrl;
  if (!saved.phishguardPendingBackendOrigin) return;

  const pendingOrigin = saved.phishguardPendingBackendOrigin;
  chrome.permissions.contains({ origins: [`${pendingOrigin}/*`] }, (granted) => {
    chrome.storage.local.remove("phishguardPendingBackendOrigin");
    statusElement.className = granted ? "" : "error";
    statusElement.textContent = granted
      ? "Backend permission granted. Click Scan Current Tab to continue."
      : "Permission to contact the configured backend was not granted. Click Scan Current Tab to try again.";
  });
});

function escapeHTML(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function normalizeBackendURL(value) {
  let url;
  try {
    url = new URL(value.trim());
  } catch {
    throw new Error("Enter a valid HTTP or HTTPS backend URL.");
  }
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS backend URLs are supported.");
  }
  if (url.username || url.password) {
    throw new Error("Backend URLs must not contain a username or password.");
  }

  const basePath = url.pathname.replace(/\/+$/, "");
  const apiPathSuffix = "/api/v1";
  const analysisPath = `${apiPathSuffix}/analyze/url`;
  let endpointPath;
  if (basePath.endsWith(analysisPath)) {
    endpointPath = basePath;
  } else if (basePath.endsWith(apiPathSuffix)) {
    endpointPath = `${basePath}/analyze/url`;
  } else {
    endpointPath = `${basePath}${analysisPath}`;
  }

  return {
    origin: url.origin,
    normalizedBase: `${url.origin}${basePath}`,
    analysisEndpoint: `${url.origin}${endpointPath}`
  };
}

function validateAnalysisResponse(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("The backend returned an invalid analysis response.");
  }
  const requiredFields = [
    "analysis_id",
    "url",
    "normalized_url",
    "classification",
    "risk_score",
    "confidence",
    "features",
    "evidence",
    "threat_intelligence",
    "created_at"
  ];
  if (requiredFields.some((field) => !Object.prototype.hasOwnProperty.call(data, field))) {
    throw new Error("The backend analysis response is missing required fields.");
  }
  if (!Number.isInteger(data.analysis_id) || data.analysis_id < 1) {
    throw new Error("The backend returned an invalid analysis identifier.");
  }
  if (typeof data.url !== "string" || !data.url.trim() ||
      typeof data.normalized_url !== "string" || !data.normalized_url.trim()) {
    throw new Error("The backend returned invalid URL details.");
  }
  if (!VALID_CLASSIFICATIONS.has(data.classification)) {
    throw new Error("The backend returned an invalid risk classification.");
  }
  if (!Number.isInteger(data.risk_score) || data.risk_score < 0 || data.risk_score > 100) {
    throw new Error("The backend returned an invalid risk score.");
  }
  if (data.confidence !== null && (typeof data.confidence !== "number" || !Number.isFinite(data.confidence))) {
    throw new Error("The backend returned invalid confidence data.");
  }
  if (!data.features || typeof data.features !== "object" || Array.isArray(data.features)) {
    throw new Error("The backend returned invalid analysis features.");
  }
  if (!Array.isArray(data.evidence) || data.evidence.some(
    (item) => !item || typeof item !== "object" || Array.isArray(item)
  )) {
    throw new Error("The backend returned invalid analysis evidence.");
  }
  if (!data.threat_intelligence || typeof data.threat_intelligence !== "object" ||
      Array.isArray(data.threat_intelligence) || typeof data.created_at !== "string" ||
      !data.created_at.trim()) {
    throw new Error("The backend returned incomplete analysis details.");
  }
}

async function readAnalysisResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  let data;
  if (!contentType.toLowerCase().includes("application/json")) {
    if (response.ok) {
      throw new Error("The backend returned a non-JSON analysis response.");
    }
    throw new Error(`The backend request failed with status ${response.status}.`);
  }

  try {
    data = await response.json();
  } catch {
    if (response.ok) {
      throw new Error("The backend returned an empty or malformed JSON response.");
    }
    throw new Error(`The backend returned an unreadable error response (${response.status}).`);
  }
  if (!response.ok) {
    const message = data && typeof data.message === "string" ? data.message : "";
    throw new Error(message || `The backend request failed with status ${response.status}.`);
  }
  validateAnalysisResponse(data);
  return data;
}

scanButton.addEventListener("click", async () => {
  scanButton.disabled = true;
  statusElement.className = "";
  statusElement.textContent = "Scanning...";

  try {
    const backendURL = normalizeBackendURL(backendInput.value);
    backendInput.value = backendURL.normalizedBase;
    await chrome.storage.local.set({
      phishguardBackendUrl: backendURL.normalizedBase,
      phishguardPendingBackendOrigin: backendURL.origin
    });
    const permissionGranted = await chrome.permissions.request({
      origins: [`${backendURL.origin}/*`]
    });
    chrome.storage.local.remove("phishguardPendingBackendOrigin");
    if (!permissionGranted) {
      throw new Error("Permission to contact the configured backend was denied.");
    }

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) throw new Error("Could not read the active tab URL.");
    if (!/^https?:\/\//i.test(tab.url)) throw new Error("Only HTTP and HTTPS tab URLs can be scanned.");
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    let response;
    let data;
    try {
      response = await fetch(backendURL.analysisEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ url: tab.url }),
        signal: controller.signal
      });
      data = await readAnalysisResponse(response);
    } catch (error) {
      if (error.name === "AbortError") throw new Error("The backend request timed out.");
      if (error instanceof TypeError) {
        throw new Error("Could not connect to the configured backend. Check the URL and try again.");
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
    const reasons = (data.evidence || []).slice(0, 5).map((item) => item.description || item.indicator).filter(Boolean);
    statusElement.className = "result";
    statusElement.innerHTML = `
      <strong>${escapeHTML(data.classification.replaceAll("_", " "))}</strong>
      <div>Risk score: ${data.risk_score} / 100</div>
      ${reasons.length ? `<div>${reasons.map((reason) => escapeHTML(reason)).join("<br>")}</div>` : "<div>No heuristic evidence triggered.</div>"}
    `;
  } catch (error) {
    statusElement.className = "error";
    statusElement.textContent = error.message || "Cannot connect to PhishGuard.";
  } finally {
    scanButton.disabled = false;
  }
});
