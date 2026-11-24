import {
  analyzeURL,
  analyzeEmail,
  uploadEmail,
  getURLHistory,
  getEmailHistory,
  getAnalysis,
  deleteAnalysis
} from "./api.js";

const $ = (id) => document.getElementById(id);
let busy = false;
let historyPage = 1;
let historyPages = 1;

function setBusy(type, isBusy) {
  busy = isBusy;
  const submit = $(`${type}-submit`);
  if (submit) {
    submit.disabled = isBusy;
    submit.textContent = isBusy ? "Analyzing..." : (type === "url" ? "Analyze URL" : "Analyze Email");
  }
  $(`${type}-loading`).classList.toggle("hidden", !isBusy);
  $(`${type}-error`).classList.add("hidden");
}

function showError(type, error) {
  const element = $(`${type}-error`);
  element.textContent = error?.message || "Analysis failed.";
  element.classList.remove("hidden");
}

function evidenceText(item) {
  return item.description || item.indicator || "Detection evidence";
}

function renderResult(containerId, data, type) {
  const container = $(containerId);
  container.classList.remove("hidden");
  const evidence = Array.isArray(data.evidence) ? data.evidence : [];
  const features = data.features && typeof data.features === "object" ? data.features : {};
  const threat = data.threat_intelligence;
  const urls = Array.isArray(data.urls) ? data.urls : [];
  const primary = type === "email"
    ? `<p><strong>From:</strong> ${escapeHTML(data.from || "Not provided")}</p>
       <p><strong>Reply-To:</strong> ${escapeHTML(data.reply_to || "Not provided")}</p>
       <p><strong>Subject:</strong> ${escapeHTML(data.subject || "Not provided")}</p>`
    : `<p><strong>Submitted URL:</strong> ${escapeHTML(data.url || "")}</p>
       <p><strong>Normalized URL:</strong> ${escapeHTML(data.normalized_url || "")}</p>`;

  container.innerHTML = `
    <h2>Analysis Results</h2>
    ${data.analysis_id ? `<p><a href="${type === "email" ? `/api/v1/email-analysis/${data.analysis_id}/report` : `/api/v1/analysis/${data.analysis_id}/report`}" download="phishguard-analysis-${data.analysis_id}.txt">Download text report</a></p>` : ""}
    ${primary}
    <div class="score-row">
      <span class="risk-badge ${riskClass(data.classification)}">${escapeHTML(formatLabel(data.classification))}</span>
      <strong>${Number(data.risk_score || 0)} / 100</strong>
    </div>
    <p><strong>Confidence:</strong> ${data.confidence === null || data.confidence === undefined ? "Not calibrated" : escapeHTML(String(data.confidence))}</p>
    <p><strong>External threat intelligence:</strong> ${escapeHTML(threat?.message || "Status unavailable")}</p>
    <h3>Reasons and evidence</h3>
    ${evidence.length ? `<ul>${evidence.map((item) => `<li>${escapeHTML(evidenceText(item))}</li>`).join("")}</ul>` : "<p>No detection evidence was triggered.</p>"}
    ${urls.length ? `<h3>Embedded URL findings</h3><ul>${urls.map((item) => `<li>${escapeHTML(item.url)} - ${escapeHTML(formatLabel(item.classification))} (${item.risk_score}/100)</li>`).join("")}</ul>` : ""}
    ${Object.keys(features).length ? `<h3>Extracted features</h3><dl class="feature-grid">${Object.entries(features).slice(0, 30).map(([key, value]) => `<div><dt>${escapeHTML(formatLabel(key))}</dt><dd>${escapeHTML(formatValue(value))}</dd></div>`).join("")}</dl>` : ""}
  `;
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatLabel(value) {
  return String(value || "unknown").replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatValue(value) {
  if (value === null) return "Not available";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.join(", ") || "None";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function riskClass(classification) {
  if (classification === "critical_risk" || classification === "high_risk") return "high";
  if (classification === "moderate_risk") return "moderate";
  return "low";
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((item) => item.classList.remove("active"));
    tab.classList.add("active");
    $(`${tab.dataset.tab}-panel`).classList.add("active");
  });
});

$("url-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  const url = $("url-input").value.trim();
  setBusy("url", true);
  try {
    const data = await analyzeURL(url);
    renderResult("url-results", data, "url");
  } catch (error) {
    showError("url", error);
  } finally {
    setBusy("url", false);
  }
});

$("email-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  const payload = {
    from: $("email-from").value.trim(),
    reply_to: $("email-reply-to").value.trim(),
    subject: $("email-subject").value.trim(),
    body_text: $("email-body").value,
    body_html: $("email-html").value
  };
  setBusy("email", true);
  try {
    const data = await analyzeEmail(payload);
    renderResult("email-results", data, "email");
  } catch (error) {
    showError("email", error);
  } finally {
    setBusy("email", false);
  }
});

$("upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  const file = $("email-file").files[0];
  if (!file) {
    showError("email", { message: "Select an .eml file." });
    return;
  }
  if (!file.name.toLowerCase().endsWith(".eml")) {
    showError("email", { message: "Only .eml files are accepted." });
    return;
  }
  setBusy("email", true);
  try {
    const data = await uploadEmail(file);
    renderResult("email-results", data, "email");
  } catch (error) {
    showError("email", error);
  } finally {
    setBusy("email", false);
  }
});

async function loadHistory() {
  const type = $("history-type").value;
  const risk = $("history-risk").value;
  const search = $("history-search").value.trim();
  $("history-error").classList.add("hidden");
  try {
    const data = type === "email"
      ? await getEmailHistory(historyPage, 10, risk, search)
      : await getURLHistory(historyPage, 10, risk, search);
    historyPages = data.pages || 1;
    $("history-page").textContent = `Page ${data.page || 1} of ${historyPages}`;
    $("history-prev").disabled = historyPage <= 1;
    $("history-next").disabled = historyPage >= historyPages;
    const items = data.items || [];
    $("history-list").innerHTML = items.length ? items.map((item) => `
      <article class="history-item">
        <div>
          <strong>${escapeHTML(type === "email" ? (item.subject || "Email analysis") : (item.url || "URL analysis"))}</strong>
          <span>${escapeHTML(formatLabel(item.classification))} - ${item.risk_score}/100</span>
        </div>
        <div class="history-actions">
          <button type="button" data-open-type="${type}" data-open-id="${item.analysis_id}">View</button>
          <button type="button" class="delete" data-delete-type="${type}" data-delete-id="${item.analysis_id}">Delete</button>
        </div>
      </article>
    `).join("") : "<p>No analysis records found.</p>";
  } catch (error) {
    $("history-error").textContent = error.message;
    $("history-error").classList.remove("hidden");
  }
}

$("history-refresh").addEventListener("click", () => { historyPage = 1; loadHistory(); });
$("history-type").addEventListener("change", () => { historyPage = 1; loadHistory(); });
$("history-risk").addEventListener("change", () => { historyPage = 1; loadHistory(); });
$("history-prev").addEventListener("click", () => { if (historyPage > 1) { historyPage -= 1; loadHistory(); } });
$("history-next").addEventListener("click", () => { if (historyPage < historyPages) { historyPage += 1; loadHistory(); } });

$("history-list").addEventListener("click", async (event) => {
  const openButton = event.target.closest("[data-open-id]");
  const deleteButton = event.target.closest("[data-delete-id]");
  if (openButton) {
    try {
      const data = await getAnalysis(openButton.dataset.openType, openButton.dataset.openId);
      const type = openButton.dataset.openType;
      document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
      document.querySelectorAll(".panel").forEach((item) => item.classList.remove("active"));
      document.querySelector(`.tab[data-tab="${type}"]`)?.classList.add("active");
      $(`${type}-panel`).classList.add("active");
      renderResult(`${type}-results`, data, type);
    } catch (error) {
      $("history-error").textContent = error.message;
      $("history-error").classList.remove("hidden");
    }
  }
  if (deleteButton && window.confirm("Delete this analysis record?")) {
    try {
      await deleteAnalysis(deleteButton.dataset.deleteType, deleteButton.dataset.deleteId);
      loadHistory();
    } catch (error) {
      $("history-error").textContent = error.message;
      $("history-error").classList.remove("hidden");
    }
  }
});
