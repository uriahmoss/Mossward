const escapeReport = (value) => String(value).replace(
  /[&<>"']/g,
  (character) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]),
);

function renderMetrics(summary) {
  const metrics = [
    ["Scans", summary.total_scans], ["Findings", summary.total_findings],
    ["Open", summary.open_findings], ["Resolved", summary.resolved_findings],
    ["Accepted risk", summary.accepted_risk],
  ];
  document.querySelector("#report-metrics").innerHTML = metrics.map(([label, value]) =>
    `<div class="metric-card"><span>${label}</span><strong>${value}</strong></div>`).join("");
}

function renderTrends(trends) {
  document.querySelector("#trend-list").innerHTML = trends.length
    ? trends.map((point) => `<div class="report-row"><strong>${escapeReport(point.date)}</strong><span>${point.findings} observed · ${point.resolved} resolved</span></div>`).join("")
    : '<div class="no-findings">No trend evidence yet.</div>';
}

function renderExceptions(exceptions) {
  document.querySelector("#exception-list").innerHTML = exceptions.length ? exceptions.map((item) => {
    const lifecycle = item.expires_at ? `Expires ${new Date(item.expires_at).toLocaleDateString()}` : `Open-ended reminder every ${item.reminder_days} days`;
    const review = item.status === "pending" ? `<div><button data-review="approved" data-id="${item.id}" class="compact-button">Approve</button><button data-review="rejected" data-id="${item.id}" class="compact-button">Reject</button></div>` : "";
    return `<div class="report-row"><div><strong>${escapeReport(item.status)} · ${escapeReport(item.finding_id)}</strong><span>${escapeReport(item.reason)} · ${lifecycle}</span></div>${review}</div>`;
  }).join("") : '<div class="no-findings">No risk exceptions recorded.</div>';
}

async function loadReports() {
  try {
    const [summaryResponse, exceptionsResponse] = await Promise.all([fetch("/api/reporting/summary"), fetch("/api/reporting/exceptions")]);
    if (!summaryResponse.ok || !exceptionsResponse.ok) throw new Error("report request failed");
    const summary = await summaryResponse.json();
    renderMetrics(summary);
    renderTrends(summary.trend || []);
    renderExceptions(await exceptionsResponse.json());
  } catch {
    document.querySelector("#report-metrics").innerHTML = '<div class="error">Reports are unavailable.</div>';
  }
}

async function loadRetention() {
  const response = await fetch("/api/admin/evidence-retention");
  if (!response.ok) return;
  const settings = await response.json();
  document.querySelector("#retention-panel").hidden = false;
  document.querySelector("#retention-days").value = settings.retention_days;
}

document.querySelector("#print-report").addEventListener("click", () => window.print());
document.querySelector("#save-retention").addEventListener("click", async () => {
  const retentionDays = Number(document.querySelector("#retention-days").value);
  const response = await fetch("/api/admin/evidence-retention", {method: "PUT", headers: {"Content-Type": "application/json", "X-Mossward-CSRF": "1"}, body: JSON.stringify({retention_days: retentionDays})});
  if (!response.ok) window.alert("Retention must be between 30 and 3650 days.");
});
document.querySelector("#exception-list").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-review]");
  if (!button) return;
  const response = await fetch(`/api/reporting/exceptions/${button.dataset.id}`, {method: "PATCH", headers: {"Content-Type": "application/json", "X-Mossward-CSRF": "1"}, body: JSON.stringify({status: button.dataset.review})});
  if (response.ok) loadReports();
});
loadReports();
loadRetention();
