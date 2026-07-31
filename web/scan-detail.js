const params = new URLSearchParams(window.location.search);
const scanID = params.get("id");
const loading = document.querySelector("#detail-loading");
const errorPanel = document.querySelector("#detail-error");
const content = document.querySelector("#detail-content");
let refreshTimer;

const escapeHTML = (value) => String(value).replace(
  /[&<>"']/g,
  (character) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]),
);

function formatDate(value) {
  if (!value) return "Not yet";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

function formatDuration(scan) {
  if (!scan.started_at) return "Not yet";
  const end = scan.completed_at ? new Date(scan.completed_at) : new Date();
  const milliseconds = Math.max(0, end - new Date(scan.started_at));
  if (milliseconds < 1000) return `${milliseconds} ms`;
  const seconds = Math.floor(milliseconds / 1000);
  if (seconds < 60) return `${seconds} sec`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${seconds % 60} sec`;
}

function render(scan) {
  const total = scan.total_checks || (scan.targets.length * scan.ports.length);
  const done = scan.status === "completed" && !scan.done_checks ? total : scan.done_checks;
  const percent = total ? Math.min(100, Math.round((done / total) * 100)) : 0;

  document.title = `${scan.name} · Mossward`;
  document.querySelector("#scan-name").textContent = scan.name;
  document.querySelector("#scan-id").textContent = `Scan ID ${scan.id}`;
  const status = document.querySelector("#scan-status");
  status.textContent = scan.status;
  status.dataset.status = scan.status;

  document.querySelector("#progress-label").textContent =
    scan.status === "queued" ? "Waiting in queue" :
    scan.status === "running" ? `${done} of ${total} checks complete` :
    scan.status === "completed" ? "Scan completed" : "Scan stopped";
  document.querySelector("#progress-percent").textContent = `${percent}%`;
  document.querySelector("#progress-bar").style.width = `${percent}%`;
  document.querySelector(".progress-track").setAttribute("aria-valuenow", String(percent));

  document.querySelector("#target-count").textContent = scan.targets.length;
  document.querySelector("#port-count").textContent = scan.ports.length;
  document.querySelector("#check-count").textContent = `${done}/${total}`;
  document.querySelector("#finding-count").textContent = scan.findings.length;

  document.querySelector("#created-at").textContent = formatDate(scan.created_at);
  document.querySelector("#started-at").textContent = formatDate(scan.started_at);
  document.querySelector("#completed-at").textContent = formatDate(scan.completed_at);
  document.querySelector("#duration").textContent = formatDuration(scan);

  document.querySelector("#target-list").innerHTML = scan.targets.map((target) => `
    <div class="target-row">
      <div><strong>${escapeHTML(target.name)}</strong><span>${escapeHTML(target.address)}</span></div>
      <span class="scope-approved">Approved</span>
    </div>
  `).join("");
  document.querySelector("#port-list").innerHTML = scan.ports
    .map((port) => `<span class="port-chip">${port}</span>`)
    .join("");

  const scanErrorPanel = document.querySelector("#scan-error-panel");
  scanErrorPanel.hidden = !scan.error;
  document.querySelector("#scan-error").textContent = scan.error || "";

  document.querySelector("#findings-summary").textContent = `${scan.findings.length} observed`;
  document.querySelector("#finding-list").innerHTML = scan.findings.length
    ? scan.findings.map((finding) => `
      <article class="finding-detail">
        <div class="finding-heading">
          <div>
            <span class="severity">${escapeHTML(finding.severity)}</span>
            <h3>${escapeHTML(finding.title)}</h3>
          </div>
          <span class="service-address">${escapeHTML(finding.address)}:${finding.port}</span>
        </div>
        <dl class="finding-fields">
          <div><dt>Service</dt><dd>${escapeHTML(finding.service)}</dd></div>
          <div><dt>Target</dt><dd>${escapeHTML(finding.target)}</dd></div>
          <div><dt>Observed</dt><dd>${escapeHTML(formatDate(finding.observed_at))}</dd></div>
        </dl>
        <div class="finding-copy"><strong>Evidence</strong><p>${escapeHTML(finding.evidence)}</p></div>
        <div class="finding-copy"><strong>Recommendation</strong><p>${escapeHTML(finding.remediation)}</p></div>
      </article>
    `).join("")
    : `<div class="no-findings"><span class="empty-icon">✓</span><strong>No reachable services observed yet</strong><span>This area updates while the scan is running.</span></div>`;
}

function showError(message) {
  loading.hidden = true;
  content.hidden = true;
  errorPanel.hidden = false;
  errorPanel.textContent = message;
}

async function loadScan() {
  if (!scanID || !/^[a-f0-9]{24}$/.test(scanID)) {
    showError("This scan link is invalid or incomplete.");
    return;
  }
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(scanID)}`);
    if (response.status === 404) {
      showError("This scan could not be found.");
      return;
    }
    if (!response.ok) throw new Error("request failed");
    const scan = await response.json();
    loading.hidden = true;
    errorPanel.hidden = true;
    content.hidden = false;
    render(scan);

    if (scan.status === "queued" || scan.status === "running") {
      refreshTimer = window.setTimeout(loadScan, 1000);
    } else if (refreshTimer) {
      window.clearTimeout(refreshTimer);
    }
  } catch {
    showError("Mossward could not load this scan. Return to Network scans and try again.");
  }
}

loadScan();
