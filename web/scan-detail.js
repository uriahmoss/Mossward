const params = new URLSearchParams(window.location.search);
const scanID = params.get("id");
const allowedViews = new Set(["overview", "services", "cves", "findings"]);
const requestedView = params.get("view");
const activeView = allowedViews.has(requestedView) ? requestedView : "overview";
const loading = document.querySelector("#detail-loading");
const errorPanel = document.querySelector("#detail-error");
const content = document.querySelector("#detail-content");
let refreshTimer;
let latestScan;
let assignableUsers = [];
const cancelButton = document.querySelector("#cancel-scan");
const resultControls = {
  service_search: {selector: "#service-search", defaultValue: ""},
  service_protocol: {selector: "#service-protocol", defaultValue: ""},
  service_sort: {selector: "#service-sort", defaultValue: "address"},
  cve_search: {selector: "#cve-search", defaultValue: ""},
  cve_severity: {selector: "#cve-severity", defaultValue: ""},
  cve_kev: {selector: "#cve-kev", defaultValue: ""},
  cve_sort: {selector: "#cve-sort", defaultValue: "score"},
  finding_search: {selector: "#finding-search", defaultValue: ""},
  finding_severity: {selector: "#finding-severity", defaultValue: ""},
  finding_service: {selector: "#finding-service", defaultValue: ""},
  finding_sort: {selector: "#finding-sort", defaultValue: "severity"},
};
const severityRank = {critical: 5, high: 4, medium: 3, low: 2, info: 1};

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

function controlValue(id) { return document.querySelector(id).value; }

function filteredObservations(observations) {
  const search = controlValue("#service-search").trim().toLowerCase();
  const protocol = controlValue("#service-protocol");
  return observations.filter((item) => (!protocol || item.protocol === protocol) && (!search ||
    `${item.target} ${item.address} ${item.product || ""} ${item.version || ""}`.toLowerCase().includes(search)))
    .sort((left, right) => {
      if (controlValue("#service-sort") === "product") return (left.product || left.protocol).localeCompare(right.product || right.protocol);
      if (controlValue("#service-sort") === "protocol") return left.protocol.localeCompare(right.protocol) || left.port - right.port;
      if (controlValue("#service-sort") === "newest") return new Date(right.observed_at) - new Date(left.observed_at);
      return left.address.localeCompare(right.address, undefined, {numeric: true}) || left.port - right.port;
    });
}

function filteredCVEs(matches) {
  const search = controlValue("#cve-search").trim().toLowerCase();
  const severity = controlValue("#cve-severity");
  const knownExploited = controlValue("#cve-kev") === "known";
  return matches.filter((item) => (!severity || item.severity === severity) && (!knownExploited || item.known_exploited) &&
    (!search || `${item.cve_id} ${item.product} ${item.version} ${item.target} ${item.address}`.toLowerCase().includes(search)))
    .sort((left, right) => {
      if (controlValue("#cve-sort") === "newest") return new Date(right.matched_at) - new Date(left.matched_at);
      if (controlValue("#cve-sort") === "id") return left.cve_id.localeCompare(right.cve_id);
      if (controlValue("#cve-sort") === "product") return left.product.localeCompare(right.product) || left.cve_id.localeCompare(right.cve_id);
      return right.cvss_score - left.cvss_score || left.cve_id.localeCompare(right.cve_id);
    });
}

function filteredFindings(findings) {
  const search = controlValue("#finding-search").trim().toLowerCase();
  const severity = controlValue("#finding-severity");
  const service = controlValue("#finding-service");
  return findings.filter((item) => (!severity || item.severity === severity) && (!service || item.service === service) &&
    (!search || `${item.title} ${item.check_id} ${item.service} ${item.target} ${item.address}`.toLowerCase().includes(search)))
    .sort((left, right) => {
      if (controlValue("#finding-sort") === "newest") return new Date(right.observed_at) - new Date(left.observed_at);
      if (controlValue("#finding-sort") === "title") return left.title.localeCompare(right.title);
      if (controlValue("#finding-sort") === "address") return left.address.localeCompare(right.address, undefined, {numeric: true}) || left.port - right.port;
      return (severityRank[right.severity] || 0) - (severityRank[left.severity] || 0) || left.title.localeCompare(right.title);
    });
}

function severityCounts(findings, cveMatches) {
  const counts = {critical: 0, high: 0, medium: 0, low: 0, info: 0};
  [...findings, ...cveMatches].forEach((item) => {
    const severity = String(item.severity || "info").toLowerCase();
    counts[severity] = (counts[severity] || 0) + 1;
  });
  return counts;
}

function renderResultPosture(scan, findings, cveMatches) {
  const counts = severityCounts(findings, cveMatches);
  const panel = document.querySelector("#result-posture");
  let level = "clear";
  let title = "No elevated findings observed";
  let description = "Review service evidence and informational checks before treating the scan as complete assurance.";
  if (["queued", "running", "paused"].includes(scan.status)) {
    level = "pending";
    title = "Results are still developing";
    description = "This summary can change until every authorized check has completed.";
  } else if (counts.critical || counts.high) {
    level = counts.critical ? "critical" : "high";
    title = "Immediate review recommended";
    description = `${counts.critical} critical and ${counts.high} high-severity results require attention.`;
  } else if (counts.medium) {
    level = "medium";
    title = "Review recommended";
    description = `${counts.medium} medium-severity ${counts.medium === 1 ? "result requires" : "results require"} review.`;
  } else if (scan.status !== "completed") {
    level = "stopped";
    title = "Scan ended before completion";
    description = "Retained evidence may represent only part of the authorized scope.";
  }
  panel.dataset.level = level;
  document.querySelector("#result-posture-title").textContent = title;
  document.querySelector("#result-posture-description").textContent = description;
  document.querySelector("#severity-breakdown").innerHTML = ["critical", "high", "medium", "low", "info"]
    .map((severity) => `<span data-severity="${severity}"><strong>${counts[severity]}</strong>${severity}</span>`).join("");
}

function render(scan) {
  const observations = scan.observations || [];
  const findings = scan.findings || [];
  const cveMatches = scan.cve_matches || [];
  const displayedObservations = filteredObservations(observations);
  const displayedCVEs = filteredCVEs(cveMatches);
  const displayedFindings = filteredFindings(findings);
  const total = scan.total_checks || (scan.targets.length * scan.ports.length);
  const done = scan.status === "completed" && !scan.done_checks ? total : scan.done_checks;
  const percent = total ? Math.min(100, Math.round((done / total) * 100)) : 0;

  document.title = `${scan.name} · Mossward`;
  document.querySelector("#scan-name").textContent = scan.name;
  document.querySelector("#scan-id").textContent = `Scan ID ${scan.id}`;
  const status = document.querySelector("#scan-status");
  status.textContent = scan.status;
  status.dataset.status = scan.status;
  cancelButton.hidden = !["queued", "running", "paused"].includes(scan.status);

  document.querySelector("#progress-label").textContent =
    scan.status === "queued" ? "Waiting in queue" :
    scan.status === "running" ? `${done} of ${total} checks complete` :
    scan.status === "completed" ? "Scan completed" : "Scan stopped";
  document.querySelector("#progress-percent").textContent = `${percent}%`;
  document.querySelector("#progress-bar").style.width = `${percent}%`;
  document.querySelector(".progress-track").setAttribute("aria-valuenow", String(percent));

  document.querySelector("#target-count").textContent = scan.targets.length;
  document.querySelector("#check-count").textContent = `${done}/${total}`;
  document.querySelector("#finding-count").textContent = observations.length;
  document.querySelector("#issue-count").textContent = findings.length;
  document.querySelector("#cve-count").textContent = cveMatches.length;
  document.querySelector("#services-nav-count").textContent = observations.length;
  document.querySelector("#cves-nav-count").textContent = cveMatches.length;
  document.querySelector("#findings-nav-count").textContent = findings.length;
  renderResultPosture(scan, findings, cveMatches);

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
  scanErrorPanel.hidden = activeView !== "overview" || !scan.error;
  document.querySelector("#scan-error").textContent = scan.error || "";

  document.querySelector("#services-summary").textContent = `${displayedObservations.length} of ${observations.length} observed`;
  document.querySelector("#service-list").innerHTML = displayedObservations.length
    ? displayedObservations.map((service) => `
      <article class="service-detail">
        <div class="finding-heading">
          <div>
            <span class="confidence">${escapeHTML(service.confidence)} confidence</span>
            <h3>${escapeHTML(service.product || service.protocol.toUpperCase())}${service.version ? ` ${escapeHTML(service.version)}` : ""}</h3>
          </div>
          <span class="service-address">${escapeHTML(service.address)}:${service.port}</span>
        </div>
        <dl class="finding-fields">
          <div><dt>Protocol</dt><dd>${escapeHTML(service.protocol)}</dd></div>
          <div><dt>Target</dt><dd>${escapeHTML(service.target)}</dd></div>
          <div><dt>Observed</dt><dd>${escapeHTML(formatDate(service.observed_at))}</dd></div>
        </dl>
        <div class="finding-copy"><strong>Evidence</strong><p>${escapeHTML(service.evidence)}</p></div>
        ${Object.keys(service.metadata || {}).length ? `
          <div class="metadata-grid">${Object.entries(service.metadata).map(([key, value]) => `
            <div><span>${escapeHTML(key.replaceAll("_", " "))}</span><strong>${escapeHTML(value || "—")}</strong></div>
          `).join("")}</div>
        ` : ""}
      </article>
    `).join("")
    : `<div class="no-findings"><span class="empty-icon">○</span><strong>No matching service observations</strong><span>Adjust the service search or protocol filter.</span></div>`;

  document.querySelector("#findings-summary").textContent = `${displayedFindings.length} of ${findings.length} findings`;

  document.querySelector("#cve-summary").textContent = `${displayedCVEs.length} of ${cveMatches.length} matches`;
  document.querySelector("#cve-list").innerHTML = displayedCVEs.length
    ? displayedCVEs.map((match) => `
      <article class="finding-detail">
        <div class="finding-heading">
          <div>
            <span class="severity" data-severity="${escapeHTML(match.severity)}">${escapeHTML(match.severity)} · CVSS ${match.cvss_score.toFixed(1)}</span>
            <h3>${escapeHTML(match.cve_id)}</h3>
            <span class="check-id">${match.known_exploited ? "CISA known exploited · " : ""}${escapeHTML(match.confidence)} confidence</span>
          </div>
          <span class="service-address">${escapeHTML(match.address)}:${match.port}</span>
        </div>
        <dl class="finding-fields">
          <div><dt>Product</dt><dd>${escapeHTML(match.product)} ${escapeHTML(match.version)}</dd></div>
          <div><dt>Target</dt><dd>${escapeHTML(match.target)}</dd></div>
          <div><dt>Matched</dt><dd>${escapeHTML(formatDate(match.matched_at))}</dd></div>
        </dl>
        <div class="finding-copy"><strong>Match evidence</strong><p>${escapeHTML(match.evidence)}</p></div>
        <div class="finding-copy"><strong>Description</strong><p>${escapeHTML(match.description)}</p></div>
        <a class="intel-link" href="${escapeHTML(match.source_url)}" target="_blank" rel="noopener noreferrer">View authoritative NVD record ↗</a>
      </article>
    `).join("")
    : `<div class="no-findings"><span class="empty-icon">○</span><strong>No matching CVEs</strong><span>Adjust the CVE search, severity, or exploitation filter.</span></div>`;
  document.querySelector("#finding-list").innerHTML = displayedFindings.length
    ? displayedFindings.map((finding) => `
      <article class="finding-detail">
        <div class="finding-heading">
          <div>
            <span class="severity" data-severity="${escapeHTML(finding.severity)}">${escapeHTML(finding.severity)}</span>
            <h3>${escapeHTML(finding.title)}</h3>
            <span class="check-id">${escapeHTML(finding.check_id)}</span>
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
        <div class="finding-workflow" data-finding-id="${escapeHTML(finding.id)}">
          <label>Status<select data-workflow-status><option value="open" ${!finding.status||finding.status==='open'?'selected':''}>Open</option><option value="in_progress" ${finding.status==='in_progress'?'selected':''}>In progress</option><option value="resolved" ${finding.status==='resolved'?'selected':''}>Resolved</option></select></label>
          <label>Assigned to<select data-workflow-assignee><option value="">Unassigned</option>${assignableUsers.map(user=>`<option value="${escapeHTML(user.id)}" ${finding.assigned_to===user.id?'selected':''}>${escapeHTML(user.display_name||user.email)}</option>`).join('')}</select></label>
          <button class="compact-button" data-save-workflow type="button">Save workflow</button>
          <button class="compact-button secondary-button" data-request-exception type="button">Request exception</button>
        </div>
      </article>
    `).join("")
    : findings.length
      ? `<div class="no-findings"><span class="empty-icon">○</span><strong>No matching security findings</strong><span>Adjust the finding search, severity, or service filter.</span></div>`
      : `<div class="no-findings"><span class="empty-icon">✓</span><strong>No security findings observed</strong><span>This area updates while the scan is running.</span></div>`;
}

function configureSectionNavigation() {
  document.querySelectorAll("[data-scan-view-link]").forEach((link) => {
    const view = link.dataset.scanViewLink;
    const linkParams = new URLSearchParams(window.location.search);
    linkParams.set("id", scanID || "");
    if (view === "overview") linkParams.delete("view"); else linkParams.set("view", view);
    link.href = `/scan-detail.html?${linkParams}`;
    link.classList.toggle("active", view === activeView);
    if (view === activeView) link.setAttribute("aria-current", "page");
  });
  document.querySelectorAll("[data-scan-view]").forEach((section) => {
    section.hidden = section.dataset.scanView !== activeView;
  });
}

function configureResultControls() {
  const protocols = [...new Set((latestScan?.observations || []).map((item) => item.protocol))].sort();
  const protocolSelect = document.querySelector("#service-protocol");
  const currentProtocol = protocolSelect.value || new URLSearchParams(window.location.search).get("service_protocol") || "";
  protocolSelect.innerHTML = `<option value="">All protocols</option>${protocols.map((protocol) => `<option value="${escapeHTML(protocol)}">${escapeHTML(protocol)}</option>`).join("")}`;
  protocolSelect.value = currentProtocol;
  const services = [...new Set((latestScan?.findings || []).map((item) => item.service).filter(Boolean))].sort();
  const serviceSelect = document.querySelector("#finding-service");
  const currentService = serviceSelect.value || new URLSearchParams(window.location.search).get("finding_service") || "";
  serviceSelect.innerHTML = `<option value="">All services</option>${services.map((service) => `<option value="${escapeHTML(service)}">${escapeHTML(service)}</option>`).join("")}`;
  serviceSelect.value = currentService;
}

function updateResultControlURL() {
  const params = new URLSearchParams(window.location.search);
  Object.entries(resultControls).forEach(([name, control]) => {
    const value = controlValue(control.selector);
    const {defaultValue} = control;
    if (value && value !== defaultValue) params.set(name, value); else params.delete(name);
  });
  window.history.replaceState(null, "", `${window.location.pathname}?${params}`);
  configureSectionNavigation();
}

function restoreResultControls() {
  const params = new URLSearchParams(window.location.search);
  Object.entries(resultControls).forEach(([name, control]) => {
    const value = params.get(name);
    if (value) document.querySelector(control.selector).value = value;
  });
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
    latestScan = scan;
    configureResultControls();
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

configureSectionNavigation();
restoreResultControls();
document.querySelectorAll(".result-toolbar input, .result-toolbar select").forEach((control) => control.addEventListener("input", () => {
  updateResultControlURL();
  if (latestScan) render(latestScan);
}));
loadScan();
fetch('/api/users').then(response=>response.ok?response.json():[]).then(users=>{assignableUsers=users.filter(user=>user.status==='active');if(latestScan)render(latestScan)}).catch(()=>{});

document.querySelector('#finding-list').addEventListener('click',async(event)=>{const button=event.target.closest('[data-save-workflow]');if(!button)return;const panel=button.closest('[data-finding-id]');button.disabled=true;const response=await fetch(`/api/findings/${encodeURIComponent(panel.dataset.findingId)}/workflow`,{method:'PATCH',headers:{'Content-Type':'application/json','X-Mossward-CSRF':'1'},body:JSON.stringify({status:panel.querySelector('[data-workflow-status]').value,assigned_to:panel.querySelector('[data-workflow-assignee]').value})});button.disabled=false;if(response.ok)await loadScan();});
document.querySelector('#finding-list').addEventListener('click',async(event)=>{const button=event.target.closest('[data-request-exception]');if(!button)return;const reason=window.prompt('Reason for accepting this risk');if(!reason)return;const openEnded=window.confirm('Leave this exception open-ended? Cancel to use a 90-day expiry.');const expiresAt=openEnded?null:new Date(Date.now()+90*86400000).toISOString();const panel=button.closest('[data-finding-id]');const response=await fetch(`/api/findings/${encodeURIComponent(panel.dataset.findingId)}/exceptions`,{method:'POST',headers:{'Content-Type':'application/json','X-Mossward-CSRF':'1'},body:JSON.stringify({reason,expires_at:expiresAt,reminder_days:30})});if(response.ok)window.alert('Exception submitted for administrator approval.');});

cancelButton.addEventListener("click", async () => {
  if (!window.confirm("Cancel this scan? Completed checks and collected evidence will be retained.")) return;
  cancelButton.disabled = true;
  const response = await fetch(`/api/scans/${encodeURIComponent(scanID)}/cancel`, {method: "POST",
    headers: {"X-Mossward-CSRF": "1"}});
  if (!response.ok) {
    const result = await response.json();
    cancelButton.disabled = false;
    errorPanel.hidden = false;
    errorPanel.textContent = result.error || "Could not cancel this scan.";
    return;
  }
  await loadScan();
});
