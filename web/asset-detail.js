const params = new URLSearchParams(window.location.search);
const escapeHTML = (value) => String(value).replace(
  /[&<>"']/g,
  (character) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]),
);

async function loadAsset() {
  const id = params.get("id") || "";
  const response = await fetch(`/api/assets/${encodeURIComponent(id)}`);
  if (!response.ok) {
    document.querySelector("#asset-detail-error").textContent = "Could not load this asset.";
    return;
  }
  const asset = await response.json();
  document.querySelector("#asset-name").textContent = asset.name;
  document.querySelector("#asset-summary").textContent = [
    asset.addresses.map((item) => item.address).join(", "),
    asset.owner || "Unassigned", asset.environment || "No environment",
    asset.classification || "Unclassified",
  ].join(" · ");
  document.querySelector("#service-list").innerHTML = asset.services.length
    ? asset.services.map(renderService).join("")
    : "No reachable services have been recorded for this asset.";
  document.querySelector("#evidence-list").innerHTML = asset.evidence.length
    ? asset.evidence.map(renderEvidence).join("") : "No provenance records are available.";
}

function renderEvidence(evidence) {
  const source = `${evidence.source_type} · ${evidence.source_id}`;
  const sourceLink = evidence.scan_id
    ? `<a class="compact-button" href="/scan-detail.html?id=${encodeURIComponent(evidence.scan_id)}">Source scan</a>` : "";
  return `<div class="session-row"><div><strong>${escapeHTML(evidence.summary)}</strong>
    <span>${escapeHTML(source)} · ${escapeHTML(evidence.record_type)} · ${new Date(evidence.collected_at).toLocaleString()}</span></div>${sourceLink}</div>`;
}

function renderService(service) {
  const product = [service.product, service.version].filter(Boolean).join(" ") || "Product not disclosed";
  return `<article class="card">
    <div class="scan-row"><strong>${escapeHTML(service.protocol)} · ${escapeHTML(service.address)}:${service.port}</strong>
      <span class="status">${escapeHTML(service.state.replace("_", " "))}</span></div>
    <p>${escapeHTML(product)} · ${escapeHTML(service.confidence)} confidence · observed ${service.observation_count} times</p>
    <p>First seen ${new Date(service.first_seen).toLocaleString()} · last seen ${new Date(service.last_seen).toLocaleString()} · last checked ${new Date(service.last_checked).toLocaleString()}</p>
    <details><summary>Observation timeline</summary>${service.events.map(renderEvent).join("")}</details>
  </article>`;
}

function renderEvent(event) {
  const product = [event.product, event.version].filter(Boolean).join(" ") || "Product not disclosed";
  const cves = event.cve_ids.length ? `CVEs: ${event.cve_ids.map(escapeHTML).join(", ")}` : "No CVE matches";
  return `<div class="session-row"><div><strong>${new Date(event.observed_at).toLocaleString()}</strong>
    <span>${escapeHTML(product)} · ${event.finding_ids.length} findings · ${cves}</span></div>
    <a class="compact-button" href="/scan-detail.html?id=${encodeURIComponent(event.scan_id)}">Source scan</a></div>`;
}

loadAsset();
