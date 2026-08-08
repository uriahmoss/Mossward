const scans = document.querySelector("#scans");

const escapeHTML = (value) => String(value).replace(
  /[&<>"']/g,
  (character) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]),
);

const emptyState = `
  <span class="empty-icon">○</span>
  <strong>No scans yet</strong>
  <span>Configure your first authorized scan to see activity here.</span>
`;

async function refresh() {
  try {
    const response = await fetch("/api/scans");
    if (!response.ok) throw new Error("Could not load scans");
    const items = await response.json();
    scans.className = items.length ? "" : "empty-state";
    scans.innerHTML = items.length ? items.map((scan) => `
      <a class="scan-item scan-item-link" href="/scan-detail.html?id=${encodeURIComponent(scan.id)}">
        <div class="scan-row">
          <strong>${escapeHTML(scan.name)}</strong>
          <span class="status">${escapeHTML(scan.status)} →</span>
        </div>
        <div class="scan-meta">
          ${scan.targets.map((target) => escapeHTML(
            target.name === target.address ? target.name : `${target.name} (${target.address})`,
          )).join(", ")}
          · ${scan.ports.length} ports · ${(scan.observations || []).length} services · ${(scan.findings || []).length} findings
        </div>
        ${scan.error ? `<div class="error">${escapeHTML(scan.error)}</div>` : ""}
      </a>
    `).join("") : emptyState;
  } catch {
    scans.className = "empty-state";
    scans.innerHTML = `<strong>Activity unavailable</strong><span>Mossward could not load recent scans.</span>`;
  }
}

refresh();
setInterval(refresh, 2000);
