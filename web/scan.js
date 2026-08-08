const scans = document.querySelector("#scans");
const searchInput = document.querySelector("#scan-search");
const statusFilter = document.querySelector("#scan-status-filter");
const sortSelect = document.querySelector("#scan-sort");
let latestScans = [];

const escapeHTML = (value) => String(value).replace(
  /[&<>"']/g,
  (character) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]),
);

function configuredScanControls() {
  const params = new URLSearchParams(window.location.search);
  searchInput.value = params.get("search") || "";
  statusFilter.value = params.get("status") || "";
  sortSelect.value = params.get("sort") || "newest";
}

function updateScanControlURL() {
  const params = new URLSearchParams();
  if (searchInput.value.trim()) params.set("search", searchInput.value.trim());
  if (statusFilter.value) params.set("status", statusFilter.value);
  if (sortSelect.value !== "newest") params.set("sort", sortSelect.value);
  window.history.replaceState(null, "", `${window.location.pathname}${params.size ? `?${params}` : ""}`);
}

function filteredScans() {
  const search = searchInput.value.trim().toLowerCase();
  const status = statusFilter.value;
  const items = latestScans.filter((scan) => {
    const targetText = scan.targets.map((target) => `${target.name} ${target.address}`).join(" ");
    return (!search || `${scan.name} ${targetText}`.toLowerCase().includes(search)) && (!status || scan.status === status);
  });
  return items.sort((left, right) => {
    if (sortSelect.value === "oldest") return new Date(left.created_at) - new Date(right.created_at);
    if (sortSelect.value === "name") return left.name.localeCompare(right.name);
    if (sortSelect.value === "status") return left.status.localeCompare(right.status) || left.name.localeCompare(right.name);
    return new Date(right.created_at) - new Date(left.created_at);
  });
}

function renderScans() {
  const items = filteredScans();
  scans.className = items.length ? "" : "empty-state";
  scans.innerHTML = items.length ? items.map((scan) => `
    <a class="scan-item scan-item-link" href="/scan-detail.html?id=${encodeURIComponent(scan.id)}">
      <div class="scan-row"><strong>${escapeHTML(scan.name)}</strong><span class="status">${escapeHTML(scan.status)} →</span></div>
      <div class="scan-meta">${scan.targets.map((target) => escapeHTML(target.name === target.address ? target.name : `${target.name} (${target.address})`)).join(", ")} · ${scan.ports.length} ports · ${(scan.observations || []).length} services · ${(scan.findings || []).length} findings</div>
      ${scan.error ? `<div class="error">${escapeHTML(scan.error)}</div>` : ""}
    </a>`).join("") : `<span class="empty-icon">○</span><strong>No matching scans</strong><span>Adjust the search or status filter, or start a new scan.</span>`;
}

async function refresh() {
  try {
    const response = await fetch("/api/scans");
    if (!response.ok) throw new Error("Could not load scans");
    latestScans = await response.json();
    renderScans();
  } catch {
    scans.className = "empty-state";
    scans.innerHTML = `<strong>Activity unavailable</strong><span>Mossward could not load recent scans.</span>`;
  }
}

[searchInput, statusFilter, sortSelect].forEach((control) => control.addEventListener("input", () => {
  updateScanControlURL();
  renderScans();
}));

configuredScanControls();
refresh();
setInterval(refresh, 2000);
