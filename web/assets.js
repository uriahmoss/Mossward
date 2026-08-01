const assetList = document.querySelector("#asset-list");
const assetError = document.querySelector("#asset-error");
const escapeHTML = (value) => String(value).replace(/[&<>"']/g, (character) => (
  {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]));

async function loadAssets() {
  const response = await fetch("/api/assets");
  if (!response.ok) { assetError.textContent = "Could not load the asset inventory."; return; }
  const assets = await response.json();
  assetList.innerHTML = assets.length ? assets.map(renderAsset).join("")
    : "No assets discovered yet. Complete an authorized scan to populate this inventory.";
  document.querySelectorAll(".asset-metadata").forEach(
    (form) => form.addEventListener("submit", saveAssetMetadata),
  );
}

function renderAsset(asset) {
  const names = asset.names.length ? `${asset.names.map(escapeHTML).join(", ")} · ` : "";
  const addresses = asset.addresses.map((item) => escapeHTML(item.address)).join(", ");
  return `<form class="session-row asset-metadata" data-id="${asset.id}"><div>
    <strong><a href="/asset-detail.html?id=${encodeURIComponent(asset.id)}">${escapeHTML(asset.name)}</a></strong>
    <span>${names}${addresses} · first seen ${new Date(asset.first_seen).toLocaleString()} · last seen ${new Date(asset.last_seen).toLocaleString()}</span></div>
    <label>Owner<input name="owner" maxlength="200" value="${escapeHTML(asset.owner)}"></label>
    <label>Environment<input name="environment" list="environment-options" maxlength="200" value="${escapeHTML(asset.environment)}"></label>
    <label>Classification<input name="classification" list="classification-options" maxlength="200" value="${escapeHTML(asset.classification)}"></label>
    <button class="compact-button" type="submit">Save</button>
    <a class="compact-button" href="/scan-detail.html?id=${encodeURIComponent(asset.last_scan_id)}">Latest scan</a></form>`;
}

async function saveAssetMetadata(event) {
  event.preventDefault(); assetError.textContent = "";
  const form = event.currentTarget;
  const response = await fetch(`/api/assets/${encodeURIComponent(form.dataset.id)}`, {method: "PATCH",
    headers: {"Content-Type": "application/json", "X-Mossward-CSRF": "1"}, body: JSON.stringify({
      owner: form.elements.owner.value, environment: form.elements.environment.value,
      classification: form.elements.classification.value})});
  if (!response.ok) { const result = await response.json(); assetError.textContent = result.error; return; }
  await loadAssets();
}

loadAssets();
