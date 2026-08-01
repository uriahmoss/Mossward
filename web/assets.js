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
  document.querySelectorAll(".asset-lifecycle").forEach(
    (button) => button.addEventListener("click", updateAssetLifecycle),
  );
  populateMergeSelectors(assets);
}

function populateMergeSelectors(assets) {
  const options = assets.map((asset) => `<option value="${asset.id}">${escapeHTML(asset.name)} · ${escapeHTML(asset.address)}</option>`).join("");
  document.querySelector("#merge-first").innerHTML = options;
  document.querySelector("#merge-second").innerHTML = options;
  if (assets.length > 1) { document.querySelector("#merge-second").selectedIndex = 1; }
}

function renderAsset(asset) {
  const names = asset.names.length ? `${asset.names.map(escapeHTML).join(", ")} · ` : "";
  const addresses = asset.addresses.map((item) => escapeHTML(item.address)).join(", ");
  const retired = asset.lifecycle.status === "retired";
  const lifecycle = retired ? `Retired · ${escapeHTML(asset.lifecycle.retirement_reason)}`
    : asset.lifecycle.status === "stale" ? "Stale" : "Active";
  return `<form class="session-row asset-metadata" data-id="${asset.id}"><div>
    <strong><a href="/asset-detail.html?id=${encodeURIComponent(asset.id)}">${escapeHTML(asset.name)}</a></strong>
    <span>${names}${addresses} · ${lifecycle} · first seen ${new Date(asset.first_seen).toLocaleString()} · last seen ${new Date(asset.last_seen).toLocaleString()}</span></div>
    <label>Owner<input name="owner" maxlength="200" value="${escapeHTML(asset.owner)}"></label>
    <label>Environment<input name="environment" list="environment-options" maxlength="200" value="${escapeHTML(asset.environment)}"></label>
    <label>Classification<input name="classification" list="classification-options" maxlength="200" value="${escapeHTML(asset.classification)}"></label>
    <button class="compact-button" type="submit">Save</button>
    <button class="compact-button asset-lifecycle" type="button" data-status="${retired ? "active" : "retired"}">${retired ? "Restore" : "Retire"}</button>
    <a class="compact-button" href="/scan-detail.html?id=${encodeURIComponent(asset.last_scan_id)}">Latest scan</a></form>`;
}

async function updateAssetLifecycle(event) {
  assetError.textContent = "";
  const button = event.currentTarget;
  const form = button.closest("form");
  const retiring = button.dataset.status === "retired";
  const reason = retiring ? window.prompt("Why is this asset being retired?") : "";
  if (retiring && reason === null) { return; }
  const response = await fetch(`/api/assets/${encodeURIComponent(form.dataset.id)}/lifecycle`, {method: "PATCH",
    headers: {"Content-Type": "application/json", "X-Mossward-CSRF": "1"},
    body: JSON.stringify({status: button.dataset.status, reason})});
  if (!response.ok) { const result = await response.json(); assetError.textContent = result.error; return; }
  await loadAssets();
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

async function loadAgingSettings() {
  const response = await fetch("/api/admin/asset-aging");
  if (!response.ok) { return; }
  const settings = await response.json();
  document.querySelector("#stale-after-days").value = settings.stale_after_days;
}

document.querySelector("#aging-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/api/admin/asset-aging", {method: "PATCH",
    headers: {"Content-Type": "application/json", "X-Mossward-CSRF": "1"},
    body: JSON.stringify({stale_after_days: Number(document.querySelector("#stale-after-days").value)})});
  if (!response.ok) { const result = await response.json(); assetError.textContent = result.error; return; }
  await loadAssets();
});

document.querySelector("#merge-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const first = document.querySelector("#merge-first").value;
  const second = document.querySelector("#merge-second").value;
  if (!first || !second || first === second) { assetError.textContent = "Select two different assets."; return; }
  window.location.href = `/asset-merge.html?first=${encodeURIComponent(first)}&second=${encodeURIComponent(second)}`;
});

loadAgingSettings();
