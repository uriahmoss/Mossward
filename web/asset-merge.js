const params = new URLSearchParams(window.location.search);
const ids = [params.get("first"), params.get("second")];
const errorBox = document.querySelector("#merge-error");
const fields = ["name", "address", "owner", "environment", "classification", "lifecycle"];
let assets = [];

const escapeHTML = (value) => String(value).replace(/[&<>"']/g, (character) => (
  {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]));

async function loadMergeReview() {
  if (!ids[0] || !ids[1] || ids[0] === ids[1]) { errorBox.textContent = "Two different assets are required."; return; }
  const responses = await Promise.all(ids.map((id) => fetch(`/api/assets/${encodeURIComponent(id)}`)));
  if (responses.some((response) => !response.ok)) { errorBox.textContent = "Could not load both assets."; return; }
  assets = await Promise.all(responses.map((response) => response.json()));
  const options = assets.map((asset, index) => `<option value="${asset.id}">${index === 0 ? "First" : "Second"}: ${escapeHTML(asset.name)}</option>`).join("");
  document.querySelector("#survivor").innerHTML = options;
  document.querySelector("#merge-fields").innerHTML = fields.map((field) => renderField(field)).join("");
}

function renderField(field) {
  const label = field[0].toUpperCase() + field.slice(1);
  const options = assets.map((asset, index) => `<option value="${asset.id}">${index === 0 ? "First" : "Second"}: ${escapeHTML(fieldValue(asset, field))}</option>`).join("");
  return `<label>${label}<select data-field="${field}">${options}</select></label>`;
}

function fieldValue(asset, field) {
  if (field === "lifecycle") { return asset.lifecycle.status; }
  return asset[field] || "(empty)";
}

function applyAll(asset) {
  document.querySelectorAll("[data-field]").forEach((select) => { select.value = asset.id; });
}

document.querySelector("#apply-first").addEventListener("click", () => applyAll(assets[0]));
document.querySelector("#apply-second").addEventListener("click", () => applyAll(assets[1]));
document.querySelector("#apply-newest").addEventListener("click", () => {
  const newest = new Date(assets[0].last_seen) >= new Date(assets[1].last_seen) ? assets[0] : assets[1];
  applyAll(newest);
  document.querySelector("#survivor").value = newest.id;
});

document.querySelector("#merge-review").addEventListener("submit", async (event) => {
  event.preventDefault();
  const survivorID = document.querySelector("#survivor").value;
  const source = (field) => document.querySelector(`[data-field="${field}"]`).value;
  const request = {survivor_id: survivorID, merged_id: ids.find((id) => id !== survivorID),
    name_from: source("name"), address_from: source("address"), owner_from: source("owner"),
    environment_from: source("environment"), classification_from: source("classification"),
    lifecycle_from: source("lifecycle")};
  const response = await fetch("/api/admin/assets/merge", {method: "POST",
    headers: {"Content-Type": "application/json", "X-Mossward-CSRF": "1"}, body: JSON.stringify(request)});
  if (!response.ok) { const result = await response.json(); errorBox.textContent = result.error; return; }
  window.location.href = `/asset-detail.html?id=${encodeURIComponent(survivorID)}`;
});

loadMergeReview();
