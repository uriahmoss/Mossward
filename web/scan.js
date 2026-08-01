const scans = document.querySelector("#scans");
const error = document.querySelector("#error");
const form = document.querySelector("#form");
const submit = document.querySelector("#submit");

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

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  error.textContent = "";
  submit.disabled = true;

  const ports = document.querySelector("#ports").value
    .split(",")
    .map((value) => Number(value.trim()))
    .filter(Number.isInteger);
  const body = {
    name: document.querySelector("#name").value,
    targets: document.querySelector("#targets").value
      .split("\n")
      .map((value) => value.trim())
      .filter(Boolean),
    ports,
    scope_policy_id: document.querySelector("#scope-policy").value,
  };

  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-Mossward-CSRF": "1"},
      body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok) {
      error.textContent = result.error || "Could not start scan";
    } else {
      window.location.href = `/scan-detail.html?id=${encodeURIComponent(result.id)}`;
    }
  } catch {
    error.textContent = "Mossward could not be reached.";
  } finally {
    submit.disabled = false;
    await refresh();
  }
});

fetch("/api/scope-policies")
  .then((response) => response.json())
  .then((policies) => {
    const select = document.querySelector("#scope-policy");
    select.innerHTML = policies.map((policy) => `<option value="${policy.id}">${escapeHTML(policy.name)} · ${policy.allowed_ports.length} ports · ${policy.max_targets} targets</option>`).join("");
    document.querySelector("#policy").textContent = policies.length ? `${policies.length} authorized ${policies.length === 1 ? "policy" : "policies"}` : "No enabled policy";
  })
  .catch(() => {
    document.querySelector("#policy").textContent = "Policy unavailable";
  });

refresh();
setInterval(refresh, 2000);
