const error = document.querySelector("#error");
const form = document.querySelector("#form");
const submit = document.querySelector("#submit");

const escapeHTML = (value) => String(value).replace(
  /[&<>"']/g,
  (character) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]),
);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  error.textContent = "";
  submit.disabled = true;
  const body = {
    name: document.querySelector("#name").value,
    targets: document.querySelector("#targets").value.split("\n").map((value) => value.trim()).filter(Boolean),
    ports: document.querySelector("#ports").value.split(",").map((value) => Number(value.trim())).filter(Number.isInteger),
    scope_policy_id: document.querySelector("#scope-policy").value,
  };
  try {
    const response = await fetch("/api/scans", {method: "POST",
      headers: {"Content-Type": "application/json", "X-Mossward-CSRF": "1"}, body: JSON.stringify(body)});
    const result = await response.json();
    if (!response.ok) {
      error.textContent = result.error || "Could not start scan";
      return;
    }
    window.location.href = `/scan-detail.html?id=${encodeURIComponent(result.id)}`;
  } catch {
    error.textContent = "Mossward could not be reached.";
  } finally {
    submit.disabled = false;
  }
});

fetch("/api/scope-policies")
  .then((response) => response.json())
  .then((policies) => {
    const select = document.querySelector("#scope-policy");
    select.innerHTML = policies.map((policy) => `<option value="${policy.id}">${escapeHTML(policy.name)} · ${policy.allowed_ports.length} ports · ${policy.max_targets} targets</option>`).join("");
    document.querySelector("#policy").textContent = policies.length ? `${policies.length} authorized ${policies.length === 1 ? "policy" : "policies"}` : "No enabled policy";
  })
  .catch(() => { document.querySelector("#policy").textContent = "Policy unavailable"; });
