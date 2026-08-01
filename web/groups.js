const csrfHeaders = {"X-Mossward-CSRF": "1", "Content-Type": "application/json"};
const pageError = document.querySelector("#groups-error");
const escapeHTML = (value) => String(value).replace(
  /[&<>"']/g,
  (character) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]),
);

let groups = [];
let assets = [];
let policies = [];

async function secureFetch(path, options) {
  let response = await fetch(path, options);
  const mfaCode = document.querySelector("#group-mfa").value;
  if (response.status !== 403 || !mfaCode) return response;
  const verified = await fetch("/api/auth/mfa/verify", {
    method: "POST", headers: csrfHeaders, body: JSON.stringify({code: mfaCode}),
  });
  if (!verified.ok) return response;
  return fetch(path, options);
}

async function loadWorkspace() {
  const responses = await Promise.all([
    fetch("/api/asset-groups"), fetch("/api/assets"),
    fetch("/api/scan-policies"), fetch("/api/scope-policies"),
  ]);
  if (responses.some((response) => !response.ok)) {
    pageError.textContent = "Could not load group settings.";
    return;
  }
  [groups, assets, policies] = await Promise.all(responses.slice(0, 3).map((response) => response.json()));
  const scopes = await responses[3].json();
  renderGroups();
  renderSelections(scopes);
  renderPolicies();
  await loadNotificationSettings();
}

async function loadNotificationSettings() {
  const [usersResponse, smtpResponse] = await Promise.all([fetch("/api/users"), fetch("/api/admin/smtp")]);
  if (!usersResponse.ok || !smtpResponse.ok) return;
  const [users, smtp] = await Promise.all([usersResponse.json(), smtpResponse.json()]);
  document.querySelector("#smtp-recipients").innerHTML = users
    .filter((user) => user.role === "administrator" && user.status === "active")
    .map((user) => `<option value="${user.id}" ${smtp.recipient_user_ids.includes(user.id) ? "selected" : ""}>${escapeHTML(user.display_name)} · ${escapeHTML(user.email)}</option>`).join("");
  document.querySelector("#smtp-enabled").checked = smtp.enabled;
  document.querySelector("#smtp-host").value = smtp.host || "";
  document.querySelector("#smtp-port").value = smtp.port || 587;
  document.querySelector("#smtp-tls").value = smtp.tls_mode || "starttls";
  document.querySelector("#smtp-username").value = smtp.username || "";
  document.querySelector("#smtp-from").value = smtp.from_address || "";
  document.querySelector("#smtp-password").placeholder = smtp.has_password ? "Password already stored; leave blank to keep it" : "SMTP password";
}

function renderGroups() {
  const policyNames = Object.fromEntries(policies.map((policy) => [policy.id, policy.name]));
  const assetNames = Object.fromEntries(assets.map((asset) => [asset.id, asset.name]));
  document.querySelector("#group-list").innerHTML = groups.length ? groups.map((group) => `
    <article class="session-row">
      <div><strong>${escapeHTML(group.name)}</strong><span>${group.asset_ids.length} assets · policies: ${
        group.scan_policy_ids.length
          ? group.scan_policy_ids.map((id) => escapeHTML(policyNames[id] || id)).join(", ")
          : "none"
      }${group.description ? ` · ${escapeHTML(group.description)}` : ""}</span>
      <span>${group.asset_ids.map((id) => `<button type="button" class="group-remove-member compact-button" data-group="${group.id}" data-asset="${id}">Remove ${escapeHTML(assetNames[id] || id)}</button>`).join(" ")}</span></div>
      <button class="group-add-policy compact-button" data-id="${group.id}">Add policy</button>
    </article>`).join("") : "No asset groups.";
  document.querySelectorAll(".group-add-policy").forEach(
    (button) => button.addEventListener("click", () => startPolicyForGroup(button.dataset.id)),
  );
  document.querySelectorAll(".group-remove-member").forEach(
    (button) => button.addEventListener("click", () => removeMembership(button.dataset.group, button.dataset.asset)),
  );
}

function renderSelections(scopes) {
  const groupOptions = groups.map(
    (group) => `<option value="${group.id}">${escapeHTML(group.name)}</option>`,
  ).join("");
  document.querySelector("#membership-group").innerHTML = groupOptions;
  document.querySelector("#scan-policy-groups").innerHTML = groupOptions;
  document.querySelector("#membership-asset").innerHTML = assets.map(
    (asset) => `<option value="${asset.id}">${escapeHTML(asset.name)} · ${escapeHTML(asset.address)}</option>`,
  ).join("");
  document.querySelector("#scan-policy-scope").innerHTML = scopes.map(
    (scope) => `<option value="${scope.id}">${escapeHTML(scope.name)}</option>`,
  ).join("");
}

function renderPolicies() {
  const groupNames = Object.fromEntries(groups.map((group) => [group.id, group.name]));
  document.querySelector("#scan-policy-list").innerHTML = policies.length ? policies.map((policy) => `
    <article class="session-row">
      <div><strong>${escapeHTML(policy.name)}</strong><span>${
        policy.group_ids.map((id) => escapeHTML(groupNames[id] || id)).join(", ")
      } · ${policy.ports.length} ports · ${policy.schedule_kind === "manual" ? "manual" : `${escapeHTML(policy.schedule_kind)} in ${escapeHTML(policy.schedule_timezone)}${policy.next_run_at ? ` · next ${new Date(policy.next_run_at).toLocaleString()}` : ""}`} · ${policy.enabled ? "enabled" : "disabled"}</span></div>
      <button class="edit-policy compact-button" data-id="${policy.id}">Edit</button>
      ${policy.enabled ? `<button class="run-policy compact-button" data-id="${policy.id}">Run now</button>` : ""}
    </article>`).join("") : "No reusable scan policies.";
  document.querySelectorAll(".edit-policy").forEach(
    (button) => button.addEventListener("click", () => editPolicy(button.dataset.id)),
  );
  document.querySelectorAll(".run-policy").forEach(
    (button) => button.addEventListener("click", () => runPolicy(button.dataset.id)),
  );
}

document.querySelector("#group-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  pageError.textContent = "";
  const response = await secureFetch("/api/admin/asset-groups", {
    method: "POST", headers: csrfHeaders, body: JSON.stringify({
      name: document.querySelector("#group-name").value,
      description: document.querySelector("#group-description").value,
    }),
  });
  if (!response.ok) {
    const result = await response.json();
    pageError.textContent = result.error;
    return;
  }
  event.target.reset();
  await loadWorkspace();
});

document.querySelector("#membership-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const groupID = document.querySelector("#membership-group").value;
  const assetID = document.querySelector("#membership-asset").value;
  const path = `/api/admin/asset-groups/${encodeURIComponent(groupID)}/members/${encodeURIComponent(assetID)}`;
  let response = await addMembership(path, false);
  if (response.status === 409) response = await authorizeOverlap(path, response);
  if (!response || response.ok) {
    if (response) await loadWorkspace();
    return;
  }
  const result = await response.json();
  pageError.textContent = result.error;
});

function addMembership(path, acknowledgeOverlap) {
  return secureFetch(path, {
    method: "POST", headers: csrfHeaders, body: JSON.stringify({acknowledge_overlap: acknowledgeOverlap}),
  });
}

async function authorizeOverlap(path, response) {
  const result = await response.json();
  if (!window.confirm(`${result.error}. Authorize this overlap?`)) return null;
  return addMembership(path, true);
}

async function removeMembership(groupID, assetID) {
  const path = `/api/admin/asset-groups/${encodeURIComponent(groupID)}/members/${encodeURIComponent(assetID)}`;
  const response = await secureFetch(path, {method: "DELETE", headers: csrfHeaders});
  if (!response.ok) {
    const result = await response.json();
    pageError.textContent = result.error;
    return;
  }
  await loadWorkspace();
}

document.querySelector("#scan-policy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = document.querySelector("#scan-policy-id").value;
  const selectedGroups = [...document.querySelector("#scan-policy-groups").selectedOptions]
    .map((option) => option.value);
  const ports = document.querySelector("#scan-policy-ports").value.split(",")
    .map((value) => Number(value.trim())).filter(Number.isInteger);
  const response = await secureFetch(
    id ? `/api/admin/scan-policies/${encodeURIComponent(id)}` : "/api/admin/scan-policies",
    {method: id ? "PUT" : "POST", headers: csrfHeaders, body: JSON.stringify({
      name: document.querySelector("#scan-policy-name").value,
      scope_policy_id: document.querySelector("#scan-policy-scope").value,
      group_ids: selectedGroups, ports,
      enabled: document.querySelector("#scan-policy-enabled").checked,
      schedule_kind: document.querySelector("#schedule-kind").value,
      schedule_expression: document.querySelector("#schedule-expression").value,
      schedule_timezone: document.querySelector("#schedule-timezone").value,
      window_start: document.querySelector("#window-start").value,
      window_end: document.querySelector("#window-end").value,
      run_missed: document.querySelector("#run-missed").checked,
      long_run_alert_seconds: Math.round(Number(document.querySelector("#long-alert-hours").value || 0) * 3600),
    })},
  );
  if (!response.ok) {
    const result = await response.json();
    pageError.textContent = result.error;
    return;
  }
  event.target.reset();
  document.querySelector("#scan-policy-id").value = "";
  await loadWorkspace();
});

function startPolicyForGroup(id) {
  document.querySelector("#scan-policy-id").value = "";
  [...document.querySelector("#scan-policy-groups").options].forEach((option) => {
    option.selected = option.value === id;
  });
  document.querySelector("#scan-policy-name").focus();
}

function editPolicy(id) {
  const policy = policies.find((item) => item.id === id);
  if (!policy) return;
  document.querySelector("#scan-policy-id").value = policy.id;
  document.querySelector("#scan-policy-name").value = policy.name;
  document.querySelector("#scan-policy-scope").value = policy.scope_policy_id;
  document.querySelector("#scan-policy-ports").value = policy.ports.join(",");
  document.querySelector("#scan-policy-enabled").checked = policy.enabled;
  document.querySelector("#schedule-kind").value = policy.schedule_kind;
  document.querySelector("#schedule-expression").value = policy.schedule_expression;
  document.querySelector("#schedule-timezone").value = policy.schedule_timezone;
  document.querySelector("#window-start").value = policy.window_start;
  document.querySelector("#window-end").value = policy.window_end;
  document.querySelector("#run-missed").checked = policy.run_missed;
  document.querySelector("#long-alert-hours").value = policy.long_run_alert_seconds / 3600;
  [...document.querySelector("#scan-policy-groups").options].forEach((option) => {
    option.selected = policy.group_ids.includes(option.value);
  });
  document.querySelector("#scan-policy-name").focus();
}

async function runPolicy(id) {
  const response = await fetch(`/api/scan-policies/${encodeURIComponent(id)}/run`, {
    method: "POST", headers: {"X-Mossward-CSRF": "1"},
  });
  const result = await response.json();
  if (!response.ok) {
    pageError.textContent = result.error;
    return;
  }
  window.location.href = `/scan-detail.html?id=${encodeURIComponent(result.id)}`;
}

document.querySelector("#smtp-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const recipientIDs = [...document.querySelector("#smtp-recipients").selectedOptions].map((option) => option.value);
  const response = await secureFetch("/api/admin/smtp", {method: "PUT", headers: csrfHeaders, body: JSON.stringify({
    enabled: document.querySelector("#smtp-enabled").checked,
    host: document.querySelector("#smtp-host").value,
    port: Number(document.querySelector("#smtp-port").value),
    tls_mode: document.querySelector("#smtp-tls").value,
    username: document.querySelector("#smtp-username").value,
    password: document.querySelector("#smtp-password").value,
    from_address: document.querySelector("#smtp-from").value,
    recipient_user_ids: recipientIDs,
  })});
  if (!response.ok) {
    const result = await response.json();
    pageError.textContent = result.error;
    return;
  }
  document.querySelector("#smtp-password").value = "";
  await loadNotificationSettings();
});

loadWorkspace();
