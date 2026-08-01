const csrfHeaders = {"X-Mossward-CSRF": "1", "Content-Type": "application/json"};
const usersError = document.querySelector("#users-error");
const escapeHTML = (value) => String(value).replace(/[&<>"']/g, (character) => (
  {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]));

async function refreshMFA() {
  return fetch("/api/auth/mfa/verify", {method: "POST", headers: csrfHeaders,
    body: JSON.stringify({code: document.querySelector("#admin-mfa").value})});
}

async function secureFetch(path, options) {
  let response = await fetch(path, options);
  if (response.status !== 403 || !document.querySelector("#admin-mfa").value) { return response; }
  if (!(await refreshMFA()).ok) { return response; }
  response = await fetch(path, options);
  return response;
}

async function loadUsers() {
  const response = await fetch("/api/users");
  if (!response.ok) { usersError.textContent = "Administrator access is required."; return; }
  const users = await response.json();
  document.querySelector("#users-list").innerHTML = users.map((user) => `<article class="session-row"><div><strong>${escapeHTML(user.display_name)}</strong><span>${escapeHTML(user.email)}</span></div>
    <select class="user-role" data-id="${user.id}"><option value="viewer" ${user.role === "viewer" ? "selected" : ""}>Viewer</option><option value="analyst" ${user.role === "analyst" ? "selected" : ""}>Analyst</option><option value="administrator" ${user.role === "administrator" ? "selected" : ""}>Administrator</option></select>
    <button class="user-status compact-button" data-id="${user.id}" data-role="${user.role}" data-status="${user.status}">${user.status === "active" ? "Disable" : "Reactivate"}</button></article>`).join("");
  document.querySelectorAll(".user-role").forEach((select) => select.addEventListener("change", () => updateUser(select.dataset.id, select.value, "active")));
  document.querySelectorAll(".user-status").forEach((button) => button.addEventListener("click", () => updateUser(button.dataset.id, button.dataset.role, button.dataset.status === "active" ? "disabled" : "active")));
}

async function loadInvitations() {
  const response = await fetch("/api/invitations");
  if (!response.ok) { return; }
  const invitations = await response.json();
  document.querySelector("#invitations-list").innerHTML = invitations.length ? invitations.map((item) => `<article class="session-row"><div><strong>${escapeHTML(item.email)}</strong><span>${escapeHTML(item.identity_kind)} · ${escapeHTML(item.role)} · expires ${new Date(item.expires_at).toLocaleString()}</span></div></article>`).join("") : "No pending invitations.";
}

async function loadCertificateStatus() {
  const response = await fetch("/api/admin/certificate-status");
  if (!response.ok) { return; }
  const status = await response.json();
  const expiry = status.expires_at ? ` · expires ${new Date(status.expires_at).toLocaleString()}` : "";
  const problem = status.last_error ? ` · ${escapeHTML(status.last_error)}` : "";
  document.querySelector("#certificate-status").innerHTML = `<article class="session-row"><div><strong>${escapeHTML(status.mode || "local")}</strong><span>${escapeHTML(status.hostname || "Server-managed certificate not enabled")} · ${escapeHTML(status.state)}${expiry}${problem}</span></div></article>`;
}

async function loadEndpointIdentity() {
  const [endpointsResponse, tokensResponse] = await Promise.all([
    fetch("/api/admin/endpoints"), fetch("/api/admin/agent-enrollment-tokens")]);
  if (endpointsResponse.status === 503) {
    document.querySelector("#endpoints-list").textContent = "Endpoint identity is not enabled on this server.";
    document.querySelector("#endpoint-enrollments").textContent = "Configure the endpoint mTLS listener to enable enrollment.";
    return;
  }
  if (!endpointsResponse.ok || !tokensResponse.ok) { return; }
  const endpoints = await endpointsResponse.json();
  const tokens = await tokensResponse.json();
  document.querySelector("#endpoints-list").innerHTML = endpoints.length ? endpoints.map((endpoint) => `<article class="session-row"><div><strong>${escapeHTML(endpoint.name)}</strong><span>${escapeHTML(endpoint.status)} · certificate expires ${new Date(endpoint.expires_at).toLocaleString()}${endpoint.last_seen_at ? ` · last seen ${new Date(endpoint.last_seen_at).toLocaleString()}` : " · never connected"}</span></div></article>`).join("") : "No endpoints enrolled.";
  document.querySelector("#endpoint-enrollments").innerHTML = tokens.length ? tokens.map((token) => `<article class="session-row"><div><strong>${escapeHTML(token.name)}</strong><span>${token.used_at ? `used ${new Date(token.used_at).toLocaleString()}` : `expires ${new Date(token.expires_at).toLocaleString()}`}</span></div></article>`).join("") : "No active enrollment tokens.";
}

document.querySelector("#endpoint-enrollment-form").addEventListener("submit", async (event) => {
  event.preventDefault(); usersError.textContent = "";
  const response = await secureFetch("/api/admin/agent-enrollment-tokens", {method: "POST", headers: csrfHeaders,
    body: JSON.stringify({name: document.querySelector("#endpoint-name").value})});
  const result = await response.json();
  if (!response.ok) { usersError.textContent = result.error; return; }
  document.querySelector("#endpoint-token-result").textContent = `Copy this one-time token now: ${result.token}`;
  event.target.reset(); await loadEndpointIdentity();
});

async function loadOIDCProviders() {
  const response = await fetch("/api/admin/oidc/providers");
  if (!response.ok) { return; }
  const providers = await response.json();
  document.querySelector("#oidc-list").innerHTML = providers.length ? providers.map((provider) => `<article class="session-row"><div><strong>${escapeHTML(provider.name)}</strong><span>${escapeHTML(provider.issuer_url)} · ${provider.enabled ? "enabled" : "disabled"}</span></div>
    <button class="oidc-test compact-button" data-id="${provider.id}">Test</button><button class="oidc-enable compact-button" data-id="${provider.id}" data-enabled="${provider.enabled}">${provider.enabled ? "Disable" : "Enable"}</button></article>`).join("") : "No OIDC providers configured.";
  document.querySelectorAll(".oidc-test").forEach((button) => button.addEventListener("click", () => testOIDCProvider(button.dataset.id)));
  document.querySelectorAll(".oidc-enable").forEach((button) => button.addEventListener("click", () => setOIDCEnabled(button.dataset.id, button.dataset.enabled !== "true")));
}

async function loadPolicy() {
  const response = await fetch("/api/admin/auth-policy");
  if (!response.ok) { return; }
  const policy = await response.json();
  document.querySelector("#session-minutes").value = policy.session_lifetime_minutes;
  document.querySelector("#retention-days").value = policy.audit_retention_days;
  document.querySelector("#mfa-analyst").checked = policy.mfa_required.analyst;
  document.querySelector("#mfa-viewer").checked = policy.mfa_required.viewer;
}

document.querySelector("#policy-form").addEventListener("submit", async (event) => {
  event.preventDefault(); usersError.textContent = "";
  const policy = {session_lifetime_minutes: Number(document.querySelector("#session-minutes").value),
    audit_retention_days: Number(document.querySelector("#retention-days").value), mfa_required: {administrator: true,
      analyst: document.querySelector("#mfa-analyst").checked, viewer: document.querySelector("#mfa-viewer").checked}};
  const response = await secureFetch("/api/admin/auth-policy", {method: "PUT", headers: csrfHeaders, body: JSON.stringify(policy)});
  if (!response.ok) { const result = await response.json(); usersError.textContent = result.error; }
});

async function loadAuditEvents() {
  const params = new URLSearchParams({q: document.querySelector("#audit-query").value,
    severity: document.querySelector("#audit-severity").value, limit: "200"});
  const response = await fetch(`/api/admin/audit-events?${params}`);
  if (!response.ok) { return; }
  const events = await response.json();
  document.querySelector("#audit-list").innerHTML = events.length ? events.map((event) => `<article class="session-row"><div><strong>${escapeHTML(event.action)}</strong><span>${new Date(event.occurred_at).toLocaleString()} · ${escapeHTML(event.severity)} · ${escapeHTML(event.source_ip || "local")}</span></div></article>`).join("") : "No matching audit events.";
}

let scopePolicies = [];
async function loadScopePolicies() {
  const response = await fetch("/api/admin/scope-policies");
  if (!response.ok) { return; }
  scopePolicies = await response.json();
  document.querySelector("#scope-policy-list").innerHTML = scopePolicies.map((policy) => `<article class="session-row"><div><strong>${escapeHTML(policy.name)}</strong><span>${policy.allowed_cidrs.length} networks · ${policy.allowed_ports.length} ports · ${policy.max_targets} targets · ${policy.max_concurrent} workers · ${policy.enabled ? "enabled" : "disabled"}</span></div><button class="scope-policy-edit compact-button" data-id="${policy.id}">Edit</button></article>`).join("");
  document.querySelectorAll(".scope-policy-edit").forEach((button) => button.addEventListener("click", () => editScopePolicy(button.dataset.id)));
}

function editScopePolicy(id) {
  const policy = scopePolicies.find((item) => item.id === id);
  if (!policy) { return; }
  document.querySelector("#scope-policy-id").value = policy.id;
  document.querySelector("#scope-policy-name").value = policy.name;
  document.querySelector("#scope-policy-cidrs").value = policy.allowed_cidrs.join(",");
  document.querySelector("#scope-policy-ports").value = policy.allowed_ports.join(",");
  document.querySelector("#scope-policy-targets").value = policy.max_targets;
  document.querySelector("#scope-policy-concurrency").value = policy.max_concurrent;
  document.querySelector("#scope-policy-enabled").checked = policy.enabled;
}

document.querySelector("#scope-policy-form").addEventListener("submit", async (event) => {
  event.preventDefault(); usersError.textContent = "";
  const id = document.querySelector("#scope-policy-id").value;
  const policy = {name: document.querySelector("#scope-policy-name").value,
    allowed_cidrs: commaValues("#scope-policy-cidrs"),
    allowed_ports: commaValues("#scope-policy-ports").map(Number).filter(Number.isInteger),
    max_targets: Number(document.querySelector("#scope-policy-targets").value),
    max_concurrent: Number(document.querySelector("#scope-policy-concurrency").value),
    enabled: document.querySelector("#scope-policy-enabled").checked};
  const path = id ? `/api/admin/scope-policies/${encodeURIComponent(id)}` : "/api/admin/scope-policies";
  const response = await secureFetch(path, {method: id ? "PUT" : "POST", headers: csrfHeaders, body: JSON.stringify(policy)});
  if (!response.ok) { const result = await response.json(); usersError.textContent = result.error; return; }
  event.target.reset(); document.querySelector("#scope-policy-id").value = ""; await loadScopePolicies();
});

document.querySelector("#audit-search").addEventListener("submit", (event) => { event.preventDefault(); loadAuditEvents(); });

async function oidcAdminAction(path, body = null) {
  const response = await secureFetch(path, {method: "POST", headers: csrfHeaders, body: body === null ? null : JSON.stringify(body)});
  if (!response.ok) { const result = await response.json(); usersError.textContent = result.error; return null; }
  return response;
}

async function testOIDCProvider(id) {
  usersError.textContent = "";
  if (await oidcAdminAction(`/api/admin/oidc/providers/${encodeURIComponent(id)}/test`)) { await loadOIDCProviders(); }
}

async function setOIDCEnabled(id, enabled) {
  usersError.textContent = "";
  if (await oidcAdminAction(`/api/admin/oidc/providers/${encodeURIComponent(id)}/enabled`, {enabled})) { await loadOIDCProviders(); }
}

const commaValues = (id) => document.querySelector(id).value.split(",").map((value) => value.trim()).filter(Boolean);
function roleMappings() {
  return Object.fromEntries(commaValues("#oidc-mappings").map((item) => item.split("=").map((value) => value.trim())).filter((item) => item.length === 2));
}
document.querySelector("#oidc-form").addEventListener("submit", async (event) => {
  event.preventDefault(); usersError.textContent = "";
  const request = {id: document.querySelector("#oidc-id").value, name: document.querySelector("#oidc-name").value,
    issuer_url: document.querySelector("#oidc-issuer").value, client_id: document.querySelector("#oidc-client-id").value,
    client_secret: document.querySelector("#oidc-secret").value, redirect_url: document.querySelector("#oidc-redirect").value,
    provisioning_mode: document.querySelector("#oidc-mode").value, allowed_tenant_id: document.querySelector("#oidc-tenant").value,
    allowed_email_domains: commaValues("#oidc-domains"), allowed_groups: commaValues("#oidc-groups"), role_mappings: roleMappings(),
    default_role: document.querySelector("#oidc-role").value, confirm_administrator_mapping: document.querySelector("#oidc-admin-confirm").checked};
  const response = await secureFetch("/api/admin/oidc/providers", {method: "POST", headers: csrfHeaders, body: JSON.stringify(request)});
  const result = await response.json();
  if (!response.ok) { usersError.textContent = result.error; return; }
  event.target.reset(); await loadOIDCProviders();
});

async function updateUser(id, role, status) {
  usersError.textContent = "";
  const response = await secureFetch(`/api/users/${encodeURIComponent(id)}`, {method: "PATCH", headers: csrfHeaders, body: JSON.stringify({role, status})});
  if (!response.ok) { const result = await response.json(); usersError.textContent = result.error; return; }
  await loadUsers();
}

document.querySelector("#invite-form").addEventListener("submit", async (event) => {
  event.preventDefault(); usersError.textContent = "";
  const response = await secureFetch("/api/invitations", {method: "POST", headers: csrfHeaders, body: JSON.stringify({
    email: document.querySelector("#invite-email").value, role: document.querySelector("#invite-role").value,
    identity_kind: document.querySelector("#invite-kind").value})});
  const result = await response.json();
  if (!response.ok) { usersError.textContent = result.error; return; }
  document.querySelector("#invite-result").textContent = `Copy this one-time invitation token now: ${result.token}`;
  event.target.reset(); await loadInvitations();
});

loadUsers(); loadInvitations(); loadOIDCProviders(); loadPolicy(); loadScopePolicies(); loadAuditEvents(); loadCertificateStatus(); loadEndpointIdentity();
