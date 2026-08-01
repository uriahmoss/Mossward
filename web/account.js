const sessionList = document.querySelector("#session-list");
const accountError = document.querySelector("#account-error");
const csrfHeaders = {"X-Mossward-CSRF": "1"};
const credentialList = document.querySelector("#credential-list");
const credentialError = document.querySelector("#credential-error");
const escapeHTML = (value) => String(value).replace(/[&<>"']/g, (character) => (
  {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]
));

function formatDate(value) {
  return new Intl.DateTimeFormat(undefined, {dateStyle: "medium", timeStyle: "short"}).format(new Date(value));
}

async function loadSessions() {
  const response = await fetch("/api/auth/sessions");
  if (!response.ok) { accountError.textContent = "Could not load active sessions."; return; }
  const sessions = await response.json();
  sessionList.innerHTML = sessions.map((session) => `
    <article class="session-row">
      <div><strong>${session.current ? "Current session" : "Session"}</strong><span>${escapeHTML(session.source_ip)} · started ${escapeHTML(formatDate(session.created_at))} · expires ${escapeHTML(formatDate(session.expires_at))}</span></div>
      ${session.current ? '<span class="status">Current</span>' : `<button class="session-revoke compact-button" data-id="${session.id}">Revoke</button>`}
    </article>`).join("");
  document.querySelectorAll(".session-revoke").forEach((button) => button.addEventListener("click", () => revokeSession(button.dataset.id)));
}

async function revokeSession(id) {
  const response = await fetch(`/api/auth/sessions/${encodeURIComponent(id)}`, {method: "DELETE", headers: csrfHeaders});
  if (!response.ok) { accountError.textContent = "Could not revoke that session."; return; }
  await loadSessions();
}

document.querySelector("#revoke-others").addEventListener("click", async () => {
  const response = await fetch("/api/auth/sessions/revoke-others", {method: "POST", headers: csrfHeaders});
  if (!response.ok) { accountError.textContent = "Could not revoke other sessions."; return; }
  await loadSessions();
});

document.querySelector("#logout").addEventListener("click", async () => {
  await fetch("/api/auth/logout", {method: "POST", headers: csrfHeaders});
  window.location.href = "/login.html";
});

loadSessions();

function decodeBase64URL(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const bytes = Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0));
  return bytes.buffer;
}

function encodeBase64URL(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function registrationOptions(options) {
  const publicKey = options.publicKey || options.response || options;
  publicKey.challenge = decodeBase64URL(publicKey.challenge);
  publicKey.user.id = decodeBase64URL(publicKey.user.id);
  (publicKey.excludeCredentials || []).forEach((item) => { item.id = decodeBase64URL(item.id); });
  return publicKey;
}

function registrationResponse(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64URL(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: encodeBase64URL(credential.response.attestationObject),
      clientDataJSON: encodeBase64URL(credential.response.clientDataJSON),
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

async function loadCredentials() {
  const response = await fetch("/api/auth/webauthn/credentials");
  if (!response.ok) { credentialError.textContent = "Could not load WebAuthn credentials."; return; }
  const credentials = await response.json();
  credentialList.innerHTML = credentials.length ? credentials.map((credential) => `
    <article class="session-row"><div><strong>${escapeHTML(credential.name)}</strong><span>Added ${escapeHTML(formatDate(credential.created_at))}</span></div>
    <button class="credential-remove compact-button" data-id="${credential.id}">Remove</button></article>`).join("") : '<div class="no-findings">No WebAuthn credentials enrolled.</div>';
  document.querySelectorAll(".credential-remove").forEach((button) => button.addEventListener("click", () => removeCredential(button.dataset.id)));
}

async function verifyMFA() {
  return fetch("/api/auth/mfa/verify", {method: "POST", headers: {...csrfHeaders, "Content-Type": "application/json"},
    body: JSON.stringify({code: document.querySelector("#mfa-code").value})});
}

document.querySelector("#webauthn-form").addEventListener("submit", async (event) => {
  event.preventDefault(); credentialError.textContent = "";
  if (!window.PublicKeyCredential) { credentialError.textContent = "This browser does not support WebAuthn."; return; }
  let begun = await fetch("/api/auth/webauthn/register/begin", {method: "POST", headers: csrfHeaders});
  if (begun.status === 403 && document.querySelector("#mfa-code").value) {
    const verified = await verifyMFA();
    if (verified.ok) { begun = await fetch("/api/auth/webauthn/register/begin", {method: "POST", headers: csrfHeaders}); }
  }
  if (!begun.ok) { credentialError.textContent = "Could not begin credential registration."; return; }
  const enrollment = await begun.json();
  try {
    const credential = await navigator.credentials.create({publicKey: registrationOptions(enrollment.options)});
    const finished = await fetch("/api/auth/webauthn/register/finish", {method: "POST", headers: {...csrfHeaders,
      "Content-Type": "application/json", "X-Mossward-Ceremony": enrollment.ceremony_token,
      "X-Mossward-Credential-Name": document.querySelector("#credential-name").value}, body: JSON.stringify(registrationResponse(credential))});
    if (!finished.ok) { throw new Error("registration rejected"); }
    event.target.reset(); await loadCredentials();
  } catch (_) { credentialError.textContent = "Credential registration was cancelled or could not be verified."; }
});

async function removeCredential(id) {
  let response = await fetch(`/api/auth/webauthn/credentials/${encodeURIComponent(id)}`, {method: "DELETE", headers: csrfHeaders});
  if (response.status === 403 && document.querySelector("#mfa-code").value) {
    const verified = await verifyMFA();
    if (verified.ok) { response = await fetch(`/api/auth/webauthn/credentials/${encodeURIComponent(id)}`, {method: "DELETE", headers: csrfHeaders}); }
  }
  if (response.status === 403) { credentialError.textContent = "Recent MFA is required. Enter a current code or sign in again with SSO."; return; }
  if (!response.ok) { credentialError.textContent = "Could not remove that credential."; return; }
  credentialError.textContent = ""; await loadCredentials();
}

loadCredentials();
