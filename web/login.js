document.querySelector("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/api/auth/login", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({
    email: document.querySelector("#email").value,
    password: document.querySelector("#password").value,
    code: document.querySelector("#code").value,
  })});
  const result = await response.json();
  if (!response.ok) { document.querySelector("#login-error").textContent = result.error; return; }
  window.location.href = "/";
});

function decodeBase64URL(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0)).buffer;
}

function encodeBase64URL(value) {
  let binary = "";
  new Uint8Array(value).forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function assertionOptions(options) {
  const publicKey = options.publicKey || options.response || options;
  publicKey.challenge = decodeBase64URL(publicKey.challenge);
  (publicKey.allowCredentials || []).forEach((item) => { item.id = decodeBase64URL(item.id); });
  return publicKey;
}

function assertionResponse(credential) {
  return {id: credential.id, rawId: encodeBase64URL(credential.rawId), type: credential.type,
    response: {authenticatorData: encodeBase64URL(credential.response.authenticatorData),
      clientDataJSON: encodeBase64URL(credential.response.clientDataJSON),
      signature: encodeBase64URL(credential.response.signature),
      userHandle: credential.response.userHandle ? encodeBase64URL(credential.response.userHandle) : null},
    clientExtensionResults: credential.getClientExtensionResults()};
}

document.querySelector("#webauthn-login").addEventListener("click", async () => {
  const error = document.querySelector("#login-error"); error.textContent = "";
  if (!window.PublicKeyCredential) { error.textContent = "This browser does not support WebAuthn."; return; }
  const begun = await fetch("/api/auth/webauthn/login/begin", {method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({email: document.querySelector("#email").value, password: document.querySelector("#password").value})});
  if (!begun.ok) { error.textContent = "Invalid email, password, or security key."; return; }
  const login = await begun.json();
  try {
    const credential = await navigator.credentials.get({publicKey: assertionOptions(login.options)});
    const finished = await fetch("/api/auth/webauthn/login/finish", {method: "POST", headers: {"Content-Type": "application/json",
      "X-Mossward-Ceremony": login.ceremony_token}, body: JSON.stringify(assertionResponse(credential))});
    if (!finished.ok) { throw new Error("authentication rejected"); }
    window.location.href = "/";
  } catch (_) { error.textContent = "Security-key authentication was cancelled or could not be verified."; }
});

async function loadSSOProviders() {
  const response = await fetch("/api/auth/oidc/providers");
  if (!response.ok) { return; }
  const providers = await response.json();
  document.querySelector("#sso-providers").innerHTML = providers.map((provider) =>
    `<a class="compact-button" href="/api/auth/oidc/${encodeURIComponent(provider.id)}/start">Sign in with ${provider.name.replace(/[&<>"']/g, "")}</a>`).join("");
}

loadSSOProviders();
