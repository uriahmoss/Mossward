let enrollmentToken = "";
const error = document.querySelector("#invite-error");
const queryToken = new URLSearchParams(window.location.search).get("token");
if (queryToken) { document.querySelector("#token").value = queryToken; }

document.querySelector("#invite-accept-form").addEventListener("submit", async (event) => {
  event.preventDefault(); error.textContent = "";
  const response = await fetch("/api/invitations/accept/begin", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({
    token: document.querySelector("#token").value, display_name: document.querySelector("#display-name").value,
    password: document.querySelector("#password").value})});
  const result = await response.json();
  if (!response.ok) { error.textContent = result.error; return; }
  enrollmentToken = result.token; document.querySelector("#totp-secret").textContent = result.secret;
  document.querySelector("#mfa-enrollment").hidden = false;
});

document.querySelector("#invite-complete-form").addEventListener("submit", async (event) => {
  event.preventDefault(); error.textContent = "";
  const response = await fetch("/api/invitations/accept/complete", {method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({token: enrollmentToken, code: document.querySelector("#code").value})});
  const result = await response.json();
  if (!response.ok) { error.textContent = result.error; return; }
  document.querySelector("#recovery-codes").textContent = result.recovery_codes.join("\n");
  document.querySelector("#recovery").hidden = false; document.querySelector("#mfa-enrollment").hidden = true;
});
