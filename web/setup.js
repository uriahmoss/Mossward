const setupForm = document.querySelector("#setup-form");
const totpStep = document.querySelector("#totp-step");
const recoveryStep = document.querySelector("#recovery-step");
let bootstrapToken = "";

setupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  document.querySelector("#setup-error").textContent = "";
  const password = document.querySelector("#password").value;
  const confirmPassword = document.querySelector("#confirm-password").value;
  if (password !== confirmPassword) {
    document.querySelector("#setup-error").textContent = "Passwords do not match.";
    document.querySelector("#confirm-password").focus();
    return;
  }
  const response = await fetch("/api/auth/bootstrap/begin", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({
    display_name: document.querySelector("#display-name").value,
    email: document.querySelector("#email").value,
    password,
    confirm_password: confirmPassword,
  })});
  const result = await response.json();
  if (!response.ok) { document.querySelector("#setup-error").textContent = result.error; return; }
  bootstrapToken = result.token;
  document.querySelector("#totp-secret").textContent = result.secret;
  document.querySelector("#totp-qr-code").src = result.qr_code_data_uri;
  setupForm.hidden = true;
  totpStep.hidden = false;
});

document.querySelector("#totp-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/api/auth/bootstrap/complete", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({
    token: bootstrapToken, code: document.querySelector("#totp-code").value,
  })});
  const result = await response.json();
  if (!response.ok) { document.querySelector("#totp-error").textContent = result.error; return; }
  document.querySelector("#recovery-codes").textContent = result.recovery_codes.join("\n");
  totpStep.hidden = true;
  recoveryStep.hidden = false;
});
