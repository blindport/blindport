const accounts = window.BlindportAccounts;
const loginRoot = document.getElementById("loginRoot");
if (loginRoot.dataset.invalidCredentials === "true") {
  const rejectedToken = accounts.activeToken();
  if (rejectedToken) accounts.forget(rejectedToken);
}
let savedAccounts = accounts.list();

function accountLabel(account, index) {
  if (account.accountId) return `Account ${account.accountId}`;
  return `Saved account ${index + 1}, token ending ${account.token.slice(-6)}`;
}

function renderSavedAccounts() {
  savedAccounts = accounts.list();
  const form = document.getElementById("savedAccountForm");
  const divider = document.getElementById("manualLoginLabel");
  const select = document.getElementById("savedAccountSelect");
  select.replaceChildren();
  savedAccounts.forEach((account, index) => {
    const option = document.createElement("option");
    option.value = String(index);
    option.textContent = accountLabel(account, index);
    select.appendChild(option);
  });
  form.hidden = savedAccounts.length === 0;
  divider.hidden = savedAccounts.length === 0;
}

document.getElementById("savedAccountForm").addEventListener("submit", (event) => {
  const index = Number.parseInt(document.getElementById("savedAccountSelect").value, 10);
  const account = savedAccounts[index];
  if (!account) {
    event.preventDefault();
    return;
  }
  accounts.setActive(account.token, account.accountId);
  document.getElementById("savedAccountToken").value = account.token;
});

document.getElementById("removeSavedAccountBtn").addEventListener("click", () => {
  const index = Number.parseInt(document.getElementById("savedAccountSelect").value, 10);
  const account = savedAccounts[index];
  if (!account) return;
  if (!window.confirm("Remove this saved account token from this browser?")) return;
  if (!accounts.forget(account.token)) {
    document.getElementById("savedAccountStatus").textContent =
      "Could not remove the saved token. Check browser storage permissions and try again.";
    return;
  }
  document.getElementById("savedAccountStatus").textContent = "Saved account removed.";
  renderSavedAccounts();
});

document.getElementById("loginForm").addEventListener("submit", () => {
  const token = document.getElementById("tokenInput").value.trim();
  if (token) accounts.setActive(token);
});

const passkeys = window.BlindportPasskeys;
const passkeyLogin = document.getElementById("passkeyLogin");
if (passkeyLogin && passkeys?.supported) {
  const button = document.getElementById("passkeyLoginBtn");
  const status = document.getElementById("passkeyLoginStatus");
  passkeyLogin.hidden = false;
  button.disabled = false;
  button.addEventListener("click", async () => {
    button.disabled = true;
    status.textContent = "Signing in with passkey.";
    try {
      await passkeys.authenticate();
      accounts.clearActive();
      window.location.assign("/dashboard");
    } catch (_) {
      status.textContent = "Passkey sign-in failed. Use a saved account or bearer token.";
      button.disabled = false;
    }
  });
}

renderSavedAccounts();
