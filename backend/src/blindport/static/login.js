const accounts = window.BlindportAccounts;
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
  event.preventDefault();
  const index = Number.parseInt(document.getElementById("savedAccountSelect").value, 10);
  const account = savedAccounts[index];
  if (!account) return;
  accounts.setActive(account.token, account.accountId);
  window.location.assign("/dashboard");
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

document.getElementById("loginForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const tok = document.getElementById("tokenInput").value.trim();
  if (!tok) return;
  const button = e.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  button.textContent = "Signing in...";
  accounts.setActive(tok);
  window.location.assign("/dashboard");
});

renderSavedAccounts();
