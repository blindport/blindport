const dashboardRoot = document.getElementById("dashboardRoot");
const accountId = dashboardRoot.dataset.accountId;
const authMethod = dashboardRoot.dataset.authMethod;
const accounts = window.BlindportAccounts;
const btcUsdPrice = Number.parseFloat(dashboardRoot.dataset.btcUsd);
const savedAccount = accounts.forAccount(accountId);
const activeToken = accounts.activeToken();
const activeAccount = accounts.list().find((account) => account.token === activeToken);
let localToken = savedAccount?.token || "";

if (!localToken && authMethod === "token" && activeAccount && !activeAccount.accountId) {
  accounts.save(activeToken, accountId);
  localToken = activeToken;
}

function authHeaders() {
  const csrfCookie = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("blindport_csrf="));
  const csrfToken = csrfCookie ? decodeURIComponent(csrfCookie.slice("blindport_csrf=".length)) : "";
  return { "Content-Type": "application/json", "X-CSRF-Token": csrfToken };
}

async function logout() {
  const button = document.getElementById("logoutBtn");
  button.disabled = true;
  try {
    await fetch("/api/v1/browser-session", { method: "DELETE", headers: authHeaders() });
  } finally {
    accounts.clearActive();
    window.location.assign("/dashboard");
  }
}

document.getElementById("logoutBtn").addEventListener("click", () => void logout());

const accountTokenControls = document.getElementById("accountTokenControls");
const accountTokenUnavailable = document.getElementById("accountTokenUnavailable");
const accountTokenInput = document.getElementById("accountToken");
if (!localToken) {
  accountTokenControls.hidden = true;
  accountTokenUnavailable.hidden = false;
} else {
  accountTokenInput.value = localToken;
}

document.getElementById("revealTokenBtn").addEventListener("click", (event) => {
  if (!localToken) return;
  const revealed = accountTokenInput.type === "text";
  accountTokenInput.type = revealed ? "password" : "text";
  event.currentTarget.textContent = revealed ? "Reveal" : "Hide";
  event.currentTarget.setAttribute("aria-pressed", String(!revealed));
});

document.getElementById("copyAccountTokenBtn").addEventListener("click", async () => {
  if (!localToken) return;
  const copied = await accounts.copyText(localToken);
  document.getElementById("accountTokenStatus").textContent = copied
    ? "Token copied."
    : "Copy failed. Reveal the token and copy it manually.";
});

document.getElementById("forgetAccountBtn").addEventListener("click", () => {
  if (!localToken || !window.confirm("Forget this account token from this browser and sign out?")) return;
  if (!accounts.forget(localToken)) {
    document.getElementById("accountTokenStatus").textContent =
      "Could not remove the saved token. Check browser storage permissions and try again.";
    return;
  }
  localToken = "";
  void logout();
});

function chooseEnabledRadio(name) {
  const checked = document.querySelector(`input[name="${name}"]:checked:not(:disabled)`);
  if (checked) return checked;
  const first = document.querySelector(`input[name="${name}"]:not(:disabled)`);
  if (first) first.checked = true;
  return first;
}

function selectedNewBillingTerm() {
  if (document.getElementById("product")?.value === "ip") return "yearly";
  return chooseEnabledRadio("newBillingTerm")?.value || "monthly";
}

function billingDays(term) {
  return term === "yearly" ? 365 : 30;
}

function selectedDashboardRelayHostnameScope() {
  return chooseEnabledRadio("dashboardRelayHostnameScope")?.value || "exact";
}

function selectedDashboardPrice(product, term) {
  if (product === "relay") {
    const scope = document.querySelector(
      `input[name="dashboardRelayHostnameScope"][value="${selectedDashboardRelayHostnameScope()}"]`,
    );
    return scope?.dataset[term === "yearly" ? "yearlyPrice" : "monthlyPrice"] || "";
  }
  const option = document.getElementById("product").selectedOptions[0];
  return option?.dataset[term === "yearly" ? "yearlyPrice" : "monthlyPrice"] || "";
}

function approximateUsd(amountSats) {
  if (!Number.isFinite(btcUsdPrice) || btcUsdPrice <= 0) return "";
  const value = Number(amountSats) * btcUsdPrice / 100000000;
  if (!Number.isFinite(value) || value <= 0) return "";
  if (value < 0.01) return "<$0.01";
  return `$${value.toFixed(2)}`;
}

function dashboardDomain() {
  const mode = chooseEnabledRadio("dashboardDomainMode");
  if (!mode) return "";
  if (mode.value === "customer") return document.getElementById("domain").value.trim();
  const label = document.getElementById("dashboardManagedLabel").value.trim().toLowerCase();
  const suffix = document.getElementById("dashboardManagedSuffix").value;
  return label && suffix ? `${label}.${suffix}` : "";
}

function updateDashboardDomainMode() {
  const mode = chooseEnabledRadio("dashboardDomainMode");
  const customer = mode && mode.value === "customer";
  document.getElementById("dashboardManagedFields").hidden = customer;
  document.getElementById("dashboardCustomerFields").hidden = !customer;
}

function updateDashboardWildcardDomainPreview() {
  const wildcard = selectedDashboardRelayHostnameScope() === "wildcard";
  const domain = document.getElementById("domain").value.trim();
  document.getElementById("dashboardWildcardDomainPreview").hidden = !wildcard;
  document.getElementById("dashboardWildcardDomainPreview").querySelector("strong").textContent =
    domain ? `*.${domain}` : "Enter a base domain";
  document.getElementById("dashboardCustomerDomainHelp").textContent = wildcard
    ? "Enter a customer-owned base domain without '*.'. It routes strict descendant hostnames and requires TLS passthrough."
    : "Enter the exact hostname to publish, not only the root domain.";
  document.getElementById("dashboardCustomerDomainLabel").textContent = wildcard
    ? "Customer-owned base domain"
    : "Full public hostname";
}

function updateDashboardRelayHostnameScope() {
  const wildcard = selectedDashboardRelayHostnameScope() === "wildcard";
  const managed = document.getElementById("dashboardManagedMode");
  const customer = document.getElementById("dashboardCustomerMode");
  managed.disabled = wildcard || managed.dataset.available !== "true";
  if (wildcard) customer.checked = true;
  updateDashboardDomainMode();
  updateDashboardWildcardDomainPreview();
}

function updateDashboardManagedPreview() {
  document.getElementById("dashboardManagedPreview").textContent =
    dashboardDomain() || "Enter a label";
}

function updateSubscriptionFields() {
  const productSelect = document.getElementById("product");
  const product = productSelect.value;
  const transport = document.getElementById("transport");
  document.getElementById("transportField").hidden = product !== "port";
  document.getElementById("domainField").hidden = product !== "relay";
  const ipSelected = product === "ip";
  const yearlyTerm = document.querySelector('input[name="newBillingTerm"][value="yearly"]');
  document.getElementById("newOrderTerm")?.toggleAttribute("hidden", ipSelected);
  document.getElementById("dashboardIpAnnualOnlyHint").hidden = !ipSelected;
  if (ipSelected && yearlyTerm) yearlyTerm.checked = true;
  updateDashboardRelayHostnameScope();
  const option = productSelect.selectedOptions[0];
  const term = selectedNewBillingTerm();
  document.querySelectorAll('input[name="dashboardRelayHostnameScope"]').forEach((scope) => {
    scope.closest("label").querySelector(".relay-scope-price").textContent =
      scope.dataset[term === "yearly" ? "yearlyPrice" : "monthlyPrice"];
    scope.closest("label").querySelector(".relay-scope-days").textContent = billingDays(term);
  });
  if (option) {
    const sats = selectedDashboardPrice(product, term);
    const usd = approximateUsd(sats);
    document.getElementById("selectedPrice").textContent =
      `${sats} sats / ${billingDays(term)} days${usd ? ` · about ${usd} USD` : ""}`;
  } else {
    document.getElementById("selectedPrice").textContent = "";
  }
  const activeSelect = product === "port" ? transport : null;
  const wildcard = selectedDashboardRelayHostnameScope() === "wildcard";
  const invalidDomain = product === "relay" && (
    !dashboardDomain() || (wildcard && dashboardDomain().startsWith("*."))
  );
  document.getElementById("createSubBtn").disabled =
    !product || !option || option.disabled ||
    (activeSelect !== null && (!activeSelect.value || activeSelect.selectedOptions[0].disabled)) ||
    invalidDomain;
}

document.getElementById("product").addEventListener("change", updateSubscriptionFields);
document.getElementById("transport").addEventListener("change", updateSubscriptionFields);
document.querySelectorAll('input[name="newBillingTerm"]').forEach((input) => {
  input.addEventListener("change", updateSubscriptionFields);
});
document.querySelectorAll('input[name="dashboardDomainMode"]').forEach((input) => {
  input.addEventListener("change", updateSubscriptionFields);
});
document.querySelectorAll('input[name="dashboardRelayHostnameScope"]').forEach((input) => {
  input.addEventListener("change", updateSubscriptionFields);
});
document.getElementById("dashboardManagedLabel").addEventListener("input", () => {
  updateDashboardManagedPreview();
  updateSubscriptionFields();
});
document.getElementById("dashboardManagedSuffix").addEventListener("change", () => {
  updateDashboardManagedPreview();
  updateSubscriptionFields();
});
document.getElementById("domain").addEventListener("input", () => {
  updateDashboardWildcardDomainPreview();
  updateSubscriptionFields();
});

async function jsonFetch(url, options) {
  const response = await fetch(url, options);
  const text = await response.text();
  let parsed = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch (error) {
      if (response.ok) throw error;
    }
  }
  if (!response.ok) {
    const error = new Error(
      typeof parsed?.detail === "string" ? parsed.detail : text || response.statusText,
    );
    error.status = response.status;
    error.payload = parsed;
    throw error;
  }
  return parsed;
}

const passkeys = window.BlindportPasskeys;
const passkeySection = document.getElementById("passkeySection");
if (passkeySection && passkeys?.supported) {
  const passkeyStatus = document.getElementById("passkeyStatus");
  const passkeyList = document.getElementById("passkeyList");
  const passkeyForm = document.getElementById("passkeyForm");
  const passkeyName = document.getElementById("passkeyName");
  const addPasskeyButton = document.getElementById("addPasskeyBtn");
  passkeySection.hidden = false;

  function renderPasskeys(credentials) {
    passkeyList.replaceChildren();
    credentials.forEach((credential) => {
      const row = document.createElement("div");
      row.className = "passkey-row";
      const name = document.createElement("strong");
      name.textContent = credential.name;
      const detail = document.createElement("span");
      detail.textContent = credential.last_used_at ? "Used" : "Not used yet";
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "button-secondary button-danger";
      remove.textContent = "Remove";
      remove.addEventListener("click", async () => {
        if (!window.confirm("Remove this passkey?")) return;
        remove.disabled = true;
        passkeyStatus.textContent = "Removing passkey.";
        try {
          await jsonFetch(`/api/v1/passkeys/${encodeURIComponent(credential.credential_id)}`, {
            method: "DELETE",
            headers: authHeaders(),
          });
          await loadPasskeys();
          passkeyStatus.textContent = "Passkey removed.";
        } catch (_) {
          passkeyStatus.textContent = "Passkey could not be removed.";
          remove.disabled = false;
        }
      });
      row.append(name, detail, remove);
      passkeyList.appendChild(row);
    });
  }

  async function loadPasskeys() {
    const credentials = await jsonFetch("/api/v1/passkeys", { headers: authHeaders() });
    renderPasskeys(credentials);
    if (!credentials.length) passkeyStatus.textContent = "No passkeys added.";
  }

  passkeyForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = passkeyName.value.trim();
    if (!name) return;
    addPasskeyButton.disabled = true;
    passkeyStatus.textContent = "Adding passkey.";
    try {
      await passkeys.register(name, authHeaders());
      passkeyName.value = "";
      await loadPasskeys();
      passkeyStatus.textContent = "Passkey added.";
    } catch (_) {
      passkeyStatus.textContent = "Passkey could not be added.";
    }
    addPasskeyButton.disabled = false;
  });

  loadPasskeys().catch(() => {
    passkeyStatus.textContent = "Passkeys are unavailable.";
  });
}

document.getElementById("newSubForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const product = document.getElementById("product").value;
  const button = document.getElementById("createSubBtn");
  const output = document.getElementById("subOut");
  const body = {
    product,
    billing_term: selectedNewBillingTerm(),
    domain: product === "relay" ? dashboardDomain() : null,
    relay_hostname_scope: product === "relay" ? selectedDashboardRelayHostnameScope() : "exact",
    transport: product === "port" ? document.getElementById("transport").value : "tcp",
    delivery: product === "ip" ? "wireguard" : "framed",
  };
  if (body.relay_hostname_scope === "wildcard" && body.domain?.startsWith("*.")) {
    output.textContent = "Enter the wildcard base domain without '*.'.";
    return;
  }
  button.disabled = true;
  button.textContent = "Creating order...";
  output.textContent = "Creating the pending order.";
  try {
    await jsonFetch("/api/v1/subscriptions", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(body),
    });
    output.textContent = "Order created. Reloading the dashboard.";
    window.setTimeout(() => window.location.reload(), 500);
  } catch (error) {
    output.textContent = `Order not created: ${error.message}`;
    button.textContent = "Create pending order";
    updateSubscriptionFields();
  }
});

function selectedPaymentTerm(card) {
  if (card.dataset.delivery === "wireguard") return "yearly";
  return card.querySelector('input[name^="paymentTerm-"]:checked')?.value || "monthly";
}

function updatePaymentTermControl(card) {
  const term = selectedPaymentTerm(card);
  const price = term === "yearly" ? card.dataset.yearlyPrice : card.dataset.monthlyPrice;
  const days = billingDays(term);
  const summary = card.querySelector(".payment-term-summary");
  const usd = approximateUsd(price);
  if (summary) {
    summary.textContent =
      `${price} sats for ${days} service days${usd ? ` · about ${usd} USD` : ""}`;
  }
  const cardUsd = card.querySelector(".cardUsd");
  if (cardUsd) cardUsd.textContent = usd ? ` · about ${usd} USD` : "";
  const button = card.querySelector(".payBtn");
  if (button && !button.disabled) {
    const verb = card.dataset.subStatus === "active" || card.dataset.subStatus === "expired"
      ? "Renew"
      : "Pay";
    button.textContent = `${verb} ${price} sats`;
    button.dataset.originalText = button.textContent;
  }
}

function selectedPaymentAmount(card, term) {
  const value = term === "yearly" ? card.dataset.yearlyPrice : card.dataset.monthlyPrice;
  return Number.parseInt(value, 10);
}

function describeNwcBudget(budget) {
  if (budget.state === "unsupported") {
    return "The wallet does not report its spending limit. Leave room for possible routing fees.";
  }
  if (budget.state === "unlimited") {
    return "The wallet reports no finite spending limit.";
  }
  const remainingMsats = Math.max(0, budget.total_budget_msats - budget.used_budget_msats);
  const remainingSats = Math.floor(remainingMsats / 1000);
  const totalSats = Math.floor(budget.total_budget_msats / 1000);
  const renewal = budget.renews_at
    ? ` Renews ${new Date(budget.renews_at * 1000).toLocaleString()}.`
    : "";
  return `Wallet budget: ${remainingSats} of ${totalSats} sats remaining.${renewal} Routing fees may also count.`;
}

function describeNwcPaymentError(code) {
  const messages = {
    expired: "This wallet connection has expired. Connect a new wallet permission.",
    insufficient_balance: "The wallet cannot cover this payment and its possible routing fees.",
    payment_failed: "The wallet could not complete the Lightning payment. A route or sufficient liquidity may be unavailable.",
    quota_exceeded: "This wallet connection has reached its spending limit. Increase the budget and allow room for possible routing fees.",
    restricted: "The wallet policy rejected this payment.",
    unauthorized: "This wallet connection is no longer authorized.",
    unsupported_capability: "This wallet connection lacks payment or lookup permission.",
    unsupported_encryption: "This wallet connection does not support NIP-44 v2.",
  };
  return messages[code] || null;
}

async function checkNwcBudget(status, requiredSats = null) {
  let budget;
  try {
    budget = await jsonFetch("/api/v1/me/nwc/budget", { headers: authHeaders() });
  } catch {
    const unavailable = {
      canPay: true,
      notice: "The wallet spending limit could not be read. The wallet will enforce it during payment.",
    };
    if (status) status.textContent = unavailable.notice;
    return unavailable;
  }
  const notice = describeNwcBudget(budget);
  if (status) status.textContent = notice;
  if (budget.state !== "available" || requiredSats === null) {
    return { canPay: true, notice };
  }
  const remainingMsats = budget.total_budget_msats - budget.used_budget_msats;
  if (remainingMsats >= requiredSats * 1000) {
    return { canPay: true, notice };
  }
  const remainingSats = Math.floor(Math.max(0, remainingMsats) / 1000);
  return {
    canPay: false,
    notice: `Wallet budget is ${remainingSats} sats, but this payment needs ${requiredSats} sats plus possible routing fees. Increase the wallet budget and try again.`,
  };
}

function preparePaymentPanel(method) {
  const panel = document.getElementById("payPanel");
  panel.dataset.paymentMethod = method;
  panel.hidden = false;
  panel.focus();
  const stablecoin = method === "stablecoin_swap";
  document.getElementById("payEyebrow").textContent = stablecoin
    ? "Stablecoin checkout"
    : "Lightning invoice";
  const qrBox = document.getElementById("qrBox");
  qrBox.hidden = stablecoin;
  qrBox.innerHTML = "";
  document.getElementById("payInvoiceDetails").hidden = stablecoin;
  document.getElementById("stablecoinNotice").hidden = !stablecoin;
  document.getElementById("payBreakdown").hidden = true;
  document.getElementById("payBolt11").textContent = "";
  document.getElementById("payAmount").textContent = "";
  document.getElementById("payUsd").textContent = "";
  const payUri = document.getElementById("payUri");
  payUri.textContent = stablecoin ? "Continue in Boltz" : "Open in wallet";
  payUri.removeAttribute("href");
  payUri.removeAttribute("target");
  payUri.removeAttribute("rel");
  return panel;
}

function setCardPaymentButtonsDisabled(card, disabled) {
  card.querySelectorAll(".payBtn, .stablecoinPayBtn, .nwcPayBtn").forEach((button) => {
    button.disabled = disabled;
    if (!disabled && button.dataset.originalText) {
      button.textContent = button.dataset.originalText;
    }
  });
}

function renderManualPayment(payment, status, externalWindow = null) {
  const stablecoin = payment.method === "stablecoin_swap";
  preparePaymentPanel(payment.method);
  document.getElementById("payBolt11").textContent = payment.invoice;
  document.getElementById("payAmount").textContent = payment.amount_sats;
  const usd = approximateUsd(payment.amount_sats);
  document.getElementById("payUsd").textContent = usd ? `(about ${usd} USD)` : "";
  const payUri = document.getElementById("payUri");
  if (stablecoin) {
    if (!payment.stablecoin_checkout_url) {
      throw new Error("Stablecoin checkout is unavailable for this payment");
    }
    const breakdown = document.getElementById("payBreakdown");
    breakdown.textContent =
      `${payment.base_amount_sats} sats service price + ${payment.markup_sats} sats stablecoin surcharge`;
    breakdown.hidden = false;
    payUri.href = payment.stablecoin_checkout_url;
    payUri.target = "_blank";
    payUri.rel = "noopener noreferrer external";
    if (externalWindow) externalWindow.location.replace(payment.stablecoin_checkout_url);
    status.textContent =
      `Waiting for payment through Boltz (${payment.stablecoin_asset}, ${payment.period_days} service days).`;
    return;
  }
  document.getElementById("qrBox").innerHTML = payment.qr_svg;
  payUri.href = payment.lightning_uri;
  status.textContent =
    `Waiting for Lightning payment (${payment.billing_term}, ${payment.period_days} days).`;
}

async function startPaymentFlow(subId, term, trigger, method) {
  const stablecoin = method === "stablecoin_swap";
  const externalWindow = stablecoin ? window.open("about:blank", "_blank") : null;
  if (externalWindow) externalWindow.opener = null;
  const status = document.getElementById("payStatus");
  const card = trigger.closest(".subscription-card");
  setCardPaymentButtonsDisabled(card, true);
  trigger.textContent = "Creating invoice...";
  preparePaymentPanel(method);
  status.textContent = stablecoin
    ? "Preparing stablecoin checkout."
    : "Creating a Lightning invoice.";
  try {
    const payment = await jsonFetch("/api/v1/payments", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ subscription_id: subId, method, billing_term: term }),
    });
    renderManualPayment(payment, status, externalWindow);
    const paid = await pollPayment(payment, status);
    if (!paid) {
      setCardPaymentButtonsDisabled(card, false);
    }
  } catch (error) {
    if (externalWindow) externalWindow.close();
    const existing = error.status === 409 ? error.payload?.existing_payment : null;
    if (existing && ["lightning", "stablecoin_swap"].includes(existing.method)) {
      try {
        renderManualPayment(existing, status);
        status.textContent =
          `${error.message}. Continue with the existing checkout or wait for it to expire.`;
        const paid = await pollPayment(existing, status);
        if (!paid) setCardPaymentButtonsDisabled(card, false);
        return;
      } catch (renderError) {
        status.textContent = `Payment error: ${renderError.message}`;
      }
    } else {
      status.textContent = `Payment error: ${error.message}`;
    }
    setCardPaymentButtonsDisabled(card, false);
  }
}

document.getElementById("copyInvoiceBtn").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  const invoice = document.getElementById("payBolt11").textContent;
  if (!invoice) return;
  const copied = await accounts.copyText(invoice);
  button.textContent = copied ? "Copied" : "Select the invoice and copy it manually";
  window.setTimeout(() => {
    button.textContent = "Copy invoice";
  }, 2500);
});

async function pollPayment(payment, status) {
  const expiresAt = Date.parse(payment.expires_at);
  const deadline = Number.isNaN(expiresAt) ? Date.now() + 600000 : expiresAt + 5000;
  while (Date.now() < deadline) {
    await new Promise((resolve) => window.setTimeout(resolve, 3000));
    let current;
    try {
      current = await jsonFetch(`/api/v1/payments/${payment.id}`, { headers: authHeaders() });
    } catch (error) {
      status.textContent = `Could not check payment: ${error.message}`;
      continue;
    }
    if (current.status === "paid") {
      status.textContent = "Payment received. Activating the subscription.";
      window.setTimeout(() => window.location.reload(), 1000);
      return true;
    }
    if (current.status === "expired" || current.status === "failed") {
      const errorMessage = describeNwcPaymentError(current.nwc_error_code);
      if (current.method === "nwc" && errorMessage) {
        status.textContent = errorMessage;
        return false;
      }
      status.textContent = `Payment ${current.status}. Refreshing the endpoint.`;
      window.setTimeout(() => window.location.reload(), 800);
      return false;
    }
  }
  status.textContent = "Payment expired. Create a new payment to try again.";
  return false;
}

async function startNwcFlow(subId, term, trigger, budgetNotice = "") {
  const originalText = trigger.dataset.originalText || trigger.textContent;
  const cardStatus = trigger.closest(".subscription-card")?.querySelector(".cardStatus");
  const status = cardStatus || document.getElementById("nwcStatus") || trigger;
  trigger.disabled = true;
  trigger.textContent = "Sending payment...";
  status.textContent = budgetNotice
    ? `Sending payment from the connected wallet. ${budgetNotice}`
    : "Sending payment from the connected wallet.";
  try {
    const payment = await jsonFetch("/api/v1/payments", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ subscription_id: subId, method: "nwc", billing_term: term }),
    });
    const errorMessage = describeNwcPaymentError(payment.nwc_error_code);
    if (payment.status === "failed" && errorMessage) {
      status.textContent = errorMessage;
      trigger.disabled = false;
      trigger.textContent = originalText;
      return;
    }
    status.textContent = `Wallet payment ${payment.nwc_state || payment.status}.`;
    const paid = await pollPayment(payment, status);
    if (paid) return;
  } catch (error) {
    const existing = error.status === 409 ? error.payload?.existing_payment : null;
    if (existing) {
      status.textContent = `${error.message}. Resuming the open payment.`;
      if (["lightning", "stablecoin_swap"].includes(existing.method)) {
        try {
          renderManualPayment(existing, document.getElementById("payStatus"));
        } catch (renderError) {
          status.textContent = `Could not restore payment: ${renderError.message}`;
        }
      }
      const paid = await pollPayment(existing, status);
      if (paid) return;
    } else {
      status.textContent = `Wallet payment error: ${error.message}`;
    }
  }
  trigger.disabled = false;
  trigger.textContent = originalText;
}

document.querySelectorAll(".subscription-card").forEach((card) => {
  updatePaymentTermControl(card);
  card.querySelectorAll('input[name^="paymentTerm-"]').forEach((input) => {
    input.addEventListener("change", () => updatePaymentTermControl(card));
  });
});

document.querySelectorAll(".payBtn").forEach((button) => {
  const card = button.closest(".subscription-card");
  button.dataset.originalText = button.textContent;
  button.addEventListener("click", () => {
    startPaymentFlow(
      button.dataset.subId,
      selectedPaymentTerm(card),
      button,
      "lightning",
    );
  });
});

document.querySelectorAll(".stablecoinPayBtn").forEach((button) => {
  const card = button.closest(".subscription-card");
  button.dataset.originalText = button.textContent;
  button.addEventListener("click", () => {
    startPaymentFlow(
      button.dataset.subId,
      selectedPaymentTerm(card),
      button,
      "stablecoin_swap",
    );
  });
});

document.querySelectorAll(".nwcPayBtn").forEach((button) => {
  const card = button.closest(".subscription-card");
  button.addEventListener("click", async () => {
    const term = selectedPaymentTerm(card);
    const status = card.querySelector(".cardStatus");
    button.disabled = true;
    status.textContent = "Checking the wallet spending limit.";
    const preflight = await checkNwcBudget(status, selectedPaymentAmount(card, term));
    if (!preflight.canPay) {
      status.textContent = preflight.notice;
      button.disabled = false;
      return;
    }
    await startNwcFlow(button.dataset.subId, term, button, preflight.notice);
  });
});

document.querySelectorAll(".inline-nwc-form").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector(".inlineNwcPayBtn");
    const input = form.querySelector(".inlineNwcUri");
    const autoRenew = form.querySelector(".inlineNwcAutoRenew");
    const card = form.closest(".subscription-card");
    const status = card.querySelector(".cardStatus");
    button.dataset.originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Connecting wallet...";
    status.textContent = "Validating wallet connection.";
    try {
      await jsonFetch("/api/v1/me/nwc", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          nwc_uri: input.value,
          auto_renew_subscription_id: autoRenew.checked ? form.dataset.subId : null,
        }),
      });
      input.value = "";
      if (autoRenew.checked) {
        card.querySelector(".autoRenewStatus").textContent = "On";
      }
      status.textContent = autoRenew.checked
        ? "Wallet connected. Automatic renewal enabled. Sending the initial payment."
        : "Wallet connected. Sending the initial payment.";
      const term = selectedPaymentTerm(card);
      const preflight = await checkNwcBudget(status, selectedPaymentAmount(card, term));
      if (!preflight.canPay) {
        status.textContent = preflight.notice;
        button.disabled = false;
        button.type = "button";
        button.textContent = "Reload dashboard";
        button.addEventListener("click", () => window.location.reload(), { once: true });
        window.setTimeout(() => window.location.reload(), 2500);
        return;
      }
      await startNwcFlow(form.dataset.subId, term, button, preflight.notice);
      button.disabled = false;
      button.type = "button";
      button.textContent = "Reload dashboard";
      button.addEventListener("click", () => window.location.reload(), { once: true });
    } catch (error) {
      input.value = "";
      status.textContent = `Wallet connection error: ${error.message}`;
      button.disabled = false;
      button.textContent = "Connect and pay";
    }
  });
});

document.querySelectorAll(".cancelSubBtn").forEach((button) => {
  button.addEventListener("click", async () => {
    if (!window.confirm("Cancel this unpaid order?")) return;
    const card = button.closest(".subscription-card");
    const status = card.querySelector(".cardStatus");
    button.disabled = true;
    status.textContent = "Checking payment state...";
    try {
      await jsonFetch(`/api/v1/subscriptions/${button.dataset.subId}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      status.textContent = "Order cancelled. Refreshing endpoints.";
      window.setTimeout(() => window.location.reload(), 400);
    } catch (error) {
      status.textContent = `Could not cancel: ${error.message}`;
      button.disabled = false;
    }
  });
});

async function resumeOpenPayment() {
  let payments;
  try {
    payments = await jsonFetch("/api/v1/payments", { headers: authHeaders() });
  } catch (error) {
    return;
  }
  const payment = payments.find((item) =>
    ["lightning", "stablecoin_swap", "nwc"].includes(item.method) &&
      ["pending", "processing"].includes(item.status)
  );
  if (!payment) return;
  const card = document.querySelector(
    `.subscription-card[data-sub-id="${CSS.escape(payment.subscription_id)}"]`,
  );
  const status = payment.method === "nwc" && card
    ? card.querySelector(".cardStatus")
    : document.getElementById("payStatus");
  if (card) setCardPaymentButtonsDisabled(card, true);
  try {
    if (payment.method === "nwc") {
      status.textContent = "Connected wallet payment is still pending.";
    } else {
      renderManualPayment(payment, status);
      status.textContent = "Payment still pending. Continue with this invoice.";
    }
    const paid = await pollPayment(payment, status);
    if (!paid && card) setCardPaymentButtonsDisabled(card, false);
  } catch (error) {
    status.textContent = `Could not restore payment: ${error.message}`;
    if (card) setCardPaymentButtonsDisabled(card, false);
  }
}

document.querySelectorAll(".autoRenewToggle").forEach((toggle) => {
  toggle.addEventListener("change", async () => {
    toggle.disabled = true;
    try {
      const result = await jsonFetch(
        `/api/v1/subscriptions/${toggle.dataset.subId}/auto-renew?enable=${toggle.checked}`,
        { method: "POST", headers: authHeaders() },
      );
      toggle.checked = result.auto_renew;
      toggle.closest(".subscription-card").querySelector(".autoRenewStatus").textContent =
        result.auto_renew ? "On" : "Off";
    } catch (error) {
      toggle.checked = !toggle.checked;
      const status = toggle.closest(".subscription-card").querySelector(".cardStatus");
      if (status) status.textContent = `Automatic renewal error: ${error.message}`;
    }
    toggle.disabled = false;
  });
});

const nwcForm = document.getElementById("nwcForm");
if (nwcForm) {
  nwcForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = document.getElementById("saveNwcBtn");
    const status = document.getElementById("nwcStatus");
    button.disabled = true;
    status.textContent = "Validating wallet connection...";
    try {
      await jsonFetch("/api/v1/me/nwc", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ nwc_uri: document.getElementById("nwcUri").value }),
      });
      document.getElementById("nwcUri").value = "";
      status.textContent = "Wallet connected. Reloading the dashboard.";
      window.setTimeout(() => window.location.reload(), 500);
    } catch (error) {
      status.textContent = `Wallet connection error: ${error.message}`;
      button.disabled = false;
    }
  });
}

const nwcBudget = document.getElementById("nwcBudget");
if (nwcBudget) {
  checkNwcBudget(nwcBudget);
}

const revokeNwcButton = document.getElementById("revokeNwcBtn");
if (revokeNwcButton) {
  revokeNwcButton.addEventListener("click", async () => {
    revokeNwcButton.disabled = true;
    const status = document.getElementById("nwcStatus");
    try {
      await jsonFetch("/api/v1/me/nwc", { method: "DELETE", headers: authHeaders() });
      status.textContent = "Wallet connection revoked. Reloading the dashboard.";
      window.setTimeout(() => window.location.reload(), 500);
    } catch (error) {
      status.textContent = `Wallet revocation error: ${error.message}`;
      revokeNwcButton.disabled = false;
    }
  });
}

const notificationEmailForm = document.getElementById("notificationEmailForm");
if (notificationEmailForm) {
  notificationEmailForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = document.getElementById("saveNotificationEmailBtn");
    const status = document.getElementById("notificationEmailStatus");
    button.disabled = true;
    status.textContent = "Saving notification preference...";
    try {
      await jsonFetch("/api/v1/me/notification-email", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ email: document.getElementById("notificationEmail").value }),
      });
      document.getElementById("notificationEmail").value = "";
      status.textContent = "Service notifications enabled. Reloading the dashboard.";
      window.setTimeout(() => window.location.reload(), 500);
    } catch (error) {
      status.textContent = `Notification preference error: ${error.message}`;
      button.disabled = false;
    }
  });
}

const deleteNotificationEmailButton = document.getElementById("deleteNotificationEmailBtn");
if (deleteNotificationEmailButton) {
  deleteNotificationEmailButton.addEventListener("click", async () => {
    deleteNotificationEmailButton.disabled = true;
    const status = document.getElementById("notificationEmailStatus");
    try {
      await jsonFetch("/api/v1/me/notification-email", {
        method: "DELETE",
        headers: authHeaders(),
      });
      status.textContent = "Service notifications disabled. Reloading the dashboard.";
      window.setTimeout(() => window.location.reload(), 500);
    } catch (error) {
      status.textContent = `Notification preference error: ${error.message}`;
      deleteNotificationEmailButton.disabled = false;
    }
  });
}

document.querySelectorAll(".verifyDomainBtn").forEach((button) => {
  button.addEventListener("click", async () => {
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Checking DNS...";
    try {
      const result = await jsonFetch(
        `/api/v1/subscriptions/${button.dataset.subId}/verify-domain`,
        { method: "POST", headers: authHeaders() },
      );
      button.textContent = result.verified ? "Verified" : result.detail;
      if (result.verified) {
        window.setTimeout(() => window.location.reload(), 600);
        return;
      }
    } catch (error) {
      button.textContent = `Check failed: ${error.message}`;
    }
    window.setTimeout(() => {
      button.disabled = false;
      button.textContent = originalText;
    }, 3000);
  });
});

function validUpstream(value) {
  if (!value || value !== value.trim() || value.length > 259 || /\s/.test(value)) return false;
  let host;
  let port;
  if (value.startsWith("[")) {
    const match = value.match(/^\[([0-9a-fA-F:.]+)\]:(\d{1,5})$/);
    if (!match || !match[1].includes(":")) return false;
    try {
      const parsed = new URL(`http://${value}/`);
      if (!parsed.hostname.startsWith("[")) return false;
    } catch (error) {
      return false;
    }
    [, host, port] = match;
  } else {
    const separator = value.lastIndexOf(":");
    if (separator < 1 || value.indexOf(":") !== separator) return false;
    host = value.slice(0, separator);
    port = value.slice(separator + 1);
    const octets = host.split(".");
    const numericIPv4 = octets.length === 4 && octets.every((octet) => /^\d+$/.test(octet));
    const ipv4 = numericIPv4 && octets.every(
      (octet) => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255,
    );
    const hostname = host.length <= 253 && host.split(".").every(
      (label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label),
    );
    if ((numericIPv4 && !ipv4) || (!ipv4 && !hostname)) return false;
  }
  if (!/^[1-9]\d{0,4}$/.test(port)) return false;
  const portNumber = Number(port);
  return host.length > 0 && portNumber >= 1 && portNumber <= 65535;
}

function validLinuxHomePath(value) {
  if (!/^\/[^\u0000-\u001F\u007F]+$/u.test(value) || value.length > 255) return false;
  if (value === "/" || value.endsWith("/") || value !== value.trim() || value.includes("//")) return false;
  return !value.split("/").some((part) => part === "." || part === "..");
}

function updateClientConfig() {
  const controls = [...document.querySelectorAll(".mapping-control")];
  if (!controls.length) return;
  let targetsValid = true;
  const terms = document.getElementById("acmeTermsAccepted");
  const termsAccepted = !terms || terms.checked;
  const mappings = controls.map((control) => {
    const input = control.querySelector(".mappingUpstream");
    const error = control.querySelector(".mapping-error");
    const valid = validUpstream(input.value);
    targetsValid = targetsValid && valid;
    input.setAttribute("aria-invalid", String(!valid));
    error.textContent = valid ? "" : "Use a hostname or IP followed by a port, for example 127.0.0.1:8080.";
    const mapping = {
      subscription_id: control.dataset.subscriptionId,
      upstream: input.value.trim(),
      tls_mode: control.dataset.tlsMode,
    };
    if (control.dataset.tlsMode === "automatic") {
      mapping.acme_terms_accepted = termsAccepted;
    }
    return mapping;
  });
  const homeInput = document.getElementById("linuxHomePath");
  const homePath = homeInput?.value.trim() || "";
  const homeValid = validLinuxHomePath(homePath);
  homeInput?.setAttribute("aria-invalid", String(!homeValid));
  const renderedHome = homeValid ? homePath : "/home/replace-me";
  const configText = JSON.stringify({
    version: 3,
    accounts: [{
      name: "default",
      token_file: `${renderedHome}/.config/blindport/accounts/default.token`,
      state_dir: `${renderedHome}/.local/state/blindport/accounts/default`,
      mappings,
    }],
  }, null, 2);
  document.getElementById("generatedClientConfig").textContent = configText;
  document.getElementById("framedConfigInstallCommand").textContent =
    `install -d -m 700 "$HOME/.config/blindport" &&\n` +
    `temporary=$(mktemp "$HOME/.config/blindport/config.json.XXXXXX") &&\n` +
    `chmod 600 "$temporary" &&\n` +
    `cat > "$temporary" <<'BLINDPORT_CONFIG' &&\n` +
    `${configText}\nBLINDPORT_CONFIG\n` +
    `([ ! -f "$HOME/.config/blindport/config.json" ] || ` +
    `install -m 600 "$HOME/.config/blindport/config.json" "$HOME/.config/blindport/config.json.backup") &&\n` +
    `mv -f -- "$temporary" "$HOME/.config/blindport/config.json"`;
  const ready = targetsValid && termsAccepted && homeValid;
  document.querySelectorAll(".configDependent").forEach((button) => {
    button.disabled = !ready;
  });
  const status = document.getElementById("configSetupStatus");
  if (!homeValid) {
    status.textContent = "Enter the absolute home directory for the Linux user that will run blindportd.";
  } else if (!targetsValid) {
    status.textContent = "Correct each local target before installing this configuration.";
  } else if (!termsAccepted) {
    status.textContent = "Review and accept the Let's Encrypt agreement to enable automatic HTTPS.";
  } else {
    status.textContent = "Configuration is ready to install.";
  }
}

document.querySelectorAll(".mappingUpstream").forEach((input) => {
  input.addEventListener("input", updateClientConfig);
});
document.getElementById("acmeTermsAccepted")?.addEventListener("change", updateClientConfig);
document.getElementById("linuxHomePath")?.addEventListener("input", updateClientConfig);

document.querySelectorAll(".copyCommandBtn").forEach((button) => {
  button.addEventListener("click", async () => {
    if (button.disabled) return;
    const command = document.getElementById(button.dataset.copyTarget).textContent;
    const originalText = button.textContent;
    const copied = await accounts.copyText(command);
    button.textContent = copied ? "Copied" : "Select and copy the command manually";
    window.setTimeout(() => {
      button.textContent = originalText;
    }, 2500);
  });
});

updateDashboardManagedPreview();
updateSubscriptionFields();
updateClientConfig();
void resumeOpenPayment();
