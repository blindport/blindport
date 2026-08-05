const dashboardRoot = document.getElementById("dashboardRoot");
const token = dashboardRoot.dataset.token;
const accountId = dashboardRoot.dataset.accountId;
const accounts = window.BlindportAccounts;
const btcUsdPrice = Number.parseFloat(dashboardRoot.dataset.btcUsd);

accounts.save(token, accountId);

function authHeaders() {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

document.getElementById("logoutBtn").addEventListener("click", () => {
  accounts.clearActive();
  window.location.assign("/dashboard");
});

const accountTokenInput = document.getElementById("accountToken");
accountTokenInput.value = token;

document.getElementById("revealTokenBtn").addEventListener("click", (event) => {
  const revealed = accountTokenInput.type === "text";
  accountTokenInput.type = revealed ? "password" : "text";
  event.currentTarget.textContent = revealed ? "Reveal" : "Hide";
  event.currentTarget.setAttribute("aria-pressed", String(!revealed));
});

document.getElementById("copyAccountTokenBtn").addEventListener("click", async () => {
  const copied = await accounts.copyText(token);
  document.getElementById("accountTokenStatus").textContent = copied
    ? "Token copied."
    : "Copy failed. Reveal the token and copy it manually.";
});

document.getElementById("forgetAccountBtn").addEventListener("click", () => {
  if (!window.confirm("Forget this account token from this browser and sign out?")) return;
  if (!accounts.forget(token)) {
    document.getElementById("accountTokenStatus").textContent =
      "Could not remove the saved token. Check browser storage permissions and try again.";
    return;
  }
  window.location.assign("/dashboard");
});

function chooseEnabledRadio(name) {
  const checked = document.querySelector(`input[name="${name}"]:checked:not(:disabled)`);
  if (checked) return checked;
  const first = document.querySelector(`input[name="${name}"]:not(:disabled)`);
  if (first) first.checked = true;
  return first;
}

function selectedNewBillingTerm() {
  return chooseEnabledRadio("newBillingTerm")?.value || "monthly";
}

function billingDays(term) {
  return term === "yearly" ? 365 : 30;
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

function updateDashboardManagedPreview() {
  document.getElementById("dashboardManagedPreview").textContent =
    dashboardDomain() || "Enter a label";
}

function updateSubscriptionFields() {
  const productSelect = document.getElementById("product");
  const product = productSelect.value;
  const delivery = document.getElementById("delivery");
  const transport = document.getElementById("transport");
  document.getElementById("deliveryField").hidden = product !== "ip";
  document.getElementById("transportField").hidden = product !== "port";
  document.getElementById("domainField").hidden = product !== "relay";
  if (product !== "ip") delivery.value = "framed";
  updateDashboardDomainMode();
  const option = productSelect.selectedOptions[0];
  const term = selectedNewBillingTerm();
  const priceKey = term === "yearly" ? "yearlyPrice" : "monthlyPrice";
  if (option) {
    const sats = option.dataset[priceKey];
    const usd = approximateUsd(sats);
    document.getElementById("selectedPrice").textContent =
      `${sats} sats / ${billingDays(term)} days${usd ? ` · about ${usd} USD` : ""}`;
  } else {
    document.getElementById("selectedPrice").textContent = "";
  }
  const activeSelect = product === "ip" ? delivery : product === "port" ? transport : null;
  const invalidDomain = product === "relay" && !dashboardDomain();
  document.getElementById("createSubBtn").disabled =
    !product || !option || option.disabled ||
    (activeSelect !== null && (!activeSelect.value || activeSelect.selectedOptions[0].disabled)) ||
    invalidDomain;
}

document.getElementById("product").addEventListener("change", updateSubscriptionFields);
document.getElementById("delivery").addEventListener("change", updateSubscriptionFields);
document.getElementById("transport").addEventListener("change", updateSubscriptionFields);
document.querySelectorAll('input[name="newBillingTerm"]').forEach((input) => {
  input.addEventListener("change", updateSubscriptionFields);
});
document.querySelectorAll('input[name="dashboardDomainMode"]').forEach((input) => {
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
document.getElementById("domain").addEventListener("input", updateSubscriptionFields);

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

document.getElementById("newSubForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const product = document.getElementById("product").value;
  const button = document.getElementById("createSubBtn");
  const output = document.getElementById("subOut");
  const body = {
    product,
    billing_term: selectedNewBillingTerm(),
    domain: product === "relay" ? dashboardDomain() : null,
    transport: product === "port" ? document.getElementById("transport").value : "tcp",
    delivery: product === "ip" ? document.getElementById("delivery").value : "framed",
  };
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
      status.textContent = `Payment ${current.status}. Refreshing the endpoint.`;
      window.setTimeout(() => window.location.reload(), 800);
      return false;
    }
  }
  status.textContent = "Payment expired. Create a new payment to try again.";
  return false;
}

async function startNwcFlow(subId, term, trigger) {
  const originalText = trigger.textContent;
  const cardStatus = trigger.closest(".subscription-card")?.querySelector(".cardStatus");
  const status = cardStatus || document.getElementById("nwcStatus") || trigger;
  trigger.disabled = true;
  trigger.textContent = "Sending payment...";
  status.textContent = "Sending payment from the connected wallet.";
  try {
    const payment = await jsonFetch("/api/v1/payments", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ subscription_id: subId, method: "nwc", billing_term: term }),
    });
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
  button.addEventListener("click", () => {
    startNwcFlow(
      button.dataset.subId,
      selectedPaymentTerm(card),
      button,
    );
  });
});

document.querySelectorAll(".inline-nwc-form").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector(".inlineNwcPayBtn");
    const input = form.querySelector(".inlineNwcUri");
    const card = form.closest(".subscription-card");
    const status = card.querySelector(".cardStatus");
    button.disabled = true;
    button.textContent = "Connecting wallet...";
    status.textContent = "Validating wallet connection.";
    try {
      await jsonFetch("/api/v1/me/nwc", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ nwc_uri: input.value }),
      });
      input.value = "";
      status.textContent = "Wallet connected. Sending the initial payment.";
      await startNwcFlow(form.dataset.subId, selectedPaymentTerm(card), button);
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

const reminderForm = document.getElementById("reminderForm");
if (reminderForm) {
  reminderForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = document.getElementById("saveReminderBtn");
    const status = document.getElementById("reminderStatus");
    button.disabled = true;
    status.textContent = "Saving reminder preference...";
    try {
      await jsonFetch("/api/v1/me/reminder-email", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ email: document.getElementById("reminderEmail").value }),
      });
      document.getElementById("reminderEmail").value = "";
      status.textContent = "Reminders enabled. Reloading the dashboard.";
      window.setTimeout(() => window.location.reload(), 500);
    } catch (error) {
      status.textContent = `Reminder preference error: ${error.message}`;
      button.disabled = false;
    }
  });
}

const deleteReminderButton = document.getElementById("deleteReminderBtn");
if (deleteReminderButton) {
  deleteReminderButton.addEventListener("click", async () => {
    deleteReminderButton.disabled = true;
    const status = document.getElementById("reminderStatus");
    try {
      await jsonFetch("/api/v1/me/reminder-email", {
        method: "DELETE",
        headers: authHeaders(),
      });
      status.textContent = "Reminders disabled. Reloading the dashboard.";
      window.setTimeout(() => window.location.reload(), 500);
    } catch (error) {
      status.textContent = `Reminder preference error: ${error.message}`;
      deleteReminderButton.disabled = false;
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

document.querySelectorAll(".copyCommandBtn").forEach((button) => {
  button.addEventListener("click", async () => {
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
void resumeOpenPayment();
