const dashboardRoot = document.getElementById("dashboardRoot");
const token = dashboardRoot.dataset.token;
const accountId = dashboardRoot.dataset.accountId;
const accounts = window.BlindportAccounts;

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
  document.getElementById("selectedPrice").textContent = option
    ? `${option.dataset[priceKey]} sats / ${billingDays(term)} days`
    : "";
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
  if (!response.ok) {
    try {
      const parsed = JSON.parse(text);
      throw new Error(typeof parsed.detail === "string" ? parsed.detail : text);
    } catch (error) {
      if (error instanceof SyntaxError) throw new Error(text || response.statusText);
      throw error;
    }
  }
  return text ? JSON.parse(text) : null;
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
  if (summary) summary.textContent = `${price} sats for ${days} service days`;
  const button = card.querySelector(".payBtn");
  if (button && !button.disabled) {
    const verb = card.dataset.subStatus === "active" || card.dataset.subStatus === "expired"
      ? "Renew"
      : "Pay";
    button.textContent = `${verb} ${price} sats for ${days} days`;
    button.dataset.originalText = button.textContent;
  }
}

async function startLightningFlow(subId, term, trigger) {
  const panel = document.getElementById("payPanel");
  const status = document.getElementById("payStatus");
  trigger.disabled = true;
  trigger.textContent = "Creating invoice...";
  panel.hidden = false;
  panel.focus();
  status.textContent = "Creating a Lightning invoice.";
  document.getElementById("qrBox").innerHTML = "";
  document.getElementById("payBolt11").textContent = "";
  document.getElementById("payAmount").textContent = "";
  document.getElementById("payUri").removeAttribute("href");
  try {
    const payment = await jsonFetch("/api/v1/payments", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ subscription_id: subId, method: "lightning", billing_term: term }),
    });
    document.getElementById("qrBox").innerHTML = payment.qr_svg;
    document.getElementById("payBolt11").textContent = payment.invoice;
    document.getElementById("payAmount").textContent = payment.amount_sats;
    document.getElementById("payUri").href = payment.lightning_uri;
    status.textContent =
      `Waiting for Lightning payment (${payment.billing_term}, ${payment.period_days} days).`;
    const paid = await pollLightningPayment(payment, status);
    if (!paid) {
      trigger.disabled = false;
      trigger.textContent = trigger.dataset.originalText;
    }
  } catch (error) {
    status.textContent = `Payment error: ${error.message}`;
    trigger.disabled = false;
    trigger.textContent = trigger.dataset.originalText;
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

async function pollLightningPayment(payment, status) {
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
      status.textContent = `Payment ${current.status}. Create a new invoice to try again.`;
      return false;
    }
  }
  status.textContent = "Payment expired. Create a new invoice to try again.";
  return false;
}

async function startNwcFlow(subId, term, trigger) {
  const originalText = trigger.textContent;
  trigger.disabled = true;
  trigger.textContent = "Sending payment...";
  try {
    const payment = await jsonFetch("/api/v1/payments", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ subscription_id: subId, method: "nwc", billing_term: term }),
    });
    const status = document.getElementById("nwcStatus");
    if (status) status.textContent = `Wallet payment ${payment.nwc_state || payment.status}.`;
    const paid = await pollLightningPayment(payment, status || trigger);
    if (paid) return;
  } catch (error) {
    const status = document.getElementById("nwcStatus");
    if (status) status.textContent = `Wallet payment error: ${error.message}`;
  }
  trigger.disabled = false;
  trigger.textContent = originalText;
}

document.querySelectorAll(".payBtn").forEach((button) => {
  const card = button.closest(".subscription-card");
  updatePaymentTermControl(card);
  card.querySelectorAll('input[name^="paymentTerm-"]').forEach((input) => {
    input.addEventListener("change", () => updatePaymentTermControl(card));
  });
  button.addEventListener("click", () => {
    startLightningFlow(
      button.dataset.subId,
      selectedPaymentTerm(card),
      button,
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
      const status = document.getElementById("nwcStatus");
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
