const orderForm = document.getElementById("orderForm");
const accounts = window.BlindportAccounts;

function readStoredToken() {
  return accounts.activeToken();
}

function storeToken(token, accountId) {
  accounts.setActive(token, accountId);
}

function selectedProduct() {
  return orderForm.querySelector('input[name="orderProduct"]:checked');
}

function selectedBillingTerm() {
  if (selectedProduct()?.value === "ip" && selectedValue("orderDelivery") === "wireguard") {
    return "yearly";
  }
  return selectedValue("orderBillingTerm") || "monthly";
}

function billingDays(term) {
  return term === "yearly" ? 365 : 30;
}

function updatePlanPrices() {
  const term = selectedBillingTerm();
  const priceKey = term === "yearly" ? "yearlyPrice" : "monthlyPrice";
  document.querySelectorAll(".plan-price").forEach((price) => {
    price.querySelector("strong").textContent = price.dataset[priceKey];
    price.querySelector("span").textContent = billingDays(term);
  });
}

function enforceRoutedYearly() {
  const routed = selectedProduct()?.value === "ip" && selectedValue("orderDelivery") === "wireguard";
  const monthly = orderForm.querySelector('input[name="orderBillingTerm"][value="monthly"]');
  const yearly = orderForm.querySelector('input[name="orderBillingTerm"][value="yearly"]');
  if (!monthly || !yearly) return;
  monthly.disabled = routed;
  if (routed) yearly.checked = true;
  updatePlanPrices();
}

function selectedValue(name) {
  const selected = orderForm.querySelector(`input[name="${name}"]:checked:not(:disabled)`);
  return selected ? selected.value : "";
}

function chooseFirstEnabled(name) {
  const current = orderForm.querySelector(`input[name="${name}"]:checked:not(:disabled)`);
  if (current) return;
  const first = orderForm.querySelector(`input[name="${name}"]:not(:disabled)`);
  if (first) first.checked = true;
}

function showStep(step) {
  const panels = {
    plan: document.getElementById("planPanel"),
    config: document.getElementById("configPanel"),
    review: document.getElementById("reviewPanel"),
  };
  const indicators = {
    plan: document.getElementById("planStep"),
    config: document.getElementById("configStep"),
    review: document.getElementById("reviewStep"),
  };
  Object.entries(panels).forEach(([name, panel]) => {
    panel.hidden = name !== step;
    indicators[name].classList.toggle("is-current", name === step);
    if (name === step) indicators[name].setAttribute("aria-current", "step");
    else indicators[name].removeAttribute("aria-current");
  });
  const heading = panels[step].querySelector("legend, h3");
  if (heading) {
    heading.setAttribute("tabindex", "-1");
    heading.focus({ preventScroll: true });
    heading.scrollIntoView({ block: "start", behavior: "instant" });
  }
}

function updateManagedPreview() {
  const label = document.getElementById("managedLabel").value.trim().toLowerCase();
  const suffix = document.getElementById("managedSuffix").value;
  document.getElementById("managedPreview").textContent =
    label && suffix ? `${label}.${suffix}` : "Enter a label";
}

function updateRelayMode() {
  chooseFirstEnabled("domainMode");
  const customer = selectedValue("domainMode") === "customer";
  document.getElementById("managedDomainFields").hidden = customer;
  document.getElementById("customerDomainFields").hidden = !customer;
}

function configureProduct() {
  const productOption = selectedProduct();
  if (!productOption) return;
  const product = productOption.value;
  document.getElementById("configProductName").textContent = productOption.dataset.name;
  document.getElementById("ipConfig").hidden = product !== "ip";
  document.getElementById("portConfig").hidden = product !== "port";
  document.getElementById("relayConfig").hidden = product !== "relay";
  if (product === "ip") chooseFirstEnabled("orderDelivery");
  if (product === "port") chooseFirstEnabled("orderTransport");
  if (product === "relay") updateRelayMode();
  enforceRoutedYearly();
}

function validateConfiguration() {
  const product = selectedProduct().value;
  if (product === "ip" && !selectedValue("orderDelivery")) {
    return "Select an available delivery mode.";
  }
  if (product === "port" && !selectedValue("orderTransport")) {
    return "Select an available transport.";
  }
  if (product !== "relay") return "";
  const mode = selectedValue("domainMode");
  if (!mode) return "Select an available domain option.";
  if (mode === "customer") {
    return document.getElementById("customerDomain").value.trim()
      ? ""
      : "Enter the customer-owned domain.";
  }
  const label = document.getElementById("managedLabel").value.trim();
  return /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label)
    ? ""
    : "Enter one valid DNS label for the managed subdomain.";
}

function orderBody() {
  const product = selectedProduct().value;
  const body = {
    product,
    billing_term: selectedBillingTerm(),
    delivery: "framed",
    transport: "tcp",
    domain: null,
  };
  if (product === "ip") body.delivery = selectedValue("orderDelivery");
  if (product === "port") body.transport = selectedValue("orderTransport");
  if (product === "relay") {
    if (selectedValue("domainMode") === "customer") {
      body.domain = document.getElementById("customerDomain").value.trim();
    } else {
      const label = document.getElementById("managedLabel").value.trim().toLowerCase();
      body.domain = `${label}.${document.getElementById("managedSuffix").value}`;
    }
  }
  return body;
}

function populateReview() {
  const product = selectedProduct();
  const body = orderBody();
  document.getElementById("reviewProduct").textContent = product.dataset.name;
  const priceKey = body.billing_term === "yearly" ? "yearlyPrice" : "monthlyPrice";
  document.getElementById("reviewPrice").textContent = product.dataset[priceKey];
  document.getElementById("reviewTerm").textContent =
    `${body.billing_term === "yearly" ? "Yearly" : "Monthly"}, ${billingDays(body.billing_term)} days`;
  let configuration = "Framed delivery";
  if (body.product === "ip") configuration = `${body.delivery} delivery`;
  if (body.product === "port") configuration = `${body.transport.toUpperCase()} tuple`;
  if (body.product === "relay") {
    configuration = selectedValue("domainMode") === "customer"
      ? `${body.domain} (CNAME)`
      : body.domain;
  }
  document.getElementById("reviewConfig").textContent = configuration;
  document.getElementById("accountOrderNote").textContent = readStoredToken()
    ? "This order will be added to the account already stored in this browser."
    : "No account token was found. This order will create an anonymous account and show its token once.";
}

async function errorDetail(response) {
  const text = await response.text();
  if (!text) return `Request failed with HTTP ${response.status}.`;
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed.detail === "string") return parsed.detail;
  } catch (_) {
    // Return the bounded server text when it is not JSON.
  }
  return text.slice(0, 500);
}

orderForm.addEventListener("change", (event) => {
  if (event.target.name === "orderProduct") {
    document.getElementById("toConfigBtn").disabled = !selectedProduct();
  }
  if (event.target.name === "domainMode") updateRelayMode();
  if (event.target.name === "orderBillingTerm") updatePlanPrices();
  if (event.target.name === "orderDelivery") enforceRoutedYearly();
});

document.querySelectorAll(".product-jump").forEach((link) => {
  link.addEventListener("click", () => {
    const option = orderForm.querySelector(
      `input[name="orderProduct"][value="${link.dataset.orderProduct}"]:not(:disabled)`,
    );
    if (!option) return;
    option.checked = true;
    document.getElementById("toConfigBtn").disabled = false;
  });
});

document.getElementById("managedLabel").addEventListener("input", updateManagedPreview);
document.getElementById("managedSuffix").addEventListener("change", updateManagedPreview);
document.getElementById("toConfigBtn").addEventListener("click", () => {
  configureProduct();
  showStep("config");
});
document.getElementById("backToPlanBtn").addEventListener("click", () => showStep("plan"));
document.getElementById("toReviewBtn").addEventListener("click", () => {
  const validation = validateConfiguration();
  if (validation) {
    document.getElementById("orderStatus").textContent = validation;
    return;
  }
  document.getElementById("orderStatus").textContent = "";
  populateReview();
  showStep("review");
});
document.getElementById("backToConfigBtn").addEventListener("click", () => showStep("config"));

orderForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = document.getElementById("placeOrderBtn");
  const status = document.getElementById("orderStatus");
  const existingToken = readStoredToken();
  button.disabled = true;
  button.textContent = "Creating order...";
  status.textContent = "Creating the pending order.";
  try {
    const response = await fetch(existingToken ? "/api/v1/subscriptions" : "/api/v2/orders", {
      method: "POST",
      headers: existingToken
        ? { Authorization: `Bearer ${existingToken}`, "Content-Type": "application/json" }
        : { "Content-Type": "application/json" },
      body: JSON.stringify(orderBody()),
    });
    if (!response.ok) throw new Error(await errorDetail(response));
    const result = await response.json();
    if (existingToken) {
      status.textContent = "Order created. Opening the dashboard.";
      window.location.assign("/dashboard");
      return;
    }
    storeToken(result.token, result.account_id);
    document.getElementById("newToken").textContent = result.token;
    document.getElementById("reviewPanel").hidden = true;
    const backup = document.getElementById("tokenBackup");
    backup.hidden = false;
    backup.focus();
    status.textContent = "The pending order is ready. Back up the new account token to continue.";
  } catch (error) {
    status.textContent = `Order not created: ${error.message}`;
    button.disabled = false;
    button.textContent = "Create pending order";
  }
});

document.getElementById("copyTokenBtn").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const copied = await accounts.copyText(document.getElementById("newToken").textContent);
    button.textContent = copied ? "Copied" : "Select the token and copy it manually";
  } catch (_) {
    button.textContent = "Select the token and copy it manually";
  }
  setTimeout(() => {
    button.disabled = false;
    button.textContent = "Copy token";
  }, 2500);
});

document.getElementById("tokenSavedCheck").addEventListener("change", (event) => {
  document.getElementById("continueDashboardBtn").disabled = !event.target.checked;
});
document.getElementById("continueDashboardBtn").addEventListener("click", () => {
  window.location.assign("/dashboard");
});

chooseFirstEnabled("domainMode");
updateRelayMode();
updateManagedPreview();
updatePlanPrices();
