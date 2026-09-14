(() => {
  "use strict";

  const STORAGE_KEY = "blindport_accounts_v1";
  const LEGACY_KEY = "blindport_token";
  const ACTIVE_KEY = "blindport_active_token_v1";
  const MAX_ACCOUNTS = 20;

  function normalizeAccount(value) {
    if (!value || typeof value.token !== "string" || !value.token.trim()) return null;
    return {
      token: value.token.trim(),
      accountId: typeof value.accountId === "string" ? value.accountId.trim() : "",
      lastUsedAt: Number.isFinite(value.lastUsedAt) ? value.lastUsedAt : 0,
    };
  }

  function readAccounts() {
    try {
      const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
      if (!Array.isArray(parsed)) return [];
      return parsed
        .map(normalizeAccount)
        .filter((account) => account !== null)
        .sort((left, right) => right.lastUsedAt - left.lastUsedAt)
        .slice(0, MAX_ACCOUNTS);
    } catch (_) {
      return [];
    }
  }

  function writeAccounts(accounts) {
    try {
      if (accounts.length === 0) {
        localStorage.removeItem(STORAGE_KEY);
        return true;
      }
      localStorage.setItem(STORAGE_KEY, JSON.stringify(accounts.slice(0, MAX_ACCOUNTS)));
      return true;
    } catch (_) {
      return false;
    }
  }

  function save(token, accountId = "") {
    const normalizedToken = typeof token === "string" ? token.trim() : "";
    if (!normalizedToken) return false;
    const accounts = readAccounts();
    const existing = accounts.find((account) => account.token === normalizedToken);
    const normalizedAccountId = typeof accountId === "string" ? accountId.trim() : "";
    const account = {
      token: normalizedToken,
      accountId: normalizedAccountId || existing?.accountId || "",
      lastUsedAt: Date.now(),
    };
    return writeAccounts([
      account,
      ...accounts.filter((candidate) => candidate.token !== normalizedToken),
    ]);
  }

  function setActive(token, accountId = "") {
    const normalizedToken = typeof token === "string" ? token.trim() : "";
    if (!normalizedToken || !save(normalizedToken, accountId)) return false;
    try {
      localStorage.setItem(ACTIVE_KEY, normalizedToken);
      return true;
    } catch (_) {
      return false;
    }
  }

  function activeToken() {
    try {
      return localStorage.getItem(ACTIVE_KEY) || "";
    } catch (_) {
      return "";
    }
  }

  function clearActive() {
    try {
      localStorage.removeItem(ACTIVE_KEY);
      return true;
    } catch (_) {
      return false;
    }
  }

  function forAccount(accountId) {
    const normalizedAccountId = typeof accountId === "string" ? accountId.trim() : "";
    if (!normalizedAccountId) return null;
    return readAccounts().find((account) => account.accountId === normalizedAccountId) || null;
  }

  function forget(token) {
    const normalizedToken = typeof token === "string" ? token.trim() : "";
    if (!normalizedToken) return false;
    const accounts = readAccounts();
    const saved = accounts.some((account) => account.token === normalizedToken);
    if (saved && !writeAccounts(accounts.filter((account) => account.token !== normalizedToken))) {
      return false;
    }
    if (activeToken() === normalizedToken) clearActive();
    return true;
  }

  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (_) {
        // Fall back to a temporary text area for older browser permission models.
      }
    }
    const field = document.createElement("textarea");
    field.value = text;
    field.setAttribute("readonly", "");
    field.className = "clipboard-field";
    document.body.appendChild(field);
    field.select();
    let copied = false;
    try {
      copied = document.execCommand("copy");
    } catch (_) {
      copied = false;
    }
    field.remove();
    return copied;
  }

  function migrateLegacyToken() {
    try {
      const legacyToken = localStorage.getItem(LEGACY_KEY);
      if (!legacyToken || setActive(legacyToken)) localStorage.removeItem(LEGACY_KEY);
    } catch (_) {
      // Storage access can be restricted by browser privacy settings.
    }
  }

  migrateLegacyToken();
  window.BlindportAccounts = Object.freeze({
    activeToken,
    clearActive,
    copyText,
    forAccount,
    forget,
    list: readAccounts,
    save,
    setActive,
  });
})();
