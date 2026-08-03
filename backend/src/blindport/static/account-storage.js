(() => {
  "use strict";

  const STORAGE_KEY = "blindport_accounts_v1";
  const LEGACY_KEY = "blindport_token";
  const COOKIE_NAME = "blindport_token";
  const MAX_ACCOUNTS = 20;

  function cookieSuffix() {
    return document.body.dataset.cookieSecure === "true" ? "; secure" : "";
  }

  function readCookie() {
    const prefix = `${COOKIE_NAME}=`;
    const cookie = document.cookie
      .split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith(prefix));
    if (!cookie) return "";
    try {
      return decodeURIComponent(cookie.slice(prefix.length));
    } catch (_) {
      return "";
    }
  }

  function writeCookie(token) {
    document.cookie =
      `${COOKIE_NAME}=${encodeURIComponent(token)}; path=/; samesite=lax${cookieSuffix()}`;
  }

  function clearCookie() {
    document.cookie =
      `${COOKIE_NAME}=; path=/; max-age=0; samesite=lax${cookieSuffix()}`;
  }

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
      localStorage.setItem(STORAGE_KEY, JSON.stringify(accounts.slice(0, MAX_ACCOUNTS)));
      return true;
    } catch (_) {
      return false;
    }
  }

  function save(token, accountId = "") {
    const normalizedToken = token.trim();
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
    const normalizedToken = token.trim();
    if (!normalizedToken) return false;
    save(normalizedToken, accountId);
    writeCookie(normalizedToken);
    return true;
  }

  function forget(token) {
    const normalizedToken = token.trim();
    const accounts = readAccounts();
    const saved = accounts.some((account) => account.token === normalizedToken);
    const removed = !saved || writeAccounts(
      accounts.filter((account) => account.token !== normalizedToken),
    );
    if (removed && readCookie() === normalizedToken) clearCookie();
    return removed;
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
      if (!legacyToken || save(legacyToken)) localStorage.removeItem(LEGACY_KEY);
    } catch (_) {
      // Restricted storage still permits cookie-only sessions.
    }
  }

  migrateLegacyToken();
  window.BlindportAccounts = Object.freeze({
    activeToken: readCookie,
    clearActive: clearCookie,
    copyText,
    forget,
    list: readAccounts,
    save,
    setActive,
  });
})();
