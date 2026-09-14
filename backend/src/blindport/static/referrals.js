(() => {
  const STORAGE_KEY = "blindport_referral_address";
  const RESERVED_SUFFIXES = ["example", "invalid", "local", "localhost", "test", "home.arpa"];

  function validAddress(value) {
    if (typeof value !== "string" || value.length > 254 || !/^[\x00-\x7F]*$/.test(value)) {
      return null;
    }
    const address = value.toLowerCase();
    if ((address.match(/@/g) || []).length !== 1) return null;
    const [localPart, domain] = address.split("@");
    if (!localPart || localPart.length > 64 || !/^[a-z0-9_.-]+$/.test(localPart)) return null;
    if (!domain || domain.length > 253 || !domain.includes(".")) return null;
    const labels = domain.split(".");
    if (!labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
      return null;
    }
    if (RESERVED_SUFFIXES.some((suffix) => domain === suffix || domain.endsWith(`.${suffix}`))) {
      return null;
    }
    const octets = domain.split(".");
    if (
      octets.length === 4 &&
      octets.every((octet) => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255)
    ) {
      return null;
    }
    return address;
  }

  function storedAddress() {
    try {
      const address = sessionStorage.getItem(STORAGE_KEY);
      return validAddress(address);
    } catch (_) {
      return null;
    }
  }

  function captureFromFragment() {
    const existing = storedAddress();
    const params = new URLSearchParams(window.location.hash.slice(1));
    const received = validAddress(params.get("ref"));
    if (!received) return existing;
    if (!existing) {
      try {
        sessionStorage.setItem(STORAGE_KEY, received);
      } catch (_) {
        return null;
      }
    }
    history.replaceState(history.state, "", `${window.location.pathname}${window.location.search}`);
    return existing || received;
  }

  captureFromFragment();
  window.BlindportReferrals = Object.freeze({
    address: storedAddress,
    validateAddress: validAddress,
  });
})();
