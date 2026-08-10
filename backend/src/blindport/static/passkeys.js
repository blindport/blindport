(() => {
  "use strict";

  const supported = Boolean(
    window.isSecureContext && window.PublicKeyCredential && navigator.credentials,
  );

  function base64urlToBuffer(value) {
    if (typeof value !== "string" || !value) throw new TypeError("invalid WebAuthn binary value");
    const padded = `${value.replace(/-/g, "+").replace(/_/g, "/")}${"=".repeat((4 - value.length % 4) % 4)}`;
    const decoded = atob(padded);
    const bytes = new Uint8Array(decoded.length);
    for (let index = 0; index < decoded.length; index += 1) bytes[index] = decoded.charCodeAt(index);
    return bytes.buffer;
  }

  function bufferToBase64url(value) {
    const bytes = new Uint8Array(value instanceof ArrayBuffer ? value : value.buffer);
    let binary = "";
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function parseCreationOptions(options) {
    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
      return PublicKeyCredential.parseCreationOptionsFromJSON(options);
    }
    return {
      ...options,
      challenge: base64urlToBuffer(options.challenge),
      user: { ...options.user, id: base64urlToBuffer(options.user.id) },
      excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
        ...credential,
        id: base64urlToBuffer(credential.id),
      })),
    };
  }

  function parseRequestOptions(options) {
    if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
      return PublicKeyCredential.parseRequestOptionsFromJSON(options);
    }
    return {
      ...options,
      challenge: base64urlToBuffer(options.challenge),
      allowCredentials: (options.allowCredentials || []).map((credential) => ({
        ...credential,
        id: base64urlToBuffer(credential.id),
      })),
    };
  }

  function credentialToJSON(credential) {
    if (typeof credential.toJSON === "function") return credential.toJSON();
    const response = credential.response;
    const serialized = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToBase64url(response.clientDataJSON),
      },
      clientExtensionResults: credential.getClientExtensionResults(),
    };
    if (response.attestationObject) {
      serialized.response.attestationObject = bufferToBase64url(response.attestationObject);
      if (typeof response.getTransports === "function") {
        serialized.response.transports = response.getTransports();
      }
    } else {
      serialized.response.authenticatorData = bufferToBase64url(response.authenticatorData);
      serialized.response.signature = bufferToBase64url(response.signature);
      serialized.response.userHandle = response.userHandle
        ? bufferToBase64url(response.userHandle)
        : null;
    }
    return serialized;
  }

  async function requestJSON(url, options) {
    const response = await fetch(url, options);
    if (!response.ok) throw new Error("passkey request failed");
    return response.json();
  }

  function jsonHeaders(headers = {}) {
    return { ...headers, "Content-Type": "application/json" };
  }

  async function authenticate() {
    if (!supported) throw new Error("passkeys are unavailable");
    const begin = await requestJSON("/api/v1/passkeys/authentication/options", { method: "POST" });
    const credential = await navigator.credentials.get({
      publicKey: parseRequestOptions(begin.options),
    });
    if (!credential) throw new Error("passkey authentication was cancelled");
    return requestJSON("/api/v1/passkeys/authentication", {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({ challenge_id: begin.challenge_id, credential: credentialToJSON(credential) }),
    });
  }

  async function register(name, headers = {}) {
    if (!supported) throw new Error("passkeys are unavailable");
    const begin = await requestJSON("/api/v1/passkeys/registration/options", {
      method: "POST",
      headers: jsonHeaders(headers),
      body: JSON.stringify({ name }),
    });
    const credential = await navigator.credentials.create({
      publicKey: parseCreationOptions(begin.options),
    });
    if (!credential) throw new Error("passkey registration was cancelled");
    return requestJSON("/api/v1/passkeys/registration", {
      method: "POST",
      headers: jsonHeaders(headers),
      body: JSON.stringify({ challenge_id: begin.challenge_id, name, credential: credentialToJSON(credential) }),
    });
  }

  window.BlindportPasskeys = Object.freeze({
    authenticate,
    register,
    supported,
  });
})();
