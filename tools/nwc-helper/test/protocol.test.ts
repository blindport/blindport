import { describe, expect, test } from "bun:test";
import { NWCClient } from "@getalby/sdk/nwc";
import {
  executeRequest,
  parseNwcUri,
  type Client,
  type ClientFactory,
} from "../src/protocol";

const pubkey = "11".repeat(32);
const secret = "22".repeat(32);
const uri = `nostr+walletconnect://${pubkey}?relay=${encodeURIComponent("wss://relay.example")}&secret=${secret}`;
const allowedRelayHosts = ["relay.example"];

function request<T extends Record<string, unknown>>(value: T): T & { allowed_relay_hosts: string[] } {
  return { ...value, allowed_relay_hosts: allowedRelayHosts };
}

function factory(overrides: Partial<Client> = {}): { create: ClientFactory; client: Client } {
  const client: Client = {
    getWalletServiceInfo: async () => ({
      encryptions: ["nip44_v2"],
      capabilities: ["pay_invoice", "lookup_invoice"],
    }),
    payInvoice: async () => ({ preimage: "33".repeat(32), fees_paid: 42 }),
    lookupInvoice: async () => ({
      state: "settled",
      payment_hash: "44".repeat(32),
      preimage: "33".repeat(32),
      fees_paid: 42,
    }),
    close: () => undefined,
    ...overrides,
  };
  return { create: () => client, client };
}

describe("NWC URI validation", () => {
  test("accepts strict canonical credentials", () => {
    expect(parseNwcUri(uri, allowedRelayHosts)).toEqual({
      relayUrls: ["wss://relay.example"],
      walletPubkey: pubkey,
      secret,
    });
  });

  test.each([
    uri.replace("nostr+walletconnect", "nostrwalletconnect"),
    uri.replace("wss%3A", "ws%3A"),
    uri.replace(`&secret=${secret}`, ""),
    uri.replace(pubkey, "abc"),
    `${uri}&budget=1`,
    `${uri}&secret=${secret}`,
  ])("rejects malformed or expanded URI surface", (value) => {
    expect(() => parseNwcUri(value, allowedRelayHosts)).toThrow();
  });

  test.each([
    uri.replace("relay.example", "evil.example"),
    uri.replace("relay.example", "relay.example%3A8443"),
  ])("rejects relay egress outside the exact standard-port allowlist", (value) => {
    expect(() => parseNwcUri(value, allowedRelayHosts)).toThrow();
  });
});

describe("wallet operations", () => {
  test("pins the private encryption selector used by SDK 8.0.3", async () => {
    const client = new NWCClient({
      relayUrls: ["wss://relay.example"],
      walletPubkey: pubkey,
      secret,
    });
    client.getWalletServiceInfo = async () => ({
      encryptions: ["nip44_v2"],
      capabilities: ["pay_invoice", "lookup_invoice"],
      notifications: [],
    });

    const response = await executeRequest(
      request({ version: 1, operation: "validate", nwc_uri: uri }),
      () => client,
    );

    expect(response.ok).toBeTrue();
    expect(client.encryptionType).toBe("nip44_v2");
  });

  test("validates NIP-44 and both capabilities", async () => {
    const { create, client } = factory();
    const response = await executeRequest(
      request({ version: 1, operation: "validate", nwc_uri: uri }),
      create,
    );
    expect(response).toEqual({
      version: 1,
      ok: true,
      result: {
        state: "valid",
        capabilities: ["pay_invoice", "lookup_invoice"],
        encryptions: ["nip44_v2"],
      },
    });
    expect((client as Client & { _encryptionType?: string })._encryptionType).toBe("nip44_v2");
  });

  test.each([
    { encryptions: ["nip04"], capabilities: ["pay_invoice", "lookup_invoice"] },
    { encryptions: ["nip44_v2"], capabilities: ["pay_invoice"] },
  ])("rejects unsafe wallet service info", async (info) => {
    const { create } = factory({ getWalletServiceInfo: async () => info });
    const response = await executeRequest(
      request({ version: 1, operation: "validate", nwc_uri: uri }),
      create,
    );
    expect(response.ok).toBeFalse();
    if (!response.ok) expect(response.error.retryable).toBeFalse();
  });

  test("returns a validated payment preimage and closes", async () => {
    let closed = false;
    const { create } = factory({ close: () => { closed = true; } });
    const response = await executeRequest(
      request({ version: 1, operation: "pay_invoice", nwc_uri: uri, invoice: "lnbc1invoice" }),
      create,
    );
    expect(response.ok).toBeTrue();
    expect(closed).toBeTrue();
  });

  test("maps not found lookup to an explicit state", async () => {
    const error = Object.assign(new Error("private wallet detail"), { code: "NOT_FOUND" });
    const { create } = factory({ lookupInvoice: async () => { throw error; } });
    const response = await executeRequest(
      request({
        version: 1,
        operation: "lookup_invoice",
        nwc_uri: uri,
        payment_hash: "44".repeat(32),
      }),
      create,
    );
    expect(response).toEqual({ version: 1, ok: true, result: { state: "not_found" } });
  });

  test("returns sanitized terminal wallet errors", async () => {
    const error = Object.assign(new Error(`leaked ${secret}`), { code: "INSUFFICIENT_BALANCE" });
    const { create } = factory({ payInvoice: async () => { throw error; } });
    const response = await executeRequest(
      request({ version: 1, operation: "pay_invoice", nwc_uri: uri, invoice: "lnbc1private" }),
      create,
    );
    expect(JSON.stringify(response)).not.toContain(secret);
    expect(JSON.stringify(response)).not.toContain("lnbc1private");
    if (!response.ok) {
      expect(response.error.code).toBe("insufficient_balance");
      expect(response.error.retryable).toBeFalse();
    }
  });
});
