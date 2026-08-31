import { describe, expect, test } from "bun:test";
import { getPublicKey, ndebitEncode, nofferEncode, type NdebitData } from "@shocknet/clink-sdk";
import {
  executeRequest,
  MAX_RESPONSE_BYTES,
  serializeResponse,
  type ClinkClient,
  type RelayResolver,
  type Response,
  type SdkFactory,
} from "../src/protocol";

const privateKey = "22".repeat(32);
const servicePubkey = "11".repeat(32);
const staticNdebit = ndebitEncode({
  pubkey: servicePubkey,
  relay: "wss://relay.example",
  pointer: "account-pointer",
});

function request<T extends Record<string, unknown>>(value: T): T & {
  ndebit: string;
  allowed_relay_hosts: string[];
  allow_public_relays: boolean;
  private_key: string;
} {
  return {
    ndebit: staticNdebit,
    allowed_relay_hosts: ["relay.example"],
    allow_public_relays: false,
    private_key: privateKey,
    ...value,
  };
}

function paymentRequest(): ReturnType<typeof request> {
  return request({
    version: 1,
    operation: "pay_invoice",
    invoice: "lnbc1externalinvoice",
    amount_sats: 21,
    description: "direct debit",
    timeout_seconds: 10,
  });
}

function factory(
  response: unknown = { res: "ok", preimage: "33".repeat(32) },
): { create: SdkFactory; client: ClinkClient; calls: NdebitData[] } {
  const calls: NdebitData[] = [];
  const client: ClinkClient = {
    Ndebit: async (data) => {
      calls.push(data);
      return response;
    },
    Stop: () => undefined,
  };
  return { create: () => client, client, calls };
}

describe("request parsing and pointer validation", () => {
  test("requires the exact operation-specific request keys", async () => {
    const valid = request({ version: 1, operation: "validate" });
    const extra = { ...valid, unexpected: true };
    const missing = { ...valid } as Record<string, unknown>;
    delete missing.private_key;

    for (const candidate of [extra, missing]) {
      const response = await executeRequest(candidate);
      expect(response).toEqual({
        version: 1,
        ok: false,
        error: {
          code: "invalid_request",
          message: "request fields are invalid",
          retryable: false,
          wallet_rejection: false,
        },
      });
    }
  });

  test("decodes a static ndebit pointer and returns the SDK-derived app public key", async () => {
    const response = await executeRequest(request({ version: 1, operation: "validate" }));

    expect(response).toEqual({
      version: 1,
      ok: true,
      result: { state: "valid", app_pubkey: getPublicKey(Uint8Array.from(Array(32).fill(0x22))) },
    });
  });

  test("rejects non-ndebit and session k1 pointers", async () => {
    const noffer = nofferEncode({
      pubkey: servicePubkey,
      relay: "wss://relay.example",
      offer: "not-a-debit",
      priceType: 0,
      price: 1,
    });
    const session = ndebitEncode({
      pubkey: servicePubkey,
      relay: "wss://relay.example",
      pointer: "account-pointer",
      k1: "44".repeat(32),
    });

    for (const ndebit of [noffer, session]) {
      const response = await executeRequest(request({ version: 1, operation: "validate", ndebit }));
      expect(response).toEqual({
        version: 1,
        ok: false,
        error: {
          code: "invalid_pointer",
          message: "ndebit pointer is invalid",
          retryable: false,
          wallet_rejection: false,
        },
      });
    }
  });

  test("rejects invalid secp256k1 keys without returning them", async () => {
    const invalidKey = "00".repeat(32);
    const response = await executeRequest(
      request({ version: 1, operation: "validate", private_key: invalidKey }),
    );

    expect(JSON.stringify(response)).not.toContain(invalidKey);
    expect(response).toEqual({
      version: 1,
      ok: false,
      error: {
        code: "invalid_request",
        message: "private_key is invalid",
        retryable: false,
        wallet_rejection: false,
      },
    });
  });
});

describe("relay policy", () => {
  test("requires the decoded relay hostname to exactly match the allowlist", async () => {
    const response = await executeRequest(
      request({ version: 1, operation: "validate", allowed_relay_hosts: ["other.example"] }),
    );

    expect(response).toEqual({
      version: 1,
      ok: false,
      error: {
        code: "relay_not_allowed",
        message: "ndebit relay host is not allowed",
        retryable: false,
        wallet_rejection: false,
      },
    });
  });

  test("checks every public-relay address for globally routable unicast", async () => {
    const resolver: RelayResolver = async () => ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"];
    const accepted = await executeRequest(
      request({
        version: 1,
        operation: "validate",
        allowed_relay_hosts: [],
        allow_public_relays: true,
      }),
      undefined,
      resolver,
    );
    expect(accepted.ok).toBeTrue();

    for (const address of ["127.0.0.1", "10.0.0.1", "169.254.169.254", "2001:db8::1", "fc00::1"]) {
      const rejected = await executeRequest(
        request({
          version: 1,
          operation: "validate",
          allowed_relay_hosts: [],
          allow_public_relays: true,
        }),
        undefined,
        async () => ["93.184.216.34", address],
      );
      expect(rejected).toEqual({
        version: 1,
        ok: false,
        error: {
          code: "relay_not_allowed",
          message: "ndebit relay host is not public",
          retryable: false,
          wallet_rejection: false,
        },
      });
    }
  });

  test("maps public-relay DNS failures to sanitized retryable transport errors", async () => {
    const response = await executeRequest(
      request({
        version: 1,
        operation: "validate",
        allowed_relay_hosts: [],
        allow_public_relays: true,
      }),
      undefined,
      async () => { throw new Error("private DNS failure"); },
    );

    expect(response).toEqual({
      version: 1,
      ok: false,
      error: {
        code: "transport",
        message: "ndebit relay name is unavailable",
        retryable: true,
        wallet_rejection: false,
      },
    });
  });
});

describe("direct debit", () => {
  test("sends an SDK payment request and always stops the relay pool", async () => {
    let stopped = false;
    const { create, client, calls } = factory();
    client.Stop = () => { stopped = true; };

    const response = await executeRequest(paymentRequest(), create);

    expect(response).toEqual({
      version: 1,
      ok: true,
      result: { state: "settled", preimage: "33".repeat(32) },
    });
    expect(calls).toEqual([{
      bolt11: "lnbc1externalinvoice",
      amount_sats: 21,
      pointer: "account-pointer",
      description: "direct debit",
    }]);
    expect(stopped).toBeTrue();
  });

  test("returns pending only for an exact successful response without a preimage", async () => {
    const { create } = factory({ res: "ok" });
    const response = await executeRequest(paymentRequest(), create);
    expect(response).toEqual({
      version: 1,
      ok: true,
      result: { state: "pending", preimage: null },
    });
  });

  test.each([
    [1, { code: "denied", message: "payment request was denied" }],
    [2, { code: "temporary_failure", message: "payment request failed temporarily" }],
    [3, { code: "expired", message: "payment request expired" }],
    [4, { code: "rate_limited", message: "payment request was rate limited" }],
    [5, { code: "invalid_amount", message: "payment amount was rejected" }],
    [6, { code: "invalid_request", message: "payment request was rejected" }],
  ] as const)("maps signed GFY code %i to %s without exposing remote text", async (code, expected) => {
    const remoteError = `remote secret ${privateKey}`;
    const { create } = factory({ res: "GFY", code, error: remoteError });
    const response = await executeRequest(paymentRequest(), create);

    expect(JSON.stringify(response)).not.toContain(remoteError);
    expect(response).toEqual({
      version: 1,
      ok: false,
      error: { ...expected, retryable: false, wallet_rejection: true },
    });
  });

  test("accepts and discards protocol-defined GFY metadata", async () => {
    const { create } = factory({
      res: "GFY",
      code: 4,
      error: "rate limit details must not escape",
      retry_after: 1_800_000_000,
    });

    expect(await executeRequest(paymentRequest(), create)).toEqual({
      version: 1,
      ok: false,
      error: {
        code: "rate_limited",
        message: "payment request was rate limited",
        retryable: false,
        wallet_rejection: true,
      },
    });
  });

  test("sanitizes the SDK timeout string and rejects malformed responses", async () => {
    const timeout = factory();
    timeout.client.Ndebit = () => Promise.reject("failed to get response in time");
    const timeoutResponse = await executeRequest(paymentRequest(), timeout.create);
    expect(timeoutResponse).toEqual({
      version: 1,
      ok: false,
      error: {
        code: "timeout",
        message: "payment request timed out",
        retryable: true,
        wallet_rejection: false,
      },
    });

    const malformed = factory({ res: "ok", preimage: "not-a-preimage" });
    const malformedResponse = await executeRequest(paymentRequest(), malformed.create);
    expect(malformedResponse).toEqual({
      version: 1,
      ok: false,
      error: {
        code: "invalid_wallet_response",
        message: "wallet returned an invalid preimage",
        retryable: false,
        wallet_rejection: false,
      },
    });
  });
});

test("serialized responses cannot exceed the protocol output limit", () => {
  const oversized = {
    version: 1,
    ok: true,
    result: { state: "valid", app_pubkey: "x".repeat(MAX_RESPONSE_BYTES) },
  } as unknown as Response;
  expect(new TextEncoder().encode(serializeResponse(oversized)).byteLength).toBeLessThanOrEqual(
    MAX_RESPONSE_BYTES,
  );
});
