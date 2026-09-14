import { lookup } from "node:dns/promises";
import {
  ClinkSDK,
  decodeBech32,
  getPublicKey,
  newNdebitPaymentRequest,
  type ClinkSettings,
  type NdebitData,
} from "@shocknet/clink-sdk";
import * as ipaddr from "ipaddr.js";

export const MAX_REQUEST_BYTES = 16_384;
export const MAX_RESPONSE_BYTES = 16_384;

const HEX64 = /^[0-9a-f]{64}$/;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const GFY_ERRORS: Readonly<Record<number, { code: string; message: string }>> = {
  1: { code: "denied", message: "payment request was denied" },
  2: { code: "temporary_failure", message: "payment request failed temporarily" },
  3: { code: "expired", message: "payment request expired" },
  4: { code: "rate_limited", message: "payment request was rate limited" },
  5: { code: "invalid_amount", message: "payment amount was rejected" },
  6: { code: "invalid_request", message: "payment request was rejected" },
};

interface RequestBase {
  version: 1;
  ndebit: string;
  allowed_relay_hosts: string[];
  allow_public_relays: boolean;
  private_key: string;
}

export type Request =
  | (RequestBase & { operation: "validate" })
  | (RequestBase & {
      operation: "pay_invoice";
      invoice: string;
      amount_sats: number;
      description: string;
      timeout_seconds: number;
    });

export interface SafeError {
  code: string;
  message: string;
  retryable: boolean;
  wallet_rejection: boolean;
}

export type Response =
  | {
      version: 1;
      ok: true;
      result:
        | { state: "valid"; app_pubkey: string }
        | { state: "settled"; preimage: string }
        | { state: "pending"; preimage: null };
    }
  | { version: 1; ok: false; error: SafeError };

export interface ClinkClient {
  Ndebit(data: NdebitData, timeoutSeconds?: number): Promise<unknown>;
  Stop(): unknown;
}

export type SdkFactory = (settings: ClinkSettings) => ClinkClient | Promise<ClinkClient>;
export type RelayResolver = (hostname: string) => Promise<string[]>;

interface DecodedPointer {
  relay: string;
  pubkey: string;
  pointer?: string;
}

class ProtocolError extends Error {
  constructor(
    readonly code: string,
    readonly safeMessage: string,
    readonly retryable = false,
  ) {
    super(safeMessage);
  }
}

function requireObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ProtocolError("invalid_request", "request must be a JSON object");
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value);
  if (actual.length !== expected.length || expected.some((key) => !Object.hasOwn(value, key))) {
    throw new ProtocolError("invalid_request", "request fields are invalid");
  }
}

function requireString(value: unknown, field: string, maxLength: number, pattern?: RegExp): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    (pattern !== undefined && !pattern.test(value))
  ) {
    throw new ProtocolError("invalid_request", `${field} is invalid`);
  }
  return value;
}

function requireBoolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") {
    throw new ProtocolError("invalid_request", `${field} is invalid`);
  }
  return value;
}

function requireAllowedRelayHosts(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 64) {
    throw new ProtocolError("invalid_request", "relay allowlist is invalid");
  }
  const hosts: string[] = [];
  for (const host of value) {
    if (typeof host !== "string" || !HOSTNAME.test(host)) {
      throw new ProtocolError("invalid_request", "relay allowlist is invalid");
    }
    hosts.push(host);
  }
  if (new Set(hosts).size !== hosts.length) {
    throw new ProtocolError("invalid_request", "relay allowlist is invalid");
  }
  return hosts;
}

function requirePositiveSafeInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new ProtocolError("invalid_request", `${field} is invalid`);
  }
  return value as number;
}

export function parseRequest(value: unknown): Request {
  const object = requireObject(value);
  const operation = object.operation;
  if (operation !== "validate" && operation !== "pay_invoice") {
    throw new ProtocolError("invalid_request", "operation is unsupported");
  }

  const common = [
    "version",
    "operation",
    "ndebit",
    "allowed_relay_hosts",
    "allow_public_relays",
    "private_key",
  ];
  const expected = operation === "pay_invoice"
    ? [...common, "invoice", "amount_sats", "description", "timeout_seconds"]
    : common;
  requireExactKeys(object, expected);
  if (object.version !== 1) {
    throw new ProtocolError("invalid_request", "protocol version is unsupported");
  }

  const allowedRelayHosts = requireAllowedRelayHosts(object.allowed_relay_hosts);
  const allowPublicRelays = requireBoolean(object.allow_public_relays, "allow_public_relays");
  if (allowPublicRelays === (allowedRelayHosts.length > 0)) {
    throw new ProtocolError("invalid_request", "relay egress policy is invalid");
  }

  const base: RequestBase = {
    version: 1,
    operation,
    ndebit: requireString(object.ndebit, "ndebit", 5_000),
    allowed_relay_hosts: allowedRelayHosts,
    allow_public_relays: allowPublicRelays,
    private_key: requireString(object.private_key, "private_key", 64, HEX64),
  } as RequestBase;

  if (operation === "validate") {
    return { ...base, operation };
  }
  return {
    ...base,
    operation,
    invoice: requireString(object.invoice, "invoice", 8_192),
    amount_sats: requirePositiveSafeInteger(object.amount_sats, "amount_sats"),
    description: requireString(object.description, "description", 100),
    timeout_seconds: (() => {
      const timeout = requirePositiveSafeInteger(object.timeout_seconds, "timeout_seconds");
      if (timeout > 120) {
        throw new ProtocolError("invalid_request", "timeout_seconds is invalid");
      }
      return timeout;
    })(),
  };
}

function privateKeyBytes(value: string): Uint8Array {
  const privateKey = new Uint8Array(32);
  for (let index = 0; index < privateKey.length; index += 1) {
    privateKey[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return privateKey;
}

function validatePrivateKey(value: string): { privateKey: Uint8Array; appPubkey: string } {
  try {
    const privateKey = privateKeyBytes(value);
    const appPubkey = getPublicKey(privateKey);
    if (!HEX64.test(appPubkey)) {
      throw new Error("invalid public key");
    }
    return { privateKey, appPubkey };
  } catch {
    throw new ProtocolError("invalid_request", "private_key is invalid");
  }
}

function decodePointer(value: string): DecodedPointer {
  try {
    const decoded = decodeBech32(value);
    if (decoded.type !== "ndebit" || decoded.data.k1 !== undefined || !HEX64.test(decoded.data.pubkey)) {
      throw new Error("invalid ndebit pointer");
    }
    return decoded.data;
  } catch {
    throw new ProtocolError("invalid_pointer", "ndebit pointer is invalid");
  }
}

function validateRelay(
  relay: string,
  allowedRelayHosts: readonly string[],
  allowPublicRelays: boolean,
): { relay: string; hostname: string } {
  let url: URL;
  try {
    url = new URL(relay);
  } catch {
    throw new ProtocolError("invalid_pointer", "ndebit relay is invalid");
  }
  if (
    url.protocol !== "wss:" ||
    url.hostname === "" ||
    url.port !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== ""
  ) {
    throw new ProtocolError("invalid_pointer", "ndebit relay must use secure websockets");
  }
  const hostname = url.hostname.toLowerCase();
  if (!allowPublicRelays && !allowedRelayHosts.includes(hostname)) {
    throw new ProtocolError("relay_not_allowed", "ndebit relay host is not allowed");
  }
  return { relay, hostname };
}

const defaultRelayResolver: RelayResolver = async (hostname) => {
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  return addresses.map(({ address }) => address);
};

export async function validatePublicRelayEgress(
  hostname: string,
  resolver: RelayResolver = defaultRelayResolver,
): Promise<void> {
  const candidate = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  let addresses: string[];
  if (ipaddr.isValid(candidate)) {
    addresses = [candidate];
  } else {
    try {
      addresses = await resolver(candidate);
    } catch {
      throw new ProtocolError("transport", "ndebit relay name is unavailable", true);
    }
  }
  if (addresses.length === 0) {
    throw new ProtocolError("transport", "ndebit relay name is unavailable", true);
  }
  for (const address of addresses) {
    try {
      if (ipaddr.process(address).range() !== "unicast") {
        throw new ProtocolError("relay_not_allowed", "ndebit relay host is not public");
      }
    } catch (error) {
      if (error instanceof ProtocolError) throw error;
      throw new ProtocolError("relay_not_allowed", "ndebit relay host is not public");
    }
  }
}

function requireExactResponseKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value);
  if (actual.length !== expected.length || expected.some((key) => !Object.hasOwn(value, key))) {
    throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid response");
  }
}

function parseNdebitResponse(value: unknown): Response {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid response");
  }
  const response = value as Record<string, unknown>;
  if (response.res === "ok") {
    const hasPreimage = Object.hasOwn(response, "preimage");
    requireExactResponseKeys(response, hasPreimage ? ["res", "preimage"] : ["res"]);
    if (!hasPreimage) {
      return { version: 1, ok: true, result: { state: "pending", preimage: null } };
    }
    if (typeof response.preimage !== "string" || !HEX64.test(response.preimage)) {
      throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid preimage");
    }
    return { version: 1, ok: true, result: { state: "settled", preimage: response.preimage } };
  }
  if (response.res === "GFY") {
    if (typeof response.error !== "string" || !Number.isSafeInteger(response.code)) {
      throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid response");
    }
    const mapped = GFY_ERRORS[response.code as number];
    if (mapped === undefined) {
      throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid response");
    }
    const optionalField = response.code === 3
      ? "delta"
      : response.code === 4
        ? "retry_after"
        : response.code === 5
          ? "range"
          : undefined;
    const hasOptionalField = optionalField !== undefined && Object.hasOwn(response, optionalField);
    requireExactResponseKeys(
      response,
      hasOptionalField
        ? ["res", "error", "code", optionalField]
        : ["res", "error", "code"],
    );
    if (
      hasOptionalField && optionalField === "retry_after" &&
      (!Number.isSafeInteger(response.retry_after) || (response.retry_after as number) < 0)
    ) {
      throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid response");
    }
    if (
      hasOptionalField && optionalField === "delta" &&
      (response.delta === null || typeof response.delta !== "object")
    ) {
      throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid response");
    }
    if (
      hasOptionalField && optionalField === "range" &&
      (response.range === null || typeof response.range !== "object")
    ) {
      throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid response");
    }
    return {
      version: 1,
      ok: false,
      error: { ...mapped, retryable: false, wallet_rejection: true },
    };
  }
  throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid response");
}

function isTransportError(error: unknown): boolean {
  if (error === null || typeof error !== "object") return false;
  const candidate = error as { name?: unknown; message?: unknown; code?: unknown };
  const details = [candidate.name, candidate.message, candidate.code]
    .filter((value): value is string => typeof value === "string")
    .join(" ");
  return /\b(econnrefused|econnreset|econnaborted|enetunreach|ehostunreach|enotfound|eai_again|etimedout)\b|network|websocket|relay|publish|connection|fetch failed/i.test(details);
}

function mapError(error: unknown): SafeError {
  if (error instanceof ProtocolError) {
    return {
      code: error.code,
      message: error.safeMessage,
      retryable: error.retryable,
      wallet_rejection: false,
    };
  }
  if (error === "failed to get response in time") {
    return {
      code: "timeout",
      message: "payment request timed out",
      retryable: true,
      wallet_rejection: false,
    };
  }
  if (isTransportError(error)) {
    return {
      code: "transport",
      message: "payment transport is unavailable",
      retryable: true,
      wallet_rejection: false,
    };
  }
  return {
    code: "internal",
    message: "payment request failed",
    retryable: true,
    wallet_rejection: false,
  };
}

const defaultSdkFactory: SdkFactory = (settings) => new ClinkSDK(settings);

export async function executeRequest(
  requestValue: unknown,
  sdkFactory: SdkFactory = defaultSdkFactory,
  relayResolver: RelayResolver = defaultRelayResolver,
): Promise<Response> {
  let client: ClinkClient | undefined;
  try {
    const request = parseRequest(requestValue);
    const { privateKey, appPubkey } = validatePrivateKey(request.private_key);
    const pointer = decodePointer(request.ndebit);
    const relay = validateRelay(
      pointer.relay,
      request.allowed_relay_hosts,
      request.allow_public_relays,
    );
    if (request.allow_public_relays) {
      await validatePublicRelayEgress(relay.hostname, relayResolver);
    }
    if (request.operation === "validate") {
      return { version: 1, ok: true, result: { state: "valid", app_pubkey: appPubkey } };
    }

    client = await sdkFactory({
      privateKey,
      relays: [relay.relay],
      toPubKey: pointer.pubkey,
      defaultTimeoutSeconds: request.timeout_seconds,
    });
    const payment = newNdebitPaymentRequest(
      request.invoice,
      request.amount_sats,
      pointer.pointer,
      undefined,
      request.description,
    );
    return parseNdebitResponse(await client.Ndebit(payment, request.timeout_seconds));
  } catch (error) {
    return { version: 1, ok: false, error: mapError(error) };
  } finally {
    if (client !== undefined) {
      try {
        client.Stop();
      } catch {
        // Pool destruction must not replace a definitive protocol result.
      }
    }
  }
}

export function serializeResponse(response: Response): string {
  const encoded = JSON.stringify(response);
  if (new TextEncoder().encode(encoded).byteLength > MAX_RESPONSE_BYTES) {
    return JSON.stringify({
      version: 1,
      ok: false,
      error: {
        code: "internal",
        message: "response exceeds maximum size",
        retryable: true,
        wallet_rejection: false,
      },
    });
  }
  return encoded;
}
