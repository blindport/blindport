import { lookup } from "node:dns/promises";
import * as ipaddr from "ipaddr.js";

export const MAX_REQUEST_BYTES = 16_384;
export const MAX_RESPONSE_BYTES = 16_384;

const HEX64 = /^[0-9a-f]{64}$/;
const REQUIRED_CAPABILITIES = ["pay_invoice", "lookup_invoice"] as const;

interface RequestBase {
  version: 1;
  nwc_uri: string;
  allowed_relay_hosts: string[];
  allow_public_relays: boolean;
}

export type Request =
  | RequestBase & { operation: "validate" }
  | RequestBase & { operation: "get_budget" }
  | {
      version: 1;
      operation: "pay_invoice";
      nwc_uri: string;
      allowed_relay_hosts: string[];
      allow_public_relays: boolean;
      invoice: string;
    }
  | {
      version: 1;
      operation: "lookup_invoice";
      nwc_uri: string;
      allowed_relay_hosts: string[];
      allow_public_relays: boolean;
      payment_hash: string;
    };

interface WalletServiceInfo {
  encryptions: string[];
  capabilities: string[];
}

interface PayResponse {
  preimage: string;
  fees_paid: number;
}

interface TransactionResponse {
  state: "settled" | "pending" | "failed" | "accepted";
  payment_hash: string;
  preimage: string;
  fees_paid: number;
}

interface BudgetResponse {
  used_budget?: number;
  total_budget?: number;
  renews_at?: number;
  renewal_period?: string;
}

export interface Client {
  getWalletServiceInfo(): Promise<WalletServiceInfo>;
  getBudget(): Promise<BudgetResponse>;
  payInvoice(request: { invoice: string }): Promise<PayResponse>;
  lookupInvoice(request: { payment_hash: string }): Promise<TransactionResponse>;
  close(): unknown;
}

export type ClientFactory = (options: {
  relayUrls: string[];
  walletPubkey: string;
  secret: string;
  lud16?: string;
}) => Client | Promise<Client>;

export type RelayResolver = (hostname: string) => Promise<string[]>;

export interface SafeError {
  code: string;
  message: string;
  retryable: boolean;
}

export type Response =
  | { version: 1; ok: true; result: Record<string, unknown> }
  | { version: 1; ok: false; error: SafeError };

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

function requireExactKeys(value: Record<string, unknown>, allowed: readonly string[]): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new ProtocolError("invalid_request", "request contains unsupported fields");
  }
}

function requireString(
  value: unknown,
  field: string,
  maxLength: number,
  pattern?: RegExp,
): string {
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

function requireAllowedRelayHosts(value: unknown): string[] {
  if (!Array.isArray(value)) {
    throw new ProtocolError("invalid_request", "relay allowlist is invalid");
  }
  const candidates: unknown[] = value;
  const hosts: string[] = [];
  for (const host of candidates) {
    if (
      typeof host !== "string" ||
      host.length === 0 ||
      host.length > 253 ||
      !/^[a-z0-9.-]+$/.test(host)
    ) {
      throw new ProtocolError("invalid_request", "relay allowlist is invalid");
    }
    hosts.push(host);
  }
  if (hosts.length > 64 || new Set(hosts).size !== hosts.length) {
    throw new ProtocolError("invalid_request", "relay allowlist is invalid");
  }
  return hosts;
}

function requireBoolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") {
    throw new ProtocolError("invalid_request", `${field} is invalid`);
  }
  return value;
}

export function parseRequest(value: unknown): Request {
  const object = requireObject(value);
  const operation = object.operation;
  if (
    operation !== "validate" &&
    operation !== "get_budget" &&
    operation !== "pay_invoice" &&
    operation !== "lookup_invoice"
  ) {
    throw new ProtocolError("invalid_request", "operation is unsupported");
  }
  const allowed = [
    "version",
    "operation",
    "nwc_uri",
    "allowed_relay_hosts",
    "allow_public_relays",
  ];
  if (operation === "pay_invoice") allowed.push("invoice");
  if (operation === "lookup_invoice") allowed.push("payment_hash");
  requireExactKeys(object, allowed);
  if (object.version !== 1) {
    throw new ProtocolError("invalid_request", "protocol version is unsupported");
  }
  const nwcUri = requireString(object.nwc_uri, "nwc_uri", 4096);
  const allowedRelayHosts = requireAllowedRelayHosts(object.allowed_relay_hosts);
  const allowPublicRelays = requireBoolean(object.allow_public_relays, "allow_public_relays");
  if (allowPublicRelays === (allowedRelayHosts.length > 0)) {
    throw new ProtocolError("invalid_request", "relay egress policy is invalid");
  }
  if (operation === "pay_invoice") {
    return {
      version: 1,
      operation,
      nwc_uri: nwcUri,
      allowed_relay_hosts: allowedRelayHosts,
      allow_public_relays: allowPublicRelays,
      invoice: requireString(object.invoice, "invoice", 8192),
    };
  }
  if (operation === "lookup_invoice") {
    return {
      version: 1,
      operation,
      nwc_uri: nwcUri,
      allowed_relay_hosts: allowedRelayHosts,
      allow_public_relays: allowPublicRelays,
      payment_hash: requireString(object.payment_hash, "payment_hash", 64, HEX64),
    };
  }
  return {
    version: 1,
    operation,
    nwc_uri: nwcUri,
    allowed_relay_hosts: allowedRelayHosts,
    allow_public_relays: allowPublicRelays,
  };
}

export function parseNwcUri(
  uri: string,
  allowedRelayHosts: readonly string[],
  allowPublicRelays = false,
): {
  relayUrls: string[];
  walletPubkey: string;
  secret: string;
  lud16?: string;
} {
  if (!uri.startsWith("nostr+walletconnect://")) {
    throw new ProtocolError("invalid_uri", "wallet connection URI is invalid");
  }
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new ProtocolError("invalid_uri", "wallet connection URI is invalid");
  }
  if (
    parsed.protocol !== "nostr+walletconnect:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.port !== "" ||
    parsed.pathname !== "" ||
    parsed.hash !== ""
  ) {
    throw new ProtocolError("invalid_uri", "wallet connection URI is invalid");
  }
  const keys = [...parsed.searchParams.keys()];
  if (keys.some((key) => !["relay", "secret", "lud16"].includes(key))) {
    throw new ProtocolError("invalid_uri", "wallet connection URI has unsupported fields");
  }
  if (
    parsed.searchParams.getAll("secret").length !== 1 ||
    parsed.searchParams.getAll("lud16").length > 1
  ) {
    throw new ProtocolError("invalid_uri", "wallet connection URI has duplicate fields");
  }
  const walletPubkey = parsed.hostname;
  const secret = parsed.searchParams.get("secret") ?? "";
  if (!HEX64.test(walletPubkey) || !HEX64.test(secret)) {
    throw new ProtocolError("invalid_uri", "wallet connection URI keys are invalid");
  }
  const relayUrls = parsed.searchParams.getAll("relay");
  if (relayUrls.length === 0 || relayUrls.length > 8) {
    throw new ProtocolError("invalid_uri", "wallet connection URI requires a relay");
  }
  for (const relay of relayUrls) {
    let relayUrl: URL;
    try {
      relayUrl = new URL(relay);
    } catch {
      throw new ProtocolError("invalid_uri", "wallet relay URL is invalid");
    }
    if (
      relay.length > 2048 ||
      relayUrl.protocol !== "wss:" ||
      relayUrl.hostname === "" ||
      relayUrl.port !== "" ||
      relayUrl.username !== "" ||
      relayUrl.password !== "" ||
      relayUrl.hash !== ""
    ) {
      throw new ProtocolError("invalid_uri", "wallet relay URL must use wss");
    }
    if (!allowPublicRelays && !allowedRelayHosts.includes(relayUrl.hostname.toLowerCase())) {
      throw new ProtocolError("relay_not_allowed", "wallet relay host is not allowed");
    }
  }
  const lud16 = parsed.searchParams.get("lud16");
  if (lud16 !== null && (lud16.length === 0 || lud16.length > 320)) {
    throw new ProtocolError("invalid_uri", "wallet lud16 is invalid");
  }
  return lud16 === null
    ? { relayUrls, walletPubkey, secret }
    : { relayUrls, walletPubkey, secret, lud16 };
}

const defaultRelayResolver: RelayResolver = async (hostname) => {
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  return addresses.map(({ address }) => address);
};

export async function validatePublicRelayEgress(
  relayUrls: readonly string[],
  resolver: RelayResolver = defaultRelayResolver,
): Promise<void> {
  for (const relay of relayUrls) {
    const rawHostname = new URL(relay).hostname;
    const hostname = rawHostname.startsWith("[") && rawHostname.endsWith("]")
      ? rawHostname.slice(1, -1)
      : rawHostname;
    let addresses: string[];
    if (ipaddr.isValid(hostname)) {
      addresses = [hostname];
    } else {
      try {
        addresses = await resolver(hostname);
      } catch {
        throw new ProtocolError("transport", "wallet relay name is unavailable", true);
      }
    }
    if (addresses.length === 0) {
      throw new ProtocolError("transport", "wallet relay name is unavailable", true);
    }
    for (const address of addresses) {
      try {
        if (ipaddr.process(address).range() !== "unicast") {
          throw new ProtocolError("relay_not_allowed", "wallet relay host is not public");
        }
      } catch (error) {
        if (error instanceof ProtocolError) throw error;
        throw new ProtocolError("relay_not_allowed", "wallet relay host is not public");
      }
    }
  }
}

function validateInfo(info: WalletServiceInfo): void {
  if (!Array.isArray(info.encryptions) || !info.encryptions.includes("nip44_v2")) {
    throw new ProtocolError(
      "unsupported_encryption",
      "wallet connection must support NIP-44 v2",
    );
  }
  if (
    !Array.isArray(info.capabilities) ||
    REQUIRED_CAPABILITIES.some((capability) => !info.capabilities.includes(capability))
  ) {
    throw new ProtocolError(
      "unsupported_capability",
      "wallet connection must allow invoice payment and lookup",
    );
  }
}

function safeHex(value: unknown, field: string, allowEmpty = false): string | null {
  if (allowEmpty && value === "") return null;
  if (typeof value !== "string" || !HEX64.test(value)) {
    throw new ProtocolError("invalid_wallet_response", `wallet returned an invalid ${field}`);
  }
  return value;
}

function safeFees(value: unknown): number | null {
  if (value === undefined) return null;
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new ProtocolError("invalid_wallet_response", "wallet returned invalid fees");
  }
  return value as number;
}

function safeBudget(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid budget");
  }
  const budget = value as Record<string, unknown>;
  const allowed = ["used_budget", "total_budget", "renews_at", "renewal_period"];
  if (Object.keys(budget).some((key) => !allowed.includes(key))) {
    throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid budget");
  }
  const hasUsed = budget.used_budget !== undefined;
  const hasTotal = budget.total_budget !== undefined;
  if (hasUsed !== hasTotal) {
    throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid budget");
  }
  if (!hasUsed) {
    if (budget.renews_at !== undefined || budget.renewal_period !== undefined) {
      throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid budget");
    }
    return { state: "unlimited" };
  }
  if (
    !Number.isSafeInteger(budget.used_budget) ||
    (budget.used_budget as number) < 0 ||
    !Number.isSafeInteger(budget.total_budget) ||
    (budget.total_budget as number) < 0 ||
    (budget.used_budget as number) > (budget.total_budget as number)
  ) {
    throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid budget");
  }
  const periods = ["daily", "weekly", "monthly", "yearly", "never"];
  if (
    typeof budget.renewal_period !== "string" ||
    !periods.includes(budget.renewal_period)
  ) {
    throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid budget");
  }
  if (
    budget.renews_at !== undefined &&
    (!Number.isSafeInteger(budget.renews_at) ||
      (budget.renews_at as number) < 0 ||
      (budget.renews_at as number) > 253_402_300_799 ||
      budget.renewal_period === "never")
  ) {
    throw new ProtocolError("invalid_wallet_response", "wallet returned an invalid budget");
  }
  return {
    state: "available",
    used_budget_msats: budget.used_budget,
    total_budget_msats: budget.total_budget,
    ...(budget.renews_at === undefined ? {} : { renews_at: budget.renews_at }),
    renewal_period: budget.renewal_period,
  };
}

function mapError(error: unknown): SafeError {
  if (error instanceof ProtocolError) {
    return { code: error.code, message: error.safeMessage, retryable: error.retryable };
  }
  const candidate = error as { code?: unknown; name?: unknown };
  const walletCode = typeof candidate.code === "string" ? candidate.code.toUpperCase() : "";
  const terminal: Record<string, string> = {
    QUOTA_EXCEEDED: "wallet spending quota was exceeded",
    RESTRICTED: "wallet policy rejected the payment",
    UNAUTHORIZED: "wallet connection is unauthorized",
    INSUFFICIENT_BALANCE: "wallet balance is insufficient",
    PAYMENT_FAILED: "wallet reported payment failure",
    EXPIRED: "wallet connection expired",
  };
  const terminalMessage = terminal[walletCode];
  if (terminalMessage !== undefined) {
    return { code: walletCode.toLowerCase(), message: terminalMessage, retryable: false };
  }
  if (walletCode === "NOT_FOUND") {
    return { code: "not_found", message: "wallet payment was not found", retryable: false };
  }
  if (walletCode === "RATE_LIMITED" || walletCode === "RATE_LIMIT") {
    return { code: "rate_limited", message: "wallet rate limit was reached", retryable: true };
  }
  const name = typeof candidate.name === "string" ? candidate.name : "";
  if (name.includes("Timeout")) {
    return { code: "timeout", message: "wallet operation timed out", retryable: true };
  }
  if (name.includes("Network") || name.includes("Publish")) {
    return { code: "transport", message: "wallet transport is unavailable", retryable: true };
  }
  return { code: "internal", message: "wallet operation failed", retryable: true };
}

const defaultFactory: ClientFactory = async (options) => {
  const { NWCClient } = await import("@getalby/sdk/nwc");
  return new NWCClient(options);
};

export async function executeRequest(
  requestValue: unknown,
  clientFactory: ClientFactory = defaultFactory,
  relayResolver: RelayResolver = defaultRelayResolver,
): Promise<Response> {
  let client: Client | undefined;
  try {
    const request = parseRequest(requestValue);
    const options = parseNwcUri(
      request.nwc_uri,
      request.allowed_relay_hosts,
      request.allow_public_relays,
    );
    if (request.allow_public_relays) {
      await validatePublicRelayEgress(options.relayUrls, relayResolver);
    }
    client = await clientFactory(options);
    const info = await client.getWalletServiceInfo();
    validateInfo(info);
    // SDK 8.0.3 otherwise negotiates again inside each request and can fall
    // back to NIP-04 if relay metadata changes after the mandatory precheck.
    const nip44Client = client as Client & {
      _encryptionType?: string;
      readonly encryptionType?: string;
    };
    nip44Client._encryptionType = "nip44_v2";
    if (
      nip44Client._encryptionType !== "nip44_v2" ||
      (nip44Client.encryptionType !== undefined && nip44Client.encryptionType !== "nip44_v2")
    ) {
      throw new ProtocolError(
        "unsupported_encryption",
        "wallet connection must use NIP-44 v2",
      );
    }
    if (request.operation === "validate") {
      return {
        version: 1,
        ok: true,
        result: {
          state: "valid",
          capabilities: [...REQUIRED_CAPABILITIES],
          encryptions: ["nip44_v2"],
        },
      };
    }
    if (request.operation === "get_budget") {
      if (!info.capabilities.includes("get_budget")) {
        return { version: 1, ok: true, result: { state: "unsupported" } };
      }
      return { version: 1, ok: true, result: safeBudget(await client.getBudget()) };
    }
    if (request.operation === "pay_invoice") {
      const paid = await client.payInvoice({ invoice: request.invoice });
      return {
        version: 1,
        ok: true,
        result: {
          state: "settled",
          preimage: safeHex(paid.preimage, "preimage"),
          fees_paid_msats: safeFees(paid.fees_paid),
        },
      };
    }
    try {
      const transaction = await client.lookupInvoice({ payment_hash: request.payment_hash });
      return {
        version: 1,
        ok: true,
        result: {
          state: transaction.state === "accepted" ? "pending" : transaction.state,
          payment_hash: safeHex(transaction.payment_hash, "payment hash"),
          preimage: safeHex(transaction.preimage, "preimage", transaction.state !== "settled"),
          fees_paid_msats: safeFees(transaction.fees_paid),
        },
      };
    } catch (error) {
      const mapped = mapError(error);
      if (mapped.code === "not_found") {
        return { version: 1, ok: true, result: { state: "not_found" } };
      }
      throw error;
    }
  } catch (error) {
    return { version: 1, ok: false, error: mapError(error) };
  } finally {
    if (client !== undefined) {
      try {
        await client.close();
      } catch {
        // Closing is best effort after the operation has a definitive result.
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
      error: { code: "response_too_large", message: "wallet response is too large", retryable: false },
    });
  }
  return encoded;
}
