import { executeRequest, MAX_REQUEST_BYTES, serializeResponse, type Response } from "./protocol";

// The SDK may log relay failures. The helper must only emit its bounded JSON response.
console.log = () => undefined;
console.info = () => undefined;
console.warn = () => undefined;
console.error = () => undefined;
console.debug = () => undefined;

async function readRequest(): Promise<unknown> {
  const reader = Bun.stdin.stream().getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_REQUEST_BYTES) throw new Error("request_too_large");
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

let response: Response;
try {
  response = await executeRequest(await readRequest());
} catch {
  response = {
    version: 1,
    ok: false,
    error: {
      code: "invalid_request",
      message: "request is invalid",
      retryable: false,
      wallet_rejection: false,
    },
  };
}
await Bun.write(Bun.stdout, serializeResponse(response));
