// Shared HTTP helper for sources: timeout, size cap, quota detection.

const TIMEOUT_MS = 8000;
const UA = 'SecurityLookupHub/1.0 (+https://github.com/jamalrizki/Security-lookup-hub)';

/** Thrown when a source says we are over its rate limit or quota. */
export class QuotaError extends Error {
  constructor(retryAfter) {
    super('rate limited');
    this.retryAfter = retryAfter;
  }
}

// rateLimitStatuses: NVD answers 403 as well as 429 when rate limited.
// cf: Cloudflare fetch options, e.g. edge-caching a large shared download.
export async function getJson(url, { accept = 'application/json', timeout = TIMEOUT_MS, maxBytes = 1_000_000, method = 'GET', body, headers = {}, rateLimitStatuses = [429], cf } = {}) {
  const res = await fetch(url, {
    method,
    body,
    headers: { accept, 'user-agent': UA, ...headers },
    signal: AbortSignal.timeout(timeout),
    redirect: 'follow',
    ...(cf ? { cf } : {}),
  });
  // Some APIs explain a 404 in a header (NVD: "message: Invalid apiKey."); pass it on.
  if (res.status === 404) return { status: 404, message: res.headers.get('message') };
  if (rateLimitStatuses.includes(res.status)) throw new QuotaError(Number(res.headers.get('retry-after')) || 60);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await readCapped(res, maxBytes);
  if (text === null) return { status: 413 };
  return { status: res.status, json: JSON.parse(text) };
}

// Reads at most maxBytes so one huge response can't blow the CPU or memory budget.
async function readCapped(res, maxBytes) {
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(all);
}
