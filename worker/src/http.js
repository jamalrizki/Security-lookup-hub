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

export async function getJson(url, { accept = 'application/json', timeout = TIMEOUT_MS, maxBytes = 1_000_000, method = 'GET', body, headers = {} } = {}) {
  const res = await fetch(url, {
    method,
    body,
    headers: { accept, 'user-agent': UA, ...headers },
    signal: AbortSignal.timeout(timeout),
    redirect: 'follow',
  });
  if (res.status === 404) return { status: 404 };
  if (res.status === 429) throw new QuotaError(Number(res.headers.get('retry-after')) || 60);
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
