// Tor exit nodes and cloud/CDN ranges, refreshed by the cron into KV (one list
// per key, ranges:<id>:v1). Lookups and GET /api/ranges only read KV; visitors
// never cause a list fetch. Reading is in js/ranges.js (shared with the browser).
//
// Each list is flattened into sorted, non-overlapping ranges, so a lookup is one
// binary search. Provider prefixes nest (an AWS "AMAZON" /16 holding an "EC2"
// /20); flattening keeps the most specific label for every address.

import { readCapped } from './http.js';
import { parseIPv4, parseIPv6 } from '../../js/detect.js';
import { RANGE_IDS } from '../../js/ranges.js';

export const RANGES_META_KEY = 'ranges:meta:v1';
export const rangesKey = (id) => `ranges:${id}:v1`;
export const RANGES_MINUTE = 7;

const UA = 'SecurityLookupHub/1.0 (+https://github.com/jamalrizki/Security-lookup-hub)';
const V6_MAX = (1n << 128n) - 1n;

// ---------- Addresses and prefixes ----------

// IPv4 stays in plain numbers (BigInt maths on AWS's ~11,000 prefixes costs more
// than the cron's CPU budget); only IPv6 needs BigInt.
function v4Range(addr, bits) {
  const o = parseIPv4(addr);
  if (!o) return null;
  const n = ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
  const size = 2 ** (32 - bits);
  const start = n - (n % size);
  return { v: 4, start, end: start + size - 1 };
}

function v6Range(addr, bits) {
  const g = parseIPv6(addr);
  if (!g) return null;
  const n = g.reduce((acc, x) => (acc << 16n) | BigInt(x), 0n);
  const host = (1n << BigInt(128 - bits)) - 1n;
  const start = n & (V6_MAX ^ host);
  return { v: 6, start, end: start | host };
}

/**
 * "3.5.140.0/22" or "2600:1f00::/40" (or a bare address) -> { v, start, end }, or
 * null. IPv4 bounds are numbers, IPv6 bounds BigInts.
 */
export function prefixRange(text) {
  const [addr, bitsText, extra] = String(text).trim().split('/');
  if (extra !== undefined) return null;
  const v6 = addr.includes(':');
  const width = v6 ? 128 : 32;
  const bits = bitsText === undefined ? width : /^\d{1,3}$/.test(bitsText) ? Number(bitsText) : NaN;
  if (!(bits >= 0 && bits <= width)) return null;
  return v6 ? v6Range(addr, bits) : v4Range(addr, bits);
}

// ---------- Parsers (each returns [{ v, start, end, label }…] or throws) ----------

function notHtml(text) {
  if (/^\s*</.test(text)) throw new Error('got an HTML page, not the list');
}

/** Tor Project bulk exit list: one address per line. Lines that aren't an address are skipped. */
export function parseTor(text) {
  notHtml(text);
  const out = [];
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (!s || s.includes('/')) continue;
    const r = prefixRange(s);
    if (r) out.push({ ...r, label: '' });
  }
  return out;
}

/** Cloudflare's ips-v4 / ips-v6: one prefix per line. */
export function parseCloudflare(text) {
  notHtml(text);
  const out = [];
  for (const line of text.split('\n')) {
    const r = line.trim() && prefixRange(line);
    if (r) out.push({ ...r, label: '' });
  }
  return out;
}

/**
 * AWS ip-ranges.json (about 2.7 MB). JSON.parse, measured at ~6 ms on the real
 * file; a regex pass over the text was ~10 times slower. AWS lists many prefixes
 * twice, once as "AMAZON" (the catch-all) and once under the service; the service wins.
 */
export function parseAws(text) {
  notHtml(text);
  const j = JSON.parse(text);
  if (!Array.isArray(j?.prefixes)) throw new Error('no prefixes in the file');
  // Pick a label per prefix text first, then parse each distinct prefix once.
  const picked = new Map();
  const clean = (x) => (typeof x === 'string' ? x.replace(/\|/g, '') : '');
  for (const p of [...j.prefixes, ...(Array.isArray(j.ipv6_prefixes) ? j.ipv6_prefixes : [])]) {
    const prefix = p?.ip_prefix || p?.ipv6_prefix;
    if (typeof prefix !== 'string') continue;
    const service = clean(p.service);
    const prev = picked.get(prefix);
    if (prev && (service === 'AMAZON' || prev.service !== 'AMAZON')) continue;
    picked.set(prefix, { region: clean(p.region), service });
  }
  const out = [];
  for (const [prefix, { region, service }] of picked) {
    const r = prefixRange(prefix);
    if (r) out.push({ ...r, label: `${region === 'GLOBAL' ? '' : region}|${service === 'AMAZON' ? '' : service}` });
  }
  return out;
}

/** Google Cloud cloud.json: { prefixes: [{ ipv4Prefix | ipv6Prefix, scope }] }. Small, so JSON.parse. */
export function parseGcp(text) {
  notHtml(text);
  const j = JSON.parse(text);
  if (!Array.isArray(j?.prefixes)) throw new Error('no prefixes in the file');
  const out = [];
  for (const p of j.prefixes) {
    const r = prefixRange(p?.ipv4Prefix || p?.ipv6Prefix || '');
    const scope = typeof p?.scope === 'string' ? p.scope.replace(/\|/g, '') : '';
    if (r) out.push({ ...r, label: `${scope === 'global' ? '' : scope}|` });
  }
  return out;
}

// ---------- Flattening ----------

const hex = (n) => n.toString(16).padStart(32, '0');
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Sorted, non-overlapping { v4, v6 } from possibly nested prefixes (prefixes never
 * partly overlap: two CIDRs are either nested or apart). The innermost label wins.
 */
export function flatten(entries) {
  const result = { v4: [], v6: [] };
  for (const v of [4, 6]) {
    const one = v === 4 ? 1 : 1n;
    const list = entries.filter((e) => e.v === v)
      // By start; at the same start, the larger range first so it encloses the smaller.
      .sort((a, b) => cmp(a.start, b.start) || cmp(b.end, a.end));
    const out = [];
    const emit = (start, end, label) => {
      if (start > end) return;
      const last = out.at(-1);
      // Join with the previous piece when it touches and has the same label.
      if (last && last[2] === label && last[1] + one === start) last[1] = end;
      else out.push([start, end, label]);
    };
    const stack = [];
    let cursor = v === 4 ? 0 : 0n;
    for (const r of list) {
      while (stack.length && stack.at(-1).end < r.start) {
        const top = stack.pop();
        emit(cursor, top.end, top.label);
        cursor = top.end + one;
      }
      const top = stack.at(-1);
      if (top && top.start === r.start && top.end === r.end) continue; // same prefix twice: first label kept
      if (top) emit(cursor, r.start - one, top.label);
      cursor = r.start;
      stack.push(r);
    }
    while (stack.length) {
      const top = stack.pop();
      emit(cursor, top.end, top.label);
      cursor = top.end + one;
    }
    result[`v${v}`] = v === 4 ? out : out.map(([s, e, l]) => [hex(s), hex(e), l]);
  }
  return result;
}

// ---------- The lists ----------

// URLs from each provider's own documentation (README: Network type). maxBytes is
// each file's measured size (Oct 29, 2026) with headroom.
export const RANGE_LISTS = {
  tor: { urls: ['https://check.torproject.org/torbulkexitlist'], maxBytes: 200_000, parse: parseTor },
  aws: { urls: ['https://ip-ranges.amazonaws.com/ip-ranges.json'], maxBytes: 6_000_000, parse: parseAws },
  gcp: { urls: ['https://www.gstatic.com/ipranges/cloud.json'], maxBytes: 600_000, parse: parseGcp },
  cloudflare: { urls: ['https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6'], maxBytes: 20_000, parse: parseCloudflare },
};

/**
 * Which lists the :07 run refreshes, by UTC hour, in a 4-hour cycle:
 *   hour % 4 = 0 -> tor, 1 -> aws, 2 -> tor, 3 -> gcp + cloudflare.
 * Tor (which changes fastest) every 2 hours; every other list every 4 hours.
 * Cloudflare's two files are a few hundred bytes, so they ride along with Google's
 * instead of taking a slot of their own (one list per run would leave each
 * provider 6 hours apart).
 */
export function rangesForRun(scheduledTime) {
  return [['tor'], ['aws'], ['tor'], ['gcp', 'cloudflare']][new Date(scheduledTime).getUTCHours() % 4];
}

async function fetchList(id) {
  const list = RANGE_LISTS[id];
  const entries = [];
  for (const url of list.urls) {
    const res = await fetch(url, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(15_000), redirect: 'follow' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await readCapped(res, list.maxBytes);
    if (text === null) throw new Error('file larger than expected');
    entries.push(...list.parse(text));
  }
  if (!entries.length) throw new Error('the list was empty');
  return flatten(entries);
}

/**
 * Refreshes the given lists. A failed or empty fetch never replaces a good list:
 * the previous copy stays and the meta key marks it stale with the error.
 * Writes one key per refreshed list plus the meta key.
 */
export async function refreshRanges(kv, ids, now = Date.now()) {
  const meta = (await kv.get(RANGES_META_KEY, 'json')) || {};
  for (const id of ids) {
    try {
      const { v4, v6 } = await fetchList(id);
      const fetchedAt = new Date(now).toISOString();
      await kv.put(rangesKey(id), JSON.stringify({ fetchedAt, ok: true, v4, v6 }));
      meta[id] = { fetchedAt, ok: true };
    } catch (err) {
      meta[id] = { ...(meta[id] || { fetchedAt: null }), ok: false, error: String(err.message || err).slice(0, 120) };
    }
  }
  await kv.put(RANGES_META_KEY, JSON.stringify(meta));
  return meta;
}

/** The stored lists, { tor: {fetchedAt, ok, v4, v6} | null, … }, read in parallel. */
export async function readRanges(kv) {
  const values = await Promise.all(RANGE_IDS.map((id) => kv?.get(rangesKey(id), 'json').catch(() => null) ?? null));
  return Object.fromEntries(RANGE_IDS.map((id, i) => [id, values[i] || null]));
}
