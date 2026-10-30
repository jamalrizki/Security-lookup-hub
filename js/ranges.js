// Network type from published lists: Tor exit nodes and cloud/CDN ranges. The
// Worker refreshes the lists into KV (worker/src/ranges.js); this file only reads
// them, so the Worker's "network" source and the browser tools (subnet calculator,
// IOC log mode, which download GET /api/ranges once) decide the same way. DOM-free.
//
// A list is { v4: [[start, end, label]…], v6: [[startHex, endHex, label]…] },
// sorted and non-overlapping: IPv4 as 32-bit numbers, IPv6 as 32-digit lowercase
// hex (which sorts like the number). label is "region|service" (either may be empty).

import { parseIPv4, parseIPv6 } from './detect.js';

export const RANGE_IDS = ['tor', 'aws', 'gcp', 'cloudflare'];
export const PROVIDERS = { aws: 'Amazon Web Services', gcp: 'Google Cloud', cloudflare: 'Cloudflare' };

/** { v: 4, key: number } or { v: 6, key: hex } for an address, or null. */
export function ipKey(ip) {
  const o = parseIPv4(ip);
  if (o) return { v: 4, key: ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3] };
  const g = parseIPv6(ip);
  if (g) return { v: 6, key: g.map((x) => x.toString(16).padStart(4, '0')).join('') };
  return null;
}

/** The [start, end, label] entry containing key, or null (binary search). */
export function findRange(entries, key) {
  let lo = 0;
  let hi = (entries?.length || 0) - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [start, end] = entries[mid];
    if (key < start) hi = mid - 1;
    else if (key > end) lo = mid + 1;
    else return entries[mid];
  }
  return null;
}

/**
 * Where an address sits in the lists: { tor, provider: { id, name, region?, service? } | null }.
 * lists: { tor, aws, gcp, cloudflare }, any of which may be missing.
 */
export function classify(lists, ip) {
  const k = ipKey(ip);
  if (!k) return null;
  const hit = (id) => findRange(lists?.[id]?.[`v${k.v}`], k.key);
  let provider = null;
  for (const id of ['aws', 'gcp', 'cloudflare']) {
    const entry = hit(id);
    if (!entry) continue;
    const [region, service] = String(entry[2] || '').split('|');
    provider = { id, name: PROVIDERS[id], ...(region ? { region } : {}), ...(service ? { service } : {}) };
    break;
  }
  return { tor: Boolean(hit('tor')), provider };
}

/** "Amazon Web Services (eu-west-1, S3)", "Cloudflare (CDN and proxy network)". */
export function providerText(p) {
  if (p.id === 'cloudflare') return 'Cloudflare (CDN and proxy network)';
  const detail = [p.region, p.service].filter(Boolean).join(', ');
  return detail ? `${p.name} (${detail})` : p.name;
}

export const NOT_LISTED = 'Not in the Tor or major cloud lists';

/** One short label for the browser tools: "Tor exit node", "In Amazon Web Services (…)", or NOT_LISTED. */
export function shortLabel(c) {
  if (!c) return '';
  const parts = [];
  if (c.tor) parts.push('Tor exit node');
  if (c.provider) parts.push(`In ${providerText(c.provider)}`);
  return parts.length ? parts.join('; ') : NOT_LISTED;
}
