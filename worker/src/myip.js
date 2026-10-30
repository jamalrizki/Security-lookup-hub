// GET /api/my-ip: the visitor's own public address and what Cloudflare already
// knows about the connection (request.cf), so no third-party service sees them.
// The address comes from CF-Connecting-IP only, which Cloudflare sets and the
// visitor can't; X-Forwarded-For and the like are ignored. Never cached, stored
// or logged (the route answers with Cache-Control: no-store).

import { detect } from '../../js/detect.js';

// request.cf fields passed on (names from Cloudflare's IncomingRequestCfProperties).
// latitude, longitude and postalCode are left out on purpose: they look exact and
// usually aren't.
const CF_FIELDS = ['country', 'region', 'city', 'timezone', 'asn', 'asOrganization'];

/** { ip, version, country, region, city, timezone, asn, asOrganization }, or { local: true }. */
export function myIp(request) {
  const d = detect(request.headers.get('cf-connecting-ip') || '');
  // Missing, private or loopback: local `wrangler dev`, where there's no public address to see.
  if ((d.type !== 'ipv4' && d.type !== 'ipv6') || d.error) return { local: true };
  const cf = request.cf || {};
  const out = { ip: d.value, version: d.type === 'ipv4' ? 4 : 6 };
  for (const k of CF_FIELDS) out[k] = cf[k] ?? null;
  return out;
}
