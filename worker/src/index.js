// Security Lookup Hub API.
//
//   GET /api/lookup?q=<indicator>   fan out to keyless sources, one combined JSON result
//   GET /api/health
//
// Guardrails (see Docs/Requirements.md): input validated with the same rules as
// the page before any outbound request; private/reserved targets rejected;
// Origin allowlist; per-visitor rate limit; results cached per indicator;
// nothing about visitors or queries is logged or stored.

import { detect } from '../../js/detect.js';
import { SOURCES, plan } from './sources.js';
import { QuotaError } from './http.js';

const CACHE_TTL = 86_400; // 24h for results
const EMPTY_TTL = 3_600; // 1h for "nothing found", so new data shows up sooner
const CACHE_VERSION = 'v1';

function corsHeaders(origin) {
  return origin
    ? { 'access-control-allow-origin': origin, 'access-control-allow-methods': 'GET, OPTIONS', 'access-control-max-age': '86400', vary: 'Origin' }
    : { vary: 'Origin' };
}

function json(body, status, origin, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...corsHeaders(origin),
      ...extra,
    },
  });
}

function allowedOrigin(request, env) {
  const origin = request.headers.get('origin');
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  return origin && allowed.includes(origin) ? origin : null;
}

const cacheUrl = (path) => new Request(`https://cache.lookup-hub.internal/${path}`);

// Site-wide quota guards for sources with tight free tiers, kept in the edge
// cache. Approximate (per data centre, not atomic), like the visitor limit.
function quotaTools(env, ctx) {
  const cache = caches.default;
  return {
    env,
    async paused(name) {
      return Boolean(await cache.match(cacheUrl(`pause/${name}`)));
    },
    /** False if the source has already been called perMinute times this minute. */
    async allow(name, perMinute) {
      const minute = Math.floor(Date.now() / 60_000);
      const key = cacheUrl(`quota/${name}/${minute}`);
      const hit = await cache.match(key);
      const used = hit ? Number(await hit.text()) || 0 : 0;
      if (used >= perMinute) return false;
      ctx.waitUntil(cache.put(key, new Response(String(used + 1), { headers: { 'cache-control': 'max-age=120' } })));
      return true;
    },
    pause(name, seconds) {
      ctx.waitUntil(cache.put(cacheUrl(`pause/${name}`), new Response('1', { headers: { 'cache-control': `max-age=${seconds}` } })));
    },
  };
}

async function runSource(id, value, ctx, tools) {
  const source = SOURCES[id];
  const base = { id, name: source.name, link: source.link(value), value };
  if (source.key && !tools.env[source.key]) {
    return { ...base, status: 'skipped', message: 'This source is not configured (no API key).', cached: false };
  }
  const cache = caches.default;
  const key = cacheUrl(`${CACHE_VERSION}/${id}/${encodeURIComponent(value)}`);

  const hit = await cache.match(key);
  if (hit) return { ...base, ...(await hit.json()), cached: true };

  if (source.key && (await tools.paused(source.key))) {
    return { ...base, status: 'skipped', message: `${source.name}\u2019s free limit is used up for now. Try again later.`, cached: false };
  }

  let result;
  try {
    result = await source.run(value, tools);
  } catch (err) {
    if (err instanceof QuotaError) {
      const quotaName = source.key || id;
      tools.pause(quotaName, Math.min(Math.max(err.retryAfter, 60), 3600));
      return { ...base, status: 'skipped', message: `${source.name} says its free limit is used up. It will be retried later.`, cached: false };
    }
    const message = err.name === 'TimeoutError' ? 'The source did not answer in time.' : `The source returned an error (${err.message}).`;
    return { ...base, status: 'error', message, cached: false };
  }
  if (result.status === 'skipped') return { ...base, ...result, cached: false };
  result.checkedAt = new Date().toISOString();
  const ttl = result.status === 'ok' ? CACHE_TTL : EMPTY_TTL;
  ctx.waitUntil(cache.put(key, new Response(JSON.stringify(result), { headers: { 'cache-control': `max-age=${ttl}` } })));
  return { ...base, ...result, cached: false };
}

// Per-visitor limit: HOURLY_LIMIT lookups per clock hour, counted in the edge
// cache (free, no daily write cap). The cache is per data centre and the
// read-then-write isn't atomic, so the limit is approximate, which is enough
// to stop one caller draining the shared free quotas. The visitor's IP is only
// stored as a salted hash, and the counter expires after the hour.
const HOURLY_LIMIT = 20;

async function rateLimited(request, env, ctx) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';

  // Cloudflare's rate limiting binding, if the plan enforces it (burst control).
  if (env.LOOKUP_LIMITER && !(await env.LOOKUP_LIMITER.limit({ key: ip })).success) return 60;

  const now = Date.now();
  const hour = Math.floor(now / 3_600_000);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${hour}:${ip}`));
  const id = [...new Uint8Array(digest)].slice(0, 16).map((b) => b.toString(16).padStart(2, '0')).join('');
  const key = cacheUrl(`rl/${id}`);
  const hit = await caches.default.match(key);
  const count = hit ? Number(await hit.text()) || 0 : 0;
  const secondsLeft = Math.ceil(((hour + 1) * 3_600_000 - now) / 1000);
  if (count >= HOURLY_LIMIT) return secondsLeft;
  ctx.waitUntil(caches.default.put(key, new Response(String(count + 1), { headers: { 'cache-control': `max-age=${secondsLeft}` } })));
  return 0;
}

async function lookup(request, env, ctx, origin) {
  const q = new URL(request.url).searchParams.get('q') || '';
  if (q.length > 2048) return json({ error: 'Input is too long.' }, 400, origin);

  const detected = detect(q);
  if (detected.type === 'empty') return json({ error: 'Nothing to look up.' }, 400, origin);
  if (detected.type === 'unknown' || detected.error) {
    return json({ error: detected.error || 'Not a supported indicator.', type: detected.type }, 422, origin);
  }

  const retryAfter = await rateLimited(request, env, ctx);
  if (retryAfter) {
    return json({ error: `Too many lookups from your connection. Try again in ${Math.ceil(retryAfter / 60)} minutes.` }, 429, origin, { 'retry-after': String(retryAfter) });
  }

  const steps = plan(detected);
  const tools = quotaTools(env, ctx);
  const sources = await Promise.all(steps.map((s) => runSource(s.id, s.value, ctx, tools)));
  return json({
    type: detected.type,
    label: detected.label,
    value: detected.value,
    host: detected.host,
    sources,
    note: steps.length ? undefined : 'No source covers this indicator type. Use the links to check it on each site.',
  }, 200, origin);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = allowedOrigin(request, env);

    if (!url.pathname.startsWith('/api/')) return json({ error: 'Not found.' }, 404, origin);
    if (request.method === 'OPTIONS') return new Response(null, { status: origin ? 204 : 403, headers: corsHeaders(origin) });
    if (request.method !== 'GET') return json({ error: 'Method not allowed.' }, 405, origin, { allow: 'GET, OPTIONS' });
    if (url.pathname === '/api/health') return json({ ok: true }, 200, origin);
    if (!origin) return json({ error: 'This API only serves the Security Lookup Hub site.' }, 403, null);
    if (url.pathname === '/api/lookup') return lookup(request, env, ctx, origin);
    return json({ error: 'Not found.' }, 404, origin);
  },
};
