// Security Lookup Hub API.
//
//   GET /api/lookup?q=<indicator>   fan out to the sources, one combined JSON result
//   GET /api/explain?q=<indicator>  plain-English AI summary of the same results (Groq)
//   GET /api/health
//
// Guardrails (see Docs/Requirements.md): input validated with the same rules as
// the page before any outbound request; private/reserved targets rejected;
// Origin allowlist; site-wide quota guards on keyed sources; results cached per
// indicator; nothing about visitors or queries is logged or stored. There is
// deliberately no per-visitor limit: every account is on a free tier with no
// payment method, so exhausting a quota pauses that source but costs nothing.

import { detect } from '../../js/detect.js';
import { SOURCES, plan } from './sources.js';
import { QuotaError } from './http.js';
import { explain, MODEL } from './explain.js';

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

/** Validates the query and runs its sources. Returns { status, body }. */
async function runLookup(request, env, ctx) {
  const q = new URL(request.url).searchParams.get('q') || '';
  if (q.length > 2048) return { status: 400, body: { error: 'Input is too long.' } };

  const detected = detect(q);
  if (detected.type === 'empty') return { status: 400, body: { error: 'Nothing to look up.' } };
  if (detected.type === 'unknown' || detected.error) {
    return { status: 422, body: { error: detected.error || 'Not a supported indicator.', type: detected.type } };
  }

  const steps = plan(detected);
  const tools = quotaTools(env, ctx);
  const sources = await Promise.all(steps.map((s) => runSource(s.id, s.value, ctx, tools)));
  return {
    status: 200,
    body: {
      type: detected.type,
      label: detected.label,
      value: detected.value,
      host: detected.host,
      sources,
      note: steps.length ? undefined : 'No source covers this indicator type. Use the links to check it on each site.',
    },
  };
}

async function lookup(request, env, ctx, origin) {
  const { status, body } = await runLookup(request, env, ctx);
  return json(body, status, origin);
}

// The explanation is built from the same (cached) source results the page
// shows, so asking for one doesn't call the threat feeds again.
async function explainRoute(request, env, ctx, origin) {
  if (!env.GROQ_API_KEY) return json({ error: 'AI explanations are not configured.' }, 503, origin);
  const { status, body } = await runLookup(request, env, ctx);
  if (status !== 200) return json(body, status, origin);
  if (!body.sources.some((s) => s.status === 'ok' || s.status === 'empty')) {
    return json({ error: 'Not enough results to explain.' }, 422, origin);
  }

  const cache = caches.default;
  const subject = body.type === 'email' ? `email:${body.value.split('@').pop()}` : body.value;
  const key = cacheUrl(`${CACHE_VERSION}/explain3/${encodeURIComponent(MODEL)}/${encodeURIComponent(subject)}`);
  const hit = await cache.match(key);
  if (hit) return json({ ...(await hit.json()), cached: true }, 200, origin);

  const tools = quotaTools(env, ctx);
  if ((await tools.paused('GROQ_API_KEY')) || !(await tools.allow('GROQ_API_KEY', 20))) {
    return json({ error: 'The AI explainer is busy (free tier limit). Try again in a minute.' }, 429, origin, { 'retry-after': '60' });
  }
  let text;
  try {
    text = await explain(body, env.GROQ_API_KEY);
  } catch (err) {
    if (err instanceof QuotaError) {
      tools.pause('GROQ_API_KEY', Math.min(Math.max(err.retryAfter, 60), 3600));
      return json({ error: 'The AI explainer has hit its free limit. Try again later.' }, 429, origin, { 'retry-after': '60' });
    }
    return json({ error: err.name === 'TimeoutError' ? 'The AI explainer took too long. Try again.' : 'The AI explainer failed. Try again later.' }, 502, origin);
  }
  // Explanations of partial results (a source skipped or errored) are not cached,
  // so a later request can explain the full picture.
  const result = { explanation: text, model: MODEL, generatedAt: new Date().toISOString() };
  if (!body.sources.some((s) => s.status === 'skipped' || s.status === 'error')) {
    ctx.waitUntil(cache.put(key, new Response(JSON.stringify(result), { headers: { 'cache-control': `max-age=${CACHE_TTL}` } })));
  }
  return json({ ...result, cached: false }, 200, origin);
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
    if (url.pathname === '/api/explain') return explainRoute(request, env, ctx, origin);
    return json({ error: 'Not found.' }, 404, origin);
  },
};
