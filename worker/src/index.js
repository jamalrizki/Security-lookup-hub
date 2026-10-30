// Security Lookup Hub API.
//
//   GET /api/lookup?q=<indicator>   fan out to the sources, one combined JSON result
//   GET /api/explain?q=<indicator>  plain-English AI summary of the same results (Groq)
//   GET /api/cve-search?q=&severity= newest NVD matches for a keyword
//   GET /api/kev-search?q=          CISA KEV entries for a vendor or product
//   GET /api/news                   feed snapshot kept in KV by the cron job (scheduled())
//   POST /api/ask                   Ask: AI answers with tools (ask.js)
//   POST /api/ask/simplify          "Make it simpler" for an Ask answer (ask.js)
//   POST /api/transcribe            Ask's voice input: raw audio -> text, Whisper on Workers AI (transcribe.js)
//   GET /api/my-ip                  the visitor's own public IP and request.cf details (myip.js); never cached
//   GET /api/health
//
// Guardrails (see Docs/Requirements.md): input validated with the same rules as
// the page before any outbound request; private/reserved targets rejected;
// Origin allowlist; site-wide quota guards on keyed sources; results cached per
// indicator; nothing about visitors or queries is logged or stored. There is
// deliberately no per-visitor limit: every account is on a free tier with no
// payment method, so exhausting a quota pauses that source but costs nothing.

import { detect } from '../../js/detect.js';
import { SOURCES, plan, validSelector } from './sources.js';
import { QuotaError } from './http.js';
import { explain, MODEL, verdict } from './explain.js';
import { validateSearch, searchCves, CVE_TTL, loadKev, kevSearch } from './cve.js';
import { NEWS_KEY, refreshNews, sourcesForRun } from './news.js';
import { handleAsk, handleSimplify } from './ask.js';
import { handleTranscribe } from './transcribe.js';
import { myIp } from './myip.js';

const CACHE_TTL = 86_400; // 24h for results
const EMPTY_TTL = 3_600; // 1h for "nothing found", so new data shows up sooner
const KEV_SEARCH_TTL = 3_600; // matches the KEV file's in-memory refresh
// Bump to drop cached results: v2 when the DNS result gained email-security fields (Phase 9);
// v3 to discard NVD "no record" answers cached while an invalid NVD key was set.
const CACHE_VERSION = 'v3';

const ASK_PATH = '/api/ask';
const SIMPLIFY_PATH = '/api/ask/simplify';
const TRANSCRIBE_PATH = '/api/transcribe';
const POST_HANDLERS = { [ASK_PATH]: handleAsk, [SIMPLIFY_PATH]: handleSimplify, [TRANSCRIBE_PATH]: handleTranscribe };
const isAskPath = (path) => Object.hasOwn(POST_HANDLERS, path);

// Every route is GET-only except Ask's, which take a POST (JSON, or audio for voice input).
function corsHeaders(origin, path = '') {
  if (!origin) return { vary: 'Origin' };
  return isAskPath(path)
    ? { 'access-control-allow-origin': origin, 'access-control-allow-methods': 'POST, OPTIONS', 'access-control-allow-headers': 'content-type', 'access-control-max-age': '86400', vary: 'Origin' }
    : { 'access-control-allow-origin': origin, 'access-control-allow-methods': 'GET, OPTIONS', 'access-control-max-age': '86400', vary: 'Origin' };
}

function json(body, status, origin, extra = {}, path = '') {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...corsHeaders(origin, path),
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

async function runSource(id, value, ctx, tools, opts = {}) {
  const source = SOURCES[id];
  const base = { id, name: source.name, link: source.link(value), value };
  // Quota name for pausing: the API key's name, or an explicit one (NVD works without a key).
  const quota = source.quota || source.key;
  if (source.key && !tools.env[source.key]) {
    return { ...base, status: 'skipped', message: 'This source is not configured (no API key).', cached: false };
  }
  const cache = caches.default;
  // Options that change the answer (a DKIM selector) are part of the cache key.
  const suffix = opts.selector ? `/dkim=${encodeURIComponent(opts.selector)}` : '';
  const key = cacheUrl(`${CACHE_VERSION}/${id}/${encodeURIComponent(value)}${suffix}`);

  const hit = await cache.match(key);
  if (hit) return { ...base, ...(await hit.json()), cached: true };

  if (quota && (await tools.paused(quota))) {
    return { ...base, status: 'skipped', message: `${source.name}\u2019s free limit is used up for now. Try again later.`, cached: false };
  }

  let result;
  try {
    result = await source.run(value, tools, opts);
  } catch (err) {
    if (err instanceof QuotaError) {
      tools.pause(quota || id, Math.min(Math.max(err.retryAfter, 60), 3600));
      return { ...base, status: 'skipped', message: `${source.name} says its free limit is used up. It will be retried later.`, cached: false };
    }
    const message = err.name === 'TimeoutError' ? 'The source did not answer in time.' : `The source returned an error (${err.message}).`;
    return { ...base, status: 'error', message, cached: false };
  }
  if (result.status === 'skipped') return { ...base, ...result, cached: false };
  result.checkedAt = new Date().toISOString();
  const okTtl = source.ttl || CACHE_TTL;
  const ttl = result.status === 'ok' ? okTtl : Math.min(EMPTY_TTL, okTtl);
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

  // Optional DKIM selector for domain and email lookups.
  const selector = (new URL(request.url).searchParams.get('dkim') || '').trim();
  if (selector && !validSelector(selector)) {
    return { status: 400, body: { error: 'DKIM selectors are DNS labels: letters, digits, - and _, separated by dots (63 per label, 100 in all).' } };
  }
  const useSelector = selector && ['domain', 'email'].includes(detected.type);

  const steps = plan(detected);
  const tools = quotaTools(env, ctx);
  const sources = await Promise.all(steps.map((s) => runSource(s.id, s.value, ctx, tools, s.id === 'dns' && useSelector ? { selector } : {})));
  return {
    status: 200,
    body: {
      type: detected.type,
      label: detected.label,
      value: detected.value,
      host: detected.host,
      sources,
      // CVE priority is decided in code (the same rule the Explain button uses).
      priority: detected.type === 'cve' ? verdict(sources) : undefined,
      note: steps.length ? undefined : 'No source covers this indicator type. Use the links to check it on each site.',
    },
  };
}

async function lookup(request, env, ctx, origin) {
  const { status, body } = await runLookup(request, env, ctx);
  return json(body, status, origin);
}

// GET /api/cve-search?q=&severity=  The 10 newest NVD matches for a keyword.
async function cveSearchRoute(request, env, ctx, origin) {
  const params = new URL(request.url).searchParams;
  const v = validateSearch(params.get('q'), params.get('severity'));
  if (v.error) return json({ error: v.error }, 400, origin);

  const cache = caches.default;
  const key = cacheUrl(`${CACHE_VERSION}/cve-search/${encodeURIComponent(v.keyword.toLowerCase())}/${v.severity || 'any'}`);
  const hit = await cache.match(key);
  if (hit) return json({ ...(await hit.json()), cached: true }, 200, origin);

  const tools = quotaTools(env, ctx);
  const busy = () => json({ error: 'NVD\u2019s free rate limit is in use. Try again in a minute.' }, 429, origin, { 'retry-after': '60' });
  if (await tools.paused('nvd')) return busy();
  let result;
  try {
    result = await searchCves(v, tools);
  } catch (err) {
    if (err instanceof QuotaError) {
      tools.pause('nvd', 60);
      return busy();
    }
    return json({ error: err.name === 'TimeoutError' ? 'NVD did not answer in time. Try again.' : 'NVD search failed. Try again later.' }, 502, origin);
  }
  if (result.skipped) return busy();
  const body = { keyword: v.keyword, severity: v.severity, ...result, checkedAt: new Date().toISOString() };
  ctx.waitUntil(cache.put(key, new Response(JSON.stringify(body), { headers: { 'cache-control': `max-age=${CVE_TTL}` } })));
  return json({ ...body, cached: false }, 200, origin);
}

// GET /api/kev-search?q=  CISA KEV entries whose vendor or product matches.
// Uses the KEV file CVE lookups already load (in memory for an hour); no new source.
async function kevSearchRoute(request, env, ctx, origin) {
  const v = validateSearch(new URL(request.url).searchParams.get('q'));
  if (v.error) return json({ error: v.error }, 400, origin);

  const cache = caches.default;
  const key = cacheUrl(`${CACHE_VERSION}/kev-search/${encodeURIComponent(v.keyword.toLowerCase())}`);
  const hit = await cache.match(key);
  if (hit) return json({ ...(await hit.json()), cached: true }, 200, origin);

  let kev;
  try {
    kev = await loadKev();
  } catch {
    return json({ error: 'The CISA KEV catalog could not be loaded. Try again later.' }, 502, origin);
  }
  const body = { ...kevSearch(kev.entries, kev.released, v.keyword), checkedAt: new Date().toISOString() };
  ctx.waitUntil(cache.put(key, new Response(JSON.stringify(body), { headers: { 'cache-control': `max-age=${KEV_SEARCH_TTL}` } })));
  return json({ ...body, cached: false }, 200, origin);
}

// GET /api/news  The feed snapshot the cron job keeps in KV; edge-cached 5 minutes.
// Visitors never trigger feed fetches.
async function newsRoute(request, env, ctx, origin) {
  if (!env.NEWS) return json({ error: 'News is not configured.' }, 503, origin);
  const cache = caches.default;
  const key = cacheUrl(`${CACHE_VERSION}/news`);
  const hit = await cache.match(key);
  if (hit) return json(await hit.json(), 200, origin);
  const value = await env.NEWS.get(NEWS_KEY, 'json');
  // Before the first cron run there is nothing yet; don't cache that.
  if (!value) return json({ sources: {}, pending: true }, 200, origin);
  ctx.waitUntil(cache.put(key, new Response(JSON.stringify(value), { headers: { 'cache-control': 'max-age=300' } })));
  return json(value, 200, origin);
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
  const sel = (new URL(request.url).searchParams.get('dkim') || '').trim();
  // style=plain: "In plain English", cached separately from the normal explanation.
  const style = new URL(request.url).searchParams.get('style') === 'plain' ? 'plain' : 'normal';
  const subject = `${body.type === 'email' ? `email:${body.value.split('@').pop()}` : body.value}${sel && ['domain', 'email'].includes(body.type) ? `/dkim=${sel}` : ''}`;
  const key = cacheUrl(`${CACHE_VERSION}/explain3/${style === 'plain' ? 'plain/' : ''}${encodeURIComponent(MODEL)}/${encodeURIComponent(subject)}`);
  const hit = await cache.match(key);
  if (hit) return json({ ...(await hit.json()), cached: true }, 200, origin);

  // No hub-side Groq limit or pause: Groq's own rate limit applies, and its 429 is passed on.
  let text;
  try {
    text = await explain(body, env.GROQ_API_KEY, { style });
  } catch (err) {
    if (err instanceof QuotaError) {
      return json({ error: 'The AI explainer is busy (Groq free tier). Try again in a minute.' }, 429, origin, { 'retry-after': '60' });
    }
    return json({ error: err.name === 'TimeoutError' ? 'The AI explainer took too long. Try again.' : 'The AI explainer failed. Try again later.' }, 502, origin);
  }
  // Explanations of partial results (a source skipped or errored) are not cached,
  // so a later request can explain the full picture.
  const result = { explanation: text, style, model: MODEL, generatedAt: new Date().toISOString() };
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
    if (request.method === 'OPTIONS') return new Response(null, { status: origin ? 204 : 403, headers: corsHeaders(origin, url.pathname) });
    if (isAskPath(url.pathname)) {
      if (request.method !== 'POST') return json({ error: 'Method not allowed.' }, 405, origin, { allow: 'POST, OPTIONS' }, url.pathname);
      if (!origin) return json({ error: 'This API only serves the Security Lookup Hub site.' }, 403, null);
      const r = await POST_HANDLERS[url.pathname](request, env, ctx, { quotaTools, runSource });
      return json(r.body, r.status, origin, r.headers || {}, url.pathname);
    }
    if (request.method !== 'GET') return json({ error: 'Method not allowed.' }, 405, origin, { allow: 'GET, OPTIONS' });
    if (url.pathname === '/api/health') return json({ ok: true }, 200, origin);
    if (!origin) return json({ error: 'This API only serves the Security Lookup Hub site.' }, 403, null);
    if (url.pathname === '/api/lookup') return lookup(request, env, ctx, origin);
    if (url.pathname === '/api/explain') return explainRoute(request, env, ctx, origin);
    if (url.pathname === '/api/cve-search') return cveSearchRoute(request, env, ctx, origin);
    if (url.pathname === '/api/kev-search') return kevSearchRoute(request, env, ctx, origin);
    if (url.pathname === '/api/news') return newsRoute(request, env, ctx, origin);
    // json() sends Cache-Control: no-store; nothing here touches the edge cache or KV.
    if (url.pathname === '/api/my-ip') return json(myIp(request), 200, origin);
    return json({ error: 'Not found.' }, 404, origin);
  },

  // Cron Trigger (wrangler.toml): refreshes the news feeds into KV.
  async scheduled(controller, env, ctx) {
    if (!env.NEWS) return;
    ctx.waitUntil(refreshNews(env.NEWS, sourcesForRun(controller.scheduledTime)));
  },
};
