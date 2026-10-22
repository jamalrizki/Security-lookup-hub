// Ask's web search: Tavily, limited to the security sites in
// data/search-domains.json. Ported from Jaizz Chat's webSearch (worker/src/tools.js).
//
// Web pages are untrusted text that can carry prompt injection, so: the query is
// checked for personal data before it leaves; results are re-checked against the
// allowlist in code (the API's own filter is not trusted alone); titles and
// excerpts are tag-stripped and capped; the model is told they are untrusted.

import SEARCH_DOMAINS from '../../data/search-domains.json' with { type: 'json' };
import { detect } from '../../js/detect.js';
import { plainText } from './news.js';

const TAVILY_URL = 'https://api.tavily.com/search';
const TIMEOUT_MS = 10000;
const MAX_RESULTS = 4;
const TITLE_MAX = 150;
const EXCERPT_MAX = 400;
// Tavily's free plan is 1,000 credits a month (1 per basic search), shared with Jaizz.
export const DAILY_WEB_SEARCHES = 25;

/** [{ host, path }] from the allowlist file; "github.com/advisories" -> host github.com, path /advisories. */
export function allowlist(data = SEARCH_DOMAINS) {
  return Object.values(data.groups).flat().map((entry) => {
    const [host, ...rest] = String(entry).toLowerCase().split('/');
    return { host, path: rest.length ? `/${rest.join('/')}` : null };
  });
}

const ALLOW = allowlist();
export const INCLUDE_DOMAINS = [...new Set(ALLOW.map((a) => a.host))];

/** True if the URL is https, has no userinfo, and is on an allowlisted host (or a subdomain of one). */
export function allowedResultUrl(raw, allow = ALLOW) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== 'https:' || u.username || u.password) return false;
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  return allow.some((a) => (host === a.host || host.endsWith(`.${a.host}`))
    && (!a.path || u.pathname === a.path || u.pathname.startsWith(`${a.path}/`)));
}

/** Returns an error message, or null if the query may be sent to the search API. */
export function checkQuery(query) {
  if (typeof query !== 'string') return 'query must be a string';
  const q = query.trim();
  if (q.length < 3 || q.length > 200) return 'query must be 3 to 200 characters';
  for (const token of q.split(/\s+/)) {
    const t = token.replace(/^[("'<[]+|[)"'>\],.;:!?]+$/g, '');
    if (!t) continue;
    // Personal data must not go to a search API.
    if (/[^\s@]+@[^\s@]+\.[^\s@]+/.test(t)) return 'queries must not contain email addresses';
    const d = detect(t);
    if (d.type === 'email') return 'queries must not contain email addresses';
    if ((d.type === 'ipv4' || d.type === 'ipv6') && d.error) return 'queries must not contain private or reserved IP addresses';
  }
  return null;
}

const utcDay = (now) => now.toISOString().slice(0, 10);

/**
 * Counts one search against the daily cap, in KV. Returns false when the cap is
 * reached. Without a KV binding (local tests) there is no cap.
 */
export async function takeDailySearch(kv, now = new Date()) {
  if (!kv) return true;
  const key = `ask:websearch:${utcDay(now)}`;
  const used = Number(await kv.get(key)) || 0;
  if (used >= DAILY_WEB_SEARCHES) return false;
  await kv.put(key, String(used + 1), { expirationTtl: 2 * 86400 });
  return true;
}

/** Tavily response -> safe results. Off-list, non-https and userinfo URLs are dropped. */
export function cleanResults(data) {
  const out = [];
  for (const r of data?.results || []) {
    if (typeof r?.url !== 'string' || !allowedResultUrl(r.url)) continue;
    const url = new URL(r.url);
    out.push({
      title: plainText(String(r.title || url.hostname), TITLE_MAX),
      url: url.href,
      domain: url.hostname.replace(/^www\./, ''),
      excerpt: plainText(String(r.content || ''), EXCERPT_MAX),
    });
    if (out.length >= MAX_RESULTS) break;
  }
  return out;
}

/** Returns { results } or { error }. */
export async function webSearch(query, env, now = new Date()) {
  const bad = checkQuery(query);
  if (bad) return { error: bad };
  if (!env.TAVILY_API_KEY) return { error: 'web search is not configured' };
  if (!(await takeDailySearch(env.NEWS, now))) return { error: 'web search is used up for today; answer without it' };
  const res = await fetch(TAVILY_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${env.TAVILY_API_KEY}` },
    body: JSON.stringify({ query: query.trim(), search_depth: 'basic', max_results: MAX_RESULTS, include_domains: INCLUDE_DOMAINS }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) return { error: `web search failed (HTTP ${res.status})` };
  return { results: cleanResults(await res.json()) };
}
