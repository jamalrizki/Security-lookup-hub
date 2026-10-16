// News feeds, refreshed by the Worker's Cron Trigger into Workers KV.
// Visitors never cause feed fetches: GET /api/news only reads KV.
//
// Workers have no DOMParser, so this is a small RSS 2.0 / Atom reader. It only
// takes title, link, date (and a plain-text summary for CISA); everything is
// tag-stripped, capped, and links must be https on the publisher's own domain.
// Headlines only for commercial outlets: no article excerpts.

import { KEV_URLS } from './cve.js';

export const NEWS_KEY = 'news:v1';
const FETCH_TIMEOUT_MS = 8000;
const MAX_FEED_BYTES = 2_000_000;
const MAX_ITEMS = 30;
const KEV_ITEMS = 25;
const TITLE_MAX = 200;
const SUMMARY_MAX = 240;
const UA = 'SecurityLookupHub/1.0 (+https://github.com/jamalrizki/Security-lookup-hub)';

export const FEEDS = [
  { id: 'kev', name: 'CISA KEV', filter: 'kev', kind: 'kev', urls: KEV_URLS, hosts: ['cisa.gov'] },
  { id: 'cisa', name: 'CISA', filter: 'advisories', kind: 'rss', urls: ['https://www.cisa.gov/cybersecurity-advisories/all.xml'], hosts: ['cisa.gov'], summary: true },
  { id: 'bleepingcomputer', name: 'BleepingComputer', filter: 'news', kind: 'rss', urls: ['https://www.bleepingcomputer.com/feed/'], hosts: ['bleepingcomputer.com'] },
];

// The cron runs at :17, :37 and :57; each run refreshes one source so a run
// stays inside the Free plan's 10 ms CPU budget. Any other minute (a manual
// trigger) refreshes them all.
export const CRON_MINUTES = { 17: 'kev', 37: 'cisa', 57: 'bleepingcomputer' };

// ---------- Text helpers ----------

const NAMED = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '–', mdash: '—', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', hellip: '…' };

export function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,8});/gi, (m, e) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : '';
    }
    return NAMED[e.toLowerCase()] ?? m;
  });
}

const stripTags = (s) => s
  .replace(/<(script|style)\b[\s\S]*?<\/\1\s*>/gi, ' ')
  .replace(/<[^>]*>/g, ' ')
  .replace(/<[^>]*$/, ' ');

/**
 * Element text as plain text: CDATA unwrapped, then entities decoded and tags
 * stripped repeatedly until stable, so double-encoded markup (&amp;lt;script&amp;gt;)
 * can't survive as tags either.
 */
export function plainText(raw, max) {
  let s = raw.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
  for (let i = 0; i < 4; i++) {
    const before = s;
    s = stripTags(decodeEntities(stripTags(s)));
    if (s === before) break;
  }
  // Tags become spaces (so <p>a</p><p>b</p> keeps a gap); drop the ones that land before punctuation.
  s = s.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').replace(/ ([.,;:!?)])/g, '$1').trim();
  return max && s.length > max ? `${s.slice(0, max - 1).replace(/\s+\S*$/, '')}\u2026` : s;
}

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

/** RFC 822 dates (including CISA's 2-digit years) and ISO 8601. Returns ISO or null. */
export function parseDate(raw) {
  const s = (raw || '').trim();
  const m = /^(?:[a-z]{3},\s*)?(\d{1,2})\s+([a-z]{3})[a-z]*\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(?:([+-]\d{4})|(gmt|ut|utc|z|[ecmp][sd]t))?/i.exec(s);
  if (m) {
    let year = Number(m[3]);
    if (m[3].length === 2) year += year < 70 ? 2000 : 1900;
    const month = MONTHS[m[2].toLowerCase()];
    if (month === undefined) return null;
    let offset = 0;
    if (m[7]) offset = (m[7][0] === '-' ? -1 : 1) * (Number(m[7].slice(1, 3)) * 60 + Number(m[7].slice(3, 5)));
    else if (m[8]) offset = { est: -300, edt: -240, cst: -360, cdt: -300, mst: -420, mdt: -360, pst: -480, pdt: -420 }[m[8].toLowerCase()] ?? 0;
    const t = Date.UTC(year, month, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6] || 0)) - offset * 60000;
    return Number.isFinite(t) ? new Date(t).toISOString() : null;
  }
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) {
    const t = Date.parse(s);
    return Number.isFinite(t) ? new Date(t).toISOString() : null;
  }
  return null;
}

/** https only, and the host must be the publisher's domain or a subdomain of it. */
export function allowedLink(raw, hosts) {
  let u;
  try {
    u = new URL(decodeEntities(raw.trim()));
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username || u.password) return null;
  const h = u.hostname.toLowerCase();
  return hosts.some((d) => h === d || h.endsWith(`.${d}`)) ? u.href : null;
}

// ---------- RSS / Atom ----------

function field(block, tags) {
  for (const tag of tags) {
    const m = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}\\s*>`, 'i').exec(block);
    if (m) return m[1];
  }
  return null;
}

function atomLink(block) {
  const links = [...block.matchAll(/<link\b([^>]*)\/?>/gi)].map((m) => m[1]);
  const pick = links.find((a) => /rel\s*=\s*["']alternate["']/i.test(a)) || links.find((a) => !/rel\s*=/i.test(a)) || links[0];
  return pick ? /href\s*=\s*["']([^"']+)["']/i.exec(pick)?.[1] ?? null : null;
}

/** Parses up to MAX_ITEMS items from an RSS 2.0 or Atom document. Never throws on bad input. */
export function parseFeed(xml, feed) {
  const items = [];
  const open = /<(item|entry)\b[^>]*>/gi;
  let m;
  while (items.length < MAX_ITEMS && (m = open.exec(xml))) {
    const end = xml.indexOf(`</${m[1]}`, open.lastIndex);
    if (end === -1) break;
    const block = xml.slice(open.lastIndex, end);
    open.lastIndex = end;

    const title = plainText(field(block, ['title']) || '', TITLE_MAX);
    const rawLink = m[1].toLowerCase() === 'entry'
      ? atomLink(block)
      : plainText(field(block, ['link']) || '') || /<guid\b[^>]*isPermaLink\s*=\s*["']true["'][^>]*>([^<]+)</i.exec(block)?.[1] || atomLink(block);
    const link = rawLink ? allowedLink(rawLink, feed.hosts) : null;
    if (!title || !link) continue; // off-domain, non-https or empty items are dropped
    const item = {
      source: feed.id,
      filter: feed.filter,
      title,
      link,
      date: parseDate(plainText(field(block, ['pubDate', 'published', 'updated', 'dc:date']) || '')),
    };
    if (feed.summary) {
      // CISA advisory pages start with "View CSAF" / "Summary" headings; skip that boilerplate.
      const text = plainText(field(block, ['description', 'summary', 'content']) || '').replace(/^(View CSAF\s*)?(Summary\s*)?/i, '');
      const summary = plainText(text, SUMMARY_MAX);
      if (summary) item.summary = summary;
    }
    items.push(item);
  }
  return items;
}

// ---------- CISA KEV ----------

/** The KEV_ITEMS most recently added entries, as news items. */
export function kevItems(catalog) {
  const list = Array.isArray(catalog?.vulnerabilities) ? catalog.vulnerabilities : [];
  return [...list]
    .filter((v) => /^CVE-\d{4}-\d{4,19}$/.test(v.cveID || ''))
    .sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)))
    .slice(0, KEV_ITEMS)
    .map((v) => ({
      source: 'kev',
      filter: 'kev',
      title: plainText(v.vulnerabilityName || v.cveID, TITLE_MAX),
      link: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(v.cveID)}`,
      date: /^\d{4}-\d{2}-\d{2}$/.test(v.dateAdded || '') ? `${v.dateAdded}T00:00:00.000Z` : null,
      cve: v.cveID,
      vendor: plainText(v.vendorProject || '', 60),
      product: plainText(v.product || '', 80),
      ransomware: v.knownRansomwareCampaignUse === 'Known',
    }));
}

// ---------- Fetching ----------

async function fetchText(url) {
  const res = await fetch(url, {
    headers: { 'user-agent': UA, accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml, application/json;q=0.9, */*;q=0.1' },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    redirect: 'follow',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  if (Number(res.headers.get('content-length')) > MAX_FEED_BYTES) throw new Error('feed too large');
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_FEED_BYTES) {
      await reader.cancel();
      throw new Error('feed too large');
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

export async function fetchFeed(feed) {
  let lastError;
  for (const url of feed.urls) {
    try {
      const text = await fetchText(url);
      if (feed.kind === 'kev') {
        // KEV entries can't be off-domain: links are built here, on cisa.gov.
        return kevItems(JSON.parse(text));
      }
      if (!/<(rss|feed|rdf:RDF)\b/i.test(text.slice(0, 2000))) throw new Error('not an RSS or Atom feed');
      return parseFeed(text, feed);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
}

// ---------- Scheduled refresh ----------

/**
 * Refreshes the given sources and writes one KV value. A source that fails or
 * returns nothing keeps its previous items and is marked stale: good data is
 * never replaced by an empty fetch.
 */
export async function refreshNews(kv, ids = FEEDS.map((f) => f.id), now = new Date()) {
  const prev = (await kv.get(NEWS_KEY, 'json')) || { sources: {} };
  const sources = { ...prev.sources };
  for (const feed of FEEDS.filter((f) => ids.includes(f.id))) {
    const old = sources[feed.id] || { items: [], fetchedAt: null };
    const base = { name: feed.name, filter: feed.filter, lastAttempt: now.toISOString() };
    try {
      const items = await fetchFeed(feed);
      sources[feed.id] = items.length
        ? { ...base, ok: true, fetchedAt: now.toISOString(), error: null, items }
        : { ...base, ok: false, fetchedAt: old.fetchedAt, error: 'the feed returned no usable items', items: old.items };
    } catch (err) {
      sources[feed.id] = { ...base, ok: false, fetchedAt: old.fetchedAt, error: String(err.message || err).slice(0, 120), items: old.items };
    }
  }
  const value = { updatedAt: now.toISOString(), sources };
  await kv.put(NEWS_KEY, JSON.stringify(value));
  return value;
}

/** Which sources a cron run refreshes, from its scheduled time. */
export function sourcesForRun(scheduledTime) {
  const id = CRON_MINUTES[new Date(scheduledTime).getUTCMinutes()];
  return id ? [id] : FEEDS.map((f) => f.id);
}
