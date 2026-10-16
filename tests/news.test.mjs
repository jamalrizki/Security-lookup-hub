import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseFeed, parseDate, kevItems, refreshNews, sourcesForRun, fetchFeed, FEEDS, NEWS_KEY, allowedLink } from '../worker/src/news.js';

const fixture = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
const feed = (id) => FEEDS.find((f) => f.id === id);
const NCSC = { id: 'ncsc', name: 'NCSC', filter: 'advisories', hosts: ['ncsc.gov.uk'], summary: true };

test('RSS: titles, links, 2-digit-year dates and CISA summaries', () => {
  const items = parseFeed(fixture('rss-cisa.xml'), feed('cisa'));
  assert.equal(items.length, 2, 'off-domain, lookalike-host and http items are dropped');
  assert.equal(items[0].title, 'Example ICS Vendor Controller Firmware');
  assert.equal(items[0].date, '2026-10-15T12:00:00.000Z');
  assert.match(items[0].summary, /^Successful exploitation .* execute code on the controller\./, 'CSAF boilerplate removed');
  assert.ok(items[0].summary.length <= 240);
  assert.ok(items[0].summary.endsWith('…'));
  assert.ok(!/[<>]/.test(items[0].summary));
  assert.equal(items[1].title, 'CISA Adds Two Known Exploited Vulnerabilities to Catalog & More', 'CDATA');
  assert.equal(items[1].summary, 'CISA has added two new vulnerabilities to its KEV catalog.');
});

test('RSS: entities decoded, hostile markup stripped, no excerpts for news outlets', () => {
  const items = parseFeed(fixture('rss-news.xml'), feed('thehackernews'));
  assert.deepEqual(items.map((i) => i.title), [
    'Hackers exploit "Example" flaw & backdoor servers — patch now',
    'Ransomware gang leaks data',
    'Double-encoded headline',
  ]);
  for (const i of items) {
    assert.ok(!/[<>]/.test(i.title), i.title);
    assert.equal(i.summary, undefined, 'commercial outlets get no excerpt');
    assert.match(i.link, /^https:\/\/thehackernews\.com\//);
  }
  assert.equal(items[0].date, '2026-10-15T20:25:04.000Z', 'timezone offset applied');
});

test('Atom: alternate link, published date, summary', () => {
  const items = parseFeed(fixture('atom.xml'), NCSC);
  assert.equal(items.length, 2);
  assert.equal(items[0].title, 'Advisory: example vulnerability in widgets');
  assert.equal(items[0].link, 'https://www.ncsc.gov.uk/news/example-advisory');
  assert.equal(items[0].date, '2026-10-14T08:30:00.000Z');
  assert.equal(items[0].summary, 'Short official summary of the advisory.');
  assert.equal(items[1].date, '2026-10-13T11:00:00.000Z');
});

test('malformed input never throws and caps items and title length', () => {
  assert.deepEqual(parseFeed(fixture('malformed.xml'), feed('thehackernews')), []);
  assert.deepEqual(parseFeed('', feed('cisa')), []);
  const many = `<rss><channel>${Array.from({ length: 50 }, (_, i) => `<item><title>${'T'.repeat(500)} ${i}</title><link>https://www.cisa.gov/a/${i}</link></item>`).join('')}</channel></rss>`;
  const items = parseFeed(many, feed('cisa'));
  assert.equal(items.length, 30);
  assert.ok(items.every((i) => i.title.length <= 200));
});

test('dates and links', () => {
  assert.equal(parseDate('Thu, 15 Oct 26 12:00:00 +0000'), '2026-10-15T12:00:00.000Z');
  assert.equal(parseDate('Mon, 05 Jan 98 00:00:00 GMT'), '1998-01-05T00:00:00.000Z');
  assert.equal(parseDate('15 Oct 2026 08:00 EDT'), '2026-10-15T12:00:00.000Z');
  assert.equal(parseDate('nonsense'), null);
  assert.equal(allowedLink('https://sub.cisa.gov/x', ['cisa.gov']), 'https://sub.cisa.gov/x');
  assert.equal(allowedLink('https://notcisa.gov/x', ['cisa.gov']), null);
  assert.equal(allowedLink('https://user@www.cisa.gov/x', ['cisa.gov']), null);
  assert.equal(allowedLink('https://www.cisa.gov/a?x=1&amp;y=2', ['cisa.gov']), 'https://www.cisa.gov/a?x=1&y=2');
});

test('KEV: the 25 most recently added entries, links built on cisa.gov', () => {
  const vulnerabilities = Array.from({ length: 40 }, (_, i) => ({
    cveID: `CVE-2026-${10000 + i}`,
    vendorProject: 'Acme',
    product: '<b>Widget</b>',
    vulnerabilityName: `Acme Widget Flaw ${i}`,
    dateAdded: `2026-09-${String((i % 28) + 1).padStart(2, '0')}`,
    knownRansomwareCampaignUse: i === 27 ? 'Known' : 'Unknown',
  }));
  vulnerabilities.push({ cveID: 'not-a-cve', dateAdded: '2026-12-31' });
  const items = kevItems({ vulnerabilities });
  assert.equal(items.length, 25);
  assert.equal(items[0].dateAdded, undefined);
  assert.equal(items[0].date, '2026-09-28T00:00:00.000Z');
  assert.ok(items.every((i) => i.link.startsWith('https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-')));
  assert.equal(items[0].product, 'Widget');
  assert.equal(items.find((i) => i.cve === 'CVE-2026-10027').ransomware, true);
});

/* ---------- fetching and the scheduled refresh ---------- */

function mockFetch(routes) {
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    for (const [needle, reply] of routes) {
      if (String(url).includes(needle)) return new Response(reply.text, { status: reply.status || 200 });
    }
    return new Response('not mocked', { status: 500 });
  };
  return calls;
}

class FakeKV {
  constructor() { this.store = new Map(); this.puts = 0; }
  async get(key, type) { const v = this.store.get(key); return v && type === 'json' ? JSON.parse(v) : v ?? null; }
  async put(key, value) { this.puts += 1; this.store.set(key, value); }
}

const KEV_JSON = JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2021-44228', vendorProject: 'Apache', product: 'Log4j2', vulnerabilityName: 'Log4j2 RCE', dateAdded: '2021-12-10', knownRansomwareCampaignUse: 'Known' }] });

test('refresh writes one KV key with all three sources', async () => {
  mockFetch([
    ['known_exploited', { text: KEV_JSON }],
    ['cisa.gov/cybersecurity-advisories', { text: fixture('rss-cisa.xml') }],
    ['feedburner.com/TheHackersNews', { text: fixture('rss-news.xml') }],
  ]);
  const kv = new FakeKV();
  const v = await refreshNews(kv, undefined, new Date('2026-10-15T12:17:00Z'));
  assert.equal(kv.puts, 1);
  assert.ok(kv.store.has(NEWS_KEY));
  assert.deepEqual(Object.keys(v.sources).sort(), ['cisa', 'kev', 'thehackernews']);
  for (const s of Object.values(v.sources)) assert.equal(s.ok, true);
  assert.equal(v.sources.kev.items[0].cve, 'CVE-2021-44228');
});

test('a failing, HTML or empty feed keeps the previous items and is marked stale', async () => {
  mockFetch([
    ['known_exploited', { text: KEV_JSON }],
    ['cisa.gov/cybersecurity-advisories', { text: fixture('rss-cisa.xml') }],
    ['feedburner.com/TheHackersNews', { text: fixture('rss-news.xml') }],
  ]);
  const kv = new FakeKV();
  await refreshNews(kv, undefined, new Date('2026-10-15T12:00:00Z'));

  mockFetch([
    ['known_exploited', { status: 403, text: 'Forbidden' }],
    ['cisa.gov/cybersecurity-advisories', { text: fixture('html-challenge.html') }],
    ['feedburner.com/TheHackersNews', { text: '<rss><channel></channel></rss>' }],
  ]);
  const v = await refreshNews(kv, undefined, new Date('2026-10-15T13:00:00Z'));
  for (const id of ['kev', 'cisa', 'thehackernews']) {
    assert.equal(v.sources[id].ok, false, id);
    assert.ok(v.sources[id].items.length > 0, `${id} kept its items`);
    assert.equal(v.sources[id].fetchedAt, '2026-10-15T12:00:00.000Z', `${id} keeps the last good time`);
    assert.ok(v.sources[id].error);
  }
  assert.match(v.sources.cisa.error, /not an RSS or Atom feed/);
});

test('each cron run refreshes one source; other minutes refresh all', async () => {
  assert.deepEqual(sourcesForRun(Date.parse('2026-10-15T12:17:00Z')), ['kev']);
  assert.deepEqual(sourcesForRun(Date.parse('2026-10-15T12:37:00Z')), ['cisa']);
  assert.deepEqual(sourcesForRun(Date.parse('2026-10-15T12:57:00Z')), ['thehackernews']);
  assert.deepEqual(sourcesForRun(Date.parse('2026-10-15T12:03:00Z')), ['kev', 'cisa', 'thehackernews']);

  const calls = mockFetch([['feedburner.com/TheHackersNews', { text: fixture('rss-news.xml') }]]);
  const kv = new FakeKV();
  await refreshNews(kv, ['thehackernews']);
  assert.equal(calls.length, 1, 'only the chosen source is fetched');
});

test('a source that is no longer configured is dropped from KV', async () => {
  mockFetch([['feedburner.com/TheHackersNews', { text: fixture('rss-news.xml') }]]);
  const kv = new FakeKV();
  await kv.put(NEWS_KEY, JSON.stringify({ sources: { bleepingcomputer: { name: 'BleepingComputer', ok: false, items: [] }, kev: { name: 'CISA KEV', ok: true, items: [{ title: 'x' }] } } }));
  const v = await refreshNews(kv, ['thehackernews']);
  assert.deepEqual(Object.keys(v.sources).sort(), ['kev', 'thehackernews']);
  assert.equal(v.sources.kev.items.length, 1, 'other sources keep their items');
});

test('KEV falls back to the GitHub mirror; oversized feeds are refused', async () => {
  const calls = mockFetch([
    ['cisa.gov/sites', { status: 500, text: '' }],
    ['raw.githubusercontent.com', { text: KEV_JSON }],
  ]);
  assert.equal((await fetchFeed(feed('kev'))).length, 1);
  assert.equal(calls.length, 2);

  mockFetch([['feedburner.com/TheHackersNews', { text: `<rss>${'x'.repeat(2_100_000)}</rss>` }]]);
  await assert.rejects(fetchFeed(feed('thehackernews')), /too large/);
});
