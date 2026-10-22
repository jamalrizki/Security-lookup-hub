import { test } from 'node:test';
import assert from 'node:assert/strict';
import { allowlist, allowedResultUrl, checkQuery, cleanResults, webSearch, takeDailySearch, INCLUDE_DOMAINS, DAILY_WEB_SEARCHES } from '../worker/src/websearch.js';

test('allowlist: hosts with optional path prefixes; Tavily gets hosts only', () => {
  const a = allowlist({ groups: { x: ['cisa.gov', 'GitHub.com/advisories'] } });
  assert.deepEqual(a, [{ host: 'cisa.gov', path: null }, { host: 'github.com', path: '/advisories' }]);
  assert.ok(INCLUDE_DOMAINS.includes('github.com'));
  assert.ok(!INCLUDE_DOMAINS.some((d) => d.includes('/')));
  assert.ok(INCLUDE_DOMAINS.length <= 300, "Tavily's include_domains limit");
});

test('result URLs: https, no userinfo, allowlisted host or subdomain, path prefix enforced', () => {
  assert.ok(allowedResultUrl('https://www.cisa.gov/news'));
  assert.ok(allowedResultUrl('https://nvd.nist.gov/vuln/detail/CVE-2024-4577'));
  assert.ok(allowedResultUrl('https://github.com/advisories/GHSA-xxxx'));
  assert.ok(!allowedResultUrl('https://github.com/someone/poc'));
  assert.ok(!allowedResultUrl('https://github.com/advisoriesX'));
  assert.ok(!allowedResultUrl('http://www.cisa.gov/news'));
  assert.ok(!allowedResultUrl('https://user@www.cisa.gov/'));
  assert.ok(!allowedResultUrl('https://u:p@www.cisa.gov/'));
  assert.ok(!allowedResultUrl('https://cisa.gov.evil.example/'));
  assert.ok(!allowedResultUrl('https://evilcisa.gov/'));
  assert.ok(!allowedResultUrl('javascript:alert(1)'));
  assert.ok(!allowedResultUrl('not a url'));
});

test('queries: 3-200 characters, no email addresses, no private or reserved IPs', () => {
  assert.equal(checkQuery('PHP CGI CVE-2024-4577 advisory'), null);
  assert.equal(checkQuery('8.8.8.8 abuse reports'), null);
  assert.match(checkQuery('ab'), /3 to 200/);
  assert.match(checkQuery('x'.repeat(201)), /3 to 200/);
  assert.match(checkQuery('breach jane@example.org'), /email/);
  assert.match(checkQuery('breach (jane[at]example[.]org)'), /email/);
  assert.match(checkQuery('scan from 192.168.1.10'), /private or reserved/);
  assert.match(checkQuery('fe80::1 attack'), /private or reserved/);
  assert.match(checkQuery(42), /string/);
});

test('cleanResults strips tags and caps title (150) and excerpt (400), at most 4 results', () => {
  const r = cleanResults({ results: [
    { title: `<script>alert(1)</script>${'T'.repeat(300)}`, url: 'https://www.cisa.gov/a', content: `<img src=x onerror=alert(1)>${'word '.repeat(200)}` },
    ...Array.from({ length: 5 }, (_, i) => ({ title: `t${i}`, url: `https://owasp.org/${i}`, content: 'c' })),
  ] });
  assert.equal(r.length, 4);
  assert.ok(r[0].title.length <= 150);
  assert.ok(r[0].excerpt.length <= 400);
  assert.ok(!/[<>]/.test(r[0].title + r[0].excerpt));
  assert.equal(r[0].domain, 'cisa.gov');
});

test('webSearch refuses bad queries and a missing key without any fetch', async () => {
  let calls = 0;
  globalThis.fetch = async () => { calls++; return new Response('{}'); };
  assert.match((await webSearch('who is bob@example.com', { TAVILY_API_KEY: 'k' })).error, /email/);
  assert.match((await webSearch('a valid query', {})).error, /not configured/);
  assert.equal(calls, 0);
});

test('daily cap: one KV write per search, expiring after 2 days; refused at the cap', async () => {
  const puts = [];
  const store = new Map();
  const kv = { get: async (k) => store.get(k) ?? null, put: async (k, v, o) => { puts.push(o); store.set(k, v); } };
  const now = new Date('2026-10-22T12:00:00Z');
  for (let i = 0; i < DAILY_WEB_SEARCHES; i++) assert.equal(await takeDailySearch(kv, now), true);
  assert.equal(await takeDailySearch(kv, now), false);
  assert.equal(store.get('ask:websearch:2026-10-22'), String(DAILY_WEB_SEARCHES));
  assert.equal(puts.length, DAILY_WEB_SEARCHES);
  assert.deepEqual(puts[0], { expirationTtl: 172800 });
  assert.equal(await takeDailySearch(kv, new Date('2026-10-23T00:00:01Z')), true, 'a new UTC day starts at zero');
});
