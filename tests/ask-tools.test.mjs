import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { TOOL_DEFINITIONS, TOOL_CAPS, FEATURES, featuresPrompt, resolveCveId, cveIdsIn, runTool, newState, nearDuplicate, searchWords } from '../worker/src/ask-tools.js';

const root = new URL('../', import.meta.url);

test('all four tool definitions together stay under 2,400 characters (they ride on every Groq call)', () => {
  assert.deepEqual(TOOL_DEFINITIONS.map((t) => t.function.name), ['search_reference', 'web_search', 'recent_news', 'cve_lookup']);
  const size = JSON.stringify(TOOL_DEFINITIONS).length;
  assert.ok(size <= 2400, `${size} characters`);
});

test('caps match the spec', () => {
  assert.deepEqual(TOOL_CAPS, { search_reference: 2, web_search: 3, cve_lookup: 3, recent_news: 2 });
});

test('every hub feature href points to a page and anchor that exist; ids are unique; about is at most 60 characters', () => {
  const ids = new Set();
  for (const f of FEATURES) {
    assert.ok(!ids.has(f.id), `duplicate id ${f.id}`);
    ids.add(f.id);
    assert.ok(f.about.length <= 60, `${f.id}: about too long`);
    assert.match(f.href, /^\.\/[a-z]*(\.html)?(#[a-z-]+)?$/, `${f.id}: relative href`);
    const [path, anchor] = f.href.slice(2).split('#');
    const page = path || 'index.html';
    assert.ok(existsSync(new URL(page, root)), `${f.id}: ${page} missing`);
    if (anchor) assert.ok(readFileSync(new URL(page, root), 'utf8').includes(`id="${anchor}"`), `${f.id}: #${anchor} missing in ${page}`);
  }
  for (const id of ['lookup', 'cves', 'news', 'analyze', 'ioc', 'link', 'headers', 'jwt', 'file', 'subnet', 'cert', 'nmap', 'actors', 'reference', 'where-to-start', 'tools']) {
    assert.ok(ids.has(id), `missing ${id}`);
  }
  assert.match(featuresPrompt(), /^lookup: /);
});

test('CVE ID check: exact, 1-2 character near-miss of exactly one, otherwise refused', () => {
  const known = cveIdsIn('look at CVE‑2024—4577 and cve-2021-44228');
  assert.deepEqual([...known], ['CVE-2024-4577', 'CVE-2021-44228']);
  assert.deepEqual(resolveCveId('CVE-2024-4577', known), { id: 'CVE-2024-4577' });
  assert.deepEqual(resolveCveId('CVE-2021-44258', known), { id: 'CVE-2021-44228', corrected: true });
  assert.deepEqual(resolveCveId('CVE-2019-0708', known), { unknown: true });
  // Ambiguous: two known IDs one character away.
  assert.deepEqual(resolveCveId('CVE-2024-1002', new Set(['CVE-2024-1001', 'CVE-2024-1003'])), { unknown: true });
});

test('cve_lookup validates the ID format first, and unknown tools are errors', async () => {
  const ctx = { env: {}, state: newState('') };
  assert.equal((await runTool('cve_lookup', { cve_id: 'CVE-1990-1234' }, ctx)).isError, true);
  assert.equal((await runTool('cve_lookup', { cve_id: 'log4shell' }, ctx)).isError, true);
  assert.equal((await runTool('shell', {}, ctx)).isError, true);
});

test('recent_news filters and returns at most 10 newest items, links only to the Sources list', async () => {
  const items = Array.from({ length: 14 }, (_, i) => ({ title: `Item ${i}`, link: `https://thehackernews.com/${i}`, date: `2026-10-${String(i + 1).padStart(2, '0')}T00:00:00.000Z` }));
  const NEWS = { get: async () => ({ sources: { thn: { name: 'The Hacker News', filter: 'news', items }, cisa: { name: 'CISA', filter: 'advisories', items: [{ title: 'Adv', link: 'https://www.cisa.gov/a', date: '2026-10-30T00:00:00.000Z' }] } } }) };
  const state = newState('');
  const r = await runTool('recent_news', { filter: 'news' }, { env: { NEWS }, state });
  assert.equal(r.result.items.length, 10);
  assert.equal(r.result.items[0].title, 'Item 13');
  assert.equal(r.result.items[0].link, undefined, 'the model gets no URLs to copy');
  assert.equal(state.sources.length, 10);
  assert.equal((await runTool('recent_news', { filter: 'bogus' }, { env: { NEWS }, state: newState('') })).isError, true);
});

test('near-duplicate web searches: reworded or reordered repeats match; a new angle, version or CVE does not', () => {
  assert.deepEqual([...searchWords('Is the IBM bulletins for PHP2Shell?')].sort(), ['bulletin', 'ibm', 'php2shell']);
  // The Oct 23 product check: two bulletin searches that were the same search.
  assert.equal(nearDuplicate('Contoso FacilityHub security bulletin PHP2Shell', 'PHP2Shell Contoso FacilityHub security bulletins'), true);
  assert.equal(nearDuplicate('Contoso FacilityHub security bulletin PHP2Shell', 'Contoso FacilityHub PHP2Shell security bulletin 2026'), true);
  assert.equal(nearDuplicate('Contoso FacilityHub security bulletin PHP2Shell', 'Contoso FacilityHub technology stack PHP'), false, 'a new angle is allowed');
  assert.equal(nearDuplicate('Apache Tomcat 9.0.1 security advisory', 'Apache Tomcat 10.1.2 security advisory'), false, 'a different version');
  assert.equal(nearDuplicate('CVE-2024-4577 exploit advisory', 'CVE-2024-4578 exploit advisory'), false, 'a different CVE');
  assert.equal(nearDuplicate('query number 1', 'query number 2'), false);
  assert.equal(nearDuplicate('the of and', 'the of and'), false, 'no significant words: never a duplicate');
});

test('a near-duplicate web_search is refused before Tavily and does not use up the cap', async () => {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push(JSON.parse(init.body).query);
    return new Response(JSON.stringify({ results: [{ title: 'Bulletin', url: 'https://www.cisa.gov/b', content: 'text' }] }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    const ctx = { env: { TAVILY_API_KEY: 'tvly-test' }, state: newState('') };
    assert.equal((await runTool('web_search', { query: 'Contoso FacilityHub security bulletin PHP2Shell' }, ctx)).isError, false);
    const dup = await runTool('web_search', { query: 'PHP2Shell Contoso FacilityHub security bulletin 2026' }, ctx);
    assert.equal(dup.isError, true);
    assert.equal(dup.summary, 'Skipped: nearly the same as an earlier search');
    assert.match(dup.result.error, /^You already searched for almost the same thing \("Contoso FacilityHub security bulletin PHP2Shell"\)/);
    assert.equal(ctx.state.counts.web_search, 1, 'the repeat did not use up the cap');
    assert.equal((await runTool('web_search', { query: 'Contoso FacilityHub technology stack' }, ctx)).isError, false);
    assert.equal((await runTool('web_search', { query: 'PHP2Shell patch guidance' }, ctx)).isError, false, 'still three real searches');
    assert.deepEqual(calls, ['Contoso FacilityHub security bulletin PHP2Shell', 'Contoso FacilityHub technology stack', 'PHP2Shell patch guidance'], 'the repeat never reached Tavily');
  } finally {
    globalThis.fetch = realFetch;
  }
});
