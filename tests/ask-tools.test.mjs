import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { TOOL_DEFINITIONS, TOOL_CAPS, FEATURES, featuresPrompt, resolveCveId, cveIdsIn, runTool, newState } from '../worker/src/ask-tools.js';

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
  for (const id of ['lookup', 'cves', 'news', 'analyze', 'ioc', 'link', 'headers', 'jwt', 'file', 'subnet', 'cert', 'nmap', 'dmarc', 'actors', 'reference', 'where-to-start', 'tools']) {
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
