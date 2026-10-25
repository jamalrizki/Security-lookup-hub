// "Exploited in my products": CISA KEV entries for a vendor or product.
// kevSearch() on a fixture catalog, the /api/kev-search route (fetch and
// caches mocked, no network), and the page's text helpers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { kevSearch, KEV_SEARCH_LIMIT, _resetKevCache } from '../worker/src/cve.js';
import worker from '../worker/src/index.js';
import { summaryLine, rowDetail, rowLabel, NOT_LISTED_NOTE } from '../js/kev-search.js';
import { ORIGIN, installCaches, exec } from './helpers/ask-stubs.mjs';

const root = new URL('../', import.meta.url);
const NOW = new Date('2026-10-25T12:00:00Z');

const entry = (cveID, vendorProject, product, dateAdded, extra = {}) => ({
  cveID, vendorProject, product, dateAdded,
  vulnerabilityName: `${vendorProject} ${product} Flaw`,
  shortDescription: `A flaw in ${product}.`,
  requiredAction: 'Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.',
  dueDate: dateAdded,
  knownRansomwareCampaignUse: 'Unknown',
  ...extra,
});

const ENTRIES = [
  entry('CVE-2024-21887', 'Ivanti', 'Connect Secure and Policy Secure', '2024-01-10', { knownRansomwareCampaignUse: 'Known', dueDate: '2024-01-22' }),
  entry('CVE-2026-1001', 'Ivanti', 'Endpoint Manager Mobile (EPMM)', '2026-10-01'),
  entry('CVE-2026-1002', 'Ivanti', 'Connect Secure', '2026-09-01', { knownRansomwareCampaignUse: 'Known' }),
  entry('CVE-2023-27997', 'Fortinet', 'FortiOS and FortiProxy', '2023-06-13'),
  entry('CVE-2019-0002', 'Microsoft', 'Windows', '2022-03-03'),
  entry('CVE-2026-1003', 'Ivanti', 'Connect  Secure', 'not a date'),
];
const MAP = new Map(ENTRIES.map((e) => [e.cveID, e]));

test('kevSearch matches vendor or product case-insensitively, newest first', () => {
  const r = kevSearch(MAP, '2026-10-23', 'IVANTI', NOW);
  assert.equal(r.total, 4);
  assert.deepEqual(r.results.map((x) => x.id), ['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2024-21887', 'CVE-2026-1003'], 'a bad date sorts last');
  assert.equal(r.catalogReleased, '2026-10-23');
  assert.equal(r.results[3].dateAdded, null, 'malformed dates are dropped, not passed on');
  assert.equal(kevSearch(MAP, null, 'fortios', NOW).total, 1, 'product name alone');
  assert.equal(kevSearch(MAP, null, 'Apple', NOW).total, 0);
});

test('kevSearch matches across vendor and product ("Ivanti Connect Secure"), extra spaces ignored', () => {
  const r = kevSearch(MAP, null, 'Ivanti Connect Secure', NOW);
  assert.deepEqual(r.results.map((x) => x.id).sort(), ['CVE-2024-21887', 'CVE-2026-1002', 'CVE-2026-1003']);
});

test('kevSearch counts recent and ransomware-linked entries over all matches', () => {
  const r = kevSearch(MAP, null, 'ivanti', NOW);
  assert.equal(r.recent, 2, 'added within 90 days of now');
  assert.equal(r.recentDays, 90);
  assert.equal(r.ransomware, 2);
  const row = r.results.find((x) => x.id === 'CVE-2024-21887');
  assert.equal(row.ransomware, true);
  assert.equal(row.dueDate, '2024-01-22');
  assert.ok(row.requiredAction.length <= 161, 'required action clipped');
});

test('kevSearch caps the rows but not the counts', () => {
  const many = new Map(Array.from({ length: 70 }, (_, i) => {
    const e = entry(`CVE-2025-${String(1000 + i)}`, 'Acme', 'Widget', `2025-01-${String((i % 28) + 1).padStart(2, '0')}`, { knownRansomwareCampaignUse: i < 5 ? 'Known' : 'Unknown' });
    return [e.cveID, e];
  }));
  const r = kevSearch(many, null, 'acme', NOW);
  assert.equal(r.total, 70);
  assert.equal(r.ransomware, 5);
  assert.equal(r.results.length, KEV_SEARCH_LIMIT);
});

/* ---------- route ---------- */

const KEV_FILE = JSON.stringify({ dateReleased: '2026-10-23T17:00:00.000Z', vulnerabilities: ENTRIES });
const env = { ALLOWED_ORIGINS: ORIGIN };
const get = (q, origin = ORIGIN) => worker.fetch(new Request(`https://w.example/api/kev-search?q=${encodeURIComponent(q)}`, { headers: origin ? { origin } : {} }), env, exec());

function mockKev(reply = () => new Response(KEV_FILE)) {
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    return String(url).includes('known_exploited_vulnerabilities.json') ? reply() : new Response('not mocked', { status: 500 });
  };
  return calls;
}

test('/api/kev-search validates the query before loading anything', async () => {
  installCaches();
  _resetKevCache();
  const calls = mockKev();
  for (const q of ['', 'x', 'a'.repeat(61), 'ivanti<script>', 'fortinet;drop']) {
    const res = await get(q);
    assert.equal(res.status, 400, q);
    assert.ok((await res.json()).error);
  }
  assert.equal(calls.length, 0);
  assert.equal((await get('ivanti', null)).status, 403, 'other sites are refused');
});

test('/api/kev-search returns the matches and caches them', async () => {
  installCaches();
  _resetKevCache();
  const calls = mockKev();
  const res = await get('  Fortinet ');
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.keyword, 'Fortinet');
  assert.equal(body.total, 1);
  assert.equal(body.catalogReleased, '2026-10-23');
  assert.equal(body.results[0].id, 'CVE-2023-27997');
  assert.equal(body.cached, false);
  const again = await (await get('fortinet')).json();
  assert.equal(again.cached, true, 'same keyword in another case hits the cache');
  assert.equal(calls.length, 1, 'the KEV file was downloaded once');
});

test('/api/kev-search reports a KEV outage instead of an empty list', async () => {
  installCaches();
  _resetKevCache();
  mockKev(() => new Response('down', { status: 503 }));
  const res = await get('ivanti');
  assert.equal(res.status, 502);
  assert.match((await res.json()).error, /could not be loaded/);
});

/* ---------- page text ---------- */

test('summary line and row text say only what the counts say', () => {
  const body = kevSearch(MAP, '2026-10-23', 'Ivanti', NOW);
  assert.equal(summaryLine(body), '4 exploited vulnerabilities in CISA’s KEV catalog for “Ivanti” (catalog released 2026-10-23). 2 added in the last 90 days, 2 linked to ransomware.');
  assert.equal(summaryLine(kevSearch(MAP, null, 'fortinet', NOW)), '1 exploited vulnerability in CISA’s KEV catalog for “fortinet”. 0 added in the last 90 days, 0 linked to ransomware.');
  assert.equal(summaryLine(kevSearch(MAP, '2026-10-23', 'apple', NOW)), 'No CISA KEV entries match “apple” (catalog released 2026-10-23).');
  assert.match(summaryLine({ ...body, total: 70 }), /Showing the 4 newest\.$/);
  assert.match(NOT_LISTED_NOTE, /does not make a product safe/);

  const row = body.results.find((x) => x.id === 'CVE-2024-21887');
  assert.equal(rowLabel(row), 'Ivanti Connect Secure and Policy Secure · added 2024-01-10');
  const detail = rowDetail(row);
  assert.match(detail, /CISA due date: 2024-01-22 \(the deadline for US federal agencies\)/);
  assert.match(detail, /Known ransomware use\./);
  assert.match(detail, /^Ivanti Connect Secure and Policy Secure Flaw\. A flaw in/);
  assert.doesNotMatch(rowDetail(body.results.find((x) => x.id === 'CVE-2026-1001')), /ransomware/);
});

test('the page has the #kev section and Ask links to it', () => {
  const html = readFileSync(new URL('cves.html', root), 'utf8');
  assert.match(html, /<section[^>]*id="kev"/);
  for (const id of ['kev-form', 'kev-q', 'kev-results']) assert.match(html, new RegExp(`id="${id}"`));
  const features = JSON.parse(readFileSync(new URL('data/hub-features.json', root), 'utf8')).features;
  assert.equal(features.find((f) => f.id === 'kev-product')?.href, './cves.html#kev');
  const js = readFileSync(new URL('js/cves.js', root), 'utf8');
  assert.doesNotMatch(js, /innerHTML/);
});
