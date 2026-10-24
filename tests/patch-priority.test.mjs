// Patch priority list (CVEs page): CVE extraction, row facts, ranking in code, CSV.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  cveIdsFromText, priorityRow, sortRows, factsLine, rowsToCsv, epssText, MAX_CVES, VERDICT_ORDER,
} from '../js/patch-priority.js';
import { cveVerdict } from '../worker/src/explain.js';

const now = new Date('2026-10-24T00:00:00Z');

/** A /api/lookup body like the Worker's, built from the same verdict rule it uses. */
function lookupBody(id, { nvd, kev, epss, skip = [] } = {}) {
  const src = (sid, name, data) => (skip.includes(sid) || data === undefined
    ? { id: sid, name, status: 'skipped', message: 'limit' }
    : { id: sid, name, status: 'ok', data });
  const sources = [src('nvd', 'NVD', nvd), src('kev', 'CISA KEV', kev), src('epss', 'FIRST EPSS', epss)];
  const ok = Object.fromEntries(sources.filter((s) => s.status === 'ok').map((s) => [s.id, s.data]));
  return { type: 'cve', value: id, sources, priority: cveVerdict(ok) };
}
const cvss = (baseScore, severity, remote = false) => ({
  status: 'Analyzed',
  cvss: { baseScore, severity, attackVector: remote ? 'NETWORK' : 'LOCAL', privilegesRequired: 'NONE', userInteraction: 'NONE' },
});
const notKev = { inKev: false };
const inKev = (dateAdded, ransomware = false) => ({ inKev: true, dateAdded, dueDate: '2026-11-01', ransomware });

test('pulls CVE IDs out of pasted text: normalised, de-duplicated, in order, capped', () => {
  const text = 'Scan found cve_2024_3400 on fw1 and CVE‑2021‑44228 twice: CVE-2021-44228. Also CVE-2023-4966.';
  assert.deepEqual(cveIdsFromText(text, MAX_CVES, now), { ids: ['CVE-2024-3400', 'CVE-2021-44228', 'CVE-2023-4966'], extra: 0, invalid: [] });

  const many = Array.from({ length: 11 }, (_, i) => `CVE-2025-${1000 + i}`).join(' ');
  const r = cveIdsFromText(many, MAX_CVES, now);
  assert.equal(MAX_CVES, 8);
  assert.equal(r.ids.length, 8);
  assert.equal(r.extra, 3);
  assert.equal(r.ids[0], 'CVE-2025-1000');

  assert.deepEqual(cveIdsFromText('CVE-1990-1234 and CVE-2030-12345', MAX_CVES, now).ids, []);
  assert.equal(cveIdsFromText('CVE-1990-1234', MAX_CVES, now).invalid.length, 1);
  assert.deepEqual(cveIdsFromText('', MAX_CVES, now), { ids: [], extra: 0, invalid: [] });
  assert.deepEqual(cveIdsFromText(null, MAX_CVES, now).ids, []);
});

test('a row keeps the Worker verdict and the facts behind it; failures become "Not enough data"', () => {
  const row = priorityRow('CVE-2021-44228', lookupBody('CVE-2021-44228', { nvd: cvss(10, 'CRITICAL', true), kev: inKev('2021-12-10', true), epss: { epss: 0.944 } }));
  assert.equal(row.verdict, 'Exploited in the wild: patch urgently');
  assert.deepEqual(row.kev, { inKev: true, dateAdded: '2021-12-10', dueDate: '2026-11-01', ransomware: true });
  assert.equal(row.epss, 0.944);
  assert.deepEqual(row.cvss, { score: 10, severity: 'CRITICAL' });
  assert.deepEqual(row.missing, []);

  const skipped = priorityRow('CVE-2025-1111', lookupBody('CVE-2025-1111', { kev: notKev, epss: { epss: 0.002 }, skip: ['nvd'] }));
  assert.equal(skipped.verdict, 'Not enough data');
  assert.equal(skipped.cvss, null);
  assert.deepEqual(skipped.missing, ['NVD']);

  for (const body of [{ error: 'Busy.' }, null, { sources: 'nope' }]) {
    const r = priorityRow('CVE-2025-2222', body);
    assert.equal(r.verdict, 'Not enough data');
    assert.ok(r.error);
    assert.equal(r.missing.length, 3);
  }
});

test('ranks by the hub verdict, then ransomware, EPSS and CVSS, then ID', () => {
  const rows = [
    priorityRow('CVE-2025-0001', lookupBody('CVE-2025-0001', { nvd: cvss(5.5, 'MEDIUM'), kev: notKev, epss: { epss: 0.001 } })),
    priorityRow('CVE-2025-0002', lookupBody('CVE-2025-0002', { nvd: cvss(9.8, 'CRITICAL', true), kev: notKev, epss: { epss: 0.02 } })),
    priorityRow('CVE-2025-0003', lookupBody('CVE-2025-0003', { nvd: cvss(7.5, 'HIGH'), kev: inKev('2025-05-01'), epss: { epss: 0.05 } })),
    priorityRow('CVE-2025-0004', lookupBody('CVE-2025-0004', { nvd: cvss(6.1, 'MEDIUM'), kev: inKev('2025-06-01', true), epss: { epss: 0.01 } })),
    priorityRow('CVE-2025-0005', lookupBody('CVE-2025-0005', { nvd: cvss(7.8, 'HIGH'), kev: notKev, epss: { epss: 0.3 } })),
    priorityRow('CVE-2025-0006', lookupBody('CVE-2025-0006', { nvd: cvss(8.8, 'HIGH'), kev: notKev, epss: { epss: 0.004 } })),
    priorityRow('CVE-2025-0007', lookupBody('CVE-2025-0007', { nvd: cvss(7.1, 'HIGH'), kev: notKev, epss: { epss: 0.004 } })),
    priorityRow('CVE-2025-0008', { error: 'Busy.' }),
    priorityRow('CVE-2025-0009', lookupBody('CVE-2025-0009', { nvd: { status: 'Rejected', cvss: null }, kev: notKev })),
  ];
  const order = sortRows(rows).map((r) => [r.id, r.verdict]);
  assert.deepEqual(order, [
    ['CVE-2025-0004', 'Exploited in the wild: patch urgently'], // KEV with ransomware first
    ['CVE-2025-0003', 'Exploited in the wild: patch urgently'],
    ['CVE-2025-0005', 'High priority'], // EPSS 30% beats EPSS 2%
    ['CVE-2025-0002', 'High priority'],
    ['CVE-2025-0006', 'Patch soon'], // same EPSS: higher CVSS first
    ['CVE-2025-0007', 'Patch soon'],
    ['CVE-2025-0001', 'Patch on your normal cycle'],
    ['CVE-2025-0008', 'Not enough data'],
    ['CVE-2025-0009', 'Rejected: not a valid vulnerability'],
  ]);
  assert.equal(rows[0].id, 'CVE-2025-0001', 'sortRows does not reorder its input');
  // An unknown verdict string sorts with "Not enough data", never at the top.
  const odd = sortRows([{ ...rows[7], id: 'CVE-2025-0010', verdict: 'Something new' }, rows[0]]);
  assert.equal(odd[0].id, 'CVE-2025-0001');
  // Every verdict cveVerdict can return is ranked.
  for (const v of ['Rejected: not a valid vulnerability', 'Exploited in the wild: patch urgently', 'High priority', 'Not enough data', 'Patch soon', 'Patch on your normal cycle', 'Low priority', 'No score yet']) {
    assert.ok(VERDICT_ORDER.includes(v), v);
  }
});

test('facts line and CSV say what is known and what was unavailable', () => {
  const a = priorityRow('CVE-2021-44228', lookupBody('CVE-2021-44228', { nvd: cvss(10, 'CRITICAL', true), kev: inKev('2021-12-10', true), epss: { epss: 0.944 } }));
  assert.equal(factsLine(a), 'In CISA KEV since 2021-12-10 (ransomware use known) · EPSS 94.4% · CVSS 10 critical');
  const b = priorityRow('CVE-2025-1111', lookupBody('CVE-2025-1111', { epss: { epss: 0.002 }, skip: ['nvd', 'kev'] }));
  assert.equal(factsLine(b), 'KEV: unknown · EPSS 0.20% · no CVSS score');
  assert.equal(epssText(null), 'unknown');

  const csv = rowsToCsv(sortRows([b, a])).split('\r\n');
  assert.equal(csv.length, 3);
  assert.match(csv[0], /^"rank","cve","hub_priority","in_kev"/);
  assert.equal(csv[1], '"1","CVE-2021-44228","Exploited in the wild: patch urgently","yes","2021-12-10","2026-11-01","known","0.9440","10","CRITICAL",""');
  assert.equal(csv[2], '"2","CVE-2025-1111","Not enough data","","","","","0.0020","","","NVD; CISA KEV"');
});

test('the CVEs page has the list form, renders without HTML parsing, and Ask can link to it', () => {
  const root = new URL('../', import.meta.url);
  const html = readFileSync(new URL('cves.html', root), 'utf8');
  for (const id of ['id="priority"', 'id="prio-form"', 'id="prio-text"', 'id="prio-results"']) assert.ok(html.includes(id), id);
  for (const f of ['js/cves.js', 'js/patch-priority.js']) {
    const src = readFileSync(new URL(f, root), 'utf8');
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(src), f);
  }
  const features = JSON.parse(readFileSync(new URL('data/hub-features.json', root), 'utf8')).features;
  assert.equal(features.find((f) => f.id === 'patch-list')?.href, './cves.html#priority');
});
