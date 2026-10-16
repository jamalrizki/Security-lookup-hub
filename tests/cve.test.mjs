// Ported from CVE Explainer's worker/test/tools.test.mjs (fetch mocked, no
// network), adapted to the hub's source shape, plus detection, priority and
// search-validation tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detect, validateCveSearch } from '../js/detect.js';
import { CVE_SOURCES, NOT_IN_KEV, _resetKevCache, searchCves, nvdKey } from '../worker/src/cve.js';
import { QuotaError } from '../worker/src/http.js';
import { cveVerdict } from '../worker/src/explain.js';
import { plan } from '../worker/src/sources.js';

/* ---------- fixtures (shapes follow the real APIs) ---------- */

const NVD_LOG4SHELL = {
  totalResults: 1,
  vulnerabilities: [{
    cve: {
      id: 'CVE-2021-44228',
      published: '2021-12-10T10:15:09.143',
      lastModified: '2025-10-27T16:15:00.000',
      vulnStatus: 'Analyzed',
      descriptions: [
        { lang: 'en', value: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other endpoints.' },
        { lang: 'es', value: 'texto en español' },
      ],
      metrics: {
        cvssMetricV31: [
          { source: '134c704f-9b21-4f2e-91b3-4a467353bcc0', type: 'Secondary', cvssData: { version: '3.1', baseScore: 9.0, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H', attackVector: 'NETWORK', attackComplexity: 'HIGH', privilegesRequired: 'NONE', userInteraction: 'NONE', scope: 'CHANGED', confidentialityImpact: 'HIGH', integrityImpact: 'HIGH', availabilityImpact: 'HIGH' } },
          { source: 'nvd@nist.gov', type: 'Primary', cvssData: { version: '3.1', baseScore: 10.0, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', attackVector: 'NETWORK', attackComplexity: 'LOW', privilegesRequired: 'NONE', userInteraction: 'NONE', scope: 'CHANGED', confidentialityImpact: 'HIGH', integrityImpact: 'HIGH', availabilityImpact: 'HIGH' } },
        ],
        cvssMetricV2: [{ source: 'nvd@nist.gov', type: 'Primary', baseSeverity: 'HIGH', cvssData: { version: '2.0', baseScore: 9.3, accessVector: 'NETWORK' } }],
      },
      weaknesses: [
        { source: 'nvd@nist.gov', type: 'Primary', description: [{ lang: 'en', value: 'CWE-502' }, { lang: 'en', value: 'CWE-20' }] },
        { source: 'security@apache.org', type: 'Secondary', description: [{ lang: 'en', value: 'CWE-502' }, { lang: 'en', value: 'CWE-9999' }] },
      ],
      configurations: [{
        nodes: [{
          operator: 'OR',
          cpeMatch: [
            { vulnerable: true, criteria: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*', versionStartIncluding: '2.0.1', versionEndExcluding: '2.3.1' },
            { vulnerable: true, criteria: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*', versionStartIncluding: '2.0.1', versionEndExcluding: '2.3.1' }, // duplicate
            { vulnerable: true, criteria: 'cpe:2.3:a:apache:log4j:2.15.0:rc1:*:*:*:*:*:*' },
            { vulnerable: false, criteria: 'cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*' },
          ],
        }],
      }],
      references: [
        { url: 'http://example.com/blog', source: 'x', tags: ['Third Party Advisory'] },
        { url: 'https://logging.apache.org/log4j/2.x/security.html', source: 'y', tags: ['Vendor Advisory'] },
        { url: 'http://example.com/poc', source: 'z', tags: ['Exploit'] },
      ],
    },
  }],
};

const NVD_REJECTED = {
  totalResults: 1,
  vulnerabilities: [{ cve: { id: 'CVE-2024-0001', published: '2024-01-01T00:00:00.000', lastModified: '2024-02-01T00:00:00.000', vulnStatus: 'Rejected', descriptions: [{ lang: 'en', value: '** REJECT ** DO NOT USE THIS CVE RECORD.' }], metrics: {} } }],
};

const NVD_SEARCH = {
  totalResults: 87,
  vulnerabilities: [
    { cve: { id: 'CVE-2019-0001', published: '2019-03-01T00:00:00.000', descriptions: [{ lang: 'en', value: 'Older issue in ExampleOS.' }], metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 5.0, baseSeverity: 'MEDIUM' } }] } } },
    { cve: { id: 'CVE-2025-0002', published: '2025-08-01T00:00:00.000', descriptions: [{ lang: 'en', value: 'Newer issue in ExampleOS.' }], metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: 9.8, baseSeverity: 'CRITICAL' } }] } } },
    { cve: { id: 'CVE-2023-0003', published: '2023-05-01T00:00:00.000', descriptions: [{ lang: 'en', value: 'Middle issue.' }], metrics: {} } },
  ],
};

// Formatted like the real CISA file. The second entry has braces inside a string value.
const KEV_TEXT = `{
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.10.08",
    "dateReleased": "2026-10-08T17:20:54.304Z",
    "count": 2,
    "vulnerabilities": [
        { "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
          "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability", "dateAdded": "2021-12-10",
          "shortDescription": "short", "requiredAction": "Apply updates.", "dueDate": "2021-12-24",
          "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": ["CWE-20"] },
        { "cveID": "CVE-2020-1111", "vendorProject": "Acme", "product": "Widget",
          "vulnerabilityName": "Acme Widget Flaw", "dateAdded": "2022-01-01", "shortDescription": "short",
          "requiredAction": "Use template {x} } then patch.", "dueDate": "2022-01-22",
          "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": [] }
    ]
}`;

/* ---------- helpers ---------- */

function mockFetch(routes) {
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    for (const [needle, reply] of routes) {
      if (String(url).includes(needle)) {
        const { status = 200, body, text } = typeof reply === 'function' ? reply(String(url)) : reply;
        return new Response(text ?? JSON.stringify(body), { status });
      }
    }
    return new Response('not mocked', { status: 500 });
  };
  return calls;
}

const tools = (env = {}, allow = true) => ({ env, allow: async () => allow, paused: async () => false, pause() {} });
const run = (id, value, env, allow) => CVE_SOURCES[id].run(value, tools(env, allow));

/* ---------- detection ---------- */

test('CVE IDs detect in any case and with copy-paste dash variants', () => {
  for (const q of ['CVE-2021-44228', 'cve-2021-44228', 'CVE‑2021‑44228', ' cve 2021 44228 ', 'CVE–2021–44228', 'CVE_2021_44228']) {
    assert.deepEqual(detect(q), { type: 'cve', value: 'CVE-2021-44228', label: 'CVE ID' }, q);
  }
});

test('future-year, pre-1999 and 3-digit CVE IDs are rejected before any request', () => {
  const next = new Date().getUTCFullYear() + 1;
  assert.ok(detect(`CVE-${next + 1}-1234`).error);
  assert.ok(!detect(`CVE-${next}-1234`).error, 'next year is allowed (IDs are reserved ahead)');
  assert.ok(detect('CVE-1998-0001').error);
  assert.match(detect('CVE-2021-123').error, /at least 4 digits/);
  // The Worker returns 422 for any detect() result with an error, before plan() or any fetch.
  assert.equal(detect('CVE-2021-123').type, 'cve');
  assert.deepEqual(plan(detect('CVE-2021-44228')).map((s) => s.id), ['nvd', 'kev', 'epss']);
});

/* ---------- NVD ---------- */

test('nvd picks NVD’s primary score and translates the vector to plain English', async () => {
  const calls = mockFetch([['services.nvd.nist.gov', { body: NVD_LOG4SHELL }]]);
  const { status, data } = await run('nvd', 'CVE-2021-44228');
  assert.equal(status, 'ok');
  assert.match(calls[0].url, /cveId=CVE-2021-44228$/);
  assert.equal(data.published, '2021-12-10');
  assert.equal(data.cvss.baseScore, 10.0);
  assert.equal(data.cvss.scoredBy, 'NVD');
  assert.equal(data.cvss.severity, 'CRITICAL');
  assert.ok(data.cvss.plainEnglish.some((l) => /remotely over the network/.test(l)));
  assert.ok(data.cvss.plainEnglish.some((l) => /No login or privileges needed/.test(l)));
  assert.ok(data.cvss.plainEnglish.some((l) => /beyond the vulnerable component/.test(l)));
  assert.ok(data.description.startsWith('Apache Log4j2'));
});

test('nvd dedupes affected products, formats ranges, skips non-vulnerable CPEs', async () => {
  mockFetch([['services.nvd.nist.gov', { body: NVD_LOG4SHELL }]]);
  const { data } = await run('nvd', 'CVE-2021-44228');
  assert.deepEqual(data.affected.map((a) => [a.vendor, a.product, a.versions]), [
    ['apache', 'log4j', '>= 2.0.1, < 2.3.1'],
    ['apache', 'log4j', '2.15.0 rc1'],
  ]);
  assert.equal(data.affectedTotal, 2);
});

test('nvd names known CWEs, de-duplicates, leaves unknown names null, and puts vendor advisories first', async () => {
  mockFetch([['services.nvd.nist.gov', { body: NVD_LOG4SHELL }]]);
  const { data } = await run('nvd', 'CVE-2021-44228');
  assert.deepEqual(data.weaknesses, [
    { id: 'CWE-502', name: 'Deserialization of Untrusted Data' },
    { id: 'CWE-20', name: 'Improper Input Validation' },
    { id: 'CWE-9999', name: null },
  ]);
  assert.equal(data.references[0].url, 'https://logging.apache.org/log4j/2.x/security.html');
});

test('nvd truncates long descriptions at 600 characters', async () => {
  const long = structuredClone(NVD_LOG4SHELL);
  long.vulnerabilities[0].cve.descriptions = [{ lang: 'en', value: 'x'.repeat(900) }];
  mockFetch([['services.nvd.nist.gov', { body: long }]]);
  const { data } = await run('nvd', 'CVE-2021-44228');
  assert.equal(data.description.length, 601);
  assert.equal(data.descriptionTruncated, true);
});

test('nvd flags rejected CVEs, handles missing metrics, and reports not-found as empty', async () => {
  mockFetch([['services.nvd.nist.gov', { body: NVD_REJECTED }]]);
  const { data } = await run('nvd', 'CVE-2024-0001');
  assert.equal(data.cvss, null);
  assert.match(data.notes[0], /REJECTED/);

  mockFetch([['services.nvd.nist.gov', { body: { totalResults: 0, vulnerabilities: [] } }]]);
  assert.equal((await run('nvd', 'CVE-2027-99999')).status, 'empty');
});

test('nvd sends a key only when it is a UUID, treats 403 as rate limiting, and skips when the minute quota is used', async () => {
  const uuid = '0a1b2c3d-1111-2222-3333-444455556666';
  const calls = mockFetch([['services.nvd.nist.gov', { body: NVD_REJECTED }]]);
  await run('nvd', 'CVE-2024-0001');
  assert.equal(calls[0].init.headers.apiKey, undefined);
  await run('nvd', 'CVE-2024-0001', { NVD_API_KEY: 'gsk_not-an-nvd-key' });
  assert.equal(calls[1].init.headers.apiKey, undefined, 'non-UUID key is not sent');
  await run('nvd', 'CVE-2024-0001', { NVD_API_KEY: uuid });
  assert.equal(calls[2].init.headers.apiKey, uuid);
  assert.equal(nvdKey({ NVD_API_KEY: 'x' }), null);

  mockFetch([['services.nvd.nist.gov', { status: 403, text: '' }]]);
  await assert.rejects(run('nvd', 'CVE-2024-0001'), QuotaError);

  const none = mockFetch([]);
  assert.equal((await run('nvd', 'CVE-2024-0001', {}, false)).status, 'skipped');
  assert.equal(none.length, 0);
});

/* ---------- KEV ---------- */

test('kev finds an entry, handles braces in text, and reports the catalog date', async () => {
  _resetKevCache();
  mockFetch([['known_exploited_vulnerabilities.json', { text: KEV_TEXT }]]);
  const { data } = await run('kev', 'CVE-2021-44228');
  assert.equal(data.inKev, true);
  assert.equal(data.vendorProject, 'Apache');
  assert.equal(data.dueDate, '2021-12-24');
  assert.equal(data.ransomware, true);
  assert.equal(data.catalogReleased, '2026-10-08');
  const braces = await run('kev', 'CVE-2020-1111');
  assert.equal(braces.data.requiredAction, 'Use template {x} } then patch.');
  assert.equal(braces.data.ransomware, false);
});

test('kev says "not listed" word for word without claiming safety, and caches the download', async () => {
  _resetKevCache();
  const calls = mockFetch([['known_exploited_vulnerabilities.json', { text: KEV_TEXT }]]);
  const { data } = await run('kev', 'CVE-2024-9999');
  assert.equal(data.inKev, false);
  assert.equal(data.message, NOT_IN_KEV);
  assert.match(data.message, /does not prove the CVE is safe or unexploited/);
  await run('kev', 'CVE-2021-44228');
  assert.equal(calls.length, 1);
});

test('kev falls back to the GitHub mirror and allows the file to exceed 1 MB', async () => {
  _resetKevCache();
  const big = KEV_TEXT.replace('"count": 2,', `"count": 2, "padding": "${'x'.repeat(1_500_000)}",`);
  const calls = mockFetch([
    ['cisa.gov', { status: 403, text: '' }],
    ['raw.githubusercontent.com', { text: big }],
  ]);
  const { data } = await run('kev', 'CVE-2021-44228');
  assert.equal(data.inKev, true);
  assert.equal(calls.length, 2);
});

/* ---------- EPSS ---------- */

test('epss converts the string fields to numbers and spells out the meaning', async () => {
  mockFetch([['api.first.org', { body: { status: 'OK', total: 1, data: [{ cve: 'CVE-2021-44228', epss: '0.944130000', percentile: '0.999440000', date: '2026-10-07' }] } }]]);
  const { data } = await run('epss', 'CVE-2021-44228');
  assert.equal(data.epss, 0.94413);
  assert.match(data.meaning, /94\.4% chance/);
  assert.match(data.meaning, /99\.9% of all scored CVEs/);
  assert.equal(data.scoreDate, '2026-10-07');
});

test('epss uses two decimals for tiny probabilities and handles "no score yet"', async () => {
  mockFetch([['api.first.org', { body: { status: 'OK', total: 1, data: [{ cve: 'CVE-2020-1111', epss: '0.00043', percentile: '0.08', date: '2026-10-07' }] } }]]);
  assert.match((await run('epss', 'CVE-2020-1111')).data.meaning, /0\.04% chance/);
  mockFetch([['api.first.org', { body: { status: 'OK', total: 0, data: [] } }]]);
  assert.equal((await run('epss', 'CVE-2026-1234')).status, 'empty');
});

/* ---------- search ---------- */

test('search fetches the END of NVD’s oldest-first list, newest first, with the severity filter', async () => {
  const calls = mockFetch([
    ['services.nvd.nist.gov', (url) => (url.endsWith('resultsPerPage=1') ? { body: { totalResults: 87, vulnerabilities: [] } } : { body: NVD_SEARCH })],
  ]);
  const r = await searchCves({ keyword: 'exampleos', severity: 'CRITICAL' }, tools());
  assert.equal(calls.length, 2);
  assert.match(calls[0].url, /resultsPerPage=1$/);
  assert.match(calls[1].url, /startIndex=67/);
  assert.match(calls[1].url, /resultsPerPage=20/);
  for (const c of calls) {
    assert.match(c.url, /keywordSearch=exampleos/);
    assert.match(c.url, /cvssV3Severity=CRITICAL/);
  }
  assert.deepEqual(r.results.map((x) => x.id), ['CVE-2025-0002', 'CVE-2023-0003', 'CVE-2019-0001']);
  assert.equal(r.total, 87);
  assert.equal(r.results[0].score, 9.8);
  assert.equal(r.results[1].severity, null);
});

test('search starts at 0 for small result sets, stops after one request when nothing matches, and returns at most 10', async () => {
  let calls = mockFetch([['services.nvd.nist.gov', (url) => (url.endsWith('resultsPerPage=1') ? { body: { totalResults: 3, vulnerabilities: [] } } : { body: NVD_SEARCH })]]);
  await searchCves({ keyword: 'tiny' }, tools());
  assert.match(calls[1].url, /startIndex=0/);

  calls = mockFetch([['services.nvd.nist.gov', { body: { totalResults: 0, vulnerabilities: [] } }]]);
  assert.deepEqual(await searchCves({ keyword: 'nothing' }, tools()), { total: 0, results: [] });
  assert.equal(calls.length, 1);

  const many = { totalResults: 40, vulnerabilities: Array.from({ length: 20 }, (_, i) => ({ cve: { id: `CVE-2025-${1000 + i}`, published: `2025-01-${String(i + 1).padStart(2, '0')}T00:00:00`, descriptions: [], metrics: {} } })) };
  mockFetch([['services.nvd.nist.gov', (url) => (url.endsWith('resultsPerPage=1') ? { body: { totalResults: 40 } } : { body: many })]]);
  const r = await searchCves({ keyword: 'lots' }, tools());
  assert.equal(r.results.length, 10);
  assert.equal(r.results[0].id, 'CVE-2025-1019');
});

test('search validation: length, characters and severity', () => {
  assert.deepEqual(validateCveSearch('  fortinet  ', 'high'), { keyword: 'fortinet', severity: 'HIGH' });
  assert.deepEqual(validateCveSearch('apache struts 2.5', ''), { keyword: 'apache struts 2.5', severity: null });
  for (const bad of ['x', '', ' ', 'a'.repeat(61), 'foo;bar', '<script>', 'a&b', '../etc', 'naïve']) assert.ok(validateCveSearch(bad).error, bad);
  assert.ok(validateCveSearch('fortinet', 'SCARY').error);
});

/* ---------- priority (verdict) ---------- */

test('CVE priority rules, in order', () => {
  const cvss = (baseScore, severity, extra = {}) => ({ baseScore, severity, attackVector: 'NETWORK', privilegesRequired: 'LOW', userInteraction: 'NONE', ...extra });
  const v = (ok) => cveVerdict(ok).verdict;
  assert.equal(v({ nvd: { status: 'Rejected', cvss: null }, kev: { inKev: true } }), 'Rejected: not a valid vulnerability');
  assert.equal(v({ nvd: { status: 'Analyzed', cvss: cvss(5, 'MEDIUM') }, kev: { inKev: true, dateAdded: '2021-12-10' } }), 'Exploited in the wild: patch urgently');
  assert.equal(v({ nvd: { status: 'Analyzed', cvss: cvss(5, 'MEDIUM') }, kev: { inKev: false }, epss: { epss: 0.1 } }), 'High priority');
  assert.equal(v({ nvd: { status: 'Analyzed', cvss: cvss(9.8, 'CRITICAL', { privilegesRequired: 'NONE' }) }, kev: { inKev: false }, epss: { epss: 0.001 } }), 'High priority');
  assert.equal(v({ nvd: { status: 'Analyzed', cvss: cvss(9.8, 'CRITICAL') }, kev: { inKev: false }, epss: { epss: 0.001 } }), 'Patch soon', 'needs privileges, so not the remote no-auth rule');
  assert.equal(v({ nvd: { status: 'Analyzed', cvss: cvss(7.5, 'HIGH') } }), 'Patch soon');
  assert.equal(v({ nvd: { status: 'Analyzed', cvss: cvss(5, 'MEDIUM') } }), 'Patch on your normal cycle');
  assert.equal(v({ nvd: { status: 'Analyzed', cvss: cvss(2, 'LOW') } }), 'Low priority');
  assert.equal(v({ nvd: { status: 'Awaiting Analysis', cvss: null } }), 'No score yet');
  assert.equal(v({}), 'Not enough data');
});
