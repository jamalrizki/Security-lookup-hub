// Parser tests using trimmed copies of real responses (captured 2026-10-14).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDomainRdap, parseDns, parseCrtSh, parseCertSpotter, parseInternetDb, parseIpRdap, plan, SOURCES } from '../worker/src/sources.js';
import { vtVerdict, parseVt, parseAbuseIpdb, parseBazaar, parseUrlhaus } from '../worker/src/keyed.js';
import { detect } from '../js/detect.js';

test('domain RDAP: dates, age, registrar, nameservers', () => {
  const r = parseDomainRdap({
    ldhName: 'GITHUB.COM',
    events: [
      { eventAction: 'registration', eventDate: '2007-10-09T18:20:50Z' },
      { eventAction: 'expiration', eventDate: '2028-10-09T18:20:50Z' },
      { eventAction: 'last changed', eventDate: '2026-09-07T09:22:52Z' },
    ],
    entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'MarkMonitor Inc.']]] }],
    status: ['client delete prohibited'],
    nameservers: [{ ldhName: 'DNS1.P08.NSONE.NET' }],
  }, Date.parse('2026-10-14T00:00:00Z'));
  assert.equal(r.domain, 'github.com');
  assert.equal(r.registrar, 'MarkMonitor Inc.');
  assert.equal(r.ageDays, 6944);
  assert.equal(r.newlyRegistered, false);
  assert.deepEqual(r.nameservers, ['dns1.p08.nsone.net']);
});

test('domain RDAP: flags newly registered domains', () => {
  const r = parseDomainRdap({ events: [{ eventAction: 'registration', eventDate: '2026-10-01T00:00:00Z' }] }, Date.parse('2026-10-14T00:00:00Z'));
  assert.equal(r.newlyRegistered, true);
  assert.equal(r.registrar, null);
});

test('DNS: records, SPF and DMARC policy', () => {
  const r = parseDns({
    A: { Status: 0, Answer: [{ type: 5, data: 'alias.example.' }, { type: 1, data: '140.82.112.3' }] },
    MX: { Status: 0, Answer: [{ type: 15, data: '1 aspmx.l.google.com.' }] },
    TXT: { Status: 0, Answer: [{ type: 16, data: '"v=spf1 ip4:192.30.252.0/22 " "include:_spf.google.com ~all"' }, { type: 16, data: '"google-site-verification=x"' }] },
    DMARC: { Status: 0, Answer: [{ type: 16, data: '"v=DMARC1; p=quarantine; sp=reject; pct=100"' }] },
  });
  assert.deepEqual(r.records.A, ['140.82.112.3'], 'CNAME answers excluded from A');
  assert.equal(r.spf, 'v=spf1 ip4:192.30.252.0/22 include:_spf.google.com ~all', 'split TXT strings joined');
  assert.equal(r.dmarcPolicy, 'quarantine');
});

test('DNS: missing SPF and DMARC', () => {
  const r = parseDns({ A: { Status: 0, Answer: [] }, TXT: { Status: 0 }, DMARC: { Status: 3 } });
  assert.equal(r.spf, null);
  assert.equal(r.dmarc, null);
  assert.equal(r.dmarcPolicy, null);
});

test('certificates: names deduped, wildcards stripped, other domains dropped', () => {
  const crt = parseCrtSh([
    { name_value: 'github.com\nwww.github.com' },
    { name_value: '*.github.com' },
    { name_value: 'www.github.com' },
    { name_value: 'evilgithub.com' },
  ], 'github.com');
  assert.deepEqual(crt.names, ['github.com', 'www.github.com']);
  assert.equal(crt.certificates, 4);

  const cs = parseCertSpotter([{ dns_names: ['f.cloud.github.com', '*.api.github.com'] }], 'github.com');
  assert.deepEqual(cs.names, ['api.github.com', 'f.cloud.github.com']);
  assert.equal(cs.firstPageOnly, true);
});

test('InternetDB and IP RDAP', () => {
  assert.deepEqual(parseInternetDb({ cpes: [], hostnames: ['dns.google'], ip: '8.8.8.8', ports: [53, 443], tags: [], vulns: [] }).ports, [53, 443]);
  const r = parseIpRdap({
    name: 'GOGL', handle: 'NET-8-8-8-0-2', startAddress: '8.8.8.0', endAddress: '8.8.8.255',
    cidr0_cidrs: [{ v4prefix: '8.8.8.0', length: 24 }], arin_originas0_originautnums: [15169], port43: 'whois.arin.net',
    entities: [{ roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'Google LLC']]] }],
  });
  assert.equal(r.owner, 'Google LLC');
  assert.deepEqual(r.cidrs, ['8.8.8.0/24']);
  assert.deepEqual(r.asns, [15169]);
  assert.equal(r.registry, 'ARIN');
});

test('plan picks sources per indicator type, verdict sources first', () => {
  const ids = (q) => plan(detect(q)).map((s) => `${s.id}:${s.value}`);
  assert.deepEqual(ids('example.com'), ['vtDomain', 'urlhausHost', 'rdap', 'dns', 'certs'].map((i) => `${i}:example.com`));
  assert.deepEqual(ids('8.8.8.8'), ['abuseipdb', 'vtIp', 'urlhausHost', 'internetdb', 'ipowner'].map((i) => `${i}:8.8.8.8`));
  assert.deepEqual(ids('https://www.example.com/x'), [
    'vtUrl:https://www.example.com/x', 'urlhausUrl:https://www.example.com/x',
    'rdap:www.example.com', 'dns:www.example.com', 'certs:www.example.com',
  ]);
  assert.deepEqual(ids('http://[2606:4700::1111]/'), [
    'vtUrl:http://[2606:4700::1111]/', 'urlhausUrl:http://[2606:4700::1111]/',
    'abuseipdb:2606:4700::1111', 'internetdb:2606:4700::1111', 'ipowner:2606:4700::1111',
  ]);
  assert.deepEqual(ids('a@example.org'), ['dns:example.org']);
  const h = 'd41d8cd98f00b204e9800998ecf8427e';
  assert.deepEqual(ids(h), ['vtFile', 'bazaar', 'urlhausPayload'].map((i) => `${i}:${h}`));
  assert.equal(plan(detect('https://evil.example.com/')).filter((s) => s.id.startsWith('vt')).length, 1, 'one VirusTotal call per URL search');
});

test('every planned source exists in the registry', () => {
  for (const q of ['example.com', '8.8.8.8', 'https://x.example.com/', 'a@example.org', 'a'.repeat(64)]) {
    for (const s of plan(detect(q))) assert.ok(SOURCES[s.id], s.id);
  }
});

// Shapes follow the VirusTotal v3, AbuseIPDB v2 and abuse.ch API docs.
test('VirusTotal verdicts and file parsing', () => {
  assert.equal(vtVerdict({ malicious: 0, suspicious: 0, undetected: 60, harmless: 10 }).verdict, 'clean');
  assert.equal(vtVerdict({ malicious: 1, undetected: 60 }).verdict, 'suspicious');
  assert.equal(vtVerdict({ malicious: 40, undetected: 20, timeout: 5 }).engines, 60, 'timeouts not counted as engines');
  assert.equal(vtVerdict({}).verdict, 'unknown');
  const f = parseVt('file', { data: { id: 'x', attributes: {
    last_analysis_stats: { malicious: 62, undetected: 5 },
    meaningful_name: 'eicar.com', type_description: 'Text', first_submission_date: 1148301722,
    popular_threat_classification: { suggested_threat_label: 'virus.eicar/test', popular_threat_name: [{ value: 'eicar', count: 40 }] },
  } } });
  assert.equal(f.verdict, 'malicious');
  assert.equal(f.label, 'virus.eicar/test');
  assert.deepEqual(f.families, ['eicar']);
  assert.equal(f.firstSeen, '2006-05-22T12:42:02.000Z');
});

test('AbuseIPDB, MalwareBazaar and URLhaus parsing', () => {
  const a = parseAbuseIpdb({ data: { abuseConfidenceScore: 100, totalReports: 512, numDistinctUsers: 80, isTor: false, countryCode: 'NL', usageType: 'Data Center/Web Hosting/Transit' } });
  assert.equal(a.score, 100);
  assert.equal(a.reports, 512);
  const b = parseBazaar({ query_status: 'ok', data: [{ sha256_hash: 'ab', signature: 'AgentTesla', first_seen: '2024-01-31 12:34:56', tags: ['exe'] }] });
  assert.equal(b.family, 'AgentTesla');
  assert.equal(b.firstSeen, '2024-01-31T12:34:56.000Z');
  const host = parseUrlhaus('host', { url_count: '3', firstseen: '2019-01-19 01:33:26 UTC', urls: [{ url: 'http://bad.example/x.exe', url_status: 'online', threat: 'malware_download', date_added: '2019-01-19 01:33:26 UTC' }] });
  assert.equal(host.urlCount, 3);
  assert.equal(host.urls[0].added, '2019-01-19T01:33:26.000Z');
});
