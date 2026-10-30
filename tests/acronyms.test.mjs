// "Security acronyms" on the Reference page (data/acronyms.json, js/acronyms.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { searchAcronyms, acronymKey, acronymProblems } from '../js/acronyms.js';

const root = new URL('../', import.meta.url);
const data = JSON.parse(readFileSync(new URL('data/acronyms.json', root), 'utf8'));
const list = data.acronyms;
const names = (r) => r.results.map((a) => a.acronym);

test('every entry has a valid shape, in alphabetical order, with no duplicate meaning', () => {
  assert.ok(list.length >= 100);
  const seen = new Set();
  let last = '';
  for (const a of list) {
    assert.deepEqual(acronymProblems(a), [], `${a.acronym}: ${acronymProblems(a).join(', ')}`);
    const k = acronymKey(a.acronym);
    assert.ok(k >= last, `${a.acronym} is out of order`);
    last = k;
    const pair = `${k}|${a.full.toLowerCase()}`;
    assert.ok(!seen.has(pair), `duplicate ${a.acronym} = ${a.full}`);
    seen.add(pair);
    assert.ok(!/[<>]|https?:/.test(a.acronym + a.full + a.plain), `${a.acronym}: no markup or links`);
  }
  assert.ok(data.source.url.startsWith('https://csrc.nist.gov/'));
});

test('exam staples are present with the standard expansion', () => {
  const want = {
    CIA: 'Confidentiality, Integrity and Availability', AAA: 'Authentication, Authorization and Accounting',
    RPO: 'Recovery Point Objective', RTO: 'Recovery Time Objective', ALE: 'Annualized Loss Expectancy',
    SLE: 'Single Loss Expectancy', ARO: 'Annualized Rate of Occurrence', SIEM: 'Security Information and Event Management',
    SOAR: 'Security Orchestration, Automation and Response', XSS: 'Cross-Site Scripting', CSRF: 'Cross-Site Request Forgery',
    PKI: 'Public Key Infrastructure', OCSP: 'Online Certificate Status Protocol', CVSS: 'Common Vulnerability Scoring System',
    KEV: 'Known Exploited Vulnerabilities', EPSS: 'Exploit Prediction Scoring System', RBAC: 'Role-Based Access Control',
  };
  for (const [acr, full] of Object.entries(want)) {
    const r = searchAcronyms(list, acr);
    assert.equal(r.exact, 1, `${acr} should have exactly one meaning`);
    assert.equal(r.results[0].full, full, acr);
  }
});

test('an acronym with several meanings shows all of them first, in list order', () => {
  const mac = searchAcronyms(list, 'mac');
  assert.equal(mac.exact, 3);
  assert.deepEqual(mac.results.slice(0, 3).map((a) => a.full), ['Media Access Control', 'Mandatory Access Control', 'Message Authentication Code']);
  for (const acr of ['PAM', 'SOC', 'CSP']) assert.equal(searchAcronyms(list, acr).exact, 2, acr);
});

test('case, spaces and punctuation in the acronym do not matter', () => {
  assert.equal(searchAcronyms(list, 'pci dss').results[0].acronym, 'PCI DSS');
  assert.equal(searchAcronyms(list, 'PCIDSS').results[0].acronym, 'PCI DSS');
  assert.equal(searchAcronyms(list, 's/mime').results[0].acronym, 'S/MIME');
  assert.equal(searchAcronyms(list, 'smime').results[0].acronym, 'S/MIME');
  assert.equal(searchAcronyms(list, 'att&ck').results[0].acronym, 'ATT&CK');
  assert.equal(searchAcronyms(list, '  Ioc ').results[0].acronym, 'IoC');
  assert.equal(searchAcronyms(list, '2fa').results[0].acronym, '2FA');
});

test('ranking: exact, then starts-with, then full name, then plain sentence', () => {
  const ip = names(searchAcronyms(list, 'ip'));
  assert.deepEqual(ip.slice(0, 2), ['IPS', 'IPsec']); // no exact "IP"; starts-with in list order
  const dns = names(searchAcronyms(list, 'dns'));
  assert.deepEqual(dns.slice(0, 2), ['DNS', 'DNSSEC']);
  assert.ok(dns.includes('DoH'), 'DoH spells out DNS in its full name');
  const rec = searchAcronyms(list, 'recovery');
  const recNames = names(rec);
  for (const a of ['DRP', 'RPO', 'RTO']) assert.ok(recNames.includes(a), `recovery should find ${a}`);
  const enc = names(searchAcronyms(list, 'encrypt'));
  assert.deepEqual(enc.slice(0, 3), ['AES', 'FDE', 'SED'], 'full-name matches first, in list order');
  for (const a of ['TLS', 'VPN', 'SSH']) assert.ok(enc.indexOf(a) > 2, `${a} matches on its plain sentence, after the full names`);
});

test('short words only match acronyms, so one letter does not list everything', () => {
  const a = searchAcronyms(list, 'a');
  assert.ok(a.results.every((x) => acronymKey(x.acronym).startsWith('a')));
  assert.ok(a.results.length < 15);
});

test('empty, missing, odd and long input never throws', () => {
  assert.deepEqual(searchAcronyms(list, ''), { results: [], kind: 'empty' });
  assert.equal(searchAcronyms(list, undefined).kind, 'empty');
  assert.equal(searchAcronyms(list, '   ').kind, 'empty');
  assert.deepEqual(searchAcronyms(list, 'zzzz-not-an-acronym').results, []);
  assert.deepEqual(searchAcronyms(list, '((([[[.*+?').results, []);
  assert.equal(searchAcronyms(list, 'x'.repeat(10000)).kind, 'text');
});

test('acronymProblems catches bad entries', () => {
  const ok = { acronym: 'X', full: 'Ex', plain: 'A thing.' };
  assert.deepEqual(acronymProblems(ok), []);
  assert.ok(acronymProblems({ ...ok, acronym: '' }).length);
  assert.ok(acronymProblems({ ...ok, acronym: '///' }).length);
  assert.ok(acronymProblems({ ...ok, acronym: 'TOOLONGACRONYM' }).length);
  assert.ok(acronymProblems({ ...ok, plain: 'No full stop' }).length);
  assert.ok(acronymProblems({ ...ok, plain: `${'x'.repeat(140)}.` }).length);
  assert.ok(acronymProblems({ ...ok, extra: 1 }).length);
});

test('the Reference page has the acronyms section and Ask can link to it', () => {
  const html = readFileSync(new URL('reference.html', root), 'utf8');
  for (const id of ['acronyms', 'acronyms-filter', 'acronyms-count', 'acronyms-list']) assert.ok(html.includes(`id="${id}"`), id);
  const js = readFileSync(new URL('js/reference.js', root), 'utf8');
  assert.ok(!/innerHTML/.test(js), 'render with textContent / DOM nodes only');
  const features = JSON.parse(readFileSync(new URL('data/hub-features.json', root), 'utf8')).features;
  assert.equal(features.find((f) => f.id === 'acronyms')?.href, './reference.html#acronyms');
});
