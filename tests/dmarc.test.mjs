// DMARC report viewer. The page parses with the browser's DOMParser; here a
// small XML stand-in (tests/helpers/xml.mjs) feeds the same readDmarc(), and
// the fixtures are hand-written samples (no real report data).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkDmarcXml, parseDmarc, readDmarc, summarize, readiness, nextStep, passes, MAX_DMARC, REAL_VOLUME } from '../js/analyze/dmarc.js';
import { XmlParser } from './helpers/xml.mjs';

const fx = (n) => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), 'utf8');
const parse = (t) => parseDmarc(t, XmlParser);
const rec = (ip, count, { dkim = false, spf = false } = {}) => ({ ip, count, dkimAligned: dkim, spfAligned: spf, dkim: [], spf: [] });
const report = (records, policy = { p: 'none', pct: null }) => ({ meta: {}, policy, records, skipped: 0 });

test('refused before parsing: entities, DTD subsets, compressed files, more than 10 MB', () => {
  const never = class { parseFromString() { throw new Error('must not be called'); } };
  assert.match(parseDmarc('<!DOCTYPE feedback [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]><feedback>&x;</feedback>', never).error, /entities/);
  assert.match(checkDmarcXml('<!DOCTYPE feedback [ ]><feedback/>'), /entities/);
  assert.match(checkDmarcXml('\x1f\x8b\x08\x00rest'), /compressed/);
  assert.match(checkDmarcXml('\x1f�\x08\x00rest'), /compressed/, 'gzip bytes read as UTF-8 text');
  assert.match(checkDmarcXml('PK\x03\x04rest'), /compressed/);
  assert.match(checkDmarcXml('<feedback>' + ' '.repeat(MAX_DMARC) + '</feedback>'), /10 MB/);
  assert.equal(checkDmarcXml(fx('dmarc-rfc7489.xml')), null);
});

test('not a report or not XML gives a plain error', () => {
  assert.match(parse('<nmaprun></nmaprun>').error, /<feedback>/);
  assert.match(parse('<feedback><report_metadata></feedback>').error, /well-formed/);
  assert.match(readDmarc(null).error, /<feedback>/);
});

test('RFC 7489 sample: header, policy and rows; a negative count is skipped', () => {
  const r = parse(fx('dmarc-rfc7489.xml'));
  assert.equal(r.meta.org, 'mail.example.net');
  assert.equal(r.meta.id, 'sample-7489-0001');
  assert.equal(r.meta.begin.toISOString(), '2025-10-26T00:00:00.000Z');
  assert.equal(r.meta.namespace, null);
  assert.deepEqual(r.policy, { domain: 'example.org', p: 'none', sp: 'none', adkim: 'r', aspf: 'r', pct: 100, testing: false });
  assert.equal(r.records.length, 4);
  assert.equal(r.skipped, 1);
  const v6 = r.records.find((x) => x.ip === '2001:db8::25');
  assert.equal(v6.dkimAligned, true);
  assert.equal(v6.spfAligned, false);
  assert.deepEqual(v6.spf, [{ domain: 'bounce.example.com', result: 'softfail' }]);
  assert.deepEqual(v6.dkim, [{ domain: 'example.org', selector: 's2', result: 'pass' }]);
});

test('RFC 9990 sample (dmarc-2.0 namespace) reads the same way', () => {
  const r = parse(fx('dmarc-rfc9990.xml'));
  assert.equal(r.meta.namespace, 'urn:ietf:params:xml:ns:dmarc-2.0');
  assert.equal(r.meta.org, 'Example Mail & Co');
  assert.equal(r.policy.p, 'quarantine');
  assert.equal(r.policy.pct, null, 'RFC 9990 has no pct');
  assert.equal(r.records.length, 2);
  assert.equal(r.records[1].disposition, 'quarantine');
});

test('totals, pass rate and failing sources come from the rows', () => {
  const s = summarize(parse(fx('dmarc-rfc7489.xml')));
  assert.equal(s.total, 1243);
  assert.equal(s.passed, 1188);
  assert.equal(s.failed, 55);
  assert.equal(s.pct, 95.5);
  assert.equal(s.sources, 4);
  assert.deepEqual(s.failing, [
    { ip: '203.0.113.7', count: 52, spfFail: true, noDkim: true },
    { ip: '198.51.100.23', count: 3, spfFail: false, noDkim: false },
  ]);
  // The same source on several rows is one failing source.
  assert.deepEqual(summarize(report([rec('192.0.2.1', 2), rec('192.0.2.1', 3), rec('192.0.2.2', 1, { spf: true })])).failing.map((f) => [f.ip, f.count]), [['192.0.2.1', 5]]);
  assert.equal(passes(rec('x', 1, { spf: true })), true);
  assert.equal(passes(rec('x', 1)), false);
});

test('readiness line: decided in code from the report and the 1% constant', () => {
  assert.equal(REAL_VOLUME, 0.01);
  const a = readiness(parse(fx('dmarc-rfc7489.xml')));
  assert.equal(a.level, 'bad');
  assert.match(a.text, /^Not ready to move to p=quarantine yet: 1 source sends real volume/);
  const b = readiness(parse(fx('dmarc-rfc9990.xml')));
  assert.equal(b.level, 'warn');
  assert.match(b.text, /^Close: .* 2 messages from small sources failed\. Check them, then move to p=reject\.$/);

  assert.equal(readiness(report([])).level, 'muted');
  assert.equal(readiness(report([rec('192.0.2.1', 0)])).level, 'muted', 'zero messages');
  // Exactly 1% is real volume; just under is not.
  assert.equal(readiness(report([rec('a', 99, { dkim: true }), rec('b', 1)])).level, 'bad');
  assert.equal(readiness(report([rec('a', 1000, { dkim: true }), rec('b', 9)])).level, 'warn');
  const all = readiness(report([rec('a', 10, { spf: true })], { p: 'quarantine', pct: 25 }));
  assert.equal(all.level, 'ok');
  assert.match(all.text, /raise pct from 25 to 100/);
  assert.match(readiness(report([rec('a', 10, { spf: true })], { p: 'reject', pct: null })).text, /already at full p=reject/);
  const enforced = readiness(report([rec('a', 10, { spf: true }), rec('b', 10)], { p: 'reject', pct: 100 }));
  assert.equal(enforced.level, 'warn');
  assert.match(enforced.text, /^Already at p=reject/);
});

test('next policy step', () => {
  assert.equal(nextStep({ p: 'none' }), 'move to p=quarantine');
  assert.equal(nextStep({ p: null }), 'move to p=quarantine');
  assert.equal(nextStep({ p: 'quarantine', pct: 100 }), 'move to p=reject');
  assert.equal(nextStep({ p: 'quarantine', pct: 10 }), 'raise pct from 10 to 100');
  assert.equal(nextStep({ p: 'reject', pct: 50 }), 'raise pct from 50 to 100');
  assert.equal(nextStep({ p: 'reject' }), null);
});

test('untrusted values are checked: counts, pct, results, dispositions, lengths', () => {
  const row = (count, extra = '') => `<record><row><source_ip>192.0.2.1</source_ip><count>${count}</count><policy_evaluated><disposition>${extra || 'none'}</disposition><dkim>PASS</dkim><spf>weird</spf></policy_evaluated></row><auth_results><spf><domain>x</domain><result>bogus</result></spf></auth_results></record>`;
  const r = parse(`<feedback><policy_published><domain>${'a'.repeat(400)}</domain><p>REJECT</p><pct>150</pct></policy_published>${row('1e3')}${row('99999999999999999')}${row('1000000000000000000')}${row('')}${row(' 7 ', 'drop-it')}</feedback>`);
  assert.equal(r.skipped, 4, 'a 19-digit count is not cut down to a valid one');
  assert.equal(r.records.length, 1);
  assert.equal(r.records[0].count, 7);
  assert.equal(r.records[0].disposition, null);
  assert.equal(r.records[0].dkimAligned, true, 'result case does not matter');
  assert.equal(r.records[0].spfAligned, false);
  assert.equal(r.records[0].spf[0].result, 'other');
  assert.equal(r.policy.p, 'reject');
  assert.equal(r.policy.pct, null);
  assert.equal(r.policy.domain.length, 253);
  // Missing optional parts don't break it.
  const bare = parse('<feedback><record><row><count>5</count></row></record></feedback>');
  assert.equal(bare.records[0].ip, null);
  assert.equal(summarize(bare).failing[0].ip, '(no IP)');
  assert.equal(bare.meta.begin, null);
});

test('page: section, file input, paste box and a fixed meaning note; no HTML parsing of report text', () => {
  const html = readFileSync(new URL('../analyze.html', import.meta.url), 'utf8');
  for (const id of ['dmarc', 'dmarc-file', 'dmarc-form', 'dmarc-input', 'dmarc-drop']) assert.ok(html.includes(`id="${id}"`), id);
  assert.match(html, /<script type="module" src="js\/analyze\/dmarc\.js"><\/script>/);
  assert.match(html, /<a href="#dmarc">/);
  const src = readFileSync(new URL('../js/analyze/dmarc.js', import.meta.url), 'utf8');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|fetch\(/.test(src));
});
