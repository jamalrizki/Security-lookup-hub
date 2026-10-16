// Email-security parsing with recorded Cloudflare DoH answers (Oct 2026),
// trimmed to the records that matter.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDns, parseSpf, parseDmarc, emailGrade, validSelector } from '../worker/src/sources.js';

const ans = (type, ...data) => ({ Status: 0, Answer: data.map((d) => ({ type, data: d })) });
const TXT = 16;
const MX = 15;

const EXAMPLE_COM = {
  A: ans(1, '93.184.215.14'),
  MX: ans(MX, '0 .'),
  TXT: ans(TXT, '"v=spf1 -all"', '"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"'),
  DMARC: ans(TXT, '"v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"'),
};

const GITHUB_COM = {
  A: ans(1, '140.82.113.4'),
  MX: ans(MX, '0 github-com.mail.protection.outlook.com.'),
  TXT: ans(TXT, '"MS=ms44452932"',
    '"v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.2" "27.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all"'),
  DMARC: ans(TXT, '"v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com; ruf=mailto:dmarc@github.com; fo=1"'),
  DKIM: ans(TXT, '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj6T5sl/RwdSqGoYWaWaFbS2UAeyPrEmd0gogocmRfS441qwR8/0KB81Hw89P0l4YiFRrXYk7NVIGfyCRHAYYZUzCkGeOysI2EjgzLFhd/NEsbRzOEc/kWkK/RO6JFq/5lOn6M9AZw/ap9tds4JG9ApgNNdSpPxp9DmvpsOSgNMVflRxQFrk3kdS4RNAPKu/OP" "oA7dlR/A/pECryjRoYgENtDXzdnK70HgCekems6UDzxDj61cjyoKoXtEMF/QsaHEQ1Gjfv014rDJBsubk/kT5VqHkWHa/ia68Z5r228Ety/wFfQNjXTx/J7KGZ9GkZlKED659eiJcLnWcKDSiQlhwIDAQAB"'),
};

test('null MX, strict SPF and DMARC reject: Protected (example.com)', () => {
  const d = parseDns(EXAMPLE_COM, { domain: 'example.com', dmarcFrom: 'example.com' });
  assert.equal(d.nullMx, true);
  assert.equal(d.spfDetails.all, '-all');
  assert.equal(d.spfDetails.lookups, 0);
  assert.deepEqual(d.dmarcDetails, { p: 'reject', sp: 'reject', pct: 100, adkim: 'strict', aspf: 'strict', rua: false });
  assert.equal(d.emailGrade, 'Protected');
  assert.match(d.emailReasons[0], /null MX/);
  assert.equal(d.parkedAdvice, false);
  assert.equal(d.dkim, null, 'no selector, no DKIM check');
});

test('split SPF strings, include counting, DKIM key size (github.com)', () => {
  const d = parseDns(GITHUB_COM, { domain: 'github.com', dmarcFrom: 'github.com', selector: 'google' });
  assert.match(d.spf, /ip4:62\.253\.227\.114/, 'quoted strings joined');
  assert.equal(d.spfDetails.all, '~all');
  assert.equal(d.spfDetails.lookups, 8);
  assert.equal(d.dmarcDetails.p, 'quarantine');
  assert.equal(d.dmarcDetails.rua, true);
  assert.equal(d.emailGrade, 'Protected');
  assert.deepEqual(d.dkim, { selector: 'google', found: true, revoked: false, keyType: 'rsa', keyBits: 2048 });
  assert.equal(d.nullMx, false);
});

test('SPF qualifiers, ptr, redirect and lookup counting', () => {
  assert.equal(parseSpf('v=spf1 include:a.example ?all').all, '?all');
  assert.equal(parseSpf('v=spf1 +all').all, '+all');
  assert.equal(parseSpf('v=spf1 all').all, '+all', 'no qualifier means +');
  assert.equal(parseSpf('v=spf1 include:a.example').all, null);
  const s = parseSpf('v=spf1 a mx ptr exists:%{i}.x.example include:b.example ip4:1.2.3.4 a:mail.example mx/24 redirect=_spf.example');
  assert.equal(s.ptr, true);
  assert.equal(s.redirect, '_spf.example');
  assert.equal(s.lookups, 8);
});

test('DMARC tags and defaults', () => {
  assert.deepEqual(parseDmarc('v=DMARC1; p=none'), { p: 'none', sp: null, pct: 100, adkim: 'relaxed', aspf: 'relaxed', rua: false });
  assert.equal(parseDmarc('v=DMARC1; p=reject; pct=25').pct, 25);
  assert.equal(parseDmarc('v=DMARC1; p=reject; pct=abc').pct, 100, 'invalid pct falls back to 100');
  assert.equal(parseDmarc(null), null);
});

test('grades: easy to spoof, partly protected, inherited subdomain policy', () => {
  const spf = (all, lookups = 1) => ({ all, lookups });
  const dm = (p, pct = 100, extra = {}) => ({ p, sp: null, pct, ...extra });
  assert.equal(emailGrade({ spf: null, dmarc: dm('reject') }).grade, 'Easy to spoof');
  assert.equal(emailGrade({ spf: spf('-all'), dmarc: null }).grade, 'Easy to spoof');
  assert.equal(emailGrade({ spf: spf('-all'), dmarc: dm('none') }).grade, 'Easy to spoof');
  assert.equal(emailGrade({ spf: spf('+all'), dmarc: dm('reject') }).grade, 'Easy to spoof');
  assert.equal(emailGrade({ spf: spf('-all'), dmarc: dm('reject'), spfMultiple: true }).grade, 'Easy to spoof');
  assert.equal(emailGrade({ spf: spf('?all'), dmarc: dm('reject') }).grade, 'Partly protected');
  const redirect = emailGrade({ spf: { all: null, redirect: '_spf.google.com', lookups: 1 }, dmarc: dm('reject') });
  assert.equal(redirect.grade, 'Protected', 'redirect= delegates the policy');
  assert.match(redirect.reasons.join(' '), /via _spf\.google\.com/);
  assert.match(emailGrade({ spf: { all: null, redirect: '_spf.google.com', lookups: 1 }, dmarc: dm('none') }).reasons[0], /hands its policy/);
  assert.equal(emailGrade({ spf: spf('-all'), dmarc: dm('quarantine', 50) }).grade, 'Partly protected');
  const over = emailGrade({ spf: spf('-all', 12), dmarc: dm('reject') });
  assert.equal(over.grade, 'Partly protected');
  assert.match(over.reasons.join(' '), /more than 10/);
  // A subdomain inherits the parent's sp=, not p=.
  assert.equal(emailGrade({ spf: spf('-all'), dmarc: dm('none', 100, { sp: 'reject', inherited: true }) }).grade, 'Protected');
  assert.equal(emailGrade({ spf: spf('-all'), dmarc: dm('reject', 100, { sp: 'none', inherited: true }) }).grade, 'Easy to spoof');
});

test('no MX at all gets parked-domain advice; inherited DMARC is labelled', () => {
  const d = parseDns({ A: ans(1, '203.0.113.1'), MX: { Status: 0 }, TXT: { Status: 0 }, DMARC: ans(TXT, '"v=DMARC1; p=none"') },
    { domain: 'shop.example.org', dmarcFrom: 'example.org' });
  assert.equal(d.noMx, true);
  assert.equal(d.parkedAdvice, true);
  assert.equal(d.dmarcDetails.inherited, true);
  assert.equal(d.dmarcDetails.from, 'example.org');
  assert.equal(d.emailGrade, 'Easy to spoof');
});

test('DKIM: missing and revoked keys', () => {
  const missing = parseDns({ ...EXAMPLE_COM, DKIM: { Status: 3 } }, { domain: 'example.com', selector: 's1' });
  assert.deepEqual(missing.dkim, { selector: 's1', found: false });
  const revoked = parseDns({ ...EXAMPLE_COM, DKIM: ans(TXT, '"v=DKIM1; p="') }, { domain: 'example.com', selector: 's1' });
  assert.equal(revoked.dkim.revoked, true);
});

test('DKIM selector validation rejects injection attempts', () => {
  for (const ok of ['s1', 'google', 'selector1', 'k1._custom', 'mail-2024', 'a.b.c', 'x'.repeat(63)]) assert.ok(validSelector(ok), ok);
  for (const bad of ['a;b', '../etc', 'a b', '', '.', 'a..b', '.a', 'a.', 'x'.repeat(64), `${'a.'.repeat(60)}a`, 's1/x', 's1%00', 'é', '<script>', 's1&dkim=2', 'x'.repeat(200)]) {
    assert.ok(!validSelector(bad), JSON.stringify(bad));
  }
  assert.ok(!validSelector(undefined));
});
