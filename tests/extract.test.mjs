import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  parsePsl, registrableDomain, toUnicode, refangText, extractIocs, toCsv, skeleton, editDistance,
  lookalikes, inspectUrl, decodeLayers, maybeBase64, parseHeaders, parseAuthResults, decodeMimeWords, MAX_TEXT,
} from '../js/extract.js';

const read = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');
const psl = parsePsl(read('../data/public_suffix_list.dat'));
const { brands } = JSON.parse(read('../data/brands.json'));

/* ---------- Public Suffix List ---------- */

test('registrable domains: multi-part suffixes, private suffixes, wildcards and exceptions', () => {
  assert.equal(registrableDomain('www.bbc.co.uk', psl).registrable, 'bbc.co.uk');
  assert.equal(registrableDomain('a.b.someone.github.io', psl).registrable, 'someone.github.io');
  assert.equal(registrableDomain('x.foo.ck', psl).registrable, 'x.foo.ck', '*.ck wildcard');
  assert.equal(registrableDomain('www.ck', psl).registrable, 'www.ck', '!www.ck exception');
  assert.equal(registrableDomain('co.uk', psl).registrable, null);
  assert.equal(registrableDomain('report.txt', psl), null, 'unknown TLD');
  assert.equal(toUnicode('xn--bcher-kva.de'), 'bücher.de');
  assert.equal(toUnicode('xn--not-valid!!.com'), 'xn--not-valid!!.com');
});

/* ---------- IOC extractor ---------- */

test('extracts refanged indicators by type, de-duplicated with counts', () => {
  const r = extractIocs(read('./fixtures/ioc-report.txt'), { psl });
  const values = (t) => (r.groups[t] || []).map((i) => i.value);
  assert.deepEqual(values('url'), ['https://login-secure.example.com/verify?id=123']);
  assert.deepEqual(values('ipv4'), ['45.33.32.156']);
  assert.equal(r.groups.ipv4[0].count, 3, 'defanged and plain forms counted together');
  assert.deepEqual(values('email'), ['soc@example.org']);
  assert.deepEqual(values('cve'), ['CVE-2021-44228', 'CVE-2024-3400']);
  assert.deepEqual(r.groups.hash.map((h) => h.note).sort(), ['MD5', 'SHA-1', 'SHA-256']);
  assert.ok(values('domain').includes('update-check.example.net'));
  assert.ok(!values('domain').some((d) => /example\.com|example\.org/.test(d)), 'URL/email hosts not double-counted');
  assert.deepEqual(values('ipv6'), ['2606:4700:4700::1111'], 'found despite the full stop after it');
});

test('drops private and internal values with reasons, and flags file-like domains', () => {
  const r = extractIocs(read('./fixtures/ioc-report.txt'), { psl });
  const dropped = Object.fromEntries(r.dropped.map((d) => [d.value, d.reason]));
  for (const v of ['10.1.2.3', '192.168.0.10', 'fe80::1', 'dc01.corp.local', 'intranet.lan', 'report.txt', 'notes.docx']) assert.ok(dropped[v], v);
  assert.match(dropped['http://198.51.100.7:8080/payload.exe'], /not public/);
  const zip = r.groups.domain.find((d) => d.value === 'invoice.zip');
  assert.match(zip.note, /file name/);
  assert.equal(r.groups.domain.find((d) => d.value === 'update-check.example.net').note, undefined);
  const all = JSON.stringify(r.groups);
  for (const noise of ['1.2.3', '12:30:45', 'aa:bb:cc', '"e.g"']) assert.ok(!all.includes(noise), noise);
});

test('IPv6 is found and validated; log mode filters lines', () => {
  const r = extractIocs('to 2606:4700:4700::1111 and ::ffff:8.8.8.8 at 12:30:45', { psl });
  assert.deepEqual(r.groups.ipv6.map((i) => i.value).sort(), ['2606:4700:4700::1111', '::ffff:8.8.8.8']);
  const log = 'GET /a from 45.33.32.156 status=200\nGET /b from 8.8.8.8 status=404\nGET /c from 45.33.32.156 status=404';
  const only404 = extractIocs(log, { psl, lineFilter: 'status=404' });
  assert.deepEqual(only404.groups.ipv4.map((i) => [i.value, i.count]), [['45.33.32.156', 1], ['8.8.8.8', 1]]);
});

test('hostile and huge input: HTML is just text, 500 KB cap, fast', () => {
  const html = '<img src=x onerror=alert(1)><a href="javascript:alert(2)">x</a> hxxps://evil[.]example[.]net/<script>';
  const r = extractIocs(html, { psl });
  assert.deepEqual(r.groups.url.map((u) => u.value), ['https://evil.example.net/']);
  const big = 'noise 45.33.32.156 hxxp://a[.]example[.]com/x '.repeat(20000); // ~880 KB
  const t = Date.now();
  const rb = extractIocs(big, { psl });
  assert.ok(Date.now() - t < 3000, `took ${Date.now() - t} ms`);
  assert.ok(rb.groups.ipv4[0].count < 20000, 'only the first 500 KB scanned');
  assert.ok(MAX_TEXT === 512000);
});

test('refangText and CSV export', () => {
  assert.equal(refangText('hxxps[:]//a[.]b(dot)c and x[at]y{.}z [://]'), 'https://a.b.c and x@y.z ://');
  const csv = toCsv([['type', 'value'], ['domain', '=HYPERLINK("http://x")'], ['note', 'say "hi"']]);
  assert.equal(csv, '"type","value"\r\n"domain","\'=HYPERLINK(""http://x"")"\r\n"note","say ""hi"""');
});

/* ---------- Link inspector ---------- */

const reasons = (u) => inspectUrl(u, { psl, brands }).reasons.join(' | ');

test('lookalikes: homoglyphs, digit swaps, near misses, subdomain abuse; real domains pass', () => {
  assert.equal(skeleton('раураl'), 'paypal', 'Cyrillic');
  assert.equal(skeleton('rnicrosoft'), 'microsoft');
  assert.equal(editDistance('paypa', 'paypal'), 1);
  assert.match(reasons('https://paypa1.com/'), /imitates PayPal/);
  assert.match(reasons('https://xn--pypal-4ve.com/'), /Mixes alphabets.*Cyrillic/);
  assert.match(reasons('https://paypall.com/'), /letters away from PayPal/);
  assert.match(reasons('https://paypal.com.login-secure.xyz/'), /only in the subdomain; the real domain is login-secure\.xyz/);
  assert.match(reasons('https://secure-paypal-login.com/'), /contains "paypal"/);
  for (const ok of ['https://www.paypal.com/signin', 'https://login.microsoftonline.com/', 'https://ibm.com/', 'https://abc.com/', 'https://www.ups.com/track', 'https://cups.org/']) {
    assert.equal(inspectUrl(ok, { psl, brands }).verdict, 'Looks normal', ok);
  }
  assert.deepEqual(lookalikes('mail.google.com', psl, brands), []);
});

test('userinfo trick, IP hosts, ports, shorteners and non-web schemes', () => {
  const r = inspectUrl('https://paypal.com@evil.example.net/login', { psl, brands });
  assert.equal(r.host, 'evil.example.net');
  assert.equal(r.userinfo, 'paypal.com');
  assert.equal(r.verdict, 'Suspicious');
  assert.match(reasons('http://203.0.113.5:8443/x'), /bare IP.*port 8443/s);
  assert.ok(inspectUrl('https://bit.ly/3xyz', { psl, brands }).shortener);
  assert.match(inspectUrl('javascript:alert(1)', { psl, brands }).error, /hostile/);
  assert.match(inspectUrl('data:text/html,<script>x</script>', { psl, brands }).error, /hostile/);
  assert.match(inspectUrl('example.com/a', { psl, brands }).notes[0], /assumed/);
  assert.equal(inspectUrl('hxxps://example[.]com', { psl, brands }).host, 'example.com');
});

test('decoding: nested percent-encoding, Base64 parameters and redirects', () => {
  assert.deepEqual(decodeLayers('%252541'), ['%252541', '%2541', '%41', 'A']);
  assert.equal(decodeLayers('%25252541').length, 4, 'stops after 3 layers');
  const nestedUrl = encodeURIComponent(encodeURIComponent('https://evil.example.net/x'));
  const r = inspectUrl(`https://example.com/r?next=${nestedUrl}&id=7`, { psl, brands });
  assert.deepEqual(r.nested, [{ param: 'next', url: 'https://evil.example.net/x' }]);
  assert.match(r.reasons.join(' '), /Redirects to another URL/);

  const b64 = btoa('https://evil.example.net/landing');
  const r2 = inspectUrl(`https://example.com/?data=${encodeURIComponent(b64)}`, { psl, brands });
  assert.equal(r2.params[0].base64, 'https://evil.example.net/landing');
  assert.equal(r2.nested[0].url, 'https://evil.example.net/landing');
  assert.equal(maybeBase64('helloworldfoo'), null, 'plain words are not Base64');
  assert.equal(maybeBase64(btoa('\u0000\u0001\u0002binary\u0003\u0004')), null, 'binary is ignored');

  const html = inspectUrl('https://example.com/<script>alert(1)</script>?q="><img src=x>', { psl, brands });
  assert.equal(html.verdict, 'Looks normal', 'markup in a URL is only text here');
  assert.match(html.path.decoded, /<script>/);
});

/* ---------- Email headers ---------- */

test('headers: hops oldest first with delays, server-seen IPs, mismatches, top auth results', () => {
  const h = parseHeaders(read('./fixtures/headers-phish.txt'), { psl });
  assert.equal(h.subject, "Account limited <script>alert('subject')</script>", 'MIME decoded; markup stays text');
  assert.equal(h.fromDomain, 'paypal.com');
  assert.deepEqual(h.hops.map((x) => x.ip), ['198.51.100.23', '8.8.4.4', null]);
  assert.deepEqual(h.hops.map((x) => x.delaySeconds), [null, 30, 2]);
  assert.equal(h.hops[1].publicIp, true);
  assert.equal(h.mismatches.length, 3);
  assert.deepEqual(h.auth.dmarc, [{ result: 'fail', domain: 'paypal.com' }], 'topmost header, not the forged one below');
  assert.equal(h.auth.spf[0].domain, 'mailer.evil-shipping.example');
  assert.equal(h.authHeaders, 2);
  assert.deepEqual(h.iocs.groups.ipv4.map((i) => i.value), ['8.8.4.4']);
});

test('headers: folded lines, body ignored, 200 KB cap, junk input', () => {
  const h = parseHeaders('Subject: part one\n  part two\nFrom: a@example.com\n\nBody line: Subject: not a header');
  assert.equal(h.subject, 'part one part two');
  assert.equal(h.headers, 2);
  assert.equal(parseHeaders('just some text without headers').headers, 0);
  const huge = parseHeaders(`X-Long: ${'a'.repeat(300 * 1024)}`);
  assert.equal(huge.headers, 1);
  assert.deepEqual(parseAuthResults('mx.example; spf=softfail smtp.mailfrom=x@y.example; dkim=none'), {
    spf: [{ result: 'softfail', domain: 'y.example' }],
    dkim: [{ result: 'none', domain: null }],
  });
  assert.equal(decodeMimeWords('=?UTF-8?Q?Caf=C3=A9_menu?='), 'Café menu');
});
