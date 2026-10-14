// Run with: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { detect, refang, defang, identifyHash, parseIPv6 } from '../js/detect.js';
import { md5 } from '../js/md5.js';
import { CODECS, base64Decode, hexDecode } from '../js/encoding.js';

test('md5 matches node:crypto across padding boundaries', () => {
  for (const len of [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 1000, 100000]) {
    const buf = randomBytes(len);
    assert.equal(md5(buf), createHash('md5').update(buf).digest('hex'), `length ${len}`);
  }
  assert.equal(md5(new TextEncoder().encode('abc')), '900150983cd24fb0d6963f7d28e17f72');
});

test('detects hashes', () => {
  assert.deepEqual(
    [32, 40, 64].map((n) => detect('A'.repeat(n)).algorithm),
    ['MD5', 'SHA-1', 'SHA-256'],
  );
  assert.equal(detect('a'.repeat(63)).type, 'unknown');
});

test('detects public and rejects reserved IPv4', () => {
  assert.equal(detect('8.8.8.8').label, 'IPv4 address');
  for (const ip of ['10.1.2.3', '192.168.0.1', '127.0.0.1', '169.254.169.254', '172.31.255.255',
    '100.64.0.1', '0.0.0.0', '255.255.255.255', '224.0.0.1', '203.0.113.7']) {
    assert.ok(detect(ip).error, ip);
  }
  assert.ok(!detect('172.32.0.1').error, '172.32/16 is public');
  assert.equal(detect('010.0.0.1').type, 'unknown', 'leading zeros rejected');
  assert.equal(detect('256.1.1.1').type, 'unknown');
});

test('parses and classifies IPv6', () => {
  assert.deepEqual(parseIPv6('::1'), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(parseIPv6('::ffff:1.2.3.4'), [0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]);
  assert.equal(parseIPv6('1::2::3'), null);
  assert.equal(parseIPv6('1:2:3:4:5:6:7:8:9'), null);
  assert.equal(detect('2606:4700:4700::1111').label, 'IPv6 address');
  for (const ip of ['::1', '::', 'fe80::1', 'fd00::1', '2001:db8::1', 'ff02::1', '::ffff:10.0.0.1', '[::1]']) {
    assert.ok(detect(ip).error, ip);
  }
  assert.ok(!detect('::ffff:8.8.8.8').error);
});

test('detects domains and rejects internal names', () => {
  assert.equal(detect('Example.COM.').value, 'example.com');
  assert.equal(detect('sub.example.co.uk').type, 'domain');
  assert.equal(detect('xn--bcher-kva.de').type, 'domain');
  assert.equal(detect('bücher.de').value, 'xn--bcher-kva.de');
  for (const d of ['localhost', 'printer.local', 'db.internal', 'router.home.arpa', 'foo.lan']) {
    assert.ok(detect(d).error, d);
  }
  for (const d of ['-bad.com', 'bad-.com', 'a..com', 'example.123', 'exa mple.com', 'a.com/path', 'bücher.de/x']) {
    assert.equal(detect(d).type, 'unknown', d);
  }
});

test('detects URLs and emails, checking the URL host', () => {
  assert.equal(detect('https://evil.example.com/a?b=1').type, 'url');
  assert.ok(detect('http://127.0.0.1:8080/admin').error);
  assert.ok(detect('http://0x7f.1/').error, 'hex-encoded loopback normalised by URL()');
  assert.ok(detect('http://[::1]/').error);
  assert.ok(detect('http://localhost/').error);
  assert.equal(detect('Someone@Example.com').type, 'email');
  assert.equal(detect('a@b').type, 'unknown');
});

test('refang and defang', () => {
  assert.equal(refang(' hxxps://bad[.]example[.]com/x '), 'https://bad.example.com/x');
  assert.equal(refang('user[at]example(.)com'), 'user@example.com');
  assert.equal(detect('hxxp://bad[.]example[.]com').type, 'url');
  assert.equal(defang('https://bad.example.com/a.php'), 'hxxps://bad[.]example[.]com/a[.]php');
});

test('identifies hash formats', () => {
  const first = (s) => identifyHash(s)[0]?.name;
  assert.equal(first('$2b$12$' + 'a'.repeat(53)), 'bcrypt');
  assert.equal(first('$6$salt$abc'), 'SHA-512 crypt');
  assert.equal(first('$argon2id$v=19$m=65536'), 'Argon2');
  assert.equal(first('d41d8cd98f00b204e9800998ecf8427e'), 'MD5');
  assert.ok(identifyHash('31d6cfe0d16ae931b73c59d7e0c089c0').some((h) => h.name === 'NTLM'));
  assert.equal(first('a'.repeat(128)), 'SHA-512');
  assert.equal(first('d41d8cd98f00b204e9800998ecf8427e:salt'), 'MD5 with salt');
  assert.deepEqual(identifyHash('not a hash'), []);
});

test('codecs round-trip UTF-8 and match Buffer', () => {
  const samples = ['', 'hello', 'héllo wörld ☃ 🔐', 'a+b=c&d/e?f'];
  for (const s of samples) {
    for (const [name, c] of Object.entries(CODECS)) assert.equal(c.decode(c.encode(s)), s, `${name}: ${s}`);
    assert.equal(CODECS.base64.encode(s), Buffer.from(s).toString('base64'));
    assert.equal(CODECS.hex.encode(s), Buffer.from(s).toString('hex'));
  }
  assert.equal(base64Decode('aGVsbG8'), 'hello', 'missing padding');
  assert.equal(base64Decode('PDw_Pz8-Pg'), '<<???>>', 'URL-safe alphabet');
  assert.equal(hexDecode('0x68 0x69'), 'hi');
  assert.equal(hexDecode('\\x68\\x69'), 'hi');
  assert.throws(() => hexDecode('abc'), /odd/);
  assert.throws(() => base64Decode('/w=='), /UTF-8/);
});
