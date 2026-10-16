// Certificate viewer: checked against openssl's reading of the same files.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseCertificate, readCertificates, sha256Fingerprint } from '../js/analyze/cert.js';

const fx = (n, enc = 'utf8') => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), enc);
const first = (pem) => readCertificates(pem).ders[0];
const NOW = Date.parse('2026-10-20T00:00:00Z');

test('self-signed RSA 2048 with DNS, wildcard, IP and email SANs', async () => {
  const der = first(fx('cert-rsa-selfsigned.pem'));
  const c = parseCertificate(der, NOW);
  assert.deepEqual(c.subject, [['C', 'GB'], ['O', 'Example Test Ltd'], ['CN', 'test.example.org']]);
  assert.equal(c.selfSigned, true);
  assert.deepEqual(c.key, { type: 'RSA', bits: 2048 });
  assert.equal(c.signatureAlgorithm, 'sha256WithRSAEncryption');
  assert.deepEqual(c.sans, ['DNS:test.example.org', 'DNS:*.test.example.org', 'IP:192.0.2.10', 'email:admin@example.org']);
  assert.equal(c.version, 3);
  assert.equal(c.expired, false);
  // openssl x509 -fingerprint -sha256
  assert.equal(await sha256Fingerprint(der), '8d366c50ad0affae1b6749e1a196020181cee68841fd909ad3c27d09fab44a1f');
});

test('EC P-256, and expiry against "now"', () => {
  const c = parseCertificate(first(fx('cert-ec-selfsigned.pem')), Date.parse('2027-01-01T00:00:00Z'));
  assert.deepEqual(c.key, { type: 'EC P-256', bits: 256 });
  assert.equal(c.signatureAlgorithm, 'ecdsa-with-SHA256');
  assert.equal(c.expired, true);
  assert.equal(parseCertificate(first(fx('cert-ec-selfsigned.pem')), Date.parse('2020-01-01T00:00:00Z')).notYetValid, true);
});

test('a CA-issued certificate (github.com, Sectigo)', async () => {
  const der = first(fx('cert-github.pem'));
  const c = parseCertificate(der, NOW);
  assert.deepEqual(c.subject, [['CN', 'github.com']]);
  assert.deepEqual(c.issuer.map(([k]) => k), ['C', 'O', 'CN']);
  assert.match(c.issuer.find(([k]) => k === 'O')[1], /Sectigo/);
  assert.equal(c.selfSigned, false);
  assert.equal(c.isCA, false);
  assert.deepEqual(c.sans, ['DNS:github.com', 'DNS:www.github.com']);
  assert.equal(c.notAfter, '2026-11-29T23:59:59.000Z');
  assert.equal(await sha256Fingerprint(der), '46b601ee08b418cf8a3a1ebfe670ba5ce43bb05a917fa8b2dd087a30471cfc63');
});

test('DER files, PEM saved as .crt, and chains', () => {
  const der = readCertificates(fx('cert-rsa-selfsigned.der', null)).ders[0];
  assert.equal(parseCertificate(der, NOW).key.bits, 2048);
  const pemBytes = new TextEncoder().encode(fx('cert-ec-selfsigned.pem'));
  assert.equal(readCertificates(pemBytes.buffer).ders.length, 1);
  const chain = `${fx('cert-github.pem')}\n${fx('cert-rsa-selfsigned.pem')}`;
  assert.equal(readCertificates(chain).ders.length, 2);
});

test('private keys are refused without parsing; junk never throws past the reader', () => {
  const withKey = `${fx('cert-rsa-selfsigned.pem')}\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n`;
  assert.deepEqual(readCertificates(withKey), { privateKey: true });
  assert.deepEqual(readCertificates('-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----'), { privateKey: true });
  assert.match(readCertificates('hello').error, /No "-----BEGIN CERTIFICATE-----"/);
  assert.match(readCertificates('-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----').error, /Base64/);
  for (const junk of [new Uint8Array([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), new Uint8Array([0x30, 0x03, 0x02, 0x01]), new Uint8Array(0), new Uint8Array([0x04, 0x00])]) {
    assert.throws(() => parseCertificate(junk));
  }
  const truncated = first(fx('cert-github.pem')).subarray(0, 300);
  assert.throws(() => parseCertificate(truncated));
});
