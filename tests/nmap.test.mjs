// Nmap viewer helpers. parseNmap itself uses the browser's DOMParser and is
// checked in Chrome; these cover the parts that don't need a DOM.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkXml, cvesIn, lookupable, filterRows, parseNmap } from '../js/analyze/nmap.js';

const fx = (n) => readFileSync(new URL(`./fixtures/${n}`, import.meta.url), 'utf8');

test('entity declarations are refused before parsing; normal Nmap output passes', () => {
  assert.match(checkXml(fx('nmap-xxe.xml')), /entities/);
  assert.match(checkXml('<!DOCTYPE x [ <!ENTITY e SYSTEM "file:///etc/passwd"> ]><nmaprun/>'), /entities/);
  assert.equal(checkXml(fx('nmap-scan.xml')), null, 'the plain <!DOCTYPE nmaprun> is fine');
  assert.equal(parseNmap(fx('nmap-xxe.xml'), class { parseFromString() { throw new Error('must not be called'); } }).error.length > 0, true);
});

test('CVE IDs in script output, normalised and de-duplicated', () => {
  assert.deepEqual(cvesIn('CVE-2023-38408 9.8 https://vulners.com/cve/CVE-2023-38408\nCVE-2024-6387'), ['CVE-2023-38408', 'CVE-2024-6387']);
  assert.deepEqual(cvesIn('cve-2016-6210 5.9 / CVE_2015_5600'), ['CVE-2016-6210', 'CVE-2015-5600']);
  assert.deepEqual(cvesIn('CVE-2021-123 too short, CVE-2099-1234 future'), []);
});

test('only public addresses get a Look up link', () => {
  assert.equal(lookupable('45.33.32.156'), true);
  assert.equal(lookupable('192.168.1.1'), false);
  assert.equal(lookupable('10.0.0.5'), false);
  assert.equal(lookupable('fe80::1'), false);
  assert.equal(lookupable('2606:4700:4700::1111'), true);
});

test('filters by port, service text and open state', () => {
  const r = { hosts: [
    { addr: '45.33.32.156', ports: [{ port: 22, service: 'ssh', product: 'OpenSSH 6.6', state: 'open' }, { port: 80, service: 'http', product: 'Apache', state: 'open' }] },
    { addr: '192.168.1.1', ports: [{ port: 443, service: 'https', product: '', state: 'filtered' }, { port: 22, service: 'ssh', product: 'OpenSSH 8.9', state: 'open' }] },
  ] };
  assert.equal(filterRows(r).length, 4);
  assert.equal(filterRows(r, { port: '22' }).length, 2);
  assert.equal(filterRows(r, { service: 'openssh 8' }).length, 1);
  assert.equal(filterRows(r, { openOnly: true }).length, 3);
});
