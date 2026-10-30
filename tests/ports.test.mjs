// "Ports and protocols" on the Reference page (data/ports.json, js/ports.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { searchPorts, portLabel, secureVersions, entryProblems } from '../js/ports.js';

const root = new URL('../', import.meta.url);
const data = JSON.parse(readFileSync(new URL('data/ports.json', root), 'utf8'));
const { ports } = data;
const byPort = (n) => ports.filter((p) => p.port === n);

test('every entry has a valid shape, in port order, with no duplicate port and transport', () => {
  assert.ok(ports.length >= 40);
  const seen = new Set();
  let last = -1;
  for (const p of ports) {
    assert.deepEqual(entryProblems(p), [], `${p.port}: ${entryProblems(p).join(', ')}`);
    assert.ok(p.port >= last, `${p.port} is out of order`);
    last = p.port;
    const key = portLabel(p);
    assert.ok(!seen.has(key), `duplicate ${key}`);
    seen.add(key);
    assert.ok(!/[<>]/.test(p.use + p.full + p.name), `${p.port}: no markup`);
  }
  assert.equal(data.source.url.startsWith('https://www.iana.org/'), true);
});

test('every "secure" port points at an entry in the list that is not itself a clear-text port', () => {
  for (const p of ports) {
    for (const n of p.secure || []) {
      assert.notEqual(n, p.port, `${p.port}: secure points at itself`);
      const alt = byPort(n);
      assert.ok(alt.length, `${p.port}: secure port ${n} is not in the list`);
      assert.ok(alt.every((a) => !a.secure), `${p.port}: secure port ${n} has its own secure version`);
    }
  }
  assert.deepEqual(secureVersions(ports, byPort(143)[0]), ['993 IMAPS']);
  assert.deepEqual(secureVersions(ports, byPort(21)[0]), ['22 SSH', '990 FTPS']);
  assert.deepEqual(secureVersions(ports, byPort(443)[0]), []);
});

test('exam staples are present with the right transport', () => {
  const want = { 21: 'TCP', 22: 'TCP', 23: 'TCP', 25: 'TCP', 53: 'TCP/UDP', 67: 'UDP', 69: 'UDP', 80: 'TCP', 88: 'TCP/UDP', 110: 'TCP', 123: 'UDP', 143: 'TCP', 161: 'UDP', 389: 'TCP/UDP', 443: 'TCP', 445: 'TCP', 514: 'UDP', 587: 'TCP', 636: 'TCP', 993: 'TCP', 995: 'TCP', 1812: 'UDP', 3389: 'TCP/UDP' };
  for (const [port, proto] of Object.entries(want)) {
    const e = byPort(Number(port));
    assert.equal(e.length, 1, `${port} missing`);
    assert.equal(e[0].proto, proto, `${port} transport`);
  }
  for (const n of [23, 445, 3389, 3306, 6379, 27017]) assert.equal(byPort(n)[0].exposed, true, `${n} should be marked exposed`);
  for (const n of [22, 443, 993]) assert.equal(byPort(n)[0].exposed, undefined, `${n} should not be marked exposed`);
});

test('search by number, with or without a transport', () => {
  assert.deepEqual(searchPorts(ports, '443').results.map(portLabel), ['443/TCP']);
  assert.deepEqual(searchPorts(ports, ' port 53 ').results.map(portLabel), ['53/TCP/UDP']);
  assert.deepEqual(searchPorts(ports, '53/udp').results.map(portLabel), ['53/TCP/UDP']);
  assert.deepEqual(searchPorts(ports, '443/udp').results, []);
  assert.deepEqual(searchPorts(ports, '161 / UDP').results.map((p) => p.name), ['SNMP']);
  const unknown = searchPorts(ports, '12345');
  assert.equal(unknown.kind, 'port');
  assert.deepEqual(unknown.results, []);
  assert.equal(unknown.error, undefined);
  const big = searchPorts(ports, '70000');
  assert.deepEqual(big.results, []);
  assert.match(big.error, /0 to 65535/);
});

test('search by name ranks exact names first, then the rest in port order', () => {
  const ssh = searchPorts(ports, 'SSH').results;
  assert.equal(ssh[0].port, 22);
  const ldap = searchPorts(ports, 'ldap').results.map((p) => p.port);
  assert.deepEqual(ldap.slice(0, 2), [389, 636]); // exact, then starts-with
  assert.ok(ldap.includes(3268), 'Global Catalog mentions LDAP');
  const mail = searchPorts(ports, 'email').results.map((p) => p.port);
  for (const n of [25, 110, 143, 465, 587, 993, 995]) assert.ok(mail.includes(n), `email should find ${n}`);
  assert.deepEqual(searchPorts(ports, 'zzzz-not-a-service').results, []);
});

test('empty search lists everything; input is cut to 60 characters and never throws', () => {
  assert.equal(searchPorts(ports, '').results.length, ports.length);
  assert.equal(searchPorts(ports, undefined).kind, 'all');
  assert.equal(searchPorts(ports, 'x'.repeat(10000)).kind, 'text');
  assert.equal(searchPorts(ports, '((([[[.*+?').results.length, 0);
});

test('entryProblems catches bad entries', () => {
  assert.ok(entryProblems({ port: 70000, proto: 'TCP', name: 'X', full: 'X', use: 'X' }).length);
  assert.ok(entryProblems({ port: 1, proto: 'SCTP', name: 'X', full: 'X', use: 'X' }).length);
  assert.ok(entryProblems({ port: 1, proto: 'TCP', name: 'X', full: 'X', use: 'X', secure: 22 }).length);
  assert.ok(entryProblems({ port: 1, proto: 'TCP', name: 'X', full: 'X', use: 'X', exposed: false }).length);
  assert.ok(entryProblems({ port: 1, proto: 'TCP', name: 'X', full: 'X', use: 'X', extra: 1 }).length);
  assert.deepEqual(entryProblems({ port: 1, proto: 'TCP', name: 'X', full: 'X', use: 'X' }), []);
});

test('the Reference page has the ports section and Ask can link to it', () => {
  const html = readFileSync(new URL('reference.html', root), 'utf8');
  for (const id of ['ports', 'ports-filter', 'ports-exposed', 'ports-count', 'ports-list']) assert.ok(html.includes(`id="${id}"`), id);
  const js = readFileSync(new URL('js/reference.js', root), 'utf8');
  assert.ok(!/innerHTML/.test(js), 'render with textContent / DOM nodes only');
  const features = JSON.parse(readFileSync(new URL('data/hub-features.json', root), 'utf8')).features;
  assert.equal(features.find((f) => f.id === 'ports')?.href, './reference.html#ports');
});
