// "Is my version affected?" (NVD card): version comparison, range parsing and the verdict,
// all decided in code. parseRange() reads the text built by the Worker's versionRange(),
// so these tests feed it that function's real output.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  cleanVersion, compareVersions, parseRange, inRange, productChoices, checkVersion,
} from '../js/version-check.js';
import { affectedProducts } from '../worker/src/cve.js';

test('cleanVersion accepts version numbers and refuses anything else', () => {
  assert.equal(cleanVersion(' 2.14.1 '), '2.14.1');
  assert.equal(cleanVersion('v2.14.1'), '2.14.1');
  assert.equal(cleanVersion('1.0.1g'), '1.0.1g');
  assert.equal(cleanVersion('2.15.0-rc1'), '2.15.0-rc1');
  for (const bad of ['', '   ', 'latest', 'v', '2.14 beta', '<script>', '1'.repeat(41), null, undefined]) {
    assert.equal(cleanVersion(bad), null, String(bad));
  }
});

test('compareVersions: numbers by value, trailing zeros, pre-releases, OpenSSL letters', () => {
  const lt = (a, b) => { assert.equal(compareVersions(a, b), -1, `${a} < ${b}`); assert.equal(compareVersions(b, a), 1, `${b} > ${a}`); };
  const eq = (a, b) => assert.equal(compareVersions(a, b), 0, `${a} = ${b}`);
  lt('2.9.1', '2.10.0');
  lt('2.14.1', '2.15.0');
  lt('2.15', '2.15.0.1');
  eq('2.15', '2.15.0');
  eq('2.15.0', '2.15.0.0');
  lt('2.15.0-rc1', '2.15.0');
  lt('2.15.0-rc1', '2.15.0-rc2');
  lt('2.15.0-beta', '2.15.0-rc1');
  lt('1.0.1', '1.0.1a');
  lt('1.0.1f', '1.0.1g');
  lt('1.0.1g', '1.0.2');
  eq('9.8p1', '9.8p1');
  lt('9.7p1', '9.8p1');
  lt('9.8', '9.8p1');
});

test('parseRange reads every shape the Worker builds', () => {
  const configurations = [{ nodes: [{ cpeMatch: [
    { vulnerable: true, criteria: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*', versionStartIncluding: '2.0.1', versionEndExcluding: '2.12.2' },
    { vulnerable: true, criteria: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*', versionStartExcluding: '2.13.0', versionEndIncluding: '2.15.0' },
    { vulnerable: true, criteria: 'cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*' },
    { vulnerable: true, criteria: 'cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*' },
    { vulnerable: true, criteria: 'cpe:2.3:o:acme:fw:*:*:*:*:*:*:*:*' },
    { vulnerable: true, criteria: 'cpe:2.3:o:acme:router:-:*:*:*:*:*:*:*' },
  ] }] }];
  const parsed = affectedProducts(configurations).map((a) => parseRange(a.versions));
  assert.deepEqual(parsed, [
    { kind: 'range', bounds: [{ op: '>=', version: '2.0.1' }, { op: '<', version: '2.12.2' }] },
    { kind: 'range', bounds: [{ op: '>', version: '2.13.0' }, { op: '<=', version: '2.15.0' }] },
    { kind: 'exact', version: '2.0', update: 'beta9' },
    { kind: 'exact', version: '2.0', update: null },
    { kind: 'any' },
    { kind: 'unknown' },
  ]);
  assert.deepEqual(parseRange('>= 1.0, nonsense'), { kind: 'unknown' });
  assert.deepEqual(parseRange(''), { kind: 'unknown' });
});

test('inRange respects inclusive and exclusive bounds', () => {
  const r = parseRange('>= 2.0.1, < 2.12.2');
  assert.equal(inRange('2.0.1', r), true);
  assert.equal(inRange('2.0', r), false);
  assert.equal(inRange('2.12.1', r), true);
  assert.equal(inRange('2.12.2', r), false);
  const r2 = parseRange('> 2.13.0, <= 2.15.0');
  assert.equal(inRange('2.13.0', r2), false);
  assert.equal(inRange('2.15.0', r2), true);
  assert.equal(inRange('2.15.1', r2), false);
  assert.equal(inRange('5', parseRange('any version')), true);
  assert.equal(inRange('5', parseRange('unspecified version')), null);
  assert.equal(inRange('2.0-beta9', parseRange('2.0 beta9')), true);
  assert.equal(inRange('2.0', parseRange('2.0 beta9')), null);
  assert.equal(inRange('2.1', parseRange('2.0 beta9')), false);
  assert.equal(inRange('2.0.0', parseRange('2.0')), true);
});

const log4j = [
  { vendor: 'apache', product: 'log4j', type: 'application', versions: '>= 2.0.1, < 2.12.2' },
  { vendor: 'apache', product: 'log4j', type: 'application', versions: '>= 2.13.0, < 2.15.0' },
  { vendor: 'cisco', product: 'webex_meetings_server', type: 'application', versions: '4.0' },
];

test('productChoices lists each vendor/product once, readable', () => {
  assert.deepEqual(productChoices(log4j), [
    { key: 'apache|log4j', label: 'apache log4j' },
    { key: 'cisco|webex_meetings_server', label: 'cisco webex meetings server' },
  ]);
  assert.deepEqual(productChoices([]), []);
});

test('verdict: affected when the version is inside a listed range', () => {
  const r = checkVersion(log4j, 3, 'apache|log4j', 'v2.14.1');
  assert.equal(r.verdict, 'affected');
  assert.deepEqual(r.matches, ['>= 2.13.0, < 2.15.0']);
  assert.match(r.text, /^2\.14\.1 is inside a range NVD lists as affected for apache log4j/);
  assert.deepEqual(r.notes, []);
});

test('verdict: not listed when outside every range, with the backport caveat', () => {
  for (const v of ['2.15.0', '2.12.2', '1.2.17', '2.17.1']) {
    const r = checkVersion(log4j, 3, 'apache|log4j', v);
    assert.equal(r.verdict, 'not-listed', v);
    assert.match(r.text, /not a guarantee/);
  }
  // Ranges of another product never count.
  assert.equal(checkVersion(log4j, 3, 'cisco|webex_meetings_server', '2.14.1').verdict, 'not-listed');
  assert.equal(checkVersion(log4j, 3, 'cisco|webex_meetings_server', '4.0').verdict, 'affected');
});

test("verdict: can't tell when NVD gives no version, or the hub only has part of the list", () => {
  const vague = [{ vendor: 'acme', product: 'router', type: 'hardware', versions: 'unspecified version' }];
  assert.equal(checkVersion(vague, 1, 'acme|router', '1.0').verdict, 'cant-tell');

  // 20 ranges on NVD, 3 received: outside the 3 is not proof.
  const partial = checkVersion(log4j, 20, 'apache|log4j', '2.17.1');
  assert.equal(partial.verdict, 'cant-tell');
  assert.ok(partial.notes.some((n) => /20 affected ranges/.test(n)));
  // ...but inside one of them is still affected, with the note.
  const hit = checkVersion(log4j, 20, 'apache|log4j', '2.14.1');
  assert.equal(hit.verdict, 'affected');
  assert.ok(hit.notes.length === 1);
});

test('verdict: exact entries with an update level need the update typed; any version is affected', () => {
  const rows = [
    { vendor: 'acme', product: 'app', type: 'application', versions: '3.1 sp2' },
    { vendor: 'acme', product: 'lib', type: 'application', versions: 'any version' },
  ];
  const r = checkVersion(rows, 2, 'acme|app', '3.1');
  assert.equal(r.verdict, 'cant-tell');
  assert.match(r.notes[0], /3\.1 sp2 specifically: check your update or service-pack level/);
  assert.equal(checkVersion(rows, 2, 'acme|app', '3.1sp2').verdict, 'affected');
  assert.equal(checkVersion(rows, 2, 'acme|app', '3.2').verdict, 'not-listed');
  assert.equal(checkVersion(rows, 2, 'acme|lib', '0.1').verdict, 'affected');
});

test('verdict: bad input is refused before any comparison', () => {
  assert.equal(checkVersion(log4j, 3, 'apache|log4j', 'latest').verdict, 'invalid');
  assert.equal(checkVersion(log4j, 3, 'apache|log4j', '').verdict, 'invalid');
  assert.equal(checkVersion(log4j, 3, 'nobody|nothing', '1.0').verdict, 'invalid');
  assert.equal(checkVersion([], 0, 'apache|log4j', '1.0').verdict, 'invalid');
});
