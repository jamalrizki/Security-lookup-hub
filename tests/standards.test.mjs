// "What does this standard ask for?" on the Reference page (data/standards.json, js/standards.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { searchStandards, standardProblems, standardUrl, standardKey, STANDARD_HOSTS } from '../js/standards.js';

const root = new URL('../', import.meta.url);
const data = JSON.parse(readFileSync(new URL('data/standards.json', root), 'utf8'));
const keys = (r) => r.items.map(standardKey);

test('frameworks: unique ids, https links on the allowed official hosts', () => {
  const ids = data.frameworks.map((f) => f.id);
  assert.deepEqual(ids, ['csf', 'cis']);
  for (const f of data.frameworks) {
    for (const k of ['name', 'by', 'about', 'url']) assert.ok(typeof f[k] === 'string' && f[k].trim(), `${f.id}: ${k}`);
    const href = standardUrl(f.url);
    assert.ok(href, `${f.id}: unsafe link`);
    assert.ok(STANDARD_HOSTS.includes(new URL(href).hostname));
  }
});

test('every item has a valid shape, and (framework, num) is unique', () => {
  const ids = data.frameworks.map((f) => f.id);
  const seen = new Set();
  for (const i of data.items) {
    assert.deepEqual(standardProblems(i, ids), [], `${standardKey(i)}: ${standardProblems(i, ids).join(', ')}`);
    const k = standardKey(i);
    assert.ok(!seen.has(k), `duplicate ${k}`);
    seen.add(k);
    assert.ok(!/[<>]|https?:/.test(i.name + i.plain + i.evidence), `${k}: no markup or links`);
  }
});

test('NIST CSF 2.0: the six functions in order with all 22 categories', () => {
  const csf = data.items.filter((i) => i.framework === 'csf');
  assert.deepEqual(csf.map((i) => [i.num, i.name]), [['GV', 'Govern'], ['ID', 'Identify'], ['PR', 'Protect'], ['DE', 'Detect'], ['RS', 'Respond'], ['RC', 'Recover']]);
  const codes = csf.flatMap((i) => i.categories.map((c) => c.code));
  assert.deepEqual(codes, ['GV.OC', 'GV.RM', 'GV.RR', 'GV.PO', 'GV.OV', 'GV.SC', 'ID.AM', 'ID.RA', 'ID.IM',
    'PR.AA', 'PR.AT', 'PR.DS', 'PR.PS', 'PR.IR', 'DE.CM', 'DE.AE', 'RS.MA', 'RS.AN', 'RS.CO', 'RS.MI', 'RC.RP', 'RC.CO']);
});

test('CIS Controls v8.1: all 18 in order with their official names', () => {
  const cis = data.items.filter((i) => i.framework === 'cis');
  assert.deepEqual(cis.map((i) => i.num), Array.from({ length: 18 }, (_, n) => String(n + 1)));
  const names = Object.fromEntries(cis.map((i) => [i.num, i.name]));
  assert.equal(names[1], 'Inventory and Control of Enterprise Assets');
  assert.equal(names[4], 'Secure Configuration of Enterprise Assets and Software');
  assert.equal(names[7], 'Continuous Vulnerability Management');
  assert.equal(names[8], 'Audit Log Management');
  assert.equal(names[9], 'Email and Web Browser Protections');
  assert.equal(names[14], 'Security Awareness and Skills Training');
  assert.equal(names[18], 'Penetration Testing');
});

test('hub links point at pages and anchors that exist', () => {
  for (const i of data.items) {
    for (const h of i.hub) {
      const [path, anchor] = h.href.slice(2).split('#');
      const page = path || 'index.html';
      const html = readFileSync(new URL(page, root), 'utf8');
      if (anchor) assert.ok(html.includes(`id="${anchor}"`), `${standardKey(i)}: #${anchor} missing in ${page}`);
    }
  }
});

test('standardUrl refuses http, other hosts, look-alikes and credentials', () => {
  assert.equal(standardUrl('http://www.nist.gov/cyberframework'), null);
  assert.equal(standardUrl('https://www.nist.gov.evil.example/'), null);
  assert.equal(standardUrl('https://evil.example/www.cisecurity.org'), null);
  assert.equal(standardUrl('https://user@www.cisecurity.org/'), null);
  assert.equal(standardUrl('https://www.nist.gov:8443/'), null);
  assert.equal(standardUrl('javascript:alert(1)'), null);
  assert.equal(standardUrl(undefined), null);
  assert.ok(standardUrl('https://www.nist.gov/cyberframework'));
});

test('CIS numbers: bare, "cis", "cis control", "control" and "#" forms; out of range says so', () => {
  for (const q of ['7', 'CIS 7', 'cis control 7', 'CIS Controls 7', 'control 7', 'cis #7', 'cis-7', ' 7 ']) {
    const r = searchStandards(data, q);
    assert.equal(r.kind, 'cis', q);
    assert.deepEqual(keys(r), ['CIS 7'], q);
  }
  for (const q of ['0', '19', 'cis 99']) {
    const r = searchStandards(data, q);
    assert.deepEqual(r.items, [], q);
    assert.match(r.error, /1 to 18/, q);
  }
});

test('CSF codes: function, "csf"/"nist csf" prefix, category and subcategory; unknown category says so', () => {
  for (const q of ['pr', 'PR', 'csf pr', 'NIST CSF PR']) assert.deepEqual(keys(searchStandards(data, q)), ['CSF PR'], q);
  for (const q of ['pr.aa', 'PR.AA', 'PR.AA-01', 'csf pr.aa', 'pr.aa 01']) {
    const r = searchStandards(data, q);
    assert.deepEqual(keys(r), ['CSF PR'], q);
    assert.equal(r.category?.code, 'PR.AA', q);
  }
  assert.equal(searchStandards(data, 'gv.sc').category.name, 'Cybersecurity Supply Chain Risk Management');
  const bad = searchStandards(data, 'pr.zz');
  assert.deepEqual(bad.items, []);
  assert.match(bad.error, /PR\.ZZ is not a CSF 2.0 category/);
  assert.deepEqual(keys(searchStandards(data, 'id')), ['CSF ID'], 'a bare function code is the function');
});

test('framework names list that framework', () => {
  assert.equal(searchStandards(data, 'cis').items.length, 18);
  assert.equal(searchStandards(data, 'CIS Controls').items.length, 18);
  assert.equal(searchStandards(data, 'nist csf').items.length, 6);
  assert.equal(searchStandards(data, 'csf').kind, 'framework');
});

test('words find the same topic across both frameworks, best match first', () => {
  const logging = keys(searchStandards(data, 'logging'));
  for (const k of ['CIS 8', 'CSF DE', 'CIS 13']) assert.ok(logging.includes(k), `logging should find ${k}`);
  const password = keys(searchStandards(data, 'password'));
  for (const k of ['CIS 5', 'CIS 6', 'CSF PR']) assert.ok(password.includes(k), `password should find ${k}`);
  const patch = keys(searchStandards(data, 'patch'));
  for (const k of ['CIS 7', 'CSF PR']) assert.ok(patch.includes(k), `patch should find ${k}`);
  assert.equal(keys(searchStandards(data, 'penetration'))[0], 'CIS 18', 'name match first');
  const supply = keys(searchStandards(data, 'supply chain'));
  for (const k of ['CSF GV', 'CIS 15']) assert.ok(supply.includes(k), `supply chain should find ${k}`);
  assert.ok(keys(searchStandards(data, 'dmarc')).includes('CIS 9'));
  assert.ok(keys(searchStandards(data, 'adverse event')).includes('CSF DE'), 'category names are searched');
});

test('empty, short, odd and long input never throws', () => {
  assert.equal(searchStandards(data, '').kind, 'all');
  assert.equal(searchStandards(data, '').items.length, 24);
  assert.equal(searchStandards(data, undefined).kind, 'all');
  assert.deepEqual(searchStandards(data, 'zq').items, [], 'two letters that are not a CSF code match nothing');
  assert.deepEqual(searchStandards(data, '((([[[.*+?').items, []);
  assert.deepEqual(searchStandards(data, 'zzzz-not-a-control').items, []);
  assert.equal(searchStandards(data, 'x'.repeat(10000)).kind, 'text');
  assert.deepEqual(searchStandards(null, 'cis 7').items, []);
});

test('standardProblems catches bad entries', () => {
  const ok = { framework: 'cis', num: '7', name: 'Continuous Vulnerability Management', plain: 'Fix things.', evidence: 'Reports.', tags: ['patch'], hub: [] };
  assert.deepEqual(standardProblems(ok), []);
  assert.ok(standardProblems({ ...ok, framework: 'pci' }).length);
  assert.ok(standardProblems({ ...ok, num: '19' }).length);
  assert.ok(standardProblems({ ...ok, plain: 'No full stop' }).length);
  assert.ok(standardProblems({ ...ok, evidence: `${'x'.repeat(160)}.` }).length);
  assert.ok(standardProblems({ ...ok, tags: ['Patch'] }).length);
  assert.ok(standardProblems({ ...ok, tags: [] }).length);
  assert.ok(standardProblems({ ...ok, categories: [] }).length, 'CIS items have no categories');
  assert.ok(standardProblems({ ...ok, hub: [{ label: 'x', href: 'https://evil.example/' }] }).length);
  assert.ok(standardProblems({ ...ok, extra: 1 }).length);
  const fn = { framework: 'csf', num: 'PR', name: 'Protect', plain: 'A.', evidence: 'B.', tags: ['mfa'], hub: [], categories: [{ code: 'PR.AA', name: 'Identity' }] };
  assert.deepEqual(standardProblems(fn), []);
  assert.ok(standardProblems({ ...fn, num: 'XX' }).length);
  assert.ok(standardProblems({ ...fn, categories: [{ code: 'DE.CM', name: 'Wrong function' }] }).length);
  assert.ok(standardProblems({ ...fn, categories: undefined }).length);
});

test('the Reference page has the standards section and renders safely', () => {
  const html = readFileSync(new URL('reference.html', root), 'utf8');
  for (const id of ['standards', 'standards-filter', 'standards-count', 'standards-list', 'standards-sources']) assert.ok(html.includes(`id="${id}"`), id);
  const js = readFileSync(new URL('js/reference.js', root), 'utf8');
  assert.ok(!/innerHTML/.test(js), 'render with textContent / DOM nodes only');
  assert.ok(/standardUrl\(/.test(js), 'official links are re-checked when rendering');
  assert.ok(/isHubHref\(h\.href\)/.test(js), 'hub links are re-checked when rendering');
});
