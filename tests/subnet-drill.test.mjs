// Subnetting practice (js/analyze/subnet-drill.js): every generated answer must
// match the calculator (subnetInfo / inRange), only private and documentation
// addresses appear, and odd input is rejected without counting as wrong.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  KINDS, MAX_PREFIX, MIN_PREFIX, seeded, makeQuestion, checkAnswer, working, blockOf, parseMaskAnswer,
} from '../js/analyze/subnet-drill.js';
import { subnetInfo, inRange } from '../js/analyze/subnet.js';

const root = new URL('../', import.meta.url);
const many = (kinds, n = 600, seed = 1) => {
  const rand = seeded(seed);
  return Array.from({ length: n }, () => makeQuestion(rand, kinds));
};

test('seeded generator is repeatable and in [0, 1)', () => {
  const a = seeded(42); const b = seeded(42);
  for (let i = 0; i < 100; i++) {
    const x = a();
    assert.equal(x, b());
    assert.ok(x >= 0 && x < 1);
  }
  assert.deepEqual(makeQuestion(seeded(7)), makeQuestion(seeded(7)));
});

test('every kind comes up, and every answer matches subnetInfo()/inRange() over many seeds', () => {
  const seen = new Set();
  for (let seed = 1; seed <= 5; seed++) {
    for (const q of many(KINDS, 400, seed)) {
      seen.add(q.kind);
      const i = subnetInfo(q.cidr);
      const expected = {
        network: i.network.split('/')[0],
        broadcast: i.broadcast,
        first: i.firstHost,
        last: i.lastHost,
        usable: Number(i.usable).toLocaleString('en-US'),
        mask: q.toMask ? i.netmask : `/${q.prefix}`,
        inrange: q.kind === 'inrange' && inRange(i.network, q.check) ? 'yes' : 'no',
      }[q.kind];
      assert.equal(q.answer, expected, `${q.kind} ${q.cidr}`);
      assert.ok(q.answer, `${q.kind} ${q.cidr} has an answer`);
      // The canonical answer always grades as correct.
      assert.equal(checkAnswer(q, q.answer).status, 'correct', `${q.kind} ${q.cidr}: ${q.answer}`);
    }
  }
  assert.deepEqual([...seen].sort(), [...KINDS].sort());
});

test('prefixes stay in /8–/30 and only private or documentation addresses appear (whole subnet inside)', () => {
  const prefixes = new Set();
  for (const q of many(KINDS, 3000, 99)) {
    prefixes.add(q.prefix);
    assert.ok(q.prefix >= MIN_PREFIX && q.prefix <= MAX_PREFIX, q.cidr);
    const b = blockOf(q.ip);
    assert.ok(b, `${q.ip} is not private/documentation`);
    assert.ok(q.prefix >= b.prefix, `${q.cidr} would leave ${b.base.join('.')}/${b.prefix}`);
    assert.equal(blockOf(q.info.network.split('/')[0]), b);
    assert.ok(q.info.broadcast && blockOf(q.info.broadcast) === b, q.cidr);
    if (q.kind === 'inrange') assert.equal(blockOf(q.check), b, `${q.check} left the block`);
    for (const shown of q.prompt.match(/\d+\.\d+\.\d+\.\d+/g) || []) {
      if (shown.startsWith('255.') || shown === q.info.netmask) continue; // a mask, not an address
      assert.ok(blockOf(shown), `${shown} in "${q.prompt}"`);
    }
  }
  assert.ok(prefixes.has(8) && prefixes.has(30), 'edge prefixes /8 and /30 come up');
});

test('"is it in range" questions are a mix of yes and no', () => {
  const qs = many(['inrange'], 400, 3);
  const yes = qs.filter((q) => q.inside).length;
  assert.ok(yes > 100 && yes < 300, `yes=${yes}`);
});

test('the issue example: 10.40.77.200/21 broadcast, with the working', () => {
  const q = { kind: 'broadcast', cidr: '10.40.77.200/21', ip: '10.40.77.200', prefix: 21, info: subnetInfo('10.40.77.200/21') };
  q.answer = q.info.broadcast;
  assert.equal(checkAnswer(q, '10.40.79.255').status, 'correct');
  const wrong = checkAnswer(q, '10.40.77.255');
  assert.equal(wrong.status, 'wrong');
  assert.match(wrong.message, /10\.40\.79\.255/);
  assert.deepEqual(working(q), [
    '/21 → mask 255.255.248.0.',
    'The 3rd octet is the interesting one: block size 256 − 248 = 8. 77 falls in 72–79, so the network is 10.40.72.0 and the broadcast is 10.40.79.255.',
  ]);
});

test('working text at octet boundaries and for counts, masks and ranges', () => {
  const mk = (kind, cidr, extra = {}) => ({ kind, cidr, ip: cidr.split('/')[0], prefix: Number(cidr.split('/')[1]), info: subnetInfo(cidr), ...extra });
  assert.match(working(mk('network', '10.9.8.7/8'))[1], /keep the first 1 octet and.*network is 10\.0\.0\.0 and the broadcast is 10\.255\.255\.255/);
  assert.match(working(mk('network', '172.20.5.1/16'))[1], /first 2 octets/);
  assert.match(working(mk('usable', '192.168.1.9/30')).at(-1), /2 host bits: 2\^2 − 2 = 2 usable/);
  assert.match(working(mk('usable', '10.40.77.200/21')).at(-1), /2\^11 − 2 = 2,046 usable/);
  assert.match(working(mk('mask', '10.0.0.1/21', { toMask: true })).at(-1), /8 \+ 8 \+ 5.*256 − 2\^3 = 248/);
  assert.match(working(mk('first', '10.40.77.200/21')).at(-1), /10\.40\.72\.1/);
  assert.match(working(mk('last', '10.40.77.200/21')).at(-1), /10\.40\.79\.254/);
  assert.match(working(mk('inrange', '10.40.77.200/21', { check: '10.40.80.3', inside: false })).at(-1), /is not between 10\.40\.72\.0 and 10\.40\.79\.255/);
});

test('answers: accepted forms', () => {
  const info = subnetInfo('10.40.77.200/21');
  const base = { cidr: '10.40.77.200/21', ip: '10.40.77.200', prefix: 21, info };
  const net = { ...base, kind: 'network', answer: '10.40.72.0' };
  assert.equal(checkAnswer(net, ' 10.40.72.0 ').status, 'correct');
  assert.equal(checkAnswer(net, '10.40.72.0/21').status, 'correct');
  assert.equal(checkAnswer(net, '10.40.72.0/20').status, 'wrong');
  const usable = { ...base, kind: 'usable', answer: '2,046' };
  for (const a of ['2046', '2,046', '2046 hosts', '2046 usable hosts', '2,046 addresses']) assert.equal(checkAnswer(usable, a).status, 'correct', a);
  assert.equal(checkAnswer(usable, '2048').status, 'wrong');
  const mask = { ...base, kind: 'mask', toMask: true, answer: '255.255.248.0' };
  for (const a of ['255.255.248.0', '/21', '21']) assert.equal(checkAnswer(mask, a).status, 'correct', a);
  assert.equal(checkAnswer({ ...mask, toMask: false, answer: '/21' }, '255.255.248.0').status, 'correct');
  assert.equal(checkAnswer(mask, '/22').status, 'wrong');
  const range = { ...base, kind: 'inrange', check: '10.40.79.1', inside: true, answer: 'yes' };
  for (const a of ['yes', 'Y', ' YES ']) assert.equal(checkAnswer(range, a).status, 'correct', a);
  assert.equal(checkAnswer(range, 'n').status, 'wrong');
});

test('hostile or odd input is invalid, not wrong', () => {
  const info = subnetInfo('192.168.10.33/27');
  const base = { cidr: '192.168.10.33/27', ip: '192.168.10.33', prefix: 27, info };
  const ip = { ...base, kind: 'broadcast', answer: info.broadcast };
  for (const a of ['', '   ', null, undefined, 'x'.repeat(41), '192.168.010.63', '192.168.10.256', '192.168.10', '<img src=x>',
    '192.168.10.63/27/1', '192.168.10.63/abc', '::1', '1e3']) {
    assert.equal(checkAnswer(ip, a).status, 'invalid', String(a));
  }
  const usable = { ...base, kind: 'usable', answer: '30' };
  for (const a of ['thirty', '-30', '30.0', '3,0', '30 bananas', '0x1e']) assert.equal(checkAnswer(usable, a).status, 'invalid', a);
  const mask = { ...base, kind: 'mask', toMask: true, answer: info.netmask };
  for (const a of ['255.255.249.0', '/33', '255.255.255.2241', 'mask']) assert.equal(checkAnswer(mask, a).status, 'invalid', a);
  const range = { ...base, kind: 'inrange', check: '192.168.10.40', inside: true, answer: 'yes' };
  for (const a of ['maybe', 'true', 'yess']) assert.equal(checkAnswer(range, a).status, 'invalid', a);
});

test('parseMaskAnswer: prefixes and contiguous dotted masks only', () => {
  assert.equal(parseMaskAnswer('/0'), 0);
  assert.equal(parseMaskAnswer('32'), 32);
  assert.equal(parseMaskAnswer('255.255.255.255'), 32);
  assert.equal(parseMaskAnswer('0.0.0.0'), 0);
  assert.equal(parseMaskAnswer('255.240.0.0'), 12);
  assert.equal(parseMaskAnswer('255.0.255.0'), null);
  assert.equal(parseMaskAnswer('/40'), null);
});

test('the Analyze page has the practice UI, loads the module, and Ask can link to it', () => {
  const html = readFileSync(new URL('analyze.html', root), 'utf8');
  for (const id of ['subnet-practice', 'drill-question', 'drill-form', 'drill-answer', 'drill-reveal', 'drill-next', 'drill-open', 'drill-result', 'drill-score']) {
    assert.ok(html.includes(`id="${id}"`), id);
  }
  assert.ok(html.includes('<script type="module" src="js/analyze/subnet-drill.js"></script>'));
  const src = readFileSync(new URL('js/analyze/subnet-drill.js', root), 'utf8');
  assert.ok(!/innerHTML|localStorage|sessionStorage|fetch\(/.test(src), 'textContent only, no storage, no network');
  const features = JSON.parse(readFileSync(new URL('data/hub-features.json', root), 'utf8')).features;
  assert.equal(features.find((f) => f.id === 'subnet-practice')?.href, './analyze.html#subnet-practice');
});
