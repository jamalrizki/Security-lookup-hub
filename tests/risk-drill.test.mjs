// Risk math practice (js/risk-drill.js): every answer is exact and comes from the
// three formulas, the parser takes fair ways of typing a number, common slips get
// their own hint, and odd input never counts as wrong.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  KINDS, KIND_NAMES, FREQUENCIES, VALUES, EF_PERCENTS, SCENARIOS, MAX_ANSWER,
  seeded, makeQuestion, parseAmount, checkAnswer, answerText, working, money, aroText, startRiskDrill,
} from '../js/risk-drill.js';
import { installDom } from './helpers/dom.mjs';

const root = new URL('../', import.meta.url);
const read = (f) => readFileSync(new URL(f, root), 'utf8');
const many = (opts, n = 500, seed = 1) => {
  const rand = seeded(seed);
  return Array.from({ length: n }, () => makeQuestion(rand, opts));
};
const aro = (f) => f.num / f.den;

test('questions are repeatable per seed, every kind comes up, and answers follow the formulas exactly', () => {
  assert.deepEqual(makeQuestion(seeded(9)), makeQuestion(seeded(9)));
  const seen = new Set();
  for (let seed = 1; seed <= 4; seed++) {
    for (const q of many({}, 500, seed)) {
      seen.add(q.kind);
      assert.ok(VALUES.includes(q.av) && EF_PERCENTS.includes(q.ef) && FREQUENCIES.includes(q.freq) && SCENARIOS.includes(q.scenario));
      assert.equal(q.sle, (q.av * q.ef) / 100);
      assert.ok(Number.isInteger(q.sle), 'SLE is whole dollars');
      assert.equal(q.ale, q.sle * aro(q.freq));
      assert.ok(Number.isInteger(q.ale), `ALE is whole dollars: ${q.sle} x ${aroText(q.freq)}`);
      if (q.kind === 'sle') assert.equal(q.answer, q.sle);
      if (q.kind === 'aro') assert.equal(q.answer, aro(q.freq));
      if (q.kind === 'ale') assert.equal(q.answer, q.ale);
      if (q.kind === 'control') {
        assert.ok(aro(q.after) < aro(q.freq), 'the safeguard lowers the ARO');
        assert.equal(q.aleAfter, q.sle * aro(q.after));
        assert.ok(Number.isInteger(q.aleAfter));
        assert.ok(q.cost > 0 && q.cost % 100 === 0);
        assert.equal(q.answer, q.ale - q.aleAfter - q.cost);
        assert.notEqual(q.answer, 0, 'never a tie');
        assert.ok(q.prompt.includes(money(q.cost)) && q.prompt.includes(q.after.text));
      }
      assert.ok(q.prompt.includes(money(q.av)) && q.prompt.includes(`${q.ef}%`) && q.prompt.includes(q.freq.text));
      assert.ok(q.prompt.length < 330, q.prompt);
      // The exact answer, typed the way the page shows it, is always correct.
      assert.equal(checkAnswer(q, answerText(q).replace(' per year', '')).status, 'correct', `${q.kind}: ${answerText(q)}`);
      assert.equal(checkAnswer(q, String(q.answer)).status, 'correct');
    }
  }
  assert.deepEqual([...seen].sort(), [...KINDS].sort());
  for (const k of KINDS) {
    assert.ok(KIND_NAMES[k]);
    assert.ok(many({ kinds: [k] }, 50).every((q) => q.kind === k), k);
  }
  assert.ok(many({ kinds: ['nope'] }, 50).every((q) => KINDS.includes(q.kind)), 'unknown kinds fall back to all');
  // Some safeguards are worth it and some are not.
  const controls = many({ kinds: ['control'] }, 400);
  assert.ok(controls.some((q) => q.answer > 0) && controls.some((q) => q.answer < 0));
});

test('the example from the idea: $250,000, 40%, once every 20 years', () => {
  const freq = FREQUENCIES.find((f) => f.every === 20);
  const q = { kind: 'ale', av: 250000, ef: 40, freq, sle: 100000, ale: 5000, answer: 5000 };
  assert.equal(checkAnswer(q, '$5,000').status, 'correct');
  const slipped = checkAnswer(q, '100000');
  assert.equal(slipped.status, 'wrong');
  assert.equal(slipped.message, 'Not quite. The answer is $5,000 per year.');
  assert.match(slipped.hint, /^That's the SLE\./);
  assert.deepEqual(working(q), [
    'SLE = AV × EF = $250,000 × 0.40 = $100,000',
    'ARO = 1 ÷ 20 = 0.05 (once every 20 years)',
    'ALE = SLE × ARO = $100,000 × 0.05 = $5,000 per year',
  ]);
});

test('parseAmount: $, commas, k/m, per year, minus, fractions and percents; anything else is null', () => {
  const cases = {
    '5000': 5000, '$5,000': 5000, ' $ 5 000 ': 5000, '5k': 5000, '$5K/yr': 5000, '5000 per year': 5000,
    '5,000 a year': 5000, '$5,000 annually': 5000, '1.2m': 1200000, '$1,200,000.00': 1200000,
    '-5000': -5000, '-$5,000': -5000, '$-5,000': -5000, '−2,500': -2500,
    '0.05': 0.05, '.25': 0.25, '1/20': 0.05, '5%': 0.05, '12': 12,
  };
  for (const [s, want] of Object.entries(cases)) assert.equal(parseAmount(s), want, s);
  for (const s of ['', '   ', 'abc', '5 dollars more', '1/0', '$$5', '5..0', '--5', '5e3', 'x'.repeat(MAX_ANSWER + 1), null, undefined]) {
    assert.equal(parseAmount(s), null, String(s));
  }
});

test('invalid input never counts; the message says what to type', () => {
  const q = makeQuestion(seeded(2), { kinds: ['ale'] });
  for (const a of ['', '  ', 'lots', 'x'.repeat(MAX_ANSWER + 1)]) assert.equal(checkAnswer(q, a).status, 'invalid', a);
  assert.equal(checkAnswer(q, 'lots').message, 'Type a dollar amount, like $5,000.');
  const r = makeQuestion(seeded(2), { kinds: ['aro'] });
  assert.equal(checkAnswer(r, 'often').message, 'Type a number, like 0.25 or 1/4.');
});

test('each common slip is caught with its own hint, and only when it differs from the answer', () => {
  const every = (n) => FREQUENCIES.find((f) => f.every === n);
  const base = { av: 200000, ef: 25, freq: every(4), sle: 50000, ale: 12500 };

  const sle = { ...base, kind: 'sle', answer: 50000 };
  assert.match(checkAnswer(sle, '5000000').hint, /whole number/);
  assert.match(checkAnswer(sle, '12500').hint, /^That's the ALE/);
  assert.match(checkAnswer(sle, '200000').hint, /whole asset value/);

  const aroQ = { ...base, kind: 'aro', answer: 0.25 };
  assert.equal(checkAnswer(aroQ, '1/4').status, 'correct');
  assert.match(checkAnswer(aroQ, '4').hint, /ARO = 1 ÷ 4, not 4/);
  const monthly = FREQUENCIES.find((f) => f.num === 12);
  assert.match(checkAnswer({ ...base, kind: 'aro', freq: monthly, answer: 12 }, '1/12').hint, /12 times a year/);

  const ale = { ...base, kind: 'ale', answer: 12500 };
  assert.match(checkAnswer(ale, '50000').hint, /^That's the SLE/);
  assert.match(checkAnswer(ale, '1250000').hint, /whole number/);
  assert.match(checkAnswer(ale, '200000').hint, /used 4 as the ARO/);
  assert.match(checkAnswer(ale, '$50k').hint, /SLE/); // AV x ARO is also 50,000 here: the SLE hint is listed first
  assert.match(checkAnswer({ ...ale, ef: 50, sle: 100000, ale: 25000, answer: 25000 }, '50000').hint, /skips the exposure factor/);
  assert.equal(checkAnswer(ale, '7').hint, undefined, 'no hint for an unrelated wrong number');

  // Control: ALE 12,500 before; once every 10 years after -> 5,000; cost 3,000 -> value 4,500.
  const control = { ...base, kind: 'control', after: every(10), aleAfter: 5000, cost: 3000, answer: 4500 };
  assert.equal(checkAnswer(control, '4,500').status, 'correct');
  assert.match(checkAnswer(control, '7500').hint, /yearly saving/);
  assert.match(checkAnswer(control, '-4500').hint, /sign is flipped/);
  assert.match(checkAnswer(control, '9500').hint, /new ALE as well/);
  assert.match(checkAnswer(control, '5000').hint, /ALE after the safeguard/);
  const steps = working(control);
  assert.equal(steps.at(-2), 'Value = ALE before − ALE after − cost = $12,500 − $5,000 − $3,000 = $4,500 per year');
  assert.match(steps.at(-1), /^Worth it: it saves \$4,500 a year more than it costs\.$/);
  assert.match(working({ ...control, cost: 9000, answer: -1500 }).at(-1), /^Not worth it on cost alone: it costs \$1,500 a year more/);
});

test('money and aroText format plainly', () => {
  assert.equal(money(0), '$0');
  assert.equal(money(1234567), '$1,234,567');
  assert.equal(money(-5000), '-$5,000');
  assert.equal(money(12.5), '$12.50');
  assert.deepEqual(FREQUENCIES.map(aroText), ['0.05', '0.1', '0.2', '0.25', '0.5', '1', '2', '4', '12']);
  for (let i = 1; i < FREQUENCIES.length; i++) assert.ok(aro(FREQUENCIES[i]) > aro(FREQUENCIES[i - 1]), 'least to most often');
});

test('the Study page has the risk math block; the drill has no innerHTML, storage or network; Ask can link to it', () => {
  const html = read('study.html');
  for (const id of ['risk-practice', 'rdrill-kind', 'rdrill-question', 'rdrill-form', 'rdrill-answer', 'rdrill-reveal', 'rdrill-next', 'rdrill-result', 'rdrill-score']) {
    assert.ok(html.includes(`id="${id}"`), id);
  }
  for (const k of KINDS) assert.ok(html.includes(`<option value="${k}">`), k);
  assert.match(read('js/study.js'), /startRiskDrill\(\{ el, \$ \}\)/);
  assert.ok(!/innerHTML|localStorage|sessionStorage|fetch\(/.test(read('js/risk-drill.js')));
  const { features } = JSON.parse(read('data/hub-features.json'));
  assert.equal(features.find((f) => f.id === 'risk-practice')?.href, './study.html#risk-practice');
});

test('page wiring: first answer scores, slips show a hint and the working, reveal never scores, type picker', () => {
  const dom = installDom(read('study.html'));
  try {
    const $ = (id) => dom.document.getElementById(id);
    const el = (tag, attrs = {}, ...kids) => {
      const n = dom.document.createElement(tag);
      for (const [k, v] of Object.entries(attrs)) if (k === 'class') n.className = v; else n.setAttribute(k, v);
      n.append(...kids.filter((k) => k != null));
      return n;
    };
    // Pick ALE so the answer can be worked out from the question text.
    $('rdrill-kind').setAttribute('value', 'ale');
    startRiskDrill({ el, $ });
    const prompt = () => $('rdrill-question').textContent;
    assert.match(prompt(), /What is the annualized loss expectancy \(ALE\)\?$/);
    assert.equal($('rdrill-score').textContent, '');
    const nums = () => {
      const t = prompt();
      const av = Number(/worth \$([\d,]+)/.exec(t)[1].replace(/,/g, ''));
      const ef = Number(/loses (\d+)%/.exec(t)[1]);
      const f = FREQUENCIES.find((x) => t.includes(x.text));
      return { sle: (av * ef) / 100, ale: (av * ef) / 100 * aro(f) };
    };

    // Invalid input: a warning, no score.
    $('rdrill-answer').value = 'lots';
    $('rdrill-form').requestSubmit();
    assert.equal($('rdrill-result').textContent, 'Type a dollar amount, like $5,000.');
    assert.equal($('rdrill-score').textContent, '');

    // The SLE when the ALE was asked: wrong, with the hint and the three working lines.
    const { sle, ale } = nums();
    $('rdrill-answer').value = String(sle);
    $('rdrill-form').requestSubmit();
    assert.equal($('rdrill-score').textContent, '0 / 1 this session');
    if (sle !== ale) assert.ok($('rdrill-result').textContent.includes("That's the SLE."));
    assert.equal($('rdrill-result').querySelectorAll('li').length, 3);
    // A second try on the same question doesn't change the score.
    $('rdrill-answer').value = String(ale);
    $('rdrill-form').requestSubmit();
    assert.match($('rdrill-result').textContent, /^✔ Correct: /);
    assert.equal($('rdrill-score').textContent, '0 / 1 this session');

    // Next: a fresh question, answered right first time.
    $('rdrill-next').click();
    assert.equal($('rdrill-result').textContent, '');
    $('rdrill-answer').value = String(nums().ale);
    $('rdrill-form').requestSubmit();
    assert.equal($('rdrill-score').textContent, '1 / 2 this session');

    // Reveal never scores.
    $('rdrill-next').click();
    $('rdrill-reveal').click();
    assert.match($('rdrill-result').textContent, /^The answer is \$/);
    $('rdrill-answer').value = String(nums().ale);
    $('rdrill-form').requestSubmit();
    assert.equal($('rdrill-score').textContent, '1 / 2 this session');

    // Changing the type asks a new question of that type.
    $('rdrill-kind').setAttribute('value', 'aro');
    $('rdrill-kind').dispatchEvent(new Event('change'));
    assert.match(prompt(), /What is the annualized rate of occurrence \(ARO\)\?$/);
  } finally {
    dom.restore();
  }
});
