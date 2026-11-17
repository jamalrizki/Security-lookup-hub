// Risk math practice (Study page, #risk-practice). Random quantitative-risk
// questions for Security+ (SY0-701 5.2), CISSP and CISM students: SLE, ARO,
// ALE, and whether a safeguard is worth its yearly cost. Every number is made
// and graded here from three formulas, with no AI and no network:
//   SLE = asset value (AV) x exposure factor (EF)
//   ALE = SLE x annualized rate of occurrence (ARO)
//   control value = ALE before - ALE after - yearly cost of the control
// Values are round and ARO is kept as a fraction, so every answer is exact.
// Pure functions are exported for tests; startRiskDrill() wires the page.

import { seeded, cryptoRand } from './analyze/subnet-drill.js';

export { seeded, cryptoRand };

export const KINDS = ['sle', 'aro', 'ale', 'control'];
export const KIND_NAMES = { sle: 'SLE', aro: 'ARO', ale: 'ALE', control: 'Is the control worth it?' };
export const MAX_ANSWER = 40;

export const VALUES = [20000, 40000, 50000, 80000, 100000, 120000, 150000, 200000, 250000, 400000, 500000, 800000, 1000000];
export const EF_PERCENTS = [10, 20, 25, 40, 50, 60, 75, 80, 100];

// How often it happens, from least to most often. `every` marks "once every N
// years" wording, where the ARO is 1/N (the classic slip is answering N).
export const FREQUENCIES = [
  { text: 'about once every 20 years', num: 1, den: 20, every: 20 },
  { text: 'about once every 10 years', num: 1, den: 10, every: 10 },
  { text: 'about once every 5 years', num: 1, den: 5, every: 5 },
  { text: 'about once every 4 years', num: 1, den: 4, every: 4 },
  { text: 'about once every 2 years', num: 1, den: 2, every: 2 },
  { text: 'about once a year', num: 1, den: 1 },
  { text: 'about twice a year', num: 2, den: 1 },
  { text: 'about four times a year', num: 4, den: 1 },
  { text: 'about once a month', num: 12, den: 1 },
];

// Scenarios written for this repo: what the asset is and what happens to it.
export const SCENARIOS = [
  { asset: 'server room', event: 'floods' },
  { asset: 'fleet of office laptops', event: 'gets hit by ransomware' },
  { asset: 'customer database', event: 'is breached' },
  { asset: 'warehouse', event: 'has a fire' },
  { asset: 'online shop', event: 'is knocked offline by a DDoS attack' },
  { asset: 'branch office', event: 'is damaged by a storm' },
  { asset: 'payment system', event: 'is hit by fraud' },
  { asset: 'file server', event: 'has a disk array failure' },
];

// Fractions of the yearly saving a control may cost (so some are worth it, some not).
const COST_SHARES = [0.25, 0.4, 0.5, 0.6, 0.75, 1.25, 1.5, 2];

const pick = (rand, list) => list[Math.floor(rand() * list.length)];

/** 1234567 -> "$1,234,567"; -5000 -> "-$5,000". Whole dollars, or cents if needed. */
export function money(n) {
  const neg = n < 0;
  const abs = Math.abs(n);
  const [int, frac] = (Number.isInteger(abs) ? String(abs) : abs.toFixed(2)).split('.');
  return `${neg ? '-' : ''}$${int.replace(/\B(?=(\d{3})+(?!\d))/g, ',')}${frac ? `.${frac}` : ''}`;
}

/** An ARO fraction as a plain decimal: 1/20 -> "0.05", 2/1 -> "2". */
export function aroText(f) {
  return String(Number((f.num / f.den).toFixed(4)));
}

const sleOf = (av, ef) => (av * ef) / 100;
const aleOf = (sle, f) => (sle * f.num) / f.den;

/**
 * Makes one question. kinds limits which kinds can come up.
 * Returns { kind, scenario, av, ef, freq, sle, ale, prompt, answer, ... } where
 * answer is the exact number; controls also carry after, cost, aleAfter.
 */
export function makeQuestion(rand, { kinds = KINDS } = {}) {
  const allowed = kinds.filter((k) => KINDS.includes(k));
  const kind = pick(rand, allowed.length ? allowed : KINDS);
  const scenario = pick(rand, SCENARIOS);
  const av = pick(rand, VALUES);
  const ef = pick(rand, EF_PERCENTS);
  // A control needs a lower frequency to move to, so it never starts at the lowest.
  const freqs = kind === 'control' ? FREQUENCIES.slice(1) : FREQUENCIES;
  const freq = pick(rand, freqs);
  const sle = sleOf(av, ef);
  const ale = aleOf(sle, freq);
  const q = { kind, scenario, av, ef, freq, sle, ale };

  const setup = `A ${scenario.asset} is worth ${money(av)}. It ${scenario.event} ${freq.text}, and each time it loses ${ef}% of its value.`;
  if (kind === 'sle') {
    q.prompt = `${setup} What is the single loss expectancy (SLE)?`;
    q.answer = sle;
  } else if (kind === 'aro') {
    q.prompt = `${setup} What is the annualized rate of occurrence (ARO)?`;
    q.answer = freq.num / freq.den;
  } else if (kind === 'ale') {
    q.prompt = `${setup} What is the annualized loss expectancy (ALE)?`;
    q.answer = ale;
  } else {
    const lower = FREQUENCIES.slice(0, FREQUENCIES.indexOf(freq));
    q.after = pick(rand, lower);
    q.aleAfter = aleOf(sle, q.after);
    const saving = ale - q.aleAfter;
    let cost = Math.round((saving * pick(rand, COST_SHARES)) / 100) * 100;
    if (cost <= 0) cost = 100;
    if (cost === saving) cost += 100; // a zero answer would make "worth it?" meaningless
    q.cost = cost;
    q.answer = saving - cost;
    q.prompt = `${setup} A safeguard costing ${money(cost)} a year would cut that to ${q.after.text}. `
      + 'What is the safeguard\'s value per year? (Type a negative number if it costs more than it saves.)';
  }
  return q;
}

/**
 * Reads a typed number. Accepts $, commas, spaces, k/m (thousand/million),
 * "/yr", "per year", a leading minus, a fraction like 1/20, and a percent.
 * Returns a number, or null if it isn't one.
 */
export function parseAmount(input) {
  let s = String(input ?? '').trim().toLowerCase();
  if (!s || s.length > MAX_ANSWER) return null;
  s = s.replace(/\s*(?:\/\s*(?:yr|year)|(?:per|a|each)\s+year|annually|usd|dollars?)\s*$/, '');
  s = s.replace(/[\s,]/g, '');
  let sign = 1;
  if (/^[-−–]/.test(s)) { sign = -1; s = s.slice(1); }
  s = s.replace(/^\$/, '');
  if (sign === 1 && /^[-−–]/.test(s)) { sign = -1; s = s.slice(1); }
  const frac = /^(\d+(?:\.\d+)?)\/(\d+(?:\.\d+)?)$/.exec(s);
  if (frac) {
    const d = Number(frac[2]);
    return d === 0 ? null : sign * (Number(frac[1]) / d);
  }
  const m = /^(\d+(?:\.\d*)?|\.\d+)(k|m|%)?$/.exec(s);
  if (!m) return null;
  const scale = { k: 1e3, m: 1e6, '%': 0.01 }[m[2]] ?? 1;
  return sign * Number(m[1]) * scale;
}

const same = (a, b) => Math.abs(a - b) <= Math.max(0.005, Math.abs(b) * 1e-9);

// Common slips, checked in order, each with its own hint. A hint is only used
// when the slip's number differs from the right answer.
function slips(q) {
  const efWhole = (n) => n * 100; // EF typed as 40 instead of 0.40 multiplies everything by 100
  const s = [];
  if (q.kind === 'sle') {
    s.push([efWhole(q.sle), 'That uses the exposure factor as a whole number. 40% is 0.40, not 40.']);
    s.push([q.ale, 'That\'s the ALE. The SLE is the cost of one incident, before multiplying by how often it happens.']);
    s.push([q.av, 'That\'s the whole asset value. One incident only loses the exposure factor\'s share of it.']);
  } else if (q.kind === 'aro') {
    if (q.freq.every) s.push([q.freq.every, `"Once every ${q.freq.every} years" means ARO = 1 ÷ ${q.freq.every}, not ${q.freq.every}.`]);
    if (q.freq.num === 12) s.push([1 / 12, 'Once a month is 12 times a year, so the ARO is 12.']);
  } else if (q.kind === 'ale') {
    s.push([q.sle, 'That\'s the SLE. Multiply it by the ARO to get the yearly figure.']);
    s.push([efWhole(q.ale), 'That uses the exposure factor as a whole number. 40% is 0.40, not 40.']);
    if (q.freq.every) s.push([q.sle * q.freq.every, `That used ${q.freq.every} as the ARO. Once every ${q.freq.every} years means ARO = 1 ÷ ${q.freq.every}.`]);
    s.push([(q.av * q.freq.num) / q.freq.den, 'That skips the exposure factor. Only part of the asset is lost each time.']);
  } else {
    s.push([q.ale - q.aleAfter, 'That\'s the yearly saving. Subtract what the safeguard costs each year.']);
    s.push([q.cost - (q.ale - q.aleAfter), 'The sign is flipped: it\'s the saving minus the cost.']);
    s.push([q.ale - q.cost, 'That subtracts the cost from the old ALE. Subtract the new ALE as well.']);
    s.push([q.aleAfter, 'That\'s the ALE after the safeguard. The value is ALE before − ALE after − cost.']);
  }
  return s.filter(([n]) => !same(n, q.answer));
}

/** The exact answer as it's shown to the student. */
export function answerText(q) {
  if (q.kind === 'aro') return aroText(q.freq);
  return q.kind === 'sle' ? money(q.answer) : `${money(q.answer)} per year`;
}

/**
 * Grades an answer. Returns { status: 'correct' | 'wrong' | 'invalid', message, hint? }.
 * 'invalid' (empty, too long, not a number) never counts against the student.
 */
export function checkAnswer(q, input) {
  const raw = String(input ?? '').trim();
  if (!raw) return { status: 'invalid', message: 'Type an answer first.' };
  if (raw.length > MAX_ANSWER) return { status: 'invalid', message: `That answer is too long (${MAX_ANSWER} characters max).` };
  const n = parseAmount(raw);
  if (n === null || !Number.isFinite(n)) {
    return { status: 'invalid', message: q.kind === 'aro' ? 'Type a number, like 0.25 or 1/4.' : 'Type a dollar amount, like $5,000.' };
  }
  if (same(n, q.answer)) return { status: 'correct', message: `Correct: ${answerText(q)}.` };
  const slip = slips(q).find(([v]) => same(n, v));
  return { status: 'wrong', message: `Not quite. The answer is ${answerText(q)}.`, ...(slip ? { hint: slip[1] } : {}) };
}

/** The worked answer, one line per step, in the hub's own words. */
export function working(q) {
  const ef = (q.ef / 100).toFixed(2);
  const aroLine = (f) => (f.every
    ? `ARO = 1 ÷ ${f.every} = ${aroText(f)} (${f.text.replace('about ', '')})`
    : `ARO = ${aroText(f)} (${f.text.replace('about ', '')})`);
  const sleLine = `SLE = AV × EF = ${money(q.av)} × ${ef} = ${money(q.sle)}`;
  const aleLine = (f, ale) => `ALE = SLE × ARO = ${money(q.sle)} × ${aroText(f)} = ${money(ale)} per year`;
  if (q.kind === 'sle') return [sleLine, 'How often it happens doesn\'t matter for the SLE; that comes in at the ALE.'];
  if (q.kind === 'aro') return [aroLine(q.freq), 'ARO is how many times a year it\'s expected; "once every N years" is 1 ÷ N.'];
  if (q.kind === 'ale') return [sleLine, aroLine(q.freq), aleLine(q.freq, q.ale)];
  const verdict = q.answer > 0
    ? `Worth it: it saves ${money(q.answer)} a year more than it costs.`
    : `Not worth it on cost alone: it costs ${money(-q.answer)} a year more than it saves.`;
  return [
    sleLine,
    `Before: ${aleLine(q.freq, q.ale)}`,
    `After: ${aleLine(q.after, q.aleAfter)}`,
    `Value = ALE before − ALE after − cost = ${money(q.ale)} − ${money(q.aleAfter)} − ${money(q.cost)} = ${money(q.answer)} per year`,
    verdict,
  ];
}

// ---------- Page wiring ----------

/** Wires #risk-practice. el/$ come from the caller so this file needs no DOM of its own. */
export function startRiskDrill({ el, $ }) {
  if (!$('rdrill-form')) return;
  const score = { right: 0, answered: 0 };
  let q = null;
  let done = false;

  const showScore = () => {
    $('rdrill-score').textContent = score.answered ? `${score.right} / ${score.answered} this session` : '';
  };
  const steps = () => el('ol', { class: 'hint mono' }, ...working(q).map((line) => el('li', {}, line)));
  const next = () => {
    const k = $('rdrill-kind').value;
    q = makeQuestion(cryptoRand, { kinds: KINDS.includes(k) ? [k] : KINDS });
    done = false;
    $('rdrill-question').textContent = q.prompt;
    $('rdrill-answer').value = '';
    $('rdrill-result').replaceChildren();
  };

  $('rdrill-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    if (!q) return;
    const r = checkAnswer(q, $('rdrill-answer').value);
    if (r.status === 'invalid') { $('rdrill-result').replaceChildren(el('p', { class: 'notice warn' }, r.message)); return; }
    // Only the first real attempt at a question counts towards the score.
    if (!done) { score.answered++; if (r.status === 'correct') score.right++; done = true; }
    $('rdrill-result').replaceChildren(...[
      el('p', { class: `verdict ${r.status === 'correct' ? 'ok' : 'bad'}` }, r.status === 'correct' ? '✔ ' : '✘ ', r.message),
      r.hint ? el('p', { class: 'hint' }, r.hint) : null,
      steps(),
    ].filter(Boolean));
    showScore();
  });
  $('rdrill-reveal').addEventListener('click', () => {
    if (!q) return;
    done = true; // revealed answers don't score
    $('rdrill-result').replaceChildren(el('p', { class: 'verdict muted' }, `The answer is ${answerText(q)}.`), steps());
  });
  $('rdrill-next').addEventListener('click', () => { next(); $('rdrill-answer').focus(); });
  $('rdrill-kind').addEventListener('change', () => next());
  next();
}
