// CVSS practice (Study page, #cvss-practice): v3.1 scores computed in code and
// pinned to NVD's published scores; every question in the bank is valid and
// its answer is re-checked here from the scoring code; the panel builds it on open.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { baseScore, parseVector, severity, roundup, vectorString, buildQuestions, METRICS, META, SCENARIOS, SEVERITIES } from '../js/cvss-drill.js';
import { validQuestion, checkPick, PAGE } from '../js/study.js';
import { installDom, settle } from './helpers/dom.mjs';

const read = (f) => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');

// Base scores as published by NVD for these vectors.
const KNOWN = [
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'Critical'], // CVE-2021-44228 (Log4Shell)
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'Critical'],
  ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8, 'High'],
  ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8, 'High'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5, 'High'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, 'Medium'], // typical reflected XSS
  ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9, 'Medium'],
  ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N', 6.4, 'Medium'],
  ['CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.8, 'Low'],
  ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N', 0, 'None'],
];

test('base scores match NVD for known vectors', () => {
  for (const [v, score, sev] of KNOWN) {
    const r = baseScore(v);
    assert.equal(r.score, score, v);
    assert.equal(r.severity, sev, v);
  }
  assert.equal(baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').impact, 5.87);
  assert.equal(baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').exploitability, 3.89);
});

test('roundup follows the v3.1 spec, including its float guard', () => {
  assert.equal(roundup(4.0), 4.0);
  assert.equal(roundup(4.02), 4.1);
  assert.equal(roundup(4.000000000001), 4.0); // float noise is not rounded up
  assert.equal(roundup(9.81), 9.9);
});

test('parseVector accepts full v3.0/v3.1 base vectors and rejects everything else', () => {
  assert.deepEqual(parseVector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
  assert.ok(parseVector('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
  for (const bad of ['', null, 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 'AV:N/AC:L/Au:N/C:P/I:P/A:P',
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H', 'CVSS:3.1/AV:N/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P', 'CVSS:3.1/AV:N:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']) {
    assert.equal(parseVector(bad), null, String(bad));
    if (bad !== null) assert.equal(baseScore(bad), null, String(bad));
  }
});

// Every legal base vector (2,592 of them).
function* allVectors() {
  const keys = METRICS.map((k) => Object.keys(META[k].values));
  const walk = function* (i, acc) {
    if (i === METRICS.length) { yield { ...acc }; return; }
    for (const v of keys[i]) yield* walk(i + 1, { ...acc, [METRICS[i]]: v });
  };
  yield* walk(0, {});
}

test('across every legal vector: score 0–10 with one decimal, severity from the bands, S:C never lowers it', () => {
  let n = 0;
  for (const m of allVectors()) {
    n += 1;
    const r = baseScore(m);
    assert.ok(r.score >= 0 && r.score <= 10 && Math.round(r.score * 10) === r.score * 10, vectorString(m));
    assert.equal(r.severity, severity(r.score));
    assert.equal(r.score === 0, m.C === 'N' && m.I === 'N' && m.A === 'N', vectorString(m));
    if (m.S === 'U') assert.ok(baseScore({ ...m, S: 'C' }).score >= r.score, vectorString(m));
  }
  assert.equal(n, 2592);
});

test('severity bands', () => {
  assert.deepEqual([0, 0.1, 3.9, 4, 6.9, 7, 8.9, 9, 10].map(severity), ['None', 'Low', 'Low', 'Medium', 'Medium', 'High', 'High', 'Critical', 'Critical']);
});

const BANK = buildQuestions();

test('the bank: every question valid, unique, same on every build, answers spread across A–D', () => {
  assert.ok(BANK.length >= 90, String(BANK.length));
  assert.deepEqual(buildQuestions(), BANK, 'fixed seed, fixed bank');
  const asked = new Set();
  for (const q of BANK) {
    assert.ok(validQuestion(q), q.q);
    const key = `${q.q}|${q.options.join('|')}`; // the "Four findings" stem repeats with different vectors
    assert.ok(!asked.has(key), `repeated: ${q.q}`);
    asked.add(key);
    assert.ok(q.why.length >= 30 && q.why.length <= 320, q.why);
    assert.ok(checkPick(q, q.answer).correct);
  }
  const at = [0, 1, 2, 3].map((i) => BANK.filter((q) => q.answer === i).length);
  assert.ok(at.every((c) => c >= BANK.length / 8), `answer positions ${at}`);
  assert.ok(!/\b(definitely|guaranteed)\b/i.test(JSON.stringify(BANK)));
});

test('the bank: computed answers are re-checked from the scoring code', () => {
  const sev = BANK.filter((q) => q.q.startsWith('A scanner reports '));
  assert.ok(sev.length >= 20);
  for (const s of ['Low', 'Medium', 'High', 'Critical']) assert.ok(sev.some((q) => q.options[q.answer] === s), s);
  for (const q of sev) {
    const v = /reports (CVSS:3\.1\/\S+)\. /.exec(q.q)[1];
    const r = baseScore(v);
    assert.equal(q.options[q.answer], r.severity, v);
    assert.ok(q.why.startsWith(`Base score ${r.score.toFixed(1)} `), q.why);
    assert.deepEqual(q.options, SEVERITIES.slice(1), 'shown in order');
  }
  const top = BANK.filter((q) => q.q.startsWith('Four findings'));
  assert.ok(top.length >= 10);
  for (const q of top) {
    const scores = q.options.map((o) => baseScore(o).score);
    const best = Math.max(...scores);
    assert.equal(scores[q.answer], best);
    assert.equal(scores.filter((s) => s > best - 0.5).length, 1, 'a clear winner');
  }
  const bands = BANK.filter((q) => /base score of [\d.]+\. Which severity/.test(q.q));
  for (const q of bands) assert.equal(q.options[q.answer], severity(Number(/of ([\d.]+)\./.exec(q.q)[1])));
});

test('the bank: each metric value has a meaning question, each scenario asks for its own metric', () => {
  for (const k of METRICS) for (const v of Object.keys(META[k].values)) {
    const q = BANK.find((x) => x.q === `In a CVSS 3.1 vector, what does ${k}:${v} mean?`);
    assert.ok(q, `${k}:${v}`);
    assert.ok(q.options[q.answer].toLowerCase().startsWith(META[k].values[v][1].slice(0, 20).toLowerCase()));
  }
  for (const [k, v, text] of SCENARIOS) {
    const q = BANK.find((x) => x.q.startsWith(text));
    assert.ok(q, text);
    assert.equal(q.options[q.answer], `${k}:${v}`);
    assert.ok(q.options.every((o) => o.startsWith(`${k}:`)), 'only that metric is offered, so no other option can also be true');
  }
});

// ---------- The panel ----------

let dom;
let loads = 0;
afterEach(() => {
  dom?.restore();
  dom = null;
  delete globalThis.fetch;
});

test('page: the CVSS panel builds its questions on open, ten at a time, graded, with no fetch for them', async () => {
  dom = installDom(read('study.html'), { url: 'https://jamalrizki.github.io/Security-lookup-hub/study.html#cvss-practice' });
  const requests = [];
  globalThis.fetch = async (input) => { requests.push(String(input)); return new Response(read(String(input))); };
  await import(`../js/study.js?cvss=${++loads}`);
  await settle();
  await settle();
  const panel = dom.document.getElementById('cvss-practice');
  assert.ok(panel.hasAttribute('open'), '#cvss-practice opens it');
  assert.deepEqual(requests.sort(), ['data/acronyms.json', 'data/ports.json', 'data/study.json']);
  const cards = panel.querySelectorAll('li.qa-card');
  assert.equal(cards.length, PAGE);
  assert.equal(panel.querySelector('.qa-range').textContent, `Questions 1–${PAGE} of ${BANK.length}`);
  const q = BANK[0];
  cards[0].querySelectorAll('.qa-options button')[q.answer].click();
  assert.ok(cards[0].querySelector('.qa-result').textContent.startsWith('Correct. '));
  assert.equal(panel.querySelector('.qa-score').textContent, `1 of 1 correct so far (of ${BANK.length}). Your score is not saved anywhere.`);
  panel.removeAttribute('open');
  panel.dispatchEvent(new Event('toggle'));
  panel.setAttribute('open', '');
  panel.dispatchEvent(new Event('toggle'));
  assert.match(panel.querySelector('.qa-score').textContent, /^1 of 1/, 'reopening keeps the session’s picks');
});

test('cvss-drill.js: no DOM, storage or network', () => {
  const js = read('js/cvss-drill.js');
  assert.ok(!/innerHTML|localStorage|sessionStorage|fetch\(|document\./.test(js));
});
