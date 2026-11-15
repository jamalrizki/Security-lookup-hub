// Study page: data/study.json's shape, grading, and the page in the DOM stand-in.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validQuestion, checkPick, OPTIONS } from '../js/study.js';
import { installDom, settle } from './helpers/dom.mjs';

const root = new URL('../', import.meta.url);
const read = (f) => readFileSync(new URL(f, root), 'utf8');
const DATA = JSON.parse(read('data/study.json'));

test('the four exams are there, each with valid questions', () => {
  assert.deepEqual(DATA.exams.map((e) => e.name), ['Security+', 'Network+', 'CySA+', 'PenTest+']);
  const ids = new Set();
  for (const exam of DATA.exams) {
    assert.match(exam.id, /^[a-z-]+$/);
    assert.ok(!ids.has(exam.id), exam.id);
    ids.add(exam.id);
    assert.ok(exam.about.length > 20, exam.id);
    assert.ok(exam.questions.length >= 3, exam.id);
    const asked = new Set();
    for (const q of exam.questions) {
      assert.ok(validQuestion(q), `${exam.id}: ${q.q}`);
      assert.ok(!asked.has(q.q), `${exam.id}: repeated question`);
      asked.add(q.q);
      assert.ok(q.why.length >= 40 && q.why.length <= 320, `${exam.id}: why length`);
    }
    // The right answer isn't always in the same place.
    assert.ok(new Set(exam.questions.map((q) => q.answer)).size > 1, `${exam.id}: answer positions`);
  }
});

test('the file says where questions may come from, and the page says they are samples', () => {
  assert.match(DATA._about, /Never paste questions from a book/);
  assert.match(DATA.note, /written for this site, not taken from any book or real exam/);
});

test('validQuestion rejects wrong shapes', () => {
  const ok = { q: 'Q?', options: ['a', 'b', 'c', 'd'], answer: 1, why: 'Because.' };
  assert.ok(validQuestion(ok));
  for (const bad of [
    null, {}, { ...ok, q: ' ' }, { ...ok, options: ['a', 'b', 'c'] }, { ...ok, options: ['a', 'b', 'c', 'c'] },
    { ...ok, options: ['a', 'b', 'c', 4] }, { ...ok, answer: 4 }, { ...ok, answer: -1 }, { ...ok, answer: '1' }, { ...ok, answer: 1.5 }, { ...ok, why: '' },
  ]) assert.equal(validQuestion(bad), false, JSON.stringify(bad));
});

test('checkPick grades in code and always gives the reason', () => {
  const q = DATA.exams[0].questions[0];
  const right = checkPick(q, q.answer);
  assert.equal(right.correct, true);
  assert.ok(right.text.startsWith('Correct. ') && right.text.endsWith(q.why));
  const wrong = checkPick(q, (q.answer + 1) % OPTIONS);
  assert.equal(wrong.correct, false);
  assert.ok(wrong.text.startsWith(`Not quite. The answer is ${'ABCD'[q.answer]}. `));
  for (const bad of [-1, OPTIONS, 1.5, '0', null, undefined]) assert.equal(checkPick(q, bad), null, String(bad));
  assert.equal(checkPick({ q: 'broken' }, 0), null);
});

// ---------- The page ----------

let dom;
let loads = 0;
async function loadPage(url = 'https://jamalrizki.github.io/Security-lookup-hub/study.html') {
  dom = installDom(read('study.html'), { url });
  const requests = [];
  globalThis.fetch = async (input) => {
    requests.push(String(input));
    return new Response(read(String(input)));
  };
  await import(`../js/study.js?page=${++loads}`);
  await settle();
  return { requests, $: (id) => dom.document.getElementById(id), doc: dom.document };
}
afterEach(() => {
  dom?.restore();
  dom = null;
  delete globalThis.fetch;
});

test('page: one closed panel per exam with its questions; only the hub’s own data is fetched', async () => {
  const { requests, $, doc } = await loadPage();
  assert.deepEqual(requests.sort(), ['data/acronyms.json', 'data/ports.json', 'data/study.json']);
  const panels = doc.querySelectorAll('details.exam');
  assert.deepEqual(panels.map((p) => p.id), DATA.exams.map((e) => `exam-${e.id}`));
  assert.ok(panels.every((p) => !p.hasAttribute('open')), 'closed until picked');
  assert.equal(panels[0].querySelector('summary').textContent, 'Security+3 questions');
  assert.equal(panels[0].querySelectorAll('li.qa-card').length, DATA.exams[0].questions.length);
  assert.equal($('study-note').textContent, DATA.note);
});

test('page: clicking an answer grades it, marks the right one, locks the card and counts once', async () => {
  const { doc } = await loadPage();
  const panel = doc.querySelector('details.exam');
  const [first, second] = panel.querySelectorAll('li.qa-card');
  const q1 = DATA.exams[0].questions[0];
  const wrongIndex = (q1.answer + 1) % OPTIONS;
  const buttons = first.querySelectorAll('button');
  assert.equal(buttons[0].textContent, `A. ${q1.options[0]}`);
  buttons[wrongIndex].click();
  assert.ok(first.querySelector('.qa-result').textContent.startsWith('Not quite. The answer is '));
  assert.ok(buttons.every((b) => b.disabled));
  assert.ok(buttons[q1.answer].textContent.startsWith('✔ '));
  for (const b of buttons) b.click(); // locked: no second count
  const score = () => panel.querySelectorAll('p.hint').at(-1).textContent;
  assert.match(score(), /^0 of 1 correct so far\. Your score is not saved anywhere\.$/);
  const q2 = DATA.exams[0].questions[1];
  second.querySelectorAll('button')[q2.answer].click();
  assert.ok(second.querySelector('.qa-result').textContent.startsWith('Correct. '));
  assert.match(score(), /^1 of 2 correct so far/);
});

test('page: #exam-<id> opens that exam', async () => {
  const { $ } = await loadPage('https://jamalrizki.github.io/Security-lookup-hub/study.html#exam-pentest-plus');
  assert.ok($('exam-pentest-plus').hasAttribute('open'));
  assert.ok(!$('exam-security-plus').hasAttribute('open'));
});

test('page: both quizzes run here, and "Show in the list" goes to the Reference lookup', async () => {
  const { $, doc } = await loadPage();
  assert.ok($('pdrill-question').textContent.length > 5, 'ports quiz asked a question');
  assert.equal($('adrill-options').querySelectorAll('button').length, 4, 'acronyms quiz shows options');
  $('pdrill-show').click();
  $('adrill-show').click();
  const [ports, acronyms] = doc.navigations.map((n) => n.href);
  assert.match(ports, /^\.\/reference\.html#ports=\d{1,5}$/);
  assert.match(acronyms, /^\.\/reference\.html#acronyms=[A-Za-z0-9%&/.+-]{1,60}$/);
});

test('study.html: in the nav, same-origin only, no storage; Reference forwards the quizzes’ old addresses', () => {
  const html = read('study.html');
  assert.match(html, /<a href="study\.html" aria-current="page">Study<\/a>/);
  const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  assert.match(csp, /connect-src 'self' https:\/\/www\.googletagmanager\.com/, 'no Worker or other API');
  const js = read('js/study.js');
  assert.ok(!/innerHTML|localStorage|sessionStorage/.test(js));
  assert.match(read('js/reference.js'), /location\.hash === '#ports-practice' \|\| location\.hash === '#acronyms-practice'\) location\.replace\(`\.\/study\.html\$\{location\.hash\}`\)/);
  for (const id of ['exams', 'ports-practice', 'acronyms-practice']) assert.ok(html.includes(`id="${id}"`), id);
});
