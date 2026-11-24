// Study page: the exam list and per-exam banks' shape, grading, paging, and the page in the DOM stand-in.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validQuestion, validTask, checkPick, shuffled, OPTIONS, PAGE } from '../js/study.js';
import { installDom, settle } from './helpers/dom.mjs';

const root = new URL('../', import.meta.url);
const read = (f) => readFileSync(new URL(f, root), 'utf8');
const DATA = JSON.parse(read('data/study.json'));
const bank = (exam) => JSON.parse(read(exam.file)).questions;
const FIRST = bank(DATA.exams[0]);

test('the exams are there, each with its own file of valid questions or tasks', () => {
  assert.deepEqual(DATA.exams.map((e) => e.name), ['Security+', 'Network+', 'CySA+', 'PenTest+', 'Linux', 'RHCSA']);
  const ids = new Set();
  for (const exam of DATA.exams) {
    assert.match(exam.id, /^[a-z-]+$/);
    assert.ok(!ids.has(exam.id), exam.id);
    ids.add(exam.id);
    assert.equal(exam.file, `data/study/${exam.id}.json`);
    assert.ok(exam.about.length > 20, exam.id);
    assert.ok(!('questions' in exam), `${exam.id}: questions live in the exam's own file`);
    const items = bank(exam);
    assert.equal(exam.count, items.length, `${exam.id}: count in study.json matches its file`);
    assert.ok(items.length >= (exam.format === "tasks" ? 150 : 140), `${exam.id}: ${items.length}`);
    if (exam.format === 'tasks') {
      for (const t of items) assert.ok(validTask(t), `${exam.id}: ${t.task}`);
      continue;
    }
    const asked = new Set();
    for (const q of items) {
      assert.ok(validQuestion(q), `${exam.id}: ${q.q}`);
      assert.ok(!asked.has(q.q), `${exam.id}: repeated question`);
      asked.add(q.q);
      assert.ok(q.why.length >= 40 && q.why.length <= 320, `${exam.id}: why length`);
    }
    // The right answer isn't always in the same place.
    assert.ok(new Set(items.map((q) => q.answer)).size > 1, `${exam.id}: answer positions`);
  }
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
  const q = FIRST[0];
  const right = checkPick(q, q.answer);
  assert.equal(right.correct, true);
  assert.ok(right.text.startsWith('Correct. ') && right.text.endsWith(q.why));
  const wrong = checkPick(q, (q.answer + 1) % OPTIONS);
  assert.equal(wrong.correct, false);
  assert.ok(wrong.text.startsWith(`Not quite. The answer is ${'ABCD'[q.answer]}. `));
  for (const bad of [-1, OPTIONS, 1.5, '0', null, undefined]) assert.equal(checkPick(q, bad), null, String(bad));
  assert.equal(checkPick({ q: 'broken' }, 0), null);
});

test('shuffled keeps every item once and leaves the input alone', () => {
  const list = [0, 1, 2, 3, 4, 5, 6, 7];
  const out = shuffled(list, () => 0.999);
  assert.deepEqual(list, [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(out.slice().sort((a, b) => a - b), list);
  assert.notDeepEqual(shuffled(list, () => 0), list);
  assert.equal(PAGE, 10);
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
  await settle();
  return { requests, $: (id) => dom.document.getElementById(id), doc: dom.document };
}
afterEach(() => {
  dom?.restore();
  dom = null;
  delete globalThis.fetch;
});

const shown = (n) => Math.min(PAGE, n);

// Opens an exam panel the way a click on its summary does, then waits for its file.
async function openExam(doc, id) {
  const panel = doc.getElementById(`exam-${id}`);
  panel.setAttribute('open', '');
  panel.dispatchEvent(new Event('toggle'));
  await settle();
  await settle();
  return panel;
}

test('page: one closed panel per exam with its count; no question file loads until a panel opens', async () => {
  const { requests, $, doc } = await loadPage();
  assert.deepEqual(requests.sort(), ['data/acronyms.json', 'data/ports.json', 'data/study.json']);
  const panels = doc.querySelectorAll('details.exam');
  assert.deepEqual(panels.map((p) => p.id), [...DATA.exams.map((e) => `exam-${e.id}`), 'ports-practice', 'acronyms-practice', 'cvss-practice']);
  assert.ok(panels.every((p) => !p.hasAttribute('open')), 'closed until picked');
  assert.equal(panels[0].querySelector('summary').textContent, `Security+${FIRST.length} questions`);
  assert.equal(panels[0].querySelectorAll('li.qa-card').length, 0, 'nothing rendered before opening');
  assert.equal($('study-note').textContent, DATA.note);
});

test('page: opening a panel fetches only that exam, once, and shows ten questions', async () => {
  const { requests, doc } = await loadPage();
  const panel = await openExam(doc, 'security-plus');
  assert.equal(requests.filter((r) => r.startsWith('data/study/')).join(), DATA.exams[0].file);
  assert.equal(panel.querySelectorAll('li.qa-card').length, shown(FIRST.length));
  assert.equal(panel.querySelector('.qa-range').textContent, `Questions 1–${shown(FIRST.length)} of ${FIRST.length}`);
  panel.removeAttribute('open');
  panel.dispatchEvent(new Event('toggle'));
  await openExam(doc, 'security-plus');
  assert.equal(requests.filter((r) => r.startsWith('data/study/')).length, 1, 'not fetched again on reopen');
});

test('page: clicking an answer grades it, marks the right one, locks the card and counts once', async () => {
  const { doc } = await loadPage();
  const panel = await openExam(doc, 'security-plus');
  const [first, second] = panel.querySelectorAll('li.qa-card');
  const q1 = FIRST[0];
  const wrongIndex = (q1.answer + 1) % OPTIONS;
  const buttons = first.querySelectorAll('.qa-options button');
  assert.equal(buttons[0].textContent, `A. ${q1.options[0]}`);
  buttons[wrongIndex].click();
  assert.ok(first.querySelector('.qa-result').textContent.startsWith('Not quite. The answer is '));
  assert.ok(buttons.every((b) => b.disabled));
  assert.ok(buttons[q1.answer].textContent.startsWith('✔ '));
  for (const b of buttons) b.click(); // locked: no second count
  const score = () => panel.querySelector('.qa-score').textContent;
  assert.equal(score(), `0 of 1 correct so far (of ${FIRST.length}). Your score is not saved anywhere.`);
  const q2 = FIRST[1];
  second.querySelectorAll('.qa-options button')[q2.answer].click();
  assert.ok(second.querySelector('.qa-result').textContent.startsWith('Correct. '));
  assert.match(score(), /^1 of 2 correct so far/);
});

test('page: Next and Previous page through the bank; an answered card stays locked when it comes back', async () => {
  const { doc } = await loadPage();
  const panel = await openExam(doc, 'security-plus');
  const pager = panel.querySelector('.qa-pager');
  const [prev, next, shuffle] = pager.querySelectorAll('button');
  assert.equal(prev.textContent, `← Previous ${PAGE}`);
  assert.equal(next.textContent, `Next ${PAGE} →`);
  assert.equal(shuffle.textContent, 'Shuffle');
  assert.equal(prev.disabled, true, 'nothing before page 1');
  const pages = Math.ceil(FIRST.length / PAGE);
  assert.equal(next.disabled, pages === 1);
  const q1 = FIRST[0];
  panel.querySelector('li.qa-card .qa-options button').click();
  if (pages > 1) {
    next.click();
    const cards = panel.querySelectorAll('li.qa-card');
    assert.equal(cards[0].querySelector('.qa-q').textContent, FIRST[PAGE].q);
    assert.equal(panel.querySelector('.qa-range').textContent, `Questions ${PAGE + 1}–${Math.min(2 * PAGE, FIRST.length)} of ${FIRST.length}`);
    assert.equal(panel.querySelector('ol.qa-list').getAttribute('start'), String(PAGE + 1));
    assert.equal(prev.disabled, false);
    prev.click();
  }
  const back = panel.querySelector('li.qa-card');
  assert.equal(back.querySelector('.qa-q').textContent, q1.q);
  assert.ok(back.querySelectorAll('.qa-options button').every((b) => b.disabled), 'still locked');
  assert.ok(back.querySelector('.qa-result').textContent.length > 10, 'still graded');
  assert.match(panel.querySelector('.qa-score').textContent, /^\d of 1 correct so far/);
});

test('page: Shuffle reorders and goes back to the first page, keeping the same questions', async () => {
  const { doc } = await loadPage();
  const panel = await openExam(doc, 'security-plus');
  const [, , shuffle] = panel.querySelector('.qa-pager').querySelectorAll('button');
  const texts = () => panel.querySelectorAll('li.qa-card .qa-q').map((p) => p.textContent);
  const all = new Set(FIRST.map((q) => q.q));
  shuffle.click();
  assert.equal(panel.querySelectorAll('li.qa-card').length, shown(FIRST.length));
  assert.ok(texts().every((t) => all.has(t)));
  assert.equal(panel.querySelector('ol.qa-list').getAttribute('start'), '1');
});

test('page: #exam-<id> opens that exam, and the quizzes’ old addresses open their panels', async () => {
  const { $, requests } = await loadPage('https://jamalrizki.github.io/Security-lookup-hub/study.html#exam-pentest-plus');
  await settle();
  assert.ok($('exam-pentest-plus').hasAttribute('open'));
  assert.ok(requests.includes('data/study/pentest-plus.json'), 'the linked exam loads its questions');
  assert.ok($('exam-pentest-plus').querySelectorAll('li.qa-card').length > 0);
  assert.ok(!$('exam-security-plus').hasAttribute('open'));
  dom.restore();
  const page = await loadPage('https://jamalrizki.github.io/Security-lookup-hub/study.html#ports-practice');
  assert.ok(page.$('ports-practice').hasAttribute('open'));
  assert.ok(!page.$('acronyms-practice').hasAttribute('open'));
});

test('page: both quizzes run in their panels, and "Show in the list" goes to the Reference lookup', async () => {
  const { $, doc } = await loadPage();
  assert.equal($('ports-practice').tagName, 'DETAILS');
  assert.equal($('acronyms-practice').tagName, 'DETAILS');
  assert.ok($('pdrill-question').textContent.length > 5, 'ports quiz asked a question');
  assert.equal($('adrill-options').querySelectorAll('button').length, 4, 'acronyms quiz shows options');
  $('pdrill-show').click();
  $('adrill-show').click();
  const [ports, acronyms] = doc.navigations.map((n) => n.href);
  assert.match(ports, /^\.\/reference\.html#ports=\d{1,5}$/);
  assert.match(acronyms, /^\.\/reference\.html#acronyms=[A-Za-z0-9%&/.+-]{1,60}$/);
});

test('page: an exam whose file fails says so in its panel; the others keep working and it retries on reopen', async () => {
  dom = installDom(read('study.html'), { url: 'https://jamalrizki.github.io/Security-lookup-hub/study.html' });
  let fail = true;
  globalThis.fetch = async (input) => (String(input) === DATA.exams[1].file && fail ? new Response('nope', { status: 500 }) : new Response(read(String(input))));
  await import(`../js/study.js?page=${++loads}`);
  await settle();
  const doc = dom.document;
  const net = await openExam(doc, 'network-plus');
  assert.match(net.querySelector('.notice.warn').textContent, /^Could not load the Network\+ questions: HTTP 500$/);
  const sec = await openExam(doc, 'security-plus');
  assert.equal(sec.querySelectorAll('li.qa-card').length, shown(FIRST.length));
  fail = false;
  net.removeAttribute('open');
  net.dispatchEvent(new Event('toggle'));
  await openExam(doc, 'network-plus');
  assert.ok(net.querySelectorAll('li.qa-card').length > 0, 'loaded on the second try');
});

test('study.html: in the nav, same-origin only, no storage; Reference forwards the quizzes’ old addresses', () => {
  const html = read('study.html');
  assert.match(html, /<a href="study\.html" aria-current="page">Study<\/a>/);
  const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  assert.match(csp, /connect-src 'self' https:\/\/www\.googletagmanager\.com/, 'no Worker or other API');
  const js = read('js/study.js');
  assert.ok(!/innerHTML|localStorage|sessionStorage/.test(js));
  assert.match(read('js/reference.js'), /location\.hash === '#ports-practice' \|\| location\.hash === '#acronyms-practice'\) location\.replace\(`\.\/study\.html\$\{location\.hash\}`\)/);
  for (const id of ['exams', 'quizzes', 'ports-practice', 'acronyms-practice', 'cvss-practice']) assert.ok(html.includes(`id="${id}"`), id);
});

test('validTask rejects wrong shapes', () => {
  const ok = { task: 'Do it.', steps: ['cmd'], check: 'See it.' };
  assert.ok(validTask(ok));
  for (const bad of [null, {}, { ...ok, task: '' }, { ...ok, steps: [] }, { ...ok, steps: [''] }, { ...ok, steps: 'cmd' }, { ...ok, check: '' }]) assert.equal(validTask(bad), false, JSON.stringify(bad));
});

test('page: the RHCSA panel shows tasks with hidden answers, revealed on request', async () => {
  const { doc } = await loadPage();
  const rhcsa = DATA.exams.find((e) => e.id === 'rhcsa');
  const tasks = bank(rhcsa);
  const panel = await openExam(doc, 'rhcsa');
  assert.equal(panel.querySelector('summary').textContent, `RHCSA${tasks.length} tasks`);
  assert.equal(panel.querySelector('.qa-range').textContent, `Tasks 1–${shown(tasks.length)} of ${tasks.length}`);
  assert.equal(panel.querySelector('.qa-score'), null, 'tasks are not graded');
  const card = panel.querySelector('li.qa-card');
  assert.equal(card.querySelector('.qa-q').textContent, tasks[0].task);
  const answer = card.querySelector('.qa-answer');
  assert.equal(answer.hidden, true, 'answer hidden until asked for');
  const show = card.querySelector('button');
  show.click();
  assert.equal(answer.hidden, false);
  assert.ok(answer.textContent.includes(tasks[0].steps[0]));
  assert.ok(answer.textContent.includes(`Check: ${tasks[0].check}`));
  assert.equal(show.textContent, 'Hide answer');
});
