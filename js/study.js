// Study page: practice questions by exam (data/study.json), plus the ports and
// acronyms quizzes, which use the same lists as the Reference page's lookups.
// Everything is graded in code and shown as text; nothing is saved or sent.

import { startPortsDrill } from './ports-drill.js';
import { startAcronymsDrill } from './acronyms-drill.js';

export const OPTIONS = 4;
const LETTERS = ['A', 'B', 'C', 'D'];

/** True for a question the page can show: text, 4 options, an answer index and a reason. */
export function validQuestion(q) {
  return Boolean(q) && typeof q.q === 'string' && q.q.trim() !== ''
    && Array.isArray(q.options) && q.options.length === OPTIONS && q.options.every((o) => typeof o === 'string' && o.trim() !== '')
    && new Set(q.options).size === OPTIONS
    && Number.isInteger(q.answer) && q.answer >= 0 && q.answer < OPTIONS
    && typeof q.why === 'string' && q.why.trim() !== '';
}

/** Grades one pick: { correct, text }, or null if the pick isn't one of the options. */
export function checkPick(q, index) {
  if (!validQuestion(q) || !Number.isInteger(index) || index < 0 || index >= OPTIONS) return null;
  const correct = index === q.answer;
  return { correct, text: `${correct ? 'Correct.' : `Not quite. The answer is ${LETTERS[q.answer]}.`} ${q.why}` };
}

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('study-exams')) {
  const $ = (id) => document.getElementById(id);
  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else node.setAttribute(k, v);
    }
    for (const c of children) if (c != null) node.append(c);
    return node;
  };

  // One card: the question, four options to click, then the answer and why.
  const card = (q, onFirstPick) => {
    const result = el('p', { class: 'qa-result', 'aria-live': 'polite' });
    const buttons = q.options.map((text, i) => {
      const b = el('button', { type: 'button', class: 'secondary' }, `${LETTERS[i]}. ${text}`);
      b.addEventListener('click', () => {
        const r = checkPick(q, i);
        for (const other of buttons) other.disabled = true;
        buttons[q.answer].textContent = `✔ ${LETTERS[q.answer]}. ${q.options[q.answer]}`;
        result.textContent = r.text;
        result.className = `qa-result verdict ${r.correct ? 'ok' : 'warn'}`;
        onFirstPick(r.correct);
      });
      return b;
    });
    return el('li', { class: 'qa-card' }, el('p', { class: 'qa-q' }, q.q), el('div', { class: 'qa-options' }, ...buttons), result);
  };

  // One accordion panel per exam.
  const panel = (exam) => {
    const questions = exam.questions.filter(validQuestion);
    let right = 0;
    let answered = 0;
    const score = el('p', { class: 'hint', 'aria-live': 'polite' });
    const count = `${questions.length} question${questions.length === 1 ? '' : 's'}`;
    return el('details', { class: 'exam', id: `exam-${exam.id}` },
      el('summary', {}, el('span', { class: 'exam-name' }, exam.name), el('span', { class: 'exam-count' }, count)),
      el('div', { class: 'exam-body' },
        el('p', { class: 'hint' }, exam.about),
        el('ol', { class: 'qa-list' }, ...questions.map((q) => card(q, (correct) => {
          answered += 1;
          if (correct) right += 1;
          score.textContent = `${right} of ${answered} correct so far. Your score is not saved anywhere.`;
        }))),
        score));
  };

  const openFromHash = () => {
    const target = /^#exam-[a-z-]+$/.test(location.hash) ? $(location.hash.slice(1)) : null;
    if (!target) return;
    target.setAttribute('open', '');
    target.scrollIntoView();
  };

  const load = async (file) => {
    const res = await fetch(file);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  };

  load('data/study.json').then((data) => {
    $('study-note').textContent = data.note || '';
    $('study-exams').replaceChildren(...(data.exams || []).map(panel));
    openFromHash();
    window.addEventListener('hashchange', openFromHash);
  }).catch((err) => {
    $('study-exams').replaceChildren(el('p', { class: 'notice warn' }, `Could not load the questions: ${err.message}`));
  });

  // The quizzes: "Show in the list" opens the matching lookup on the Reference page.
  load('data/ports.json').then((data) => {
    startPortsDrill(data.ports || [], { el, $, showInList: (port) => { location.href = `./reference.html#ports=${port}`; } });
  }).catch((err) => {
    $('pdrill-result').replaceChildren(el('p', { class: 'notice warn' }, `Could not load the port list: ${err.message}`));
  });
  load('data/acronyms.json').then((data) => {
    startAcronymsDrill(data.acronyms || [], { el, $, showInList: (acronym) => { location.href = `./reference.html#acronyms=${encodeURIComponent(acronym)}`; } });
  }).catch((err) => {
    $('adrill-result').replaceChildren(el('p', { class: 'notice warn' }, `Could not load the acronym list: ${err.message}`));
  });
}
