// Study page: practice questions by exam (data/study.json), plus the ports and
// acronyms quizzes, which use the same lists as the Reference page's lookups.
// Everything is graded in code and shown as text; nothing is saved or sent.

import { startPortsDrill } from './ports-drill.js';
import { startAcronymsDrill } from './acronyms-drill.js';

export const OPTIONS = 4;
const LETTERS = ['A', 'B', 'C', 'D'];
/** Questions or tasks shown at a time. */
export const PAGE = 10;

/** True for a question the page can show: text, 4 options, an answer index and a reason. */
export function validQuestion(q) {
  return Boolean(q) && typeof q.q === 'string' && q.q.trim() !== ''
    && Array.isArray(q.options) && q.options.length === OPTIONS && q.options.every((o) => typeof o === 'string' && o.trim() !== '')
    && new Set(q.options).size === OPTIONS
    && Number.isInteger(q.answer) && q.answer >= 0 && q.answer < OPTIONS
    && typeof q.why === 'string' && q.why.trim() !== '';
}

/** True for a hands-on task the page can show: what to do, the steps, and how to check it. */
export function validTask(t) {
  return Boolean(t) && typeof t.task === 'string' && t.task.trim() !== ''
    && Array.isArray(t.steps) && t.steps.length > 0 && t.steps.every((x) => typeof x === 'string' && x.trim() !== '')
    && typeof t.check === 'string' && t.check.trim() !== '';
}

/** A shuffled copy (Fisher–Yates); `random` is swappable for tests. */
export function shuffled(list, random = Math.random) {
  const out = list.slice();
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
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
  // `picked` is an earlier pick of this question (from another page visit), shown locked.
  const card = (q, picked, onFirstPick) => {
    const result = el('p', { class: 'qa-result', 'aria-live': 'polite' });
    const lock = (i) => {
      const r = checkPick(q, i);
      for (const other of buttons) other.disabled = true;
      buttons[q.answer].textContent = `✔ ${LETTERS[q.answer]}. ${q.options[q.answer]}`;
      result.textContent = r.text;
      result.className = `qa-result verdict ${r.correct ? 'ok' : 'warn'}`;
      return r;
    };
    const buttons = q.options.map((text, i) => {
      const b = el('button', { type: 'button', class: 'secondary' }, `${LETTERS[i]}. ${text}`);
      b.addEventListener('click', () => {
        if (b.disabled) return;
        onFirstPick(i, lock(i).correct);
      });
      return b;
    });
    if (picked !== undefined) lock(picked);
    return el('li', { class: 'qa-card' }, el('p', { class: 'qa-q' }, q.q), el('div', { class: 'qa-options' }, ...buttons), result);
  };

  // A hands-on task: the answer stays hidden until asked for, since it can't be graded here.
  const taskCard = (t) => {
    const answer = el('div', { class: 'qa-answer', hidden: '' },
      el('ol', { class: 'qa-steps' }, ...t.steps.map((x) => el('li', {}, el('code', {}, x)))),
      el('p', { class: 'hint' }, el('strong', {}, 'Check: '), t.check));
    const show = el('button', { type: 'button', class: 'secondary small' }, 'Show answer');
    show.addEventListener('click', () => {
      answer.hidden = !answer.hidden;
      show.textContent = answer.hidden ? 'Show answer' : 'Hide answer';
    });
    return el('li', { class: 'qa-card' }, el('p', { class: 'qa-q' }, t.task), el('div', {}, show), answer);
  };

  // One exam's questions, ten at a time, inside its panel. Picks are kept per question,
  // so paging back shows answered cards still locked and the score counts once.
  const examBody = (exam, items) => {
    const tasks = exam.format === 'tasks';
    const all = items.filter(tasks ? validTask : validQuestion);
    let order = all.map((_, i) => i);
    let page = 0;
    let right = 0;
    const picks = new Map();
    const list = el('ol', { class: 'qa-list' });
    const range = el('span', { class: 'qa-range', 'aria-live': 'polite' });
    const prev = el('button', { type: 'button', class: 'secondary small' }, `← Previous ${PAGE}`);
    const next = el('button', { type: 'button', class: 'secondary small' }, `Next ${PAGE} →`);
    const shuffle = el('button', { type: 'button', class: 'secondary small' }, 'Shuffle');
    const score = el('p', { class: 'hint qa-score', 'aria-live': 'polite' });
    const pages = () => Math.max(1, Math.ceil(order.length / PAGE));

    const showScore = () => {
      score.textContent = picks.size ? `${right} of ${picks.size} correct so far (of ${all.length}). Your score is not saved anywhere.` : '';
    };
    const render = () => {
      const from = page * PAGE;
      const shown = order.slice(from, from + PAGE);
      list.setAttribute('start', String(from + 1));
      list.replaceChildren(...shown.map((i) => (tasks ? taskCard(all[i]) : card(all[i], picks.get(i), (pick, correct) => {
        picks.set(i, pick);
        if (correct) right += 1;
        showScore();
      }))));
      range.textContent = all.length ? `${tasks ? 'Tasks' : 'Questions'} ${from + 1}–${from + shown.length} of ${all.length}` : '';
      prev.disabled = page === 0;
      next.disabled = page >= pages() - 1;
    };
    const go = (to, scroll) => {
      page = Math.min(Math.max(0, to), pages() - 1);
      render();
      if (scroll) list.scrollIntoView?.({ block: 'start' });
    };
    prev.addEventListener('click', () => go(page - 1, true));
    next.addEventListener('click', () => go(page + 1, true));
    shuffle.addEventListener('click', () => {
      order = shuffled(order);
      go(0, true);
    });
    render();
    return [el('div', { class: 'qa-pager' }, prev, range, next, shuffle), list, tasks ? null : score];
  };

  // One accordion panel per exam. Its question file is fetched the first time the
  // panel opens, so the page only downloads the exams someone actually looks at.
  const panel = (exam) => {
    const tasks = exam.format === 'tasks';
    const noun = tasks ? 'task' : 'question';
    const n = Number.isInteger(exam.count) ? exam.count : null;
    const count = n === null ? `${noun}s` : `${n} ${noun}${n === 1 ? '' : 's'}`;
    const holder = el('div', { class: 'qa-holder' }, el('p', { class: 'hint' }, `Loading the ${exam.name} ${noun}s…`));
    const details = el('details', { class: 'exam', id: `exam-${exam.id}` },
      el('summary', {}, el('span', { class: 'exam-name' }, exam.name), el('span', { class: 'exam-count' }, count)),
      el('div', { class: 'exam-body' }, el('p', { class: 'hint' }, exam.about), holder));
    let loading = null;
    details.ensureLoaded = () => {
      loading ||= load(exam.file).then((f) => {
        holder.replaceChildren(...examBody(exam, f.questions || []).filter(Boolean));
      }).catch((err) => {
        loading = null; // closing and reopening the panel tries again
        holder.replaceChildren(el('p', { class: 'notice warn' }, `Could not load the ${exam.name} ${noun}s: ${err.message}`));
      });
      return loading;
    };
    details.addEventListener('toggle', () => {
      if (details.hasAttribute('open')) details.ensureLoaded();
    });
    return details;
  };

  const openFromHash = () => {
    const target = /^#(exam-[a-z-]+|ports-practice|acronyms-practice)$/.test(location.hash) ? $(location.hash.slice(1)) : null;
    if (!target) return;
    target.setAttribute('open', '');
    target.ensureLoaded?.();
    target.scrollIntoView();
  };

  const load = async (file) => {
    const res = await fetch(file);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  };

  // The exam list. Each exam's own question file loads when its panel is opened.
  load('data/study.json').then((data) => {
    $('study-note').textContent = data.note || '';
    const exams = (data.exams || []).filter((e) => /^data\/study\/[a-z-]+\.json$/.test(e.file || ''));
    $('study-exams').replaceChildren(...exams.map(panel));
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
