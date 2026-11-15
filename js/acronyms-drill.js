// Acronyms practice (Reference page, #acronyms-practice). Multiple-choice
// questions for Security+, CySA+ and CISSP students, built from
// data/acronyms.json, so the quiz and the "Security acronyms" list above it can
// never disagree. No AI, no network beyond the same data file, no storage: the
// session score lives in a variable. Pure functions are exported for tests;
// startAcronymsDrill() wires the page.

import { seeded, cryptoRand } from './analyze/subnet-drill.js';
import { acronymKey } from './acronyms.js';

export { seeded, cryptoRand };

// 'full':    "What does XSS stand for?" -> pick the expansion.
// 'meaning': a plain sentence -> pick the acronym it describes.
export const KINDS = ['full', 'meaning'];
export const CHOICES = 4;

// Acronyms close enough that one's plain sentence fairly fits another (a TOTP
// is an OTP; a DDoS is a DoS). Two from the same group never share a question.
export const CONFUSABLE = [
  ['2FA', 'MFA'], ['OTP', 'TOTP'], ['MAC', 'HMAC'], ['DoS', 'DDoS'], ['IDS', 'HIDS'],
  ['EDR', 'XDR'], ['NGFW', 'UTM'], ['SSL', 'TLS', 'HTTPS'], ['IPsec', 'VPN'],
  ['PII', 'PHI'], ['SSO', 'SAML'], ['SSH', 'SFTP'], ['STIX', 'TAXII'],
];

/** Keys of acronyms that may not be offered alongside this one (itself included). */
export function clashes(acronym) {
  const key = acronymKey(acronym);
  const out = new Set([key]);
  for (const g of CONFUSABLE) if (g.some((a) => acronymKey(a) === key)) for (const a of g) out.add(acronymKey(a));
  return out;
}

/** Lower case, letters and digits only, for comparing expansions. */
const fullKey = (s) => String(s ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');

/** True when the plain sentence names its own acronym ("ARP replies"), which would give the answer away. */
export function plainGivesAway(a) {
  const key = acronymKey(a.acronym);
  return String(a.plain).split(/[^A-Za-z0-9&/+-]+/).some((w) => acronymKey(w) === key);
}

/** Entries a kind can ask about. */
export function pool(list, kind) {
  return kind === 'meaning' ? list.filter((a) => !plainGivesAway(a)) : list.slice();
}

/** Every meaning of the entry's acronym in the list (MAC has three). */
export const meaningsOf = (list, a) => list.filter((x) => acronymKey(x.acronym) === acronymKey(a.acronym));

function shuffle(rand, arr) {
  const out = arr.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/**
 * Picks wrong options. A wrong option is never another meaning of the same
 * acronym, never a CONFUSABLE neighbour of the answer or of another option,
 * and never repeats an option already chosen. Acronyms that start with
 * the same character come first, so the letters alone don't give it away.
 */
function distractors(rand, list, entry, kind, n) {
  const key = acronymKey(entry.acronym);
  const seen = new Set([kind === 'full' ? fullKey(entry.full) : key]);
  const banned = clashes(entry.acronym);
  const taken = [];
  const ok = (a) => !banned.has(acronymKey(a.acronym));
  const first = key[0];
  const near = shuffle(rand, list.filter((a) => ok(a) && acronymKey(a.acronym)[0] === first));
  const far = shuffle(rand, list.filter((a) => ok(a) && acronymKey(a.acronym)[0] !== first));
  const out = [];
  for (const a of [...near, ...far]) {
    if (out.length >= n) break;
    const k = kind === 'full' ? fullKey(a.full) : acronymKey(a.acronym);
    if (seen.has(k) || taken.some((t) => t.has(acronymKey(a.acronym)))) continue;
    seen.add(k);
    taken.push(clashes(a.acronym));
    out.push(a);
  }
  return out;
}

/**
 * Makes one question. Returns { kind, entry, prompt, options, correct, answer }
 * where options are strings, correct is the index of the right one and answer
 * is the line shown on a miss.
 */
export function makeQuestion(rand, list, { kinds = KINDS } = {}) {
  const allowed = kinds.filter((k) => KINDS.includes(k));
  const from = allowed.length ? allowed : KINDS;
  const kind = from[Math.floor(rand() * from.length)];
  const entries = pool(list, kind);
  if (entries.length < CHOICES) return null;
  const entry = entries[Math.floor(rand() * entries.length)];
  const wrong = distractors(rand, list, entry, kind, CHOICES - 1);
  if (wrong.length < CHOICES - 1) return null;
  const label = (a) => (kind === 'full' ? a.full : a.acronym);
  const options = shuffle(rand, [entry, ...wrong]);
  const several = meaningsOf(list, entry).length > 1;
  const prompt = kind === 'full'
    ? `What does ${entry.acronym} stand for?${several ? ` (${entry.acronym} has more than one meaning; one of them is below.)` : ''}`
    : `Which acronym is this? "${entry.plain}"`;
  return {
    kind,
    entry,
    prompt,
    options: options.map(label),
    correct: options.indexOf(entry),
    answer: `${entry.acronym}: ${entry.full}`,
  };
}

/**
 * Grades a choice by index. Returns { status: 'correct' | 'wrong' | 'invalid', message }.
 * Anything that isn't one of the option indexes is 'invalid' and never counts.
 */
export function checkChoice(q, index) {
  if (!q || !Number.isInteger(index) || index < 0 || index >= q.options.length) {
    return { status: 'invalid', message: 'Pick one of the options.' };
  }
  return index === q.correct
    ? { status: 'correct', message: 'Correct.' }
    : { status: 'wrong', message: `Not quite. The answer is ${q.answer}.` };
}

/** The list's own line for the entry, plus its other meanings if any. */
export function explain(list, q) {
  const others = meaningsOf(list, q.entry).filter((a) => a !== q.entry).map((a) => a.full);
  return [
    `${q.entry.acronym}: ${q.entry.full}. ${q.entry.plain}`,
    others.length ? `${q.entry.acronym} can also mean ${others.join(' or ')}.` : null,
  ].filter(Boolean).join(' ');
}

// ---------- Page wiring ----------

/**
 * Wires #acronyms-practice. el/$ come from the caller so this file needs no DOM
 * of its own; showInList(acronym) fills the list's search box.
 */
export function startAcronymsDrill(list, { el, $, showInList }) {
  if (!$('adrill-options') || list.length < CHOICES) return;
  const score = { right: 0, answered: 0 };
  let q = null;

  const showScore = () => {
    $('adrill-score').textContent = score.answered ? `${score.right} / ${score.answered} this session` : '';
  };
  const lock = (chosen) => {
    [...$('adrill-options').querySelectorAll('button')].forEach((b, i) => {
      b.disabled = true;
      if (i === q.correct) b.textContent = `✔ ${q.options[i]}`;
      else if (i === chosen) b.textContent = `✘ ${q.options[i]}`;
    });
  };
  const next = () => {
    q = makeQuestion(cryptoRand, list);
    $('adrill-question').textContent = q ? q.prompt : 'No questions available.';
    $('adrill-result').replaceChildren();
    $('adrill-options').replaceChildren(...(q ? q.options : []).map((text, i) => {
      const b = el('button', { type: 'button', class: 'secondary' }, text);
      b.addEventListener('click', () => choose(i));
      return b;
    }));
  };
  function choose(i) {
    const r = checkChoice(q, i);
    if (r.status === 'invalid') return;
    score.answered++;
    if (r.status === 'correct') score.right++;
    lock(i);
    $('adrill-result').replaceChildren(
      el('p', { class: `verdict ${r.status === 'correct' ? 'ok' : 'bad'}` }, r.status === 'correct' ? '✔ ' : '✘ ', r.message),
      el('p', { class: 'hint' }, explain(list, q)),
    );
    showScore();
  }

  $('adrill-reveal').addEventListener('click', () => {
    if (!q) return;
    lock(-1); // revealed answers don't score
    $('adrill-result').replaceChildren(el('p', { class: 'verdict muted' }, `The answer is ${q.answer}.`), el('p', { class: 'hint' }, explain(list, q)));
  });
  $('adrill-next').addEventListener('click', () => { next(); $('adrill-options').querySelector('button')?.focus(); });
  $('adrill-show').addEventListener('click', () => { if (q) showInList(q.entry.acronym); });
  next();
}
