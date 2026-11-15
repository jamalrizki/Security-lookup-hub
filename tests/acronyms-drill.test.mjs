// Acronyms practice (js/acronyms-drill.js): every question and option comes
// from data/acronyms.json, exactly one option is right, and the page wiring
// scores only the first pick.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  KINDS, CHOICES, CONFUSABLE, seeded, makeQuestion, checkChoice, explain, pool, plainGivesAway,
  meaningsOf, clashes, startAcronymsDrill,
} from '../js/acronyms-drill.js';
import { acronymKey } from '../js/acronyms.js';
import { installDom } from './helpers/dom.mjs';

const root = new URL('../', import.meta.url);
const { acronyms } = JSON.parse(readFileSync(new URL('data/acronyms.json', root), 'utf8'));
const find = (acr, full) => acronyms.find((a) => a.acronym === acr && (!full || a.full === full));
const many = (opts, n = 400, seed = 1) => {
  const rand = seeded(seed);
  return Array.from({ length: n }, () => makeQuestion(rand, acronyms, opts));
};

test('every acronym in CONFUSABLE is in data/acronyms.json, and groups don\'t overlap', () => {
  const seen = new Set();
  for (const g of CONFUSABLE) {
    for (const a of g) {
      assert.ok(acronyms.some((x) => x.acronym === a), a);
      assert.ok(!seen.has(a), `${a} is in two groups`);
      seen.add(a);
    }
  }
  assert.ok(clashes('ddos').has('dos'));
  assert.deepEqual([...clashes('XSS')], ['xss']);
});

test('a plain sentence that names its own acronym is never a "which acronym" question', () => {
  assert.ok(plainGivesAway(find('ARP')));
  assert.ok(plainGivesAway(find('SSL')));
  assert.ok(plainGivesAway(find('SOC', 'System and Organization Controls')));
  assert.ok(!plainGivesAway(find('SOC', 'Security Operations Center')));
  assert.ok(!plainGivesAway(find('XSS')));
  assert.ok(!plainGivesAway(find('ALE')), 'naming SLE and ARO is fine for ALE');
  const meaning = pool(acronyms, 'meaning');
  assert.ok(!meaning.includes(find('ARP')));
  assert.ok(meaning.length > 140);
  assert.equal(pool(acronyms, 'full').length, acronyms.length);
});

test('questions are repeatable per seed; both kinds come up; exactly one option is right', () => {
  assert.deepEqual(makeQuestion(seeded(5), acronyms), makeQuestion(seeded(5), acronyms));
  const seen = new Set();
  const asked = new Set();
  for (let seed = 1; seed <= 5; seed++) {
    for (const q of many({}, 400, seed)) {
      assert.ok(q, 'a question is always made');
      seen.add(q.kind);
      asked.add(q.entry);
      const e = q.entry;
      assert.ok(acronyms.includes(e), 'the entry is the list entry itself');
      assert.equal(q.options.length, CHOICES);
      assert.equal(new Set(q.options.map((o) => o.toLowerCase())).size, CHOICES, `repeated option: ${q.options}`);
      assert.equal(q.options[q.correct], q.kind === 'full' ? e.full : e.acronym);
      assert.equal(q.answer, `${e.acronym}: ${e.full}`);
      if (q.kind === 'full') {
        assert.ok(q.prompt.includes(e.acronym));
        assert.ok(!q.prompt.includes(e.full), 'the prompt does not give the answer');
        // No other option is another meaning of the same acronym (CSP, MAC, PAM, SOC).
        const others = meaningsOf(acronyms, e).map((a) => a.full);
        for (const [i, o] of q.options.entries()) if (i !== q.correct) assert.ok(!others.includes(o), `${e.acronym}: ${o}`);
        assert.ok(q.options.every((o) => acronyms.some((a) => a.full === o)));
      } else {
        assert.ok(q.prompt.includes(e.plain));
        assert.ok(!plainGivesAway(e));
        assert.ok(q.options.every((o) => acronyms.some((a) => a.acronym === o)));
      }
      // No two options come from the same CONFUSABLE group or share an acronym.
      const keys = q.options.map((o) => acronymKey(q.kind === 'full' ? acronyms.find((a) => a.full === o).acronym : o));
      for (let i = 0; i < keys.length; i++) {
        for (let j = i + 1; j < keys.length; j++) assert.ok(!clashes(keys[i]).has(keys[j]), `${keys[i]} with ${keys[j]}`);
      }
    }
  }
  assert.deepEqual([...seen].sort(), [...KINDS].sort());
  assert.ok(asked.size > 120, `most entries come up (${asked.size})`);
});

test('the right answer lands in every position, and "full" options prefer the same first letter', () => {
  const positions = new Set(many({}, 200).map((q) => q.correct));
  assert.deepEqual([...positions].sort(), [0, 1, 2, 3]);
  let same = 0;
  let total = 0;
  for (const q of many({ kinds: ['full'] }, 300, 7)) {
    const first = acronymKey(q.entry.acronym)[0];
    for (const [i, o] of q.options.entries()) {
      if (i === q.correct) continue;
      total++;
      if (acronymKey(acronyms.find((a) => a.full === o).acronym)[0] === first) same++;
    }
  }
  assert.ok(same / total > 0.5, `${same}/${total} distractors share the first letter`);
});

test('kinds can be limited; an unknown kind falls back to all; a tiny list makes no question', () => {
  for (const q of many({ kinds: ['meaning'] }, 50)) assert.equal(q.kind, 'meaning');
  for (const q of many({ kinds: ['full'] }, 50)) assert.equal(q.kind, 'full');
  assert.ok(many({ kinds: ['nope'] }, 20).every(Boolean));
  assert.equal(makeQuestion(seeded(1), acronyms.slice(0, 3)), null);
});

test('a multi-meaning acronym says so in the question and the explanation lists the others', () => {
  let q;
  for (let s = 1; s < 2000 && !q; s++) {
    const c = makeQuestion(seeded(s), acronyms, { kinds: ['full'] });
    if (c.entry.acronym === 'MAC') q = c;
  }
  assert.ok(q, 'MAC comes up');
  assert.match(q.prompt, /^What does MAC stand for\? \(MAC has more than one meaning; one of them is below\.\)$/);
  const text = explain(acronyms, q);
  assert.ok(text.startsWith(`MAC: ${q.entry.full}. ${q.entry.plain}`));
  assert.match(text, /MAC can also mean .+ or .+\.$/);
  assert.equal(explain(acronyms, { entry: find('XSS') }), `XSS: Cross-Site Scripting. ${find('XSS').plain}`);
});

test('grading: the right index is correct, another is wrong, anything else is invalid', () => {
  const q = makeQuestion(seeded(3), acronyms);
  assert.equal(checkChoice(q, q.correct).status, 'correct');
  const wrong = (q.correct + 1) % CHOICES;
  const r = checkChoice(q, wrong);
  assert.equal(r.status, 'wrong');
  assert.equal(r.message, `Not quite. The answer is ${q.answer}.`);
  for (const bad of [-1, CHOICES, 1.5, '0', null, undefined, NaN]) assert.equal(checkChoice(q, bad).status, 'invalid', String(bad));
  assert.equal(checkChoice(null, 0).status, 'invalid');
});

test('the Reference page has the practice block under the acronym list', () => {
  const html = readFileSync(new URL('reference.html', root), 'utf8');
  for (const id of ['acronyms-practice', 'adrill-question', 'adrill-options', 'adrill-reveal', 'adrill-next', 'adrill-show', 'adrill-result', 'adrill-score']) {
    assert.ok(html.includes(`id="${id}"`), id);
  }
  assert.ok(html.indexOf('id="acronyms-practice"') > html.indexOf('id="acronyms-list"'));
  const js = readFileSync(new URL('js/reference.js', root), 'utf8');
  assert.match(js, /startAcronymsDrill\(acronyms,/);
  const drill = readFileSync(new URL('js/acronyms-drill.js', root), 'utf8');
  assert.ok(!/innerHTML|localStorage|sessionStorage|fetch\(/.test(drill), 'no innerHTML, storage or network in the drill');
});

test('page wiring: one pick per question scores, options lock, reveal never scores, Show in the list', () => {
  const html = readFileSync(new URL('reference.html', root), 'utf8');
  const dom = installDom(html);
  try {
    const $ = (id) => dom.document.getElementById(id);
    const el = (tag, attrs = {}, ...kids) => {
      const n = dom.document.createElement(tag);
      for (const [k, v] of Object.entries(attrs)) if (k === 'class') n.className = v; else n.setAttribute(k, v);
      n.append(...kids.filter((k) => k != null));
      return n;
    };
    const shown = [];
    startAcronymsDrill(acronyms, { el, $, showInList: (a) => shown.push(a) });
    const buttons = () => $('adrill-options').querySelectorAll('button');
    assert.equal(buttons().length, CHOICES);
    assert.match($('adrill-question').textContent, /^(What does .+ stand for\?|Which acronym is this\? ".+")/);
    assert.equal($('adrill-score').textContent, '');

    // Pick every option in turn: only the first click counts, the rest are disabled.
    const first = buttons()[0];
    first.click();
    assert.equal($('adrill-score').textContent.endsWith('/ 1 this session'), true);
    assert.ok(buttons().every((b) => b.disabled));
    assert.equal(buttons().filter((b) => b.textContent.startsWith('✔ ')).length, 1, 'the right option is marked');
    assert.match($('adrill-result').textContent, /(Correct\.|Not quite\. The answer is )/);
    for (const b of buttons()) b.click();
    assert.ok($('adrill-score').textContent.endsWith('/ 1 this session'));

    $('adrill-show').click();
    assert.equal(shown.length, 1);
    assert.ok(acronyms.some((a) => a.acronym === shown[0]));

    // Next question, reveal: no score change, options locked.
    $('adrill-next').click();
    assert.ok(buttons().every((b) => !b.disabled));
    assert.equal($('adrill-result').textContent, '');
    $('adrill-reveal').click();
    assert.match($('adrill-result').textContent, /^The answer is /);
    assert.ok(buttons().every((b) => b.disabled));
    assert.ok($('adrill-score').textContent.endsWith('/ 1 this session'));
  } finally {
    dom.restore();
  }
});
