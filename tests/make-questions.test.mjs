// rag/make_questions.mjs: picking passages, reading model replies, checking and assembling the banks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  usable, pickPassages, rejected, OFF_TOPIC, systemPrompt, parseReply, workersAiText, copiesPassage, keepItems, shuffleOptions, assemble, PER_PASSAGE,
} from '../rag/make_questions.mjs';

const PASSAGE = 'The recovery time objective is the maximum time a system can be down before the business is harmed, while the recovery point objective '
  + 'is the maximum amount of data loss, measured in time, that is acceptable. Both come from the business impact analysis and drive the backup schedule. '
  + 'A differential backup copies everything changed since the last full backup, so each one grows until the next full backup runs. '
  + 'An incremental backup copies only what changed since the last backup of any kind, which makes restores take longer because every increment is needed.';

const words = (n) => Array.from({ length: n }, (_, i) => `word${i}`).join(' ');

test('usable drops short, numeric and front-matter passages', () => {
  assert.ok(usable({ text: PASSAGE }));
  assert.equal(usable({ text: 'too short' }), false);
  assert.equal(usable({ text: `${words(60)} All rights reserved.` }), false);
  assert.equal(usable({ text: `Chapter 1 ....... 3 Chapter 2 ....... 17 ${'4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 '}` }), false);
  assert.equal(usable(null), false);
});

test('pickPassages spreads picks through each book in proportion, stably', () => {
  const chunks = [];
  for (let i = 0; i < 90; i += 1) chunks.push({ id: `a-${i}`, book_id: 'a', text: `${PASSAGE} ${i}` });
  for (let i = 0; i < 30; i += 1) chunks.push({ id: `b-${i}`, book_id: 'b', text: `${PASSAGE} ${i}` });
  chunks.push({ id: 'c-0', book_id: 'c', text: PASSAGE });
  const picks = pickPassages(chunks, ['a', 'b'], 12);
  assert.equal(picks.length, 12);
  assert.equal(picks.filter((c) => c.book_id === 'a').length, 9);
  assert.equal(picks.filter((c) => c.book_id === 'b').length, 3);
  assert.deepEqual(picks.map((c) => c.id), pickPassages(chunks, ['a', 'b'], 12).map((c) => c.id), 'stable');
  assert.ok(!picks.some((c) => c.book_id === 'c'), 'only the exam’s books');
  assert.deepEqual(pickPassages(chunks, ['zzz'], 5), []);
  assert.equal(pickPassages(chunks, ['a'], 200).length, 90, 'never more than there are');
});

test('the prompts ask for the exam’s format and JSON only', () => {
  const mc = systemPrompt({ name: 'Security+', id: 'security-plus' });
  assert.match(mc, /Security\+/);
  assert.match(mc, new RegExp(`At most ${PER_PASSAGE.questions} questions`));
  assert.match(mc, /"questions":\[/);
  const tasks = systemPrompt({ name: 'RHCSA', id: 'rhcsa', format: 'tasks' });
  assert.match(tasks, /"tasks":\[/);
  assert.ok(!/options/.test(tasks));
});

test('parseReply finds the JSON object in a reply, or gives null', () => {
  assert.deepEqual(parseReply('{"questions":[]}'), { questions: [] });
  assert.deepEqual(parseReply('Sure! ```json\n{"questions":[{"q":"x"}]}\n```'), { questions: [{ q: 'x' }] });
  for (const bad of ['', 'no json here', '{broken', '[1,2]', null, 5]) assert.equal(parseReply(bad), null, String(bad));
});

test('workersAiText reads the output shapes Workers AI uses', () => {
  assert.equal(workersAiText({ result: { response: 'hi' } }), 'hi');
  assert.equal(workersAiText({ result: { response: { questions: [] } } }), '{"questions":[]}');
  assert.equal(workersAiText({ result: { choices: [{ message: { content: 'c' } }] } }), 'c');
  assert.equal(workersAiText({ result: { output: [{ content: [{ type: 'reasoning_text', text: 'thinking' }] }, { content: [{ type: 'output_text', text: 'answer' }] }] } }), 'answer');
  assert.equal(workersAiText({}), '');
});

test('copiesPassage catches a run of ten words lifted from the passage', () => {
  assert.equal(copiesPassage('The recovery time objective is the maximum time a system can be down', PASSAGE), true);
  assert.equal(copiesPassage('Which measure sets how long a system may stay down before the business suffers?', PASSAGE), false);
  assert.equal(copiesPassage('short', PASSAGE), false);
});

const good = {
  q: 'A company decides it can lose at most two hours of data in a disaster. Which measure records that decision?',
  options: ['The recovery point objective', 'The recovery time objective', 'The mean time between failures', 'The annualised loss expectancy'],
  answer: 0,
  why: 'The recovery point objective is how much data, measured in time, the business can afford to lose, so two hours of data is an RPO.',
};

test('keepItems keeps only well-formed, original questions and caps the count', () => {
  const reply = {
    questions: [
      good,
      { ...good, q: 'Which option is right?', options: ['a', 'b', 'c', 'All of the above'] },
      { ...good, q: 'Copied: the recovery time objective is the maximum time a system can be down before the business is harmed?' },
      { ...good, q: 'Short why?', why: 'Too short.' },
      { ...good, q: 'Bad answer?', answer: 7 },
      { ...good, q: 'Three options?', options: ['a', 'b', 'c'] },
    ],
  };
  const kept = keepItems({ name: 'x' }, reply, PASSAGE);
  assert.deepEqual(kept, [good]);
  assert.deepEqual(keepItems({ name: 'x' }, null, PASSAGE), []);
  assert.deepEqual(keepItems({ name: 'x' }, { questions: 'nope' }, PASSAGE), []);
  const many = { questions: Array.from({ length: 6 }, (_, i) => ({ ...good, q: `${good.q} v${i}` })) };
  assert.equal(keepItems({ name: 'x' }, many, PASSAGE).length, PER_PASSAGE.questions);
  const task = { task: 'Create the user alice with uid 2001.', steps: ['useradd -u 2001 alice'], check: 'id alice shows uid=2001.' };
  assert.deepEqual(keepItems({ format: 'tasks' }, { tasks: [task, { task: 'x', steps: [] }] }, PASSAGE), [task]);
});

test('shuffleOptions keeps the right answer right, in a stable order per question', () => {
  const s = shuffleOptions(good);
  assert.equal(s.options[s.answer], good.options[good.answer]);
  assert.deepEqual(s.options.slice().sort(), good.options.slice().sort());
  assert.deepEqual(shuffleOptions(good), s);
  const positions = new Set(Array.from({ length: 12 }, (_, i) => shuffleOptions({ ...good, q: `${good.q} ${i}` }).answer));
  assert.ok(positions.size > 1, 'the answer moves around');
});

test('assemble de-duplicates across passages and leaves tasks as they are', () => {
  const records = [{ chunk: 'a', items: [good, { ...good, q: `${good.q}  ` }] }, { chunk: 'b', items: [{ ...good, q: 'Another one entirely?' }] }];
  const out = assemble({ format: undefined }, records);
  assert.equal(out.length, 2);
  const task = { task: 'Do x.', steps: ['x'], check: 'y' };
  assert.deepEqual(assemble({ format: 'tasks' }, [{ items: [task, task] }]), [task]);
});

test('rejected drops off-topic items and listed ones', () => {
  assert.equal(rejected(good), false);
  assert.equal(rejected({ ...good, q: 'Which format is NOT listed in the passage?' }), true);
  assert.equal(rejected({ ...good, why: 'Earn CEUs every three years.' }), true);
  assert.equal(rejected({ ...good, q: 'How do you book the Security+ exam with Pearson VUE?' }), true);
  assert.equal(rejected(good, new Set([good.q.toLowerCase().match(/[a-z0-9]+/g).join(' ')])), true);
  assert.ok(OFF_TOPIC.test('this chapter'));
  const out = assemble({}, [{ items: [good, { ...good, q: 'What does the passage say?' }] }]);
  assert.equal(out.length, 1);
});
