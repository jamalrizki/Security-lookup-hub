#!/usr/bin/env node
/**
 * Builds the Study tab's question banks (data/study/<exam>.json) from the library:
 * passages of each exam's books in security-books/.rag/chunks.jsonl (made by
 * rag/ingest_books.py), study guides and practice-test books alike. For each passage
 * an AI model writes new questions on the concepts it covers (hands-on tasks for an
 * exam with "format": "tasks"); every one is checked in code before it is kept.
 *
 *   node rag/make_questions.mjs --dry-run                 plan only: passages per exam, estimated calls
 *   ANTHROPIC_API_KEY=... node rag/make_questions.mjs     or, with Workers AI:
 *   CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_API_TOKEN=... node rag/make_questions.mjs --provider workers-ai
 *   node rag/make_questions.mjs --provider local --endpoint http://127.0.0.1:8799   (a `wrangler dev` worker
 *       with an AI binding that forwards { model, messages, max_tokens, temperature }: no token needed)
 *   node rag/make_questions.mjs --assemble                rebuild data/study/*.json from what's generated
 *   Options: --exam <id>, --target <n per exam>, --neurons <Workers AI budget for this run>
 *
 * - Which books feed which exam: security-books/.rag/study-sources.json (gitignored, so no
 *   book titles reach the public repo): { "<exam id>": ["<file as in manifest.json>", ...] }.
 * - Resumable: each passage's result is appended to security-books/.rag/questions/<exam>.jsonl,
 *   and passages already there are skipped, so a crash, Ctrl-C or a daily limit costs nothing.
 * - Keys come from the environment only: never put one in a file in this repo or paste it into a chat.
 * - Workers AI's free allowance is 10,000 neurons a day, shared with the live Worker (Ask's
 *   reference search, voice). A run stops at --neurons (default 5,000) and the next run resumes.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validQuestion, validTask, OPTIONS } from '../js/study.js';
import { isJunk } from '../worker/scripts/embed-books.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RAG = path.join(ROOT, 'security-books/.rag');

export const PER_PASSAGE = { questions: 3, tasks: 2 };
export const DEFAULT_TARGET = { questions: 150, tasks: 60 };
export const WHY_MIN = 40;
export const WHY_MAX = 320;
/** A question or option sharing this many words in a row with its passage is dropped. */
export const COPY_RUN = 10;
export const DEFAULT_NEURONS = 5000;
export const WORKERS_AI_MODEL = '@cf/openai/gpt-oss-120b';
// Workers AI pricing for that model (developers.cloudflare.com/workers-ai/platform/pricing, Nov 2026).
export const NEURONS_PER_M = { input: 31818, output: 68182 };
export const ANTHROPIC_MODEL = 'claude-haiku-5-5';

// ---------- Picking passages ----------

const FRONT_MATTER = /all rights reserved|\bISBN\b|library of congress|printed in the united states|table of contents/i;

/** True for a passage worth writing questions from. */
export function usable(chunk) {
  return Boolean(chunk?.text) && !isJunk(chunk.text) && !FRONT_MATTER.test(chunk.text);
}

/**
 * Picks `count` passages spread evenly through the given books, each book's share in
 * proportion to its size, in a stable order (same input -> same picks).
 */
export function pickPassages(chunks, bookIds, count) {
  const byBook = bookIds.map((id) => chunks.filter((c) => c.book_id === id && usable(c)));
  const total = byBook.reduce((n, list) => n + list.length, 0);
  if (!total || count <= 0) return [];
  const picks = [];
  for (const list of byBook) {
    const share = Math.min(list.length, Math.round((count * list.length) / total));
    for (let k = 0; k < share; k += 1) picks.push(list[Math.floor(((k + 0.5) * list.length) / share)]);
  }
  return picks;
}

// ---------- Asking the model ----------

export function systemPrompt(exam) {
  if (exam.format === 'tasks') {
    return [
      `You write hands-on practice tasks for the ${exam.name} exam, from a passage of study material about Red Hat Enterprise Linux.`,
      'For each distinct skill in the passage that a person can practise on their own RHEL virtual machine, write one task, in your own words.',
      `Rules: "task" says what to do and the end state to reach, with concrete names (users, paths, devices like /dev/vdb). "steps" are the commands or file lines, in order, one per item. "check" says how to confirm it worked. Everything must be supported by the passage. At most ${PER_PASSAGE.tasks} tasks.`,
      'If the passage is front matter, an index, a contents page or has nothing to practise, return an empty list.',
      'Reply with JSON only: {"tasks":[{"task":"...","steps":["..."],"check":"..."}]}',
    ].join('\n');
  }
  return [
    `You write multiple-choice practice questions for the ${exam.name} exam, from a passage of study material. The passage may come from a study guide or from a practice-test book (questions with answers and explanations).`,
    'For each distinct exam concept in the passage, write one new question that tests the same fact or skill at the same difficulty, with your own wording, scenario and wrong options. Do not reuse the passage\'s sentences or option text.',
    `Rules: exactly ${OPTIONS} options, one correct; the wrong options are plausible to someone who hasn't studied; no "all of the above" or "none of the above"; options don't refer to each other by letter. "answer" is the 0-based index of the correct option. "why" is one or two plain sentences (${WHY_MIN} to ${WHY_MAX - 20} characters) saying why the answer is right. Everything must be supported by the passage. At most ${PER_PASSAGE.questions} questions.`,
    'If the passage is front matter, an index, a contents page or has nothing testable, return an empty list.',
    'Reply with JSON only: {"questions":[{"q":"...","options":["...","...","...","..."],"answer":0,"why":"..."}]}',
  ].join('\n');
}

export const userPrompt = (chunk) => `Passage:\n<<<\n${chunk.text}\n>>>`;

/** The JSON object in a model reply (tolerates code fences or words around it), or null. */
export function parseReply(text) {
  if (typeof text !== 'string') return null;
  const a = text.indexOf('{');
  const b = text.lastIndexOf('}');
  if (a < 0 || b <= a) return null;
  try {
    const obj = JSON.parse(text.slice(a, b + 1));
    return obj && typeof obj === 'object' ? obj : null;
  } catch {
    return null;
  }
}

/** Text out of a Workers AI /ai/run result, whichever output shape the model uses. */
export function workersAiText(result) {
  const r = result?.result ?? result;
  if (typeof r?.response === 'string') return r.response;
  if (r?.response && typeof r.response === 'object') return JSON.stringify(r.response);
  const choice = r?.choices?.[0]?.message?.content;
  if (typeof choice === 'string') return choice;
  if (Array.isArray(r?.output)) {
    return r.output.flatMap((item) => (Array.isArray(item?.content) ? item.content : []))
      .filter((c) => typeof c?.text === 'string' && c.type !== 'reasoning_text').map((c) => c.text).join('\n');
  }
  return '';
}

const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });

async function post(url, headers, body) {
  for (const wait of [0, 5000, 20000, 60000]) {
    if (wait) await sleep(wait);
    const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
    if (res.ok) return res.json();
    if (res.status !== 429 && res.status < 500) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
  throw new Error('still rate-limited or failing after retries');
}

/** One call: { text, neurons }. */
let endpoint = 'http://127.0.0.1:8799';

async function ask(provider, system, user) {
  if (provider === 'anthropic') {
    const r = await post('https://api.anthropic.com/v1/messages',
      { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      { model: process.env.QUESTIONS_MODEL || ANTHROPIC_MODEL, max_tokens: 4000, system, messages: [{ role: 'user', content: user }] });
    return { text: (r.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('\n'), neurons: 0 };
  }
  const model = process.env.QUESTIONS_MODEL || WORKERS_AI_MODEL;
  const body = { model, messages: [{ role: 'system', content: system }, { role: 'user', content: user }], max_tokens: 4000, temperature: 0.4 };
  const r = provider === 'local'
    ? await post(endpoint, {}, body)
    : await post(`https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/ai/run/${model}`, { authorization: `Bearer ${process.env.CLOUDFLARE_API_TOKEN}` }, body);
  const usage = r?.result?.usage || {};
  const inTok = usage.prompt_tokens ?? usage.input_tokens ?? 900;
  const outTok = usage.completion_tokens ?? usage.output_tokens ?? 1200;
  return { text: workersAiText(r), neurons: (inTok * NEURONS_PER_M.input + outTok * NEURONS_PER_M.output) / 1e6 };
}

// ---------- Checking and assembling ----------

const words = (s) => String(s).toLowerCase().match(/[a-z0-9]+/g) || [];

/** True when `text` repeats COPY_RUN or more words in a row from the passage. */
export function copiesPassage(text, passage, run = COPY_RUN) {
  const w = words(text);
  if (w.length < run) return false;
  const p = ` ${words(passage).join(' ')} `;
  for (let i = 0; i + run <= w.length; i += 1) if (p.includes(` ${w.slice(i, i + run).join(' ')} `)) return true;
  return false;
}

/** The items from one reply that pass every check (shape, lengths, not copied from the passage). */
export function keepItems(exam, reply, passage) {
  const tasks = exam.format === 'tasks';
  const list = Array.isArray(reply?.[tasks ? 'tasks' : 'questions']) ? reply[tasks ? 'tasks' : 'questions'] : [];
  const out = [];
  for (const raw of list.slice(0, tasks ? PER_PASSAGE.tasks : PER_PASSAGE.questions)) {
    if (tasks) {
      const t = { task: String(raw?.task ?? '').trim(), steps: Array.isArray(raw?.steps) ? raw.steps.map((s) => String(s).trim()) : [], check: String(raw?.check ?? '').trim() };
      if (validTask(t) && !copiesPassage(t.task, passage)) out.push(t);
      continue;
    }
    const q = {
      q: String(raw?.q ?? '').trim(),
      options: Array.isArray(raw?.options) ? raw.options.map((o) => String(o).trim()) : [],
      answer: raw?.answer,
      why: String(raw?.why ?? '').trim(),
    };
    if (!validQuestion(q) || q.why.length < WHY_MIN || q.why.length > WHY_MAX) continue;
    if (q.options.some((o) => /\b(all|none) of the above\b/i.test(o))) continue;
    if ([q.q, ...q.options].some((s) => copiesPassage(s, passage))) continue;
    out.push(q);
  }
  return out;
}

const hashInt = (s) => crypto.createHash('sha256').update(s).digest().readUInt32BE(0);

/** Same question with its options in a stable shuffled order (models favour some positions). */
export function shuffleOptions(q) {
  let seed = hashInt(q.q);
  const rand = () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed / 4294967296; };
  const order = q.options.map((_, i) => i);
  for (let i = order.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rand() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  return { ...q, options: order.map((i) => q.options[i]), answer: order.indexOf(q.answer) };
}

/** All kept items from the generated records, de-duplicated, ready for data/study/<exam>.json. */
export function assemble(exam, records) {
  const seen = new Set();
  const out = [];
  for (const rec of records) {
    for (const item of rec.items || []) {
      const key = words(item.q ?? item.task).join(' ');
      if (!key || seen.has(key)) continue;
      seen.add(key);
      out.push(exam.format === 'tasks' ? item : shuffleOptions(item));
    }
  }
  return out;
}

// ---------- Running it ----------

const readJsonl = (file) => (fs.existsSync(file)
  ? fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean)
  : []);

function writeBank(examMeta, records) {
  const items = assemble(examMeta, records);
  if (!items.length) return 0;
  fs.writeFileSync(path.join(ROOT, `data/study/${examMeta.id}.json`), `${JSON.stringify({ questions: items }, null, 1)}\n`);
  return items.length;
}

async function main(argv) {
  const flag = (name) => argv.includes(`--${name}`);
  const opt = (name) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : undefined; };
  const study = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/study.json'), 'utf8'));
  const sourcesFile = path.join(RAG, 'study-sources.json');
  if (!fs.existsSync(sourcesFile)) throw new Error(`missing ${sourcesFile}: { "<exam id>": ["<book file as in manifest.json>", ...] }`);
  const sources = JSON.parse(fs.readFileSync(sourcesFile, 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(path.join(RAG, 'manifest.json'), 'utf8'));
  const idOf = new Map((manifest.books || []).map((b) => [b.file, b.id]));
  const exams = study.exams.filter((e) => sources[e.id] && (!opt('exam') || e.id === opt('exam')));
  const provider = opt('provider') || (process.env.ANTHROPIC_API_KEY ? 'anthropic' : 'workers-ai');
  const budget = Number(opt('neurons') || DEFAULT_NEURONS);
  if (opt('endpoint')) endpoint = opt('endpoint');
  const outDir = path.join(RAG, 'questions');
  fs.mkdirSync(outDir, { recursive: true });

  const chunks = readJsonl(path.join(RAG, 'chunks.jsonl'));
  const plan = [];
  for (const exam of exams) {
    const kind = exam.format === 'tasks' ? 'tasks' : 'questions';
    const bookIds = sources[exam.id].map((f) => idOf.get(f)).filter(Boolean);
    const missing = sources[exam.id].filter((f) => !idOf.has(f));
    if (missing.length) console.log(`${exam.id}: not in manifest.json, skipped: ${missing.length} file(s)`);
    const target = Number(opt('target') || DEFAULT_TARGET[kind]);
    // Some passages yield fewer items (or none), so plan a third more than the bare minimum.
    const passages = pickPassages(chunks, bookIds, Math.ceil((target / PER_PASSAGE[kind]) * 1.33));
    const file = path.join(outDir, `${exam.id}.jsonl`);
    const records = readJsonl(file);
    const done = new Set(records.map((r) => r.chunk));
    const todo = passages.filter((c) => !done.has(c.id));
    const have = assemble(exam, records).length;
    console.log(`${exam.id}: ${bookIds.length} book(s), ${passages.length} passages planned, ${todo.length} to do, ${have} ${kind} so far (target ${target})`);
    plan.push({ exam, kind, target, file, records, todo, system: systemPrompt(exam), kept: have });
  }
  if (flag('dry-run')) return;
  if (!flag('assemble')) {
    if (provider === 'anthropic' && !process.env.ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY is not set');
    if (provider === 'workers-ai' && !(process.env.CLOUDFLARE_ACCOUNT_ID && process.env.CLOUDFLARE_API_TOKEN)) throw new Error('CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN must be set');
    // Round-robin over the exams, so a run cut short by the budget still fills each evenly.
    let spent = 0;
    let stopped = false;
    while (!stopped && plan.some((p) => p.todo.length && p.kept < p.target)) {
      for (const p of plan) {
        if (!p.todo.length || p.kept >= p.target) continue;
        if (provider !== 'anthropic' && spent >= budget) { console.log(`neuron budget for this run (${budget}) reached; run again tomorrow to resume`); stopped = true; break; }
        const chunk = p.todo.shift();
        try {
          const { text, neurons } = await ask(provider, p.system, userPrompt(chunk));
          spent += neurons;
          const items = keepItems(p.exam, parseReply(text), chunk.text);
          const rec = { chunk: chunk.id, items };
          fs.appendFileSync(p.file, `${JSON.stringify(rec)}\n`);
          p.records.push(rec);
          p.kept = assemble(p.exam, p.records).length;
          process.stdout.write(`  ${p.exam.id} ${chunk.id}: kept ${items.length}, ${p.kept} so far${provider !== 'anthropic' ? ` (~${Math.round(spent)} neurons)` : ''}\n`);
        } catch (err) {
          console.log(`  ${p.exam.id} ${chunk.id}: ${err.message}`);
          if (/HTTP 40[13]/.test(err.message)) throw err;
        }
      }
    }
  }
  for (const p of plan) console.log(`${p.exam.id}: wrote ${writeBank(p.exam, p.records)} ${p.kind} to data/study/${p.exam.id}.json`);
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main(process.argv.slice(2)).catch((err) => { console.error(err.message); process.exit(1); });
}
