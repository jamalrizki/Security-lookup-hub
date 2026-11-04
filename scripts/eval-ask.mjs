// Ask eval: a fixed question set, graded in code (no model-as-judge).
//
//   node scripts/eval-ask.mjs                      runs tests/evals/beginner.json against a local
//                                                  `wrangler dev` (http://127.0.0.1:8787)
//   node scripts/eval-ask.mjs --set students       another set: beginner (default), students, work
//                                                  (a name from tests/evals/, or a path to a .json)
//   node scripts/eval-ask.mjs --only q02,q19       just those questions
//   node scripts/eval-ask.mjs --grade <dir>        re-grade saved answers, no network
//   node scripts/eval-ask.mjs --prod               the deployed Worker (uses paid questions)
//
// Answers are saved, one JSON file per question, to tests/evals/out/ (gitignored). Only
// Jamal's own eval questions and answers are stored; nothing about visitors. Never part
// of `npm test`: tests/eval-grade.test.mjs tests grade() on hand-written answers instead.

import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const LOCAL_URL = 'http://127.0.0.1:8787';
export const PROD_URL = 'https://security-lookup-hub.jamal-598.workers.dev';
// The Worker only answers allowlisted origins; this one is in ALLOWED_ORIGINS for local work.
const ORIGIN = 'http://localhost:8000';
const DAILY_PAID = 100;

/** Lower-case, straight apostrophes and quotes, single spaces: what the keyword checks match against. */
export function normalize(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/[‘’ʼ]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[‐-―]/g, '-')
    .replace(/\s+/g, ' ');
}

/** "change + password" needs every part; "call your bank" needs the phrase. */
export function matches(text, alternative) {
  const parts = alternative.split(' + ').map((p) => normalize(p).trim()).filter(Boolean);
  return parts.length > 0 && parts.every((p) => text.includes(p));
}

export const wordCount = (text) => String(text || '').split(/\s+/).filter((w) => /[\p{L}\p{N}]/u.test(w)).length;

// Raw URLs, and the Worker's defanged form of a URL the model wrote anyway (hxxps://x[.]y).
const URL_RE = /\b(?:https?|hxxps?):\/\/\S+/i;
// A refusal, as models usually word one. Checked only for mustDecline questions.
const DECLINE_RE = /\b(?:can(?:'|no)t|can not|won't|will not|unable to|not able to|not going to|refuse|decline)\b[^.!?\n]{0,60}\b(?:help|make|create|build|write|provide|do that|assist|copy|clone|imitate)/;

/** Expectations for one question: its own fields over the set's defaults (mustNotInclude adds up). */
export function expectationsFor(q, defaults = {}) {
  return {
    ...defaults,
    ...q,
    mustNotInclude: [...(defaults.mustNotInclude || []), ...(q.mustNotInclude || [])],
  };
}

/**
 * Grades one /api/ask JSON answer ({ reply, hub, sources, trace } or { error }) against
 * expectations. Returns { pass, failures: [short reasons] }. Same answer, same verdict.
 */
export function grade(answer, exp) {
  const failures = [];
  if (!answer || typeof answer.reply !== 'string' || !answer.reply.trim()) {
    return { pass: false, failures: [`no answer${answer?.error ? ` (${String(answer.error).slice(0, 80)})` : ''}`] };
  }
  const reply = answer.reply;
  const text = normalize(reply);
  const hubIds = new Set((Array.isArray(answer.hub) ? answer.hub : []).map((h) => h?.id));
  const tools = new Set((Array.isArray(answer.trace) ? answer.trace : []).map((t) => t?.tool));

  for (const id of exp.mustHub || []) if (!hubIds.has(id)) failures.push(`missing [[${id}]]`);
  for (const group of exp.mustInclude || []) {
    if (!group.some((alt) => matches(text, alt))) failures.push(`missing one of: ${group.slice(0, 3).join(' / ')}${group.length > 3 ? ' …' : ''}`);
  }
  for (const phrase of exp.mustNotInclude || []) if (matches(text, phrase)) failures.push(`banned phrase: "${phrase}"`);
  if (exp.maxWords && wordCount(reply) > exp.maxWords) failures.push(`${wordCount(reply)} words (max ${exp.maxWords})`);
  for (const name of exp.mustCallTool || []) if (!tools.has(name)) failures.push(`no ${name} call`);
  if (exp.mustDecline && !DECLINE_RE.test(text)) failures.push('did not decline');
  if (URL_RE.test(reply)) failures.push('URL in reply');
  return { pass: failures.length === 0, failures };
}

/** Grades every answer in { [id]: answer }; missing answers fail. Returns rows in set order. */
export function gradeSet(set, answers) {
  return set.questions.map((q) => {
    const answer = answers[q.id];
    const { pass, failures } = answer ? grade(answer, expectationsFor(q, set.defaults)) : { pass: false, failures: ['not run'] };
    const webSearches = (answer?.trace || []).filter((t) => t?.tool === 'web_search').length;
    return { id: q.id, topic: q.topic, pass, failures, webSearches, model: answer?.model || null, fallback: answer?.fallback || null };
  });
}

/** "beginner: 17/20 pass; failures: q07 missing [[what-now]], q12 banned phrase: "it's fine"" */
export function summaryLine(setName, rows) {
  const passed = rows.filter((r) => r.pass).length;
  const failed = rows.filter((r) => !r.pass).map((r) => `${r.id} ${r.failures.join(', ')}`);
  return `${setName}: ${passed}/${rows.length} pass${failed.length ? `; failures: ${failed.join('; ')}` : ''}`;
}

const EVALS = join(ROOT, 'tests/evals');

/** The question sets in tests/evals/, by name (file name without .json). */
export function setNames() {
  return readdirSync(EVALS).filter((f) => f.endsWith('.json')).map((f) => f.replace(/\.json$/, '')).sort();
}

/** "students" → tests/evals/students.json; anything with a slash or .json is a path. */
export function setPath(nameOrPath) {
  const v = String(nameOrPath || '');
  if (/[\\/]|\.json$/i.test(v)) return resolve(v);
  if (!setNames().includes(v)) throw new Error(`Unknown set "${v}". Sets: ${setNames().join(', ')}`);
  return join(EVALS, `${v}.json`);
}

export function loadSet(path = join(EVALS, 'beginner.json')) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

// ---------- runner (CLI only) ----------

export function parseArgs(argv) {
  const opts = { url: LOCAL_URL, prod: false, only: null, grade: null, set: join(EVALS, 'beginner.json') };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--prod') opts.prod = true;
    else if (a === '--url') opts.url = argv[++i];
    else if (a === '--only') opts.only = new Set(String(argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean));
    else if (a === '--grade') opts.grade = argv[++i];
    else if (a === '--set') opts.set = setPath(argv[++i]);
    else throw new Error(`Unknown option: ${a}`);
  }
  if (opts.prod) opts.url = PROD_URL;
  else if (/workers\.dev|github\.io/i.test(opts.url || '')) throw new Error('That looks like the deployed Worker: pass --prod instead of --url, so the cost warning is shown.');
  return opts;
}

async function askOne(url, question) {
  try {
    const res = await fetch(`${url.replace(/\/+$/, '')}/api/ask`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: ORIGIN },
      body: JSON.stringify({ messages: [{ role: 'user', content: question }] }),
      signal: AbortSignal.timeout(90_000),
    });
    const body = await res.json().catch(() => ({ error: `HTTP ${res.status}, not JSON` }));
    return res.ok ? body : { error: body.error || `HTTP ${res.status}`, status: res.status };
  } catch (err) {
    return { error: err.name === 'TimeoutError' ? 'timed out after 90 s' : String(err.message || err) };
  }
}

function readSaved(dir) {
  const answers = {};
  for (const f of readdirSync(dir)) if (/^q\w+\.json$/.test(f)) answers[f.replace(/\.json$/, '')] = JSON.parse(readFileSync(join(dir, f), 'utf8'));
  return answers;
}

function printRows(set, rows) {
  for (const r of rows) {
    const via = r.model ? ` [${r.model}${r.fallback ? ', fallback' : ''}]` : '';
    console.log(`${r.pass ? 'PASS' : 'FAIL'} ${r.id} ${r.topic}${via}${r.pass ? '' : ` — ${r.failures.join(', ')}`}`);
  }
  console.log('');
  console.log(summaryLine(set.set || 'eval', rows));
  console.log(`Web searches used: ${rows.reduce((n, r) => n + r.webSearches, 0)} (Tavily: 25/day cap in code)`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const set = loadSet(opts.set);
  if (opts.grade) {
    const saved = readSaved(resolve(opts.grade));
    // Only the questions that run saved (an --only run saves a few).
    const ran = { ...set, questions: set.questions.filter((q) => q.id in saved && (!opts.only || opts.only.has(q.id))) };
    printRows(ran, gradeSet(ran, saved));
    return;
  }
  const questions = set.questions.filter((q) => !opts.only || opts.only.has(q.id));
  if (opts.prod) {
    console.log(`WARNING: --prod sends ${questions.length} questions to the deployed Worker.`);
    console.log(`They use ${questions.length} of Ask's ${DAILY_PAID} daily paid Claude questions (prepaid credit) and may use Tavily web searches.`);
    console.log('Starting in 10 seconds; press Ctrl+C to cancel.');
    await new Promise((r) => setTimeout(r, 10_000));
  }
  const out = join(ROOT, 'tests/evals/out', `${set.set || 'eval'}-${new Date().toISOString().replace(/[:.]/g, '-')}`);
  mkdirSync(out, { recursive: true });
  const answers = {};
  for (const q of questions) {
    answers[q.id] = await askOne(opts.url, q.question);
    writeFileSync(join(out, `${q.id}.json`), JSON.stringify(answers[q.id], null, 2));
    const [row] = gradeSet({ ...set, questions: [q] }, answers);
    console.log(`${row.pass ? 'PASS' : 'FAIL'} ${q.id}${row.pass ? '' : ` — ${row.failures.join(', ')}`}`);
  }
  console.log(`\nSaved to ${out}\n`);
  printRows({ ...set, questions }, gradeSet({ ...set, questions }, answers));
}

if (process.argv[1] && existsSync(process.argv[1]) && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((err) => {
    console.error(err.message || err);
    process.exit(1);
  });
}
