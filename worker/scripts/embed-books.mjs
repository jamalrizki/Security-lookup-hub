#!/usr/bin/env node
/**
 * Embed the book chunks with Workers AI (bge-small-en-v1.5, 384 dims) and write
 * Vectorize-ready NDJSON. Run from the repo root, after rag/ingest_books.py:
 *
 *   CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_API_TOKEN=... node worker/scripts/embed-books.mjs [--books DIR] [--dry-run]
 *
 * Ported from Jaizz Chat (jazz-fact-chat/worker/scripts/embed-books.mjs).
 * - Reads DIR/.rag/chunks.jsonl, writes DIR/.rag/vectors.ndjson (DIR defaults to security-books/, gitignored).
 * - Resumable: vectors already in the output file are skipped, so a crash or Ctrl-C costs nothing,
 *   and adding books later only embeds the new ones.
 * - Vector id "<book id>-<chunk number>"; metadata is the chunk text and the book id ONLY:
 *   no titles, authors or file names ever reach Cloudflare.
 * - Budget guard: at most MAX_VECTORS vectors in all for this index. Vectorize's free plan
 *   stores 5 million dimensions per account, and this index has the hub's account to itself:
 *   12,000 x 384 = ~4.61 M. Whole books that don't fit are listed and left out.
 * - Neurons: Workers AI's free allowance is 10,000 a day. A run stops cleanly at about
 *   MAX_NEURONS_PER_RUN (estimated at Jaizz's measured rate) and the next run resumes.
 * - The token needs the "Workers AI" permission. It is read from the environment only:
 *   never put it in a file in this repo and never paste it into a chat.
 * - --dry-run prints the plan (totals, books that don't fit) and embeds nothing.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const MODEL = '@cf/baai/bge-small-en-v1.5'; // must match EMBED_MODEL in worker/src/reference.js
export const DIMS = 384;
export const BATCH = 20;
export const MAX_VECTORS = 12000;
export const MAX_NEURONS_PER_RUN = 8000;
// Jaizz: embedding 2,968 chunks cost about 2,550 neurons.
export const NEURONS_PER_CHUNK = 2550 / 2968;

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** Contents / index pages: mostly page numbers. They'd match queries and say nothing. */
export function isJunk(text) {
  const toks = text.split(/\s+/).filter(Boolean);
  if (toks.length < 40) return true;
  const numeric = toks.filter((t) => /^[\dIVXivx.,()\-–]+$/.test(t)).length;
  return numeric / toks.length > 0.25;
}

export const metadataFor = (c) => ({ book_id: c.book_id, text: c.text });

/**
 * Decides what this run embeds. Books are taken whole, in chunks-file order, while the
 * index total (already embedded + planned) stays within maxVectors; then the run is cut
 * at maxNeurons. Returns { todo, notFit: [{ book_id, chunks }], total, deferred }.
 */
export function planEmbedding(chunks, done, { maxVectors = MAX_VECTORS, maxNeurons = MAX_NEURONS_PER_RUN } = {}) {
  const usable = chunks.filter((c) => !isJunk(c.text));
  const byBook = new Map();
  for (const c of usable) {
    if (!byBook.has(c.book_id)) byBook.set(c.book_id, []);
    byBook.get(c.book_id).push(c);
  }
  let total = usable.filter((c) => done.has(c.id)).length;
  const planned = [];
  const notFit = [];
  for (const [bookId, list] of byBook) {
    const fresh = list.filter((c) => !done.has(c.id));
    if (!fresh.length) continue;
    if (total + fresh.length > maxVectors) {
      notFit.push({ book_id: bookId, chunks: fresh.length });
      continue;
    }
    total += fresh.length;
    planned.push(...fresh);
  }
  const perRun = Math.max(BATCH, Math.floor(maxNeurons / NEURONS_PER_CHUNK / BATCH) * BATCH);
  return { todo: planned.slice(0, perRun), notFit, total, deferred: Math.max(0, planned.length - perRun) };
}

function readDone(out) {
  const done = new Set();
  if (!fs.existsSync(out)) return done;
  const good = [];
  for (const line of fs.readFileSync(out, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try { done.add(JSON.parse(line).id); good.push(line); } catch { /* partial tail from a crash */ }
  }
  fs.writeFileSync(out, good.length ? `${good.join('\n')}\n` : '');
  return done;
}

async function embed(texts, { base, account, token }) {
  let lastErr;
  for (let attempt = 1; attempt <= 6; attempt++) {
    try {
      const res = await fetch(`${base}/accounts/${account}/ai/run/${MODEL}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: texts }),
      });
      if (res.status === 429 || res.status >= 500) throw Object.assign(new Error(`HTTP ${res.status}`), { retry: true });
      const body = await res.json().catch(() => null);
      if (res.status === 401 || res.status === 403) throw new Error(`HTTP ${res.status}: the API token was rejected. It needs the "Workers AI" permission on this account.`);
      if (!res.ok || !body?.success) throw new Error(`HTTP ${res.status}: ${JSON.stringify(body?.errors ?? '').slice(0, 300)}`);
      const data = body.result?.data;
      if (!Array.isArray(data) || data.length !== texts.length || data.some((v) => !Array.isArray(v) || v.length !== DIMS)) {
        throw new Error('unexpected embedding shape from Workers AI');
      }
      return data;
    } catch (err) {
      lastErr = err;
      if (!err.retry && !/fetch failed|ECONN|ETIMEDOUT/i.test(err.message)) throw err;
      const wait = 1500 * attempt;
      console.warn(`  attempt ${attempt} failed (${err.message}); retrying in ${wait / 1000}s`);
      await new Promise((r) => setTimeout(r, wait));
    }
  }
  throw lastErr;
}

async function main(argv) {
  if (path.resolve(process.cwd()) !== ROOT) {
    console.error(`Run this from the repo root (${ROOT}).`);
    process.exit(1);
  }
  const opt = (name, def) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : def);
  const books = path.resolve(opt('--books', path.join(ROOT, 'security-books')));
  const IN = path.join(books, '.rag', 'chunks.jsonl');
  const OUT = path.join(books, '.rag', 'vectors.ndjson');
  const dryRun = argv.includes('--dry-run');
  if (!fs.existsSync(IN)) {
    console.error(`Can't find ${IN}. Run the ingest first: python3 rag/ingest_books.py`);
    process.exit(1);
  }
  const account = process.env.CLOUDFLARE_ACCOUNT_ID;
  const token = process.env.CLOUDFLARE_API_TOKEN;
  if (!dryRun && (!account || !token)) {
    console.error('Set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN in this terminal first (see the README).');
    process.exit(1);
  }

  const chunks = fs.readFileSync(IN, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const done = readDone(OUT);
  const plan = planEmbedding(chunks, done);
  const junk = chunks.filter((c) => isJunk(c.text)).length;
  console.log(`${chunks.length} chunks · ${junk} skipped as contents/index pages · ${done.size} already embedded`);
  console.log(`Index total after all planned books: ${plan.total.toLocaleString('en-US')} vectors (cap ${MAX_VECTORS.toLocaleString('en-US')}) = ${(plan.total * DIMS).toLocaleString('en-US')} dimensions`);
  for (const b of plan.notFit) console.log(`  DOESN'T FIT: book ${b.book_id} (${b.chunks} chunks). Remove a book or raise the cap knowingly.`);
  console.log(`This run: ${plan.todo.length} to embed (≈${Math.round(plan.todo.length * NEURONS_PER_CHUNK)} neurons)${plan.deferred ? `; ${plan.deferred} more after today's neuron budget, so run again tomorrow` : ''}`);
  if (dryRun || !plan.todo.length) return;

  const api = { base: process.env.CF_API_BASE || 'https://api.cloudflare.com/client/v4', account, token };
  for (let i = 0; i < plan.todo.length; i += BATCH) {
    const batch = plan.todo.slice(i, i + BATCH);
    const vectors = await embed(batch.map((c) => c.text), api);
    const lines = batch.map((c, j) => JSON.stringify({ id: c.id, values: vectors[j].map((x) => Math.round(x * 1e6) / 1e6), metadata: metadataFor(c) }));
    fs.appendFileSync(OUT, `${lines.join('\n')}\n`);
    const n = Math.min(i + BATCH, plan.todo.length);
    if (n % 200 === 0 || n === plan.todo.length) console.log(`  ${n}/${plan.todo.length} embedded · ≈${Math.round(n * NEURONS_PER_CHUNK)} neurons this run`);
  }
  console.log(`Done. ${OUT}`);
  if (plan.deferred) console.log(`Stopped at this run's neuron budget. Run the same command tomorrow to continue (${plan.deferred} left).`);
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
