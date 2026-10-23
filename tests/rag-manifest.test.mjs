// The reference-library pipeline (rag/ and worker/scripts/embed-books.mjs), offline.
// poppler (pdfinfo, pdftotext, pdftoppm) and tesseract are replaced by small stand-ins
// on PATH that read the simple PDFs generated here, so the tests need neither installed.
// Cloudflare's embedding API is a local HTTP stub.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { planEmbedding, metadataFor, MAX_VECTORS, BATCH } from '../worker/scripts/embed-books.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

// ---------- fixtures ----------

const SENTENCES = [
  'A firewall filters traffic between networks based on rules that an administrator defines for each service.',
  'Defenders should log every change to those rules, because an attacker who gains access will often open a quiet path for later use.',
  'Segmentation limits how far an intruder can move once they are inside, and it makes unusual traffic easier to notice.',
  'Patch management is the routine work of finding, testing and installing updates before known flaws are exploited.',
  'Multi-factor authentication stops most password spraying, but it must also cover remote access and administrative accounts.',
  'An incident response plan names who decides what, how evidence is kept, and when the business must be told.',
  'Backups only help if they are tested, kept offline or immutable, and restored often enough that the team trusts them.',
  'Phishing remains the most common way in, so reporting buttons and quick feedback to staff matter more than annual training.',
];
const prose = (page) => Array.from({ length: 14 }, (_, i) => SENTENCES[(page * 3 + i) % SENTENCES.length]).join(' ');

/** A minimal valid PDF, one content stream per page ("" for an image-only "scanned" page). */
function makePdf(pages) {
  const objs = [];
  const add = (body) => { objs.push(body); return objs.length; };
  const catalog = add(null);
  const pagesObj = add(null);
  const font = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  const kids = [];
  for (const text of pages) {
    const stream = text ? `BT /F1 10 Tf 72 720 Td (${text}) Tj ET` : 'q Q';
    const content = add(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
    kids.push(add(`<< /Type /Page /Parent ${pagesObj} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${font} 0 R >> >> /Contents ${content} 0 R >>`));
  }
  objs[catalog - 1] = `<< /Type /Catalog /Pages ${pagesObj} 0 R >>`;
  objs[pagesObj - 1] = `<< /Type /Pages /Kids [${kids.map((k) => `${k} 0 R`).join(' ')}] /Count ${kids.length} >>`;
  let out = '%PDF-1.4\n';
  const offsets = objs.map((body, i) => { const at = out.length; out += `${i + 1} 0 obj\n${body}\nendobj\n`; return at; });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root ${catalog} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

function makeBooks(dir) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'text-book.pdf'), makePdf([0, 1, 2, 3, 4, 5].map(prose)));
  fs.writeFileSync(path.join(dir, 'scanned-book.pdf'), makePdf(['', '', '']));
  fs.writeFileSync(path.join(dir, 'locked-book.pdf'), Buffer.concat([makePdf([prose(0)]), Buffer.from('% /Encrypt marker for the stub\n')]));
  fs.writeFileSync(path.join(dir, 'broken.pdf'), Buffer.from('this is not a pdf at all'));
  fs.writeFileSync(path.join(dir, 'notes.txt'), 'ignored');
  fs.mkdirSync(path.join(dir, 'subfolder'));
  fs.writeFileSync(path.join(dir, 'subfolder', 'nested.pdf'), makePdf([prose(1)]));
}

// Stand-ins for poppler and tesseract (Python, so they run anywhere the pipeline does).
const STUBS = {
  pdfinfo: `import sys, re
data = open(sys.argv[-1], 'rb').read()
if not data.startswith(b'%PDF-'):
    sys.stderr.write("Syntax Error: Couldn't find trailer dictionary\\n"); sys.exit(1)
if b'/Encrypt' in data:
    sys.stderr.write('Command Line Error: Incorrect password\\n'); sys.exit(1)
print('Pages:          %d' % len(re.findall(rb'/Type /Page\\b(?!s)', data)))
`,
  pdftotext: `import sys, re
data = open(sys.argv[-2], 'rb').read()
if not data.startswith(b'%PDF-') or b'/Encrypt' in data: sys.exit(1)
pages = [b' '.join(re.findall(rb'\\((.*?)\\) Tj', s)).decode() for s in re.findall(rb'stream\\n(.*?)\\nendstream', data, re.S)]
sys.stdout.write('\\f'.join(pages) + '\\f')
`,
  pdftoppm: `import sys
args = sys.argv[1:]
n = args[args.index('-f') + 1]
open('%s-%s.png' % (args[-1], n), 'wb').write(b'not really a png')
`,
  tesseract: `import sys
open(sys.argv[2] + '.txt', 'w').write(${JSON.stringify(SENTENCES.join(' ') + ' ' + SENTENCES.slice().reverse().join(' '))})
`,
};

function stubBin() {
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'slh-stubs-'));
  for (const [name, src] of Object.entries(STUBS)) {
    fs.writeFileSync(path.join(bin, name), `#!/usr/bin/env python3\n${src}`, { mode: 0o755 });
  }
  return bin;
}

const env = (bin, extra = {}) => ({ ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`, ...extra });
const run = (cmd, args, opts) => spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', ...opts });
// Async, so a stub server in this process can answer the child (spawnSync would block it).
const runAsync = (cmd, args, opts) => new Promise((resolve) => {
  const child = spawn(cmd, args, { cwd: ROOT, ...opts });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', (d) => { stderr += d; });
  child.on('close', (status) => resolve({ status, stdout, stderr }));
});
const sha8 = (file) => `s${createHash('sha256').update(fs.readFileSync(file)).digest('hex').slice(0, 8)}`;

function listFiles(dir) {
  const out = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else out.push(path.relative(dir, p)); } };
  walk(dir);
  return out.sort();
}

let hasPython = true;
try { execFileSync('python3', ['--version']); } catch { hasPython = false; }
let hasGit = true;
try { execFileSync('git', ['rev-parse', '--git-dir'], { cwd: ROOT, stdio: 'ignore' }); } catch { hasGit = false; }

// ---------- build_manifest.py ----------

test('manifest: text PDF, scanned PDF needing OCR, unreadable files skipped; ids stable; writes only .rag/', { skip: !hasPython && 'python3 not available' }, () => {
  const bin = stubBin();
  const books = fs.mkdtempSync(path.join(os.tmpdir(), 'slh-books-'));
  try {
    makeBooks(books);
    const before = listFiles(books);
    const r = run('python3', ['rag/build_manifest.py', '--books', books], { env: env(bin) });
    assert.equal(r.status, 0, r.stderr);
    const manifest = JSON.parse(fs.readFileSync(path.join(books, '.rag', 'manifest.json'), 'utf8'));
    const byFile = Object.fromEntries(manifest.books.map((b) => [b.file, b]));
    assert.deepEqual(Object.keys(byFile).sort(), ['scanned-book.pdf', 'text-book.pdf'], 'only top-level PDF/EPUB that can be read');
    assert.equal(byFile['text-book.pdf'].ocr, false);
    assert.equal(byFile['text-book.pdf'].pages, 6);
    assert.equal(byFile['scanned-book.pdf'].ocr, true);
    assert.equal(byFile['text-book.pdf'].id, sha8(path.join(books, 'text-book.pdf')));
    assert.match(byFile['scanned-book.pdf'].id, /^s[0-9a-f]{8}$/);
    assert.deepEqual(manifest.skipped.map((s) => s.file).sort(), ['broken.pdf', 'locked-book.pdf']);
    assert.match(manifest.skipped.find((s) => s.file === 'locked-book.pdf').reason, /encrypted or DRM/);

    // Re-running keeps ids (and hand-set fields); renaming a file keeps its id.
    manifest.books[0].ocr_source = 'raw';
    fs.writeFileSync(path.join(books, '.rag', 'manifest.json'), JSON.stringify(manifest));
    fs.renameSync(path.join(books, 'text-book.pdf'), path.join(books, 'renamed.pdf'));
    assert.equal(run('python3', ['rag/build_manifest.py', '--books', books], { env: env(bin) }).status, 0);
    const again = JSON.parse(fs.readFileSync(path.join(books, '.rag', 'manifest.json'), 'utf8'));
    assert.equal(again.books.find((b) => b.file === 'renamed.pdf').id, byFile['text-book.pdf'].id);
    assert.equal(again.books.find((b) => b.id === manifest.books[0].id).ocr_source, 'raw');

    const after = listFiles(books).filter((f) => f !== 'renamed.pdf');
    const added = after.filter((f) => !before.includes(f));
    assert.deepEqual(added, ['.rag/manifest.json'], 'nothing written outside .rag/');
  } finally {
    fs.rmSync(books, { recursive: true, force: true });
    fs.rmSync(bin, { recursive: true, force: true });
  }
});

test('pipeline scripts refuse to run outside the repo root', { skip: !hasPython && 'python3 not available' }, () => {
  const elsewhere = os.tmpdir();
  for (const [cmd, args] of [
    ['python3', [path.join(ROOT, 'rag/build_manifest.py')]],
    ['python3', [path.join(ROOT, 'rag/ingest_books.py')]],
    ['bash', [path.join(ROOT, 'rag/ocr_books.sh')]],
    [process.execPath, [path.join(ROOT, 'worker/scripts/embed-books.mjs'), '--dry-run']],
  ]) {
    const r = spawnSync(cmd, args, { cwd: elsewhere, encoding: 'utf8' });
    assert.notEqual(r.status, 0, args[0]);
    assert.match(r.stderr, /Run this from the repo root/, args[0]);
  }
});

// ---------- embed-books.mjs budget guard ----------

const fakeChunks = (book, n) => Array.from({ length: n }, (_, i) => ({ id: `${book}-${String(i).padStart(4, '0')}`, book_id: book, text: SENTENCES[i % SENTENCES.length].repeat(3) }));

test('budget guard: whole books up to 9,000 vectors; books that do not fit are listed', () => {
  const chunks = [...fakeChunks('sa', 5000), ...fakeChunks('sb', 3000), ...fakeChunks('sc', 2000), ...fakeChunks('sd', 900)];
  const plan = planEmbedding(chunks, new Set(), { maxNeurons: Infinity });
  assert.equal(MAX_VECTORS, 9000);
  assert.deepEqual(plan.notFit, [{ book_id: 'sc', chunks: 2000 }]);
  assert.equal(plan.total, 8900, 'sd still fits after sc is left out');
  assert.equal(plan.todo.length, 8900);
  assert.ok(plan.total <= MAX_VECTORS);

  // Already-embedded vectors count toward the cap and are not redone.
  const done = new Set(chunks.slice(0, 5000).map((c) => c.id));
  const next = planEmbedding(chunks, done, { maxNeurons: Infinity });
  assert.equal(next.todo.length, 3900);
  assert.ok(next.todo.every((c) => !done.has(c.id)));
});

test('neuron guard: a run stops at its neuron budget and the rest is deferred', () => {
  // At Jaizz's rate the whole 9,000-vector cap is ~7,730 neurons, so the default 8,000
  // budget fits in one run; a smaller budget shows the stop.
  const full = planEmbedding(fakeChunks('sa', 9000), new Set());
  assert.equal(full.deferred, 0);
  assert.ok(full.todo.length * (2550 / 2968) <= 8000);
  const plan = planEmbedding(fakeChunks('sa', 9000), new Set(), { maxNeurons: 1000 });
  assert.ok(plan.todo.length * (2550 / 2968) <= 1000, `${plan.todo.length} chunks`);
  assert.equal(plan.todo.length % BATCH, 0);
  assert.equal(plan.deferred, 9000 - plan.todo.length);
});

test('vector metadata is the chunk text and the book id only', () => {
  assert.deepEqual(metadataFor({ id: 'sa-0001', book_id: 'sa', text: 't', section: 'Chapter 1: Secret Title', pdf_page: 3, words: 1 }), { book_id: 'sa', text: 't' });
});

// ---------- full pipeline inside the gitignored folder ----------

function cfStub() {
  let calls = 0;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      calls++;
      const { text } = JSON.parse(body);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ success: true, result: { shape: [text.length, 384], data: text.map(() => new Array(384).fill(0.01)) } }));
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, calls: () => calls })));
}

test('full pipeline run inside security-books/ leaves git status unchanged', { timeout: 60000, skip: (!hasPython || !hasGit) && 'python3 or git not available' }, async () => {
  const bin = stubBin();
  const books = path.join(ROOT, 'security-books', `_pipeline-test-${process.pid}`);
  const status = () => execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: ROOT, encoding: 'utf8' });
  const cf = await cfStub();
  try {
    const before = status();
    makeBooks(books);
    const e = env(bin, { CF_API_BASE: `http://127.0.0.1:${cf.port}`, CLOUDFLARE_ACCOUNT_ID: 'test-account', CLOUDFLARE_API_TOKEN: 'test-token' });
    for (const [cmd, args, extra] of [
      ['python3', ['rag/build_manifest.py', '--books', books]],
      ['bash', ['rag/ocr_books.sh'], { BOOKS_DIR: books }],
      ['python3', ['rag/ingest_books.py', '--books', books]],
      [process.execPath, ['worker/scripts/embed-books.mjs', '--books', books]],
    ]) {
      const r = await runAsync(cmd, args, { env: { ...e, ...extra } });
      assert.equal(r.status, 0, `${args[0]}: ${r.stderr}\n${r.stdout}`);
    }
    const rag = path.join(books, '.rag');
    const chunks = fs.readFileSync(path.join(rag, 'chunks.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const manifest = JSON.parse(fs.readFileSync(path.join(rag, 'manifest.json'), 'utf8'));
    const ids = manifest.books.map((b) => b.id).sort();
    assert.deepEqual([...new Set(chunks.map((c) => c.book_id))].sort(), ids, 'the text book and the OCRed book both produced chunks');
    for (const c of chunks) {
      assert.match(c.id, /^s[0-9a-f]{8}-\d{4}$/);
      assert.ok(!('book' in c) && !('author' in c) && !('cite' in c), 'no titles or authors in chunks');
    }
    const vectors = fs.readFileSync(path.join(rag, 'vectors.ndjson'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(vectors.length, chunks.length);
    for (const v of vectors) {
      assert.deepEqual(Object.keys(v.metadata).sort(), ['book_id', 'text']);
      assert.equal(v.values.length, 384);
    }
    assert.ok(fs.readFileSync(path.join(rag, 'report.txt'), 'utf8').includes('locked-book.pdf'), 'unreadable books are in the report');
    // Resumable: a second run embeds nothing new.
    const callsBefore = cf.calls();
    assert.equal((await runAsync(process.execPath, ['worker/scripts/embed-books.mjs', '--books', books], { env: e })).status, 0);
    assert.equal(cf.calls(), callsBefore);

    assert.deepEqual(listFiles(books).filter((f) => !f.startsWith('.rag/')).sort(), ['broken.pdf', 'locked-book.pdf', 'notes.txt', 'scanned-book.pdf', 'subfolder/nested.pdf', 'text-book.pdf'], 'scripts only write under .rag/');
    assert.equal(status(), before, 'git status --porcelain shows nothing new');
  } finally {
    cf.server.close();
    fs.rmSync(books, { recursive: true, force: true });
    fs.rmSync(bin, { recursive: true, force: true });
  }
});

test('ingest skips a book that is not in English and reports it', { skip: !hasPython && 'python3 not available' }, () => {
  const bin = stubBin();
  const books = fs.mkdtempSync(path.join(os.tmpdir(), 'slh-books-'));
  try {
    const italian = 'Il firewall filtra il traffico tra le reti secondo regole che un amministratore definisce per ogni servizio della rete aziendale nella sede principale.';
    fs.writeFileSync(path.join(books, 'libro.pdf'), makePdf(Array.from({ length: 4 }, () => `${italian} `.repeat(8))));
    assert.equal(run('python3', ['rag/build_manifest.py', '--books', books], { env: env(bin) }).status, 0);
    const r = run('python3', ['rag/ingest_books.py', '--books', books], { env: env(bin) });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /SKIPPED: not English/);
    assert.equal(fs.readFileSync(path.join(books, '.rag', 'chunks.jsonl'), 'utf8').trim(), '');
  } finally {
    fs.rmSync(books, { recursive: true, force: true });
    fs.rmSync(bin, { recursive: true, force: true });
  }
});
