// The reference-library search ported from Jaizz Chat (worker/src/books.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pickPassages, searchReference, EMBED_MODEL, RERANK_MODEL } from '../worker/src/reference.js';

const m = (id, score, text = `text of ${id} `.repeat(5), rerank) => ({ id, score, metadata: { text, book_id: id.split('-')[0] }, ...(rerank === undefined ? {} : { rerank }) });

test('pickPassages: floors, reranker order, neighbour dedupe, 3 passages, 2,200 characters', () => {
  const picked = pickPassages([
    m('sa-1', 0.9, undefined, 0.6),
    m('sa-2', 0.8, undefined, 0.95), // best rerank
    m('sa-3', 0.7, undefined, 0.9), // neighbour of sa-2: skipped
    m('sb-9', 0.4, undefined, 0.99), // under the embedding floor
    m('sc-5', 0.7, 'x '.repeat(3000), 0.8),
    m('sd-1', 0.7, undefined, 0.45), // under the rerank floor
    m('se-1', 0.7, undefined, 0.7),
  ]);
  assert.deepEqual(picked.map((p) => p.id), ['sa-2', 'sc-5', 'se-1']);
  assert.ok(picked[1].text.length <= 2201);
});

test('searchReference: found false without bindings; text only, no ids, plus the "own words" note', async () => {
  assert.equal((await searchReference('q', {})).found, false);
  const used = [];
  const env = {
    AI: { run: async (model, input) => { used.push(model); return model === RERANK_MODEL ? { response: input.contexts.map((_, id) => ({ id, score: 0.9 })) } : { data: [new Array(384).fill(0)] }; } },
    BOOKS: { query: async (v, opts) => { assert.equal(opts.topK, 30); assert.equal(opts.returnMetadata, 'all'); return { matches: [m('s12345678-4', 0.8, 'Kerberoasting passage one. '.repeat(5)), m('s12345678-10', 0.7, 'Kerberoasting passage two. '.repeat(5))] }; } },
  };
  const r = await searchReference('What is Kerberoasting?', env);
  assert.equal(r.found, true);
  assert.deepEqual(Object.keys(r.passages[0]), ['text']);
  assert.ok(!JSON.stringify(r).includes('s12345678'));
  assert.match(r.note, /own words/);
  assert.match(r.note, /do not name or cite/);
  assert.deepEqual(used, [EMBED_MODEL, RERANK_MODEL]);
});

test('searchReference: nothing over the cutoff is found: false', async () => {
  const env = {
    AI: { run: async (model, input) => (model === RERANK_MODEL ? { response: input.contexts.map((_, id) => ({ id, score: 0.1 })) } : { data: [new Array(384).fill(0)] }) },
    BOOKS: { query: async () => ({ matches: [m('sa-1', 0.8), m('sa-5', 0.7)] }) },
  };
  assert.equal((await searchReference('Something off-topic', env)).found, false);
});
