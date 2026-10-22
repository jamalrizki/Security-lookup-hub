// Ask's reference library (RAG). Ported from Jaizz Chat (jazz-fact-chat,
// worker/src/books.js): same embedding model, reranker, cutoffs and passage cap.
//
//   1. Embed the question with the SAME model used at index time
//      (worker/scripts/embed-books.mjs); vectors from two models can't be compared.
//   2. Pull a wide candidate pool from Vectorize (BOOKS binding).
//   3. Rerank question + passage together and keep the best few.
//
// The library's sources are never named: vectors carry only the chunk text and
// an opaque book id. Passage text travels Vectorize -> this function -> the
// model, and never reaches the page or the trace.

export const EMBED_MODEL = '@cf/baai/bge-small-en-v1.5';
export const EMBED_DIMS = 384;
// Embedding scores from a small model bunch into a narrow band for on- and
// off-topic passages alike, so the reranker does the real choosing.
export const RERANK_MODEL = '@cf/baai/bge-reranker-base';

const FETCH_K = 30; // candidate pool (Vectorize allows up to 50 with metadata)
const RETURN_N = 3; // passages given to the model (Groq free tier: ~8k tokens a minute)
const MIN_SCORE = 0.5; // coarse embedding floor; only drops garbage
const RERANK_MIN = 0.5; // in Jaizz's tests on-topic passages scored 0.69-0.97, off-topic 0.00-0.44
const MAX_PASSAGE_CHARS = 2200;

const NOTE = 'Background from the reference library. Explain it in your own words: do not quote or copy phrasing, '
  + 'and do not name or cite the source, its title or its authors. If the passages do not answer the question, say so.';

/** "s1a2b3c4d-42" -> { book: "s1a2b3c4d", n: 42 } */
function idParts(id) {
  const m = /^(.*)-(\d+)$/.exec(String(id));
  return m ? { book: m[1], n: Number(m[2]) } : { book: String(id), n: -1 };
}

function clip(text, max) {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  const space = cut.lastIndexOf(' ');
  return `${cut.slice(0, space > max * 0.8 ? space : max)}…`;
}

/** Chooses which matches to use: threshold, neighbour dedupe, size cap. No network. */
export function pickPassages(matches, { max = RETURN_N, minScore = MIN_SCORE, minRerank = RERANK_MIN } = {}) {
  const picked = [];
  const reranked = matches.length > 0 && matches.every((m) => typeof m.rerank === 'number');
  const ordered = [...matches]
    .filter((m) => m.score >= minScore && (!reranked || m.rerank >= minRerank))
    .sort((a, b) => (reranked ? b.rerank - a.rerank : b.score - a.score));
  for (const m of ordered) {
    if (picked.length >= max) break;
    const text = m.metadata?.text;
    if (typeof text !== 'string' || !text.trim()) continue;
    const p = idParts(m.id);
    // Chunks overlap by 50 words, so a neighbour of one we already have is mostly repeated text.
    if (picked.some((q) => q.book === p.book && Math.abs(q.n - p.n) === 1)) continue;
    picked.push({ ...p, id: m.id, score: m.score, rerank: m.rerank, text: clip(text, MAX_PASSAGE_CHARS) });
  }
  return picked;
}

/**
 * Scores every candidate against the question. Returns the matches with a
 * numeric `rerank`, or null if the reply looks wrong (then embedding order is
 * used, so a reranker hiccup degrades the answer instead of breaking the tool).
 */
async function rerank(query, matches, env) {
  const usable = matches.filter((m) => typeof m.metadata?.text === 'string' && m.metadata.text.trim());
  if (usable.length < 2) return null;
  try {
    const out = await env.AI.run(RERANK_MODEL, {
      query,
      contexts: usable.map((m) => ({ text: m.metadata.text })),
      top_k: usable.length,
    });
    const rows = out?.response;
    if (!Array.isArray(rows) || rows.length === 0) return null;
    const scored = new Map();
    for (const r of rows) {
      if (!Number.isInteger(r?.id) || r.id < 0 || r.id >= usable.length || typeof r.score !== 'number' || !Number.isFinite(r.score)) return null;
      scored.set(r.id, r.score);
    }
    if (scored.size !== usable.length) return null;
    return usable.map((m, i) => ({ ...m, rerank: scored.get(i) }));
  } catch {
    return null;
  }
}

/** Returns { found: false, message } or { found: true, passages: [{ text }], note }. */
export async function searchReference(query, env) {
  // Ask works before the index exists: without the bindings the model is told
  // to answer from general knowledge or the other tools.
  if (!env?.AI || !env?.BOOKS) {
    return { found: false, message: 'The reference library is not available. Use the other tools, or answer well-known basics directly.' };
  }
  const emb = await env.AI.run(EMBED_MODEL, { text: [query] });
  const vector = emb?.data?.[0];
  if (!Array.isArray(vector) || vector.length !== EMBED_DIMS) throw new Error('embedding failed');

  const res = await env.BOOKS.query(vector, { topK: FETCH_K, returnMetadata: 'all' });
  const candidates = res?.matches || [];
  const reranked = await rerank(query, candidates.filter((m) => m.score >= MIN_SCORE), env);
  const passages = pickPassages(reranked || candidates);

  // Local debugging only (DEBUG_ASK=1 in worker/.dev.vars): ids and scores to the
  // wrangler dev console. Never passage text, never into the response.
  if (env.DEBUG_ASK === '1') {
    console.log('[reference]', JSON.stringify({
      reranked: Boolean(reranked),
      used: passages.map((p) => ({ id: p.id, sim: Number(p.score.toFixed(3)), rerank: p.rerank === undefined ? undefined : Number(p.rerank.toFixed(3)) })),
    }));
  }

  if (!passages.length) {
    return { found: false, message: 'Nothing in the reference library matched closely. Try web_search, or say you could not find it; do not guess specifics.' };
  }
  return { found: true, passages: passages.map((p) => ({ text: p.text })), note: NOTE };
}
