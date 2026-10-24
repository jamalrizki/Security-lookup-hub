// Plain-language modes: Explain "In plain English" and Ask "Make it simpler". Offline.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/src/index.js';
import { keepSourceFacts, newFacts } from '../worker/src/plain.js';
import { plainChecked, facts, PLAIN_SYSTEM } from '../worker/src/explain.js';
import { SIMPLIFY_SYSTEM } from '../worker/src/ask.js';
import { askTiming } from '../worker/src/ask.js';
import { ORIGIN, installCaches, exec, memoryKv, installFetch, modelScript, say, cveRoutes, PHP_CVE } from './helpers/ask-stubs.mjs';

beforeEach(() => { installCaches(); askTiming.sleep = async () => {}; });

const GROQ = 'api.groq.com';
const env = (extra = {}) => ({ ALLOWED_ORIGINS: ORIGIN, ASK_MODEL: 'groq:openai/gpt-oss-120b', GROQ_API_KEY: 'gsk', NEWS: memoryKv(), ...extra });

/* ---------- the shared "no new facts" check ---------- */

test('keepSourceFacts drops sentences that add a CVE ID, a link or a number; keeps rounding and small counts', () => {
  const source = `${PHP_CVE} has a CVSS score of 9.8 and an 11.6% chance of exploitation. Patch PHP to 8.3.36.`;
  const rewrite = [
    `${PHP_CVE} is very serious: it scores 9.8 out of 10.`,
    'There is about a 12% chance attackers use it soon.',
    'It was found by 40 researchers.',
    'Also see CVE-2026-999999.',
    'Read https://evil.example/x for more.',
    'Update PHP to 8.3.36 or newer.',
  ].join(' ');
  const out = keepSourceFacts(rewrite, source);
  assert.equal(out, `${PHP_CVE} is very serious: it scores 9.8 out of 10. There is about a 12% chance attackers use it soon. Update PHP to 8.3.36 or newer.`);
  assert.deepEqual(newFacts('Read https://evil.example/x.', source).urls, ['https://evil.example/x']);
});

/* ---------- Explain: In plain English ---------- */

const lookup = {
  type: 'cve', value: PHP_CVE,
  sources: [
    { id: 'nvd', name: 'NVD', status: 'ok', data: { id: PHP_CVE, status: 'Analyzed', cvss: { severity: 'CRITICAL', baseScore: 9.8, version: '3.1', plainEnglish: [], attackVector: 'NETWORK', privilegesRequired: 'NONE', userInteraction: 'NONE' }, weaknesses: [], published: '2024-06-09', description: 'Argument injection in PHP-CGI.' } },
    { id: 'kev', name: 'CISA KEV', status: 'ok', data: { inKev: true, dateAdded: '2024-06-12', ransomware: true } },
    { id: 'epss', name: 'FIRST EPSS', status: 'ok', data: { epss: 0.9436, percentile: 0.9995, scoreDate: '2026-10-21' } },
  ],
};

test('plain explanation keeps the verdict word for word and the numbers; invented numbers are dropped', () => {
  const f = facts(lookup);
  assert.equal(f.overall.verdict, 'Exploited in the wild: patch urgently');
  const model = 'This is a dangerous flaw in PHP. It scores 9.8 out of 10, and there is a 94.36% chance attackers will use it. Experts say 5000 servers are exposed.\nNext step: update PHP today.';
  const out = plainChecked(model, f);
  assert.ok(out.startsWith('Exploited in the wild: patch urgently\n'), 'verdict first, word for word, even when the model left it out');
  assert.match(out, /9\.8 out of 10/);
  assert.match(out, /94\.36%/);
  assert.ok(!out.includes('5000'), 'a number that is not in the facts is dropped');
  assert.match(out, /Next step: update PHP today\./);
  assert.equal(plainChecked('Exploited in the wild: patch urgently\nPatch now.', f), 'Exploited in the wild: patch urgently\nPatch now.', 'no duplicate verdict line');
});

test('GET /api/explain?style=plain: same Groq call and facts, the plain prompt, cached separately', async () => {
  const bodies = [];
  installFetch([
    [GROQ, (u, i, body) => { bodies.push(body); return { choices: [{ message: { content: body.messages[0].content === PLAIN_SYSTEM ? 'Plain words. Next step: patch.' : 'Exploited in the wild: patch urgently\n- NVD: 9.8.' } }] }; }],
    ...cveRoutes(),
  ]);
  const get = async (q) => (await worker.fetch(new Request(`https://w.example/api/explain?q=${PHP_CVE}${q}`, { headers: { origin: ORIGIN } }), env(), exec())).json();
  const plain = await get('&style=plain');
  const normal = await get('');
  assert.equal(plain.style, 'plain');
  assert.equal(plain.explanation, 'Exploited in the wild: patch urgently\nPlain words. Next step: patch.');
  assert.equal(normal.style, 'normal');
  assert.notEqual(plain.explanation, normal.explanation, 'separate cache entries');
  assert.equal(bodies.length, 2);
  assert.equal(bodies[0].messages[1].content, bodies[1].messages[1].content, 'the same facts go to the model');
  assert.equal(bodies[0].model, bodies[1].model);
  assert.equal((await get('&style=plain')).cached, true);
});

/* ---------- Ask: Make it simpler ---------- */

async function simplify(payload, e = env()) {
  const res = await worker.fetch(new Request('https://w.example/api/ask/simplify', {
    method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/json' }, body: JSON.stringify(payload),
  }), e, exec());
  return { status: res.status, body: await res.json() };
}

const ORIGINAL = `${PHP_CVE} is in CISA KEV. NVD scores it 9.8, and EPSS gives an 11.6% chance of exploitation. The hub's priority is to patch urgently.\n\n- Update PHP to 8.3.36.`;

test('the rewrite adds no CVE IDs, links or numbers that were not in the original; tools are off', async () => {
  const model = modelScript([(body) => {
    assert.equal(body.tool_choice, 'none');
    assert.equal(body.messages[0].content, SIMPLIFY_SYSTEM);
    assert.match(body.messages[1].content, /^Question:\nIs this PHP bug serious\?\n\nAnswer to rewrite:\n/);
    return say(`This PHP bug (${PHP_CVE}) is being used by attackers right now. It scores 9.8 out of 10. It is related to CVE-2024-9999. Read https://php.example/fix first. About 3000 sites are hit.\n\n- Update PHP to 8.3.36.`);
  }]);
  installFetch([[GROQ, model.handler]]);
  const { status, body } = await simplify({ question: 'Is this PHP bug serious?', answer: ORIGINAL });
  assert.equal(status, 200);
  assert.equal(body.reply, `This PHP bug (${PHP_CVE}) is being used by attackers right now. It scores 9.8 out of 10.\n\n- Update PHP to 8.3.36.`);
  assert.equal(body.model, 'openai/gpt-oss-120b');
});

test('simplify: validation, CORS, and the daily paid cap and fallback notes apply', async () => {
  installFetch([]);
  assert.equal((await simplify({ question: '', answer: 'x' })).status, 400);
  assert.equal((await simplify({ question: 'q', answer: 'x'.repeat(3001) })).status, 400);
  const pre = await worker.fetch(new Request('https://w.example/api/ask/simplify', { method: 'OPTIONS', headers: { origin: ORIGIN } }), env(), exec());
  assert.equal(pre.headers.get('access-control-allow-methods'), 'POST, OPTIONS');

  const day = new Date().toISOString().slice(0, 10);
  installFetch([[GROQ, modelScript([say('Simple words.')]).handler]]);
  const r = await simplify({ question: 'q', answer: 'Long answer.' }, env({ ASK_MODEL: 'anthropic:claude-haiku-5-5', ANTHROPIC_API_KEY: 'k', NEWS: memoryKv({ [`ask:paid:${day}`]: '100' }) }));
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.fallback, { from: 'anthropic:claude-haiku-5-5', reason: 'daily limit' });
});

test('prompt sizes', () => {
  assert.ok(PLAIN_SYSTEM.length < 1000, String(PLAIN_SYSTEM.length));
  assert.ok(SIMPLIFY_SYSTEM.length < 1200, String(SIMPLIFY_SYSTEM.length));
  assert.match(SIMPLIFY_SYSTEM, /busy executive, or a five-year-old/);
  assert.match(SIMPLIFY_SYSTEM, /No jargon, acronyms, CVE IDs, scores, percentages or version numbers/);
  assert.match(SIMPLIFY_SYSTEM, /"What to do:"/);
});

test('the simple version is capped at 1,200 characters in code', async () => {
  const long = Array.from({ length: 40 }, (_, i) => `Sentence ${i} keeps going about the same thing.`).join(' ');
  installFetch([[GROQ, modelScript([say(long)]).handler]]);
  const { body } = await simplify({ question: 'q', answer: long });
  assert.ok(body.reply.length <= 1202, String(body.reply.length));
});
