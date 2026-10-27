// Phase 18, Worker side: the visitor's Stop (request.signal) ends the loop. No more
// model or tool calls after it fires, and it never looks like a provider failure.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/src/index.js';
import { askTiming } from '../worker/src/ask.js';
import { _resetKevCache } from '../worker/src/cve.js';
import { ORIGIN, installCaches, exec, memoryKv, installFetch, modelScript, toolCall, say, cveRoutes, PHP_CVE } from './helpers/ask-stubs.mjs';

const GROQ = 'api.groq.com';
const ANTHROPIC = 'api.anthropic.com/v1/messages';

beforeEach(() => {
  installCaches();
  _resetKevCache();
  askTiming.sleep = async () => {};
});

const stoppable = (messages, controller, path = '/api/ask') => new Request(`https://security-lookup-hub.example${path}`, {
  method: 'POST',
  headers: { origin: ORIGIN, 'content-type': 'application/json' },
  body: JSON.stringify(path === '/api/ask' ? { messages } : messages),
  signal: controller.signal,
});

test('aborted between tool rounds: the loop stops and the model is not called again', async () => {
  const controller = new AbortController();
  const model = modelScript([toolCall(['cve_lookup', { cve_id: PHP_CVE }]), say('should never be asked for')]);
  const routes = cveRoutes();
  // The visitor presses Stop while the CVE tool runs.
  routes[0] = ['services.nvd.nist.gov', (url) => { controller.abort(); return routes0(url); }];
  const routes0 = cveRoutes()[0][1];
  const calls = installFetch([[GROQ, model.handler], ...routes]);
  const env = { ALLOWED_ORIGINS: ORIGIN, ASK_MODEL: 'groq:openai/gpt-oss-120b', GROQ_API_KEY: 'k', NEWS: memoryKv() };
  const res = await worker.fetch(stoppable([{ role: 'user', content: `Is ${PHP_CVE} bad?` }], controller), env, exec());
  assert.equal(res.status, 499);
  assert.deepEqual(await res.json(), { error: 'Stopped.' });
  assert.equal(model.bodies.length, 1, 'one model call, none after the Stop');
  assert.equal(model.remaining(), 1);
  assert.equal(calls.filter((c) => c.url.includes(GROQ)).length, 1);
});

test('aborted before a second tool call in the same round: that tool never runs', async () => {
  const controller = new AbortController();
  const model = modelScript([toolCall(['recent_news', { filter: 'all' }], ['cve_lookup', { cve_id: PHP_CVE }])]);
  const kv = memoryKv();
  const realGet = kv.get.bind(kv);
  kv.get = async (k, t) => { if (k === 'news:v1') controller.abort(); return realGet(k, t); };
  const calls = installFetch([[GROQ, model.handler], ...cveRoutes()]);
  const env = { ALLOWED_ORIGINS: ORIGIN, ASK_MODEL: 'groq:openai/gpt-oss-120b', GROQ_API_KEY: 'k', NEWS: kv };
  const res = await worker.fetch(stoppable([{ role: 'user', content: `news on ${PHP_CVE}?` }], controller), env, exec());
  assert.equal(res.status, 499);
  assert.ok(!calls.some((c) => c.url.includes('nvd')), 'cve_lookup never ran');
});

test('the signal reaches the model calls (Groq fetch, Anthropic SDK), and a Stop is not a fallback reason', async () => {
  const controller = new AbortController();
  const seen = [];
  installFetch([
    [ANTHROPIC, (url, init) => {
      seen.push(init.signal);
      controller.abort();
      throw Object.assign(new Error('aborted'), { name: 'AbortError' });
    }],
    [GROQ, () => { throw new Error('Groq must not be used after a Stop'); }],
  ]);
  const env = { ALLOWED_ORIGINS: ORIGIN, ANTHROPIC_API_KEY: 'sk-ant', GROQ_API_KEY: 'k', OPENROUTER_API_KEY: 'or', NEWS: memoryKv() };
  const res = await worker.fetch(stoppable([{ role: 'user', content: 'What is MFA?' }], controller), env, exec());
  assert.equal(res.status, 499);
  assert.ok(seen[0], 'the Anthropic request carries a signal');
  assert.equal(seen[0].aborted, true, 'and it is the visitor\'s Stop');
  // A stopped question still counted toward the daily paid cap (taken at the start).
  assert.equal(env.NEWS.map.size, 1);

  const c2 = new AbortController();
  let groqSignal;
  installFetch([[GROQ, (url, init) => { groqSignal = init.signal; return { model: 'm', choices: [{ message: say('MFA is a second factor.') }] }; }]]);
  const env2 = { ALLOWED_ORIGINS: ORIGIN, ASK_MODEL: 'groq:openai/gpt-oss-120b', GROQ_API_KEY: 'k', NEWS: memoryKv() };
  const ok = await worker.fetch(stoppable([{ role: 'user', content: 'What is MFA?' }], c2), env2, exec());
  assert.equal(ok.status, 200);
  c2.abort();
  assert.equal(groqSignal.aborted, true, 'the Groq fetch signal follows the visitor\'s Stop (and the timeout)');
});

test('Make it simpler stops the same way', async () => {
  const controller = new AbortController();
  controller.abort();
  installFetch([[GROQ, () => { throw new Error('not called'); }]]);
  const env = { ALLOWED_ORIGINS: ORIGIN, ASK_MODEL: 'groq:openai/gpt-oss-120b', GROQ_API_KEY: 'k', NEWS: memoryKv() };
  const res = await worker.fetch(stoppable({ question: 'q', answer: 'a long answer' }, controller, '/api/ask/simplify'), env, exec());
  assert.equal(res.status, 499);
});

test('wrangler.toml opts in to request.signal on client disconnect', async () => {
  const { readFileSync } = await import('node:fs');
  const toml = readFileSync(new URL('../worker/wrangler.toml', import.meta.url), 'utf8');
  assert.match(toml, /^compatibility_flags = \["enable_request_signal"\]$/m);
});
