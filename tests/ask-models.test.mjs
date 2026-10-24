// Ask's model setting, the Anthropic adapter and the free Groq fallback, offline.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/src/index.js';
import { askTiming } from '../worker/src/ask.js';
import { askModel, isBillingError, toAnthropic, fromAnthropic, DEFAULT_ASK_MODEL, DAILY_PAID_QUESTIONS, ALL_BUSY, takePaidQuestion } from '../worker/src/ask-models.js';
import { _resetKevCache } from '../worker/src/cve.js';
import { ORIGIN, installCaches, exec, memoryKv, installFetch, modelScript, say, askRequest, cveRoutes, PHP_CVE } from './helpers/ask-stubs.mjs';

const ANTHROPIC = 'api.anthropic.com/v1/messages';
const GROQ = 'api.groq.com';
const env = (extra = {}) => ({ ALLOWED_ORIGINS: ORIGIN, ANTHROPIC_API_KEY: 'sk-ant-test', GROQ_API_KEY: 'gsk-test', NEWS: memoryKv(), ...extra });

async function ask(content, e) {
  const res = await worker.fetch(askRequest([{ role: 'user', content }]), e, exec());
  return { status: res.status, body: await res.json() };
}

beforeEach(() => {
  installCaches();
  _resetKevCache();
  askTiming.sleep = async () => {};
});

/** A scripted Messages API: each step is a list of content blocks, a function(body) -> blocks, or { httpStatus, error }. */
function claudeScript(steps) {
  const queue = [...steps];
  const bodies = [];
  const handler = (url, init, body) => {
    bodies.push(body);
    if (!queue.length) throw new Error('Claude script ran out of steps');
    let step = queue.shift();
    if (typeof step === 'function') step = step(body);
    if (step.httpStatus) return { httpStatus: step.httpStatus, text: JSON.stringify({ type: 'error', error: step.error }) };
    const usesTool = step.some((b) => b.type === 'tool_use');
    return {
      id: `msg_${bodies.length}`, type: 'message', role: 'assistant', model: body.model, content: step,
      stop_reason: usesTool ? 'tool_use' : 'end_turn', stop_sequence: null,
      usage: { input_tokens: 100, output_tokens: 20, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 },
    };
  };
  return { handler, bodies, remaining: () => queue.length };
}
const thinking = (text) => ({ type: 'thinking', thinking: text, signature: `sig-${text.length}` });
const toolUse = (id, name, input) => ({ type: 'tool_use', id, name, input });
const text = (t) => ({ type: 'text', text: t });

/* ---------- setting ---------- */

test('ASK_MODEL: provider prefix, default Claude Haiku 5.5, anything malformed means the default', () => {
  assert.equal(DEFAULT_ASK_MODEL, 'anthropic:claude-haiku-5-5');
  assert.deepEqual(askModel({}), { provider: 'anthropic', model: 'claude-haiku-5-5' });
  assert.deepEqual(askModel({ ASK_MODEL: 'anthropic:claude-sonnet-5-5' }), { provider: 'anthropic', model: 'claude-sonnet-5-5' });
  assert.deepEqual(askModel({ ASK_MODEL: 'groq:openai/gpt-oss-120b' }), { provider: 'groq', model: 'openai/gpt-oss-120b' });
  assert.deepEqual(askModel({ ASK_MODEL: 'openai:gpt-5.5-mini' }), { provider: 'openai', model: 'gpt-5.5-mini' });
  for (const bad of ['claude-haiku-5-5', 'mistral:large', 'anthropic:', ' : ']) assert.deepEqual(askModel({ ASK_MODEL: bad }), { provider: 'anthropic', model: 'claude-haiku-5-5' }, bad);
});

test('billing errors: credit balance, billing_error, bad key, insufficient_quota; not overloads or bad requests', () => {
  assert.ok(isBillingError({ status: 400, message: '400 {"type":"error","error":{"type":"invalid_request_error","message":"Your credit balance is too low to access the Anthropic API."}}' }));
  assert.ok(isBillingError({ status: 403, error: { type: 'error', error: { type: 'billing_error' } } }));
  assert.ok(isBillingError({ status: 401 }));
  assert.ok(isBillingError({ status: 429, message: 'HTTP 429: {"error":{"code":"insufficient_quota"}}' }));
  assert.ok(isBillingError({ noKey: true }));
  assert.ok(!isBillingError({ status: 529, message: 'overloaded' }));
  assert.ok(!isBillingError({ status: 400, message: 'messages: roles must alternate' }));
  assert.ok(!isBillingError(new Error('fetch failed')));
});

/* ---------- adapter ---------- */

test('toAnthropic: cached system prompt, merged turns, tool results first, mid-conversation instructions as user text, Claude turns replayed as-is', () => {
  const raw = [thinking('plan'), toolUse('toolu_1', 'cve_lookup', { cve_id: PHP_CVE }), toolUse('toolu_2', 'recent_news', {})];
  const { system, messages } = toAnthropic([
    { role: 'system', content: 'You are Ask.' },
    { role: 'user', content: 'q1' },
    { role: 'assistant', content: 'a1' },
    { role: 'user', content: 'q2' },
    { role: 'assistant', content: null, tool_calls: [], claude: raw },
    { role: 'tool', tool_call_id: 'toolu_1', content: '{"x":1}' },
    { role: 'tool', tool_call_id: 'toolu_2', content: '{"y":2}' },
    { role: 'system', content: 'Tool budget used up.' },
    { role: 'assistant', content: null, tool_calls: [{ id: 'call_9', function: { name: 'web_search', arguments: '{"query":"php"}' } }] },
    { role: 'tool', tool_call_id: 'call_9', content: '{}' },
  ]);
  assert.deepEqual(system, [{ type: 'text', text: 'You are Ask.', cache_control: { type: 'ephemeral' } }]);
  assert.deepEqual(messages.map((m) => m.role), ['user', 'assistant', 'user', 'assistant', 'user', 'assistant', 'user']);
  assert.deepEqual(messages[3].content, raw, 'thinking + tool_use replayed unchanged');
  assert.deepEqual(messages[4].content.map((b) => b.type), ['tool_result', 'tool_result', 'text'], 'one user turn, results first');
  assert.match(messages[4].content[2].text, /^\[Ask service instruction\] Tool budget used up\.$/);
  assert.deepEqual(messages[5].content, [toolUse('call_9', 'web_search', { query: 'php' })], 'another provider\'s tool call converted');
});

test('fromAnthropic: text joined, tool_use -> tool_calls, raw blocks kept for replay', () => {
  const m = fromAnthropic({ content: [thinking('x'), text('Looking it up.'), toolUse('toolu_7', 'cve_lookup', { cve_id: PHP_CVE })] });
  assert.equal(m.content, 'Looking it up.');
  assert.deepEqual(m.tool_calls, [{ id: 'toolu_7', type: 'function', function: { name: 'cve_lookup', arguments: JSON.stringify({ cve_id: PHP_CVE }) } }]);
  assert.equal(m.claude.length, 3);
});

test('Claude Haiku 5.5 end to end: native tool use, thinking replayed, cached system, no temperature/thinking/effort sent', async () => {
  const claude = claudeScript([
    [thinking('need the CVE data'), toolUse('toolu_1', 'cve_lookup', { cve_id: PHP_CVE })],
    (body) => {
      const last = body.messages[body.messages.length - 1];
      assert.equal(last.role, 'user');
      assert.equal(last.content[0].type, 'tool_result');
      assert.equal(last.content[0].tool_use_id, 'toolu_1');
      assert.deepEqual(body.messages[body.messages.length - 2].content[0], thinking('need the CVE data'), 'thinking block passed back');
      return [text(`${PHP_CVE} is in CISA KEV; the hub's priority is to patch urgently.`)];
    },
  ]);
  const calls = installFetch([[ANTHROPIC, claude.handler], ...cveRoutes()]);
  const { status, body } = await ask(`Is ${PHP_CVE} serious?`, env());
  assert.equal(status, 200);
  assert.equal(body.provider, 'anthropic');
  assert.equal(body.model, 'claude-haiku-5-5');
  assert.equal(body.fallback, undefined);
  assert.equal(body.trace[0].tool, 'cve_lookup');
  assert.ok(!calls.some((c) => c.url.includes(GROQ)), 'Groq not used');
  const first = claude.bodies[0];
  assert.equal(first.model, 'claude-haiku-5-5');
  assert.equal(first.max_tokens, 4000, 'room for adaptive thinking');
  assert.equal(first.temperature, undefined);
  assert.equal(first.thinking, undefined, 'no budget_tokens form: adaptive thinking is the default');
  assert.equal(first.output_config, undefined, 'effort stays at the model default');
  assert.deepEqual(first.tool_choice, { type: 'auto' });
  assert.equal(first.system[0].cache_control.type, 'ephemeral');
  assert.match(first.system[0].text, /^You are Ask/);
  assert.deepEqual(first.tools.map((t) => t.name), ['search_reference', 'web_search', 'recent_news', 'cve_lookup']);
  assert.ok(first.tools.every((t) => t.input_schema?.type === 'object' && !t.function));
  assert.deepEqual(first.messages, [{ role: 'user', content: [{ type: 'text', text: `Is ${PHP_CVE} serious?` }] }]);
});

test('ASK_EFFORT sets output_config.effort; Sonnet 5.5 is a setting away; the final round sends tool_choice none', async () => {
  const claude = claudeScript([[text('SPF lists the servers allowed to send mail for a domain.')]]);
  installFetch([[ANTHROPIC, claude.handler]]);
  await ask('What is SPF?', env({ ASK_EFFORT: 'high', ASK_MODEL: 'anthropic:claude-sonnet-5-5' }));
  assert.deepEqual(claude.bodies[0].output_config, { effort: 'high' });
  assert.equal(claude.bodies[0].model, 'claude-sonnet-5-5');

  const bad = claudeScript([[text('ok.')]]);
  installFetch([[ANTHROPIC, bad.handler]]);
  await ask('What is SPF?', env({ ASK_EFFORT: 'turbo' }));
  assert.equal(bad.bodies[0].output_config, undefined, 'an unknown effort is ignored');

  const loop = claudeScript([
    ...[1, 2, 3, 4].map((n) => [toolUse(`toolu_${n}`, 'search_reference', { query: `query number ${n}` })]),
    (body) => {
      assert.deepEqual(body.tool_choice, { type: 'none' });
      assert.match(body.messages.at(-1).content.at(-1).text, /Tool budget used up/);
      return [text('Done.')];
    },
  ]);
  installFetch([[ANTHROPIC, loop.handler]]);
  const { body } = await ask('Keep searching', env());
  assert.equal(loop.remaining(), 0);
  assert.equal(body.reply, 'Done.');
});

/* ---------- free fallback ---------- */

test('a credit-balance error from Anthropic moves the question to free Groq, and the response says so', async () => {
  const claude = claudeScript([{ httpStatus: 400, error: { type: 'invalid_request_error', message: 'Your credit balance is too low to access the Anthropic API. Please go to Plans & Billing to upgrade or purchase credits.' } }]);
  const groq = modelScript([say('SPF lists the servers allowed to send mail for a domain.')]);
  installFetch([[ANTHROPIC, claude.handler], [GROQ, groq.handler]]);
  const { status, body } = await ask('What is SPF?', env());
  assert.equal(status, 200);
  assert.equal(body.provider, 'groq');
  assert.equal(body.model, 'openai/gpt-oss-120b');
  assert.deepEqual(body.fallback, { from: 'anthropic:claude-haiku-5-5', reason: 'credit or billing' });
  assert.equal(claude.bodies.length, 1, 'no retry on a billing error');
});

test('no Anthropic key: straight to Groq; a non-billing Anthropic failure is not hidden by the fallback', async () => {
  const groq = modelScript([say('ok.')]);
  const calls = installFetch([[GROQ, groq.handler]]);
  const { body } = await ask('What is SPF?', env({ ANTHROPIC_API_KEY: undefined }));
  assert.deepEqual(body.fallback, { from: 'anthropic:claude-haiku-5-5', reason: 'no API key' });
  assert.ok(!calls.some((c) => c.url.includes('anthropic')));

  const claude = claudeScript([{ httpStatus: 404, error: { type: 'not_found_error', message: 'model: claude-haiku-9' } }]);
  const calls2 = installFetch([[ANTHROPIC, claude.handler], [GROQ, modelScript([say('x')]).handler]]);
  const r = await ask('What is SPF?', env({ ASK_MODEL: 'anthropic:claude-haiku-9' }));
  assert.equal(r.status, 502);
  assert.ok(!calls2.some((c) => c.url.includes(GROQ)));
});

test('the fallback holds for the rest of the question: once on Groq, later calls stay on Groq', async () => {
  const claude = claudeScript([{ httpStatus: 403, error: { type: 'billing_error', message: 'billing' } }]);
  const groq = modelScript([
    { role: 'assistant', content: null, tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'cve_lookup', arguments: JSON.stringify({ cve_id: PHP_CVE }) } }] },
    say(`${PHP_CVE}: patch urgently.`),
  ]);
  installFetch([[ANTHROPIC, claude.handler], [GROQ, groq.handler], ...cveRoutes()]);
  const { body } = await ask(`Tell me about ${PHP_CVE}`, env());
  assert.equal(claude.bodies.length, 1);
  assert.equal(groq.bodies.length, 2);
  assert.equal(body.fallback.reason, 'credit or billing');
  assert.ok(!JSON.stringify(groq.bodies[1].messages).includes('"claude"'), 'Claude-only fields are not sent to Groq');
});

/* ---------- the daily paid cap and the free chain ---------- */

const OPENROUTER = 'openrouter.ai';
const today = () => new Date().toISOString().slice(0, 10);

test('daily paid cap: 100 questions a day go to the paid model, counted in KV; then free Groq with a note', async () => {
  assert.equal(DAILY_PAID_QUESTIONS, 100);
  const news = memoryKv({ [`ask:paid:${today()}`]: '99' });
  const claude = claudeScript([[text('Answer from Claude.')]]);
  installFetch([[ANTHROPIC, claude.handler]]);
  let r = await ask('What is SPF?', env({ NEWS: news }));
  assert.equal(r.body.provider, 'anthropic', 'the 100th question still goes to the paid model');
  assert.equal(news.map.get(`ask:paid:${today()}`), '100');
  assert.deepEqual(news.puts.at(-1).opts, { expirationTtl: 172800 });

  const groq = modelScript([say('Answer from Groq.')]);
  const calls = installFetch([[ANTHROPIC, claudeScript([]).handler], [GROQ, groq.handler]]);
  r = await ask('What is SPF?', env({ NEWS: news }));
  assert.equal(r.body.provider, 'groq');
  assert.deepEqual(r.body.fallback, { from: 'anthropic:claude-haiku-5-5', reason: 'daily limit' });
  assert.ok(!calls.some((c) => c.url.includes('anthropic')), 'the paid model is not called after the cap');
  assert.equal(news.map.get(`ask:paid:${today()}`), '100', 'no write once the cap is reached');
});

test('the daily cap counts per UTC day, and only for a paid model', async () => {
  const store = new Map();
  const kv = { get: async (k) => store.get(k) ?? null, put: async (k, v) => { store.set(k, v); } };
  store.set('ask:paid:2026-10-23', '100');
  assert.equal(await takePaidQuestion(kv, new Date('2026-10-23T23:59:59Z')), false);
  assert.equal(await takePaidQuestion(kv, new Date('2026-10-24T00:00:01Z')), true, 'resets at midnight UTC');
  const news = memoryKv();
  installFetch([[GROQ, modelScript([say('ok.')]).handler]]);
  await ask('What is SPF?', env({ ASK_MODEL: 'groq:openai/gpt-oss-120b', NEWS: news }));
  assert.equal(news.puts.length, 0, 'the free model is not counted');
});

test('free chain: Groq busy -> OpenRouter answers, and the response says so', async () => {
  const groq = modelScript([{ httpStatus: 429, text: '{"error":{"message":"Rate limit reached. Please try again in 45s."}}' }]);
  const or = modelScript([(body) => { assert.equal(body.model, 'openrouter/free'); return say('Answer from OpenRouter.'); }]);
  installFetch([[GROQ, groq.handler], [OPENROUTER, (u, i, b) => ({ ...or.handler(u, i, b), model: 'meta-llama/llama-4-maverick:free' })]]);
  const { status, body } = await ask('What is SPF?', env({ ASK_MODEL: 'groq:openai/gpt-oss-120b', OPENROUTER_API_KEY: 'or-key' }));
  assert.equal(status, 200);
  assert.equal(body.provider, 'openrouter');
  assert.equal(body.model, 'meta-llama/llama-4-maverick:free', 'the model that actually answered');
  assert.deepEqual(body.relay, { from: 'groq', to: 'openrouter', reason: 'busy' });
});

test('free chain: a Groq timeout or 5xx also goes to OpenRouter; once there, the question stays there', async () => {
  const or = modelScript([
    { role: 'assistant', content: null, tool_calls: [{ id: 'c1', type: 'function', function: { name: 'cve_lookup', arguments: JSON.stringify({ cve_id: PHP_CVE }) } }] },
    say('done.'),
  ]);
  let groqCalls = 0;
  installFetch([[GROQ, () => { groqCalls++; return { httpStatus: 503, text: 'unavailable' }; }], [OPENROUTER, or.handler], ...cveRoutes()]);
  const { body } = await ask(`About ${PHP_CVE}`, env({ ASK_MODEL: 'groq:openai/gpt-oss-120b', OPENROUTER_API_KEY: 'or-key' }));
  assert.equal(groqCalls, 1, 'Groq is not retried for the rest of the question');
  assert.equal(or.bodies.length, 2);
  assert.equal(body.relay.reason, 'unavailable');

  const slow = modelScript([say('from OpenRouter after a timeout.')]);
  installFetch([[GROQ, () => { throw Object.assign(new Error('timed out'), { name: 'TimeoutError' }); }], [OPENROUTER, slow.handler]]);
  const r = await ask('What is SPF?', env({ ASK_MODEL: 'groq:openai/gpt-oss-120b', OPENROUTER_API_KEY: 'or-key' }));
  assert.equal(r.body.relay.reason, 'timeout');
});

test('paid cap reached + Groq busy -> OpenRouter, with both notes; everything busy -> "all free AI providers are busy"', async () => {
  const news = memoryKv({ [`ask:paid:${today()}`]: '100' });
  installFetch([[GROQ, () => ({ httpStatus: 429, text: 'try again in 30s' })], [OPENROUTER, modelScript([say('ok.')]).handler]]);
  let r = await ask('What is SPF?', env({ NEWS: news, OPENROUTER_API_KEY: 'or-key' }));
  assert.equal(r.body.fallback.reason, 'daily limit');
  assert.equal(r.body.relay.to, 'openrouter');

  installFetch([[GROQ, () => ({ httpStatus: 429, text: 'try again in 30s' })], [OPENROUTER, () => ({ httpStatus: 429, text: 'rate limited' })]]);
  r = await ask('What is SPF?', env({ NEWS: news, OPENROUTER_API_KEY: 'or-key' }));
  assert.equal(r.status, 429);
  assert.equal(r.body.error, ALL_BUSY);
  assert.equal(ALL_BUSY, 'All free AI providers are busy. Try again in a minute.');
});

test('no hub-side Groq guards: no per-minute counter, no pause after a 429 (Ask and Explain)', async () => {
  const cache = installCaches();
  installFetch([[GROQ, () => ({ httpStatus: 429, text: 'try again in 30s' })]]);
  await ask('What is SPF?', env({ ASK_MODEL: 'groq:openai/gpt-oss-120b' }));
  assert.ok(![...cache.keys()].some((k) => /quota\/(ask|GROQ_API_KEY)|pause\/GROQ_API_KEY/.test(k)), [...cache.keys()].join());
  const src = (await import('node:fs')).readFileSync(new URL('../worker/src/index.js', import.meta.url), 'utf8');
  const explainRoute = src.slice(src.indexOf('async function explainRoute'), src.indexOf('export default'));
  assert.ok(!/allow\('GROQ_API_KEY'|paused\('GROQ_API_KEY'|pause\('GROQ_API_KEY'/.test(explainRoute), 'Explain has no Groq guard either');
});
