import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { preSendCheck, historyForSend, checkedHub, checkedSources, cvePrompt, answeredBy, PRIVATE_KEY_MESSAGE, MAX_HISTORY } from '../js/ask.js';

const root = new URL('../', import.meta.url);
const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const JWT = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ sub: '1234567890', name: 'Jane', iat: 1516239022 })}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;
const features = JSON.parse(readFileSync(new URL('data/hub-features.json', root), 'utf8')).features;

test('pre-send: a private key is blocked', () => {
  const r = preSendCheck('is this ok?\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----');
  assert.deepEqual(r, { block: PRIVATE_KEY_MESSAGE });
  assert.ok(preSendCheck('-----BEGIN OPENSSH PRIVATE KEY-----').block);
});

test('pre-send: a JWT offers the JWT decoder with just the token', () => {
  const r = preSendCheck(`How do I read this JWT? ${JWT}`);
  assert.equal(r.tool, 'jwt');
  assert.equal(r.name, 'JWT decoder');
  assert.equal(r.payload, JWT);
  assert.equal(preSendCheck('How do I read a JWT? Mine looks like aaaa.bbbb.cccc'), null, 'not JSON, not a JWT');
  assert.equal(preSendCheck('Is setup.tar.gz safe? see example.co.uk'), null);
});

test('pre-send: raw email headers offer the header analyzer', () => {
  const headers = 'Received: from a.example (a.example [203.0.113.5]) by mx.example; Tue, 21 Oct 2026 10:00:00 +0000\nReceived: from b.example by a.example; Tue, 21 Oct 2026 09:59:00 +0000\nFrom: x@example.org\nSubject: hi';
  const r = preSendCheck(`Is this phishing?\n${headers}`);
  assert.equal(r.tool, 'headers');
  assert.ok(r.payload.startsWith('Received:'));
  assert.equal(preSendCheck('Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=example.org').tool, 'headers');
  assert.equal(preSendCheck('What does a Received: header mean?'), null, 'one mention mid-sentence is a question, not headers');
});

test('pre-send: a PEM certificate offers the certificate viewer', () => {
  const pem = readFileSync(new URL('tests/fixtures/cert-rsa-selfsigned.pem', root), 'utf8');
  const r = preSendCheck(`What is wrong with this cert?\n${pem}`);
  assert.equal(r.tool, 'cert');
  assert.match(r.payload, /^-----BEGIN CERTIFICATE-----/);
  assert.equal(preSendCheck('What is Kerberoasting?'), null);
});

test('history: at most the last 8 messages are sent; long earlier answers are clipped', () => {
  const history = Array.from({ length: 10 }, (_, i) => ({ role: i % 2 ? 'assistant' : 'user', content: i === 9 ? 'a'.repeat(5000) : `m${i}` }));
  const sent = historyForSend(history, 'new question');
  assert.equal(sent.length, MAX_HISTORY);
  assert.equal(sent.at(-1).content, 'new question');
  assert.equal(sent.at(-1).role, 'user');
  assert.equal(sent.at(-2).content.length, 3000);
  assert.ok(sent.every((m) => ['user', 'assistant'].includes(m.role)));
});

test('"Ask about this CVE" fill text', () => {
  assert.equal(cvePrompt('CVE-2024-4577'), 'Explain CVE-2024-4577: what is it, is it being exploited, and what should I do?');
});

test('hub links are re-checked against data/hub-features.json; javascript: and unknown ids are dropped', () => {
  const hub = checkedHub([
    { id: 'jwt', name: 'X', href: './analyze.html#jwt' },
    { id: 'jwt', name: 'dup', href: './analyze.html#jwt' },
    { id: 'lookup', href: 'javascript:alert(1)' },
    { id: 'evil', href: './evil.html' },
    { id: 'news', href: 'https://evil.example/' },
    null,
  ], features);
  assert.deepEqual(hub, [{ id: 'jwt', name: 'JWT decoder', href: './analyze.html#jwt' }]);
  assert.deepEqual(checkedHub('nope', features), []);
});

test('sources: https only, no userinfo, javascript: dropped', () => {
  const s = checkedSources([
    { n: 1, title: 'ok', url: 'https://www.cisa.gov/a' },
    { n: 2, title: 'js', url: 'javascript:alert(1)' },
    { n: 3, title: 'http', url: 'http://www.cisa.gov/b' },
    { n: 4, title: 'user', url: 'https://u@www.cisa.gov/c' },
    { n: 5, title: 'data', url: 'data:text/html,<script>alert(1)</script>' },
  ]);
  assert.deepEqual(s.map((x) => x.url), ['https://www.cisa.gov/a']);
});

test('the page has the Ask box, its script, and keeps the existing CVE Explainer link', () => {
  const html = readFileSync(new URL('index.html', root), 'utf8');
  for (const id of ['ask', 'ask-form', 'ask-input', 'ask-send', 'ask-new', 'ask-count', 'ask-thread', 'ask-examples']) assert.ok(html.includes(`id="${id}"`), id);
  assert.ok(html.includes('<script type="module" src="js/ask.js"></script>'));
  assert.ok(html.includes('Your questions go to the AI model (Groq) and, for web searches, to Tavily. Nothing is stored.'));
  const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  assert.ok(csp.includes('https://security-lookup-hub.jamal-598.workers.dev'));
  const lookup = readFileSync(new URL('js/lookup.js', root), 'utf8');
  assert.ok(lookup.includes('Try CVE Explainer'));
  assert.ok(lookup.includes('Ask about this CVE'));
  const ask = readFileSync(new URL('js/ask.js', root), 'utf8');
  assert.ok(!/localStorage|location\.hash\s*=|history\.(push|replace)State/.test(ask), 'questions never stored or put in the URL');
});

test('Analyze handoff: taken once, by the right tool, and ignored after a minute', async () => {
  const store = new Map();
  globalThis.sessionStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
  const { takeHandoff, HANDOFF_KEY } = await import('../js/analyze/handoff.js');
  const { HANDOFF_KEY: askKey } = await import('../js/ask.js');
  assert.equal(HANDOFF_KEY, askKey, 'the Ask box and the Analyze page use the same key');
  const put = (h) => store.set(HANDOFF_KEY, JSON.stringify(h));
  put({ tool: 'jwt', text: 'eyJ.x.y', at: 1000 });
  assert.equal(takeHandoff('cert', 1500), null, 'another tool leaves it alone');
  assert.equal(takeHandoff('jwt', 1500), 'eyJ.x.y');
  assert.equal(takeHandoff('jwt', 1600), null, 'removed after the first read');
  put({ tool: 'jwt', text: 'old', at: 1000 });
  assert.equal(takeHandoff('jwt', 1000 + 61_000), null, 'stale');
  assert.equal(store.size, 0, 'a stale handoff is still removed');
  put({ tool: 'jwt', text: 'from an older cached ask.js' });
  assert.equal(takeHandoff('jwt', 5_000_000), 'from an older cached ask.js', 'no timestamp: accepted');
  delete globalThis.sessionStorage;
});

test('"Answered by" names the model that answered, and every step that changed it', () => {
  assert.equal(answeredBy({ model: 'claude-haiku-5-5' }), 'Answered by claude-haiku-5-5. AI can be wrong: check the sources.');
  assert.equal(answeredBy({ model: 'openai/gpt-oss-120b', fallback: { from: 'anthropic:claude-haiku-5-5', reason: 'credit or billing' } }),
    'Answered by openai/gpt-oss-120b (free fallback: claude-haiku-5-5 was unavailable). AI can be wrong: check the sources.');
  assert.match(answeredBy({ model: 'openai/gpt-oss-120b', fallback: { from: 'anthropic:claude-haiku-5-5', reason: 'no API key' } }), /was not configured/);
  assert.equal(answeredBy({ model: 'openai/gpt-oss-120b', fallback: { from: 'anthropic:claude-haiku-5-5', reason: 'daily limit' } }),
    "Answered by openai/gpt-oss-120b (today's AI limit (switched to the free model)). AI can be wrong: check the sources.");
  assert.equal(answeredBy({ model: 'meta-llama/llama-4-maverick:free', fallback: { reason: 'daily limit', from: 'anthropic:claude-haiku-5-5' }, relay: { from: 'groq', to: 'openrouter' } }),
    "Answered by meta-llama/llama-4-maverick:free (today's AI limit (switched to the free model); Groq is busy, answered by OpenRouter). AI can be wrong: check the sources.");
  assert.equal(answeredBy({}), 'Answered by the AI model. AI can be wrong: check the sources.');
});
