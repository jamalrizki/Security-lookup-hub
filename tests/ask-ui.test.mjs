import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { preSendCheck, historyForSend, checkedHub, checkedSources, cvePrompt, answeredBy, PRIVATE_KEY_MESSAGE, MAX_HISTORY, askHref, lookupHref, readAskFragment, indicatorOnly, enterSends } from '../js/ask.js';

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

test('the Ask page is the chat: intro, examples, route to Lookup, thread, composer; Lookup keeps the CVE Explainer link', () => {
  const html = readFileSync(new URL('index.html', root), 'utf8');
  for (const id of ['ask', 'ask-empty', 'ask-form', 'ask-input', 'ask-send', 'ask-new', 'ask-top', 'ask-count', 'ask-thread', 'ask-examples', 'ask-notice']) assert.ok(html.includes(`id="${id}"`), id);
  assert.ok(html.includes('<script type="module" src="js/ask.js"></script>'));
  const empty = html.slice(html.indexOf('<div id="ask-empty"'), html.indexOf('<div class="chat-top"'));
  assert.match(empty, /<h1 id="ask-h" class="block-title">Ask AI<\/h1>/);
  const hints = [...empty.matchAll(/<p class="hint">([^<]*)<\/p>/g)].map((m) => m[1]);
  assert.deepEqual(hints, ['Ask AI a security question. Answers draw on a reference library, current security news and the hub’s data, and can be wrong.'], 'the Ask intro is exactly this one line');
  assert.match(empty, /Have an IP, domain, hash, URL or CVE\? <a href="\.\/lookup\.html">Look it up &rarr;<\/a>/);
  assert.equal((empty.match(/class="chip"/g) || []).length, 3, 'three example chips');
  // The composer comes after the thread, pinned to the bottom.
  assert.ok(html.indexOf('id="ask-thread"') < html.indexOf('id="ask-form"'));
  assert.match(html, /<div class="chat-dock">/);
  // The standard hero (Matrix redesign), first in <main>, before the chat.
  assert.ok(html.indexOf('<section class="hero">') > html.indexOf('<main id="main" class="chat-main">'));
  assert.ok(html.indexOf('<section class="hero">') < html.indexOf('<section class="chat"'));
  assert.match(html, /<h1 class="hero-title"><span class="hero-outline">Ask<\/span><span class="hero-fill" aria-hidden="true">Ask<\/span><\/h1>/);
  assert.match(html, /MODULE 01\/08/);
  assert.match(/<meta name="viewport" content="([^"]+)"/.exec(html)[1], /viewport-fit=cover/, 'safe-area insets apply');
  const css = readFileSync(new URL('css/style.css', root), 'utf8');
  assert.match(css, /\.chat-dock \{\s*position: sticky;\s*bottom: 0;/);
  assert.match(css, /env\(safe-area-inset-bottom/);
  assert.match(css, /min-height: 100dvh/);
  const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  assert.ok(csp.includes('https://security-lookup-hub.jamal-598.workers.dev'));
  const lookup = readFileSync(new URL('js/lookup.js', root), 'utf8');
  assert.ok(lookup.includes('Try CVE Explainer'));
  assert.ok(lookup.includes('Ask about this CVE'));
  assert.ok(lookup.includes('askHref(cvePrompt(id))'), '"Ask about this CVE" opens Ask with the question filled in');
  const ask = readFileSync(new URL('js/ask.js', root), 'utf8');
  assert.ok(!/localStorage|location\.hash\s*=|history\.pushState/.test(ask), 'questions never stored or put in the URL');
  const replaces = [...ask.matchAll(/history\.replaceState\(([^)]*)\)/g)].map((m) => m[1]);
  assert.deepEqual(replaces, ["null, '', location.pathname + location.search"], 'replaceState only ever removes the fragment');
});

test('#ask= fill links: decoded, capped at 1,000 characters, never anything else', () => {
  assert.equal(askHref(cvePrompt('CVE-2021-44228')), './#ask=Explain%20CVE-2021-44228%3A%20what%20is%20it%2C%20is%20it%20being%20exploited%2C%20and%20what%20should%20I%20do%3F');
  assert.equal(readAskFragment(askHref(cvePrompt('CVE-2021-44228')).slice(2)), cvePrompt('CVE-2021-44228'));
  assert.equal(readAskFragment('#ask=what+is+DMARC'), 'what is DMARC');
  assert.equal(readAskFragment(`#ask=${'a'.repeat(1500)}`).length, 1000);
  assert.equal(readAskFragment('#ask=%E0%A4%A'), null, 'malformed encoding is ignored');
  assert.equal(readAskFragment('#ask='), null);
  assert.equal(readAskFragment('#q=8.8.8.8'), null);
  assert.equal(readAskFragment(''), null);
  assert.equal(lookupHref('hxxp://bad[.]example'), './lookup.html#q=hxxp%3A%2F%2Fbad%5B.%5Dexample');
});

test('indicator-only questions: one indicator Lookup handles; a question that contains one is sent', () => {
  assert.deepEqual(indicatorOnly(' 8.8.8.8 '), { type: 'ipv4', value: '8.8.8.8', what: 'an IPv4 address' });
  assert.deepEqual(indicatorOnly('CVE-2021-44228'), { type: 'cve', value: 'CVE-2021-44228', what: 'a CVE ID' });
  assert.equal(indicatorOnly('example.com').what, 'a domain');
  assert.equal(indicatorOnly('hxxps://bad[.]example/login').what, 'a URL');
  assert.equal(indicatorOnly('a@example.com').what, 'an email address');
  assert.equal(indicatorOnly('2001:4860:4860::8888').what, 'an IPv6 address');
  assert.equal(indicatorOnly('5f4dcc3b5aa765d61d8327deb882cf99').what, 'an MD5 hash');
  assert.equal(indicatorOnly('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855').what, 'a SHA-256 hash');
  for (const q of ['is 8.8.8.8 safe to use as DNS?', 'phishing', 'Log4Shell', 'setup.exe', '10.0.0.1', 'What is CVE-2021-44228?']) assert.equal(indicatorOnly(q), null, q);
});

test('Enter sends on desktop, Shift+Enter is a new line; on touch screens Enter is a new line', () => {
  assert.equal(enterSends({ key: 'Enter' }, false), true);
  assert.equal(enterSends({ key: 'Enter', shiftKey: true }, false), false);
  assert.equal(enterSends({ key: 'Enter', isComposing: true }, false), false, 'IME composition');
  assert.equal(enterSends({ key: 'Enter' }, true), false);
  assert.equal(enterSends({ key: 'Enter', metaKey: true }, true), true, 'Cmd/Ctrl+Enter always sends');
  assert.equal(enterSends({ key: 'a' }, false), false);
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

test('section numbers come from page order: empty placeholders, a CSS counter, Lookup 01 first on its page', () => {
  const css = readFileSync(new URL('css/style.css', root), 'utf8');
  assert.match(css, /main \{ counter-reset: section; \}/);
  assert.match(css, /\.num::before \{ counter-increment: section; content: counter\(section, decimal-leading-zero\); \}/);
  for (const page of ['lookup.html', 'analyze.html']) {
    const html = readFileSync(new URL(page, root), 'utf8');
    const nums = [...html.matchAll(/<span class="num"[^>]*>([^<]*)<\/span>/g)].map((m) => m[1]);
    assert.ok(nums.length >= 5, page);
    assert.ok(nums.every((n) => n === ''), `${page}: no hard-coded numbers, so they can't drift`);
  }
  const html = readFileSync(new URL('lookup.html', root), 'utf8');
  const order = [...html.matchAll(/<span class="num"[^>]*><\/span>\s*<h2 id="([a-z-]+)"/g)].map((m) => m[1]);
  assert.deepEqual(order, ['search-h', 'pw-h', 'hid-h', 'calc-h', 'dec-h']);
  assert.match(html, /<h2 id="search-h" class="block-title">Lookup<\/h2>/);
});

test('phones: form fields are 16px (no iOS zoom), pinch-zoom stays enabled, chips wrap', () => {
  const css = readFileSync(new URL('css/style.css', root), 'utf8');
  const mobile = css.slice(css.lastIndexOf('@media (max-width: 720px)'));
  assert.match(mobile, /select, textarea,\s*\.ask-form textarea, \.row > input, \.dkim-row input \{ font-size: 16px; \}/);
  assert.match(css, /\.chip \{ max-width: 100%; overflow-wrap: anywhere;/);
  assert.ok(!/body\s*\{[^}]*overflow-x:\s*hidden/.test(css), 'not hidden on body');
  for (const page of ['index.html', 'lookup.html', 'analyze.html', 'cves.html', 'news.html']) {
    const html = readFileSync(new URL(page, root), 'utf8');
    const vp = /<meta name="viewport" content="([^"]+)"/.exec(html)[1];
    assert.ok(!/maximum-scale|user-scalable/.test(vp), `${page}: pinch-zoom allowed`);
  }
});

test('Analyze: every tool has a fixed "What does this mean?" note right after its result, no AI', () => {
  const html = readFileSync(new URL('analyze.html', root), 'utf8');
  for (const tool of ['ioc', 'link', 'headers', 'jwt', 'file', 'subnet', 'cert', 'nmap']) {
    assert.match(html, new RegExp(`<div id="${tool}-result" class="result" aria-live="polite"></div>\\s*<details class="meaning"><summary>What does this mean\\?</summary><p>[^<]{60,}</p></details>`), tool);
  }
});
