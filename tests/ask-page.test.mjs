// The Ask page (index.html + js/ask.js) in a small DOM stand-in, with fetch
// stubbed: what the visitor sees and what is (or isn't) sent.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { installDom, settle, type, Event } from './helpers/dom.mjs';

const root = new URL('../', import.meta.url);
const HTML = readFileSync(new URL('index.html', root), 'utf8');
const FEATURES = readFileSync(new URL('data/hub-features.json', root), 'utf8');
let loads = 0;
let dom;

const ANSWER = { reply: 'Google runs 8.8.8.8 as a public DNS resolver.', sources: [], trace: [], lookups: [{ type: 'ipv4', value: '8.8.8.8' }], hub: [], model: 'claude-haiku-5-5', provider: 'anthropic' };

/**
 * Loads the Ask page. api(path, body, init) answers Worker calls (default: ANSWER);
 * returns { doc, calls, $ }. calls lists Worker requests only.
 */
async function loadPage({ url, api = () => ANSWER, touch = false, navigator } = {}) {
  dom = installDom(HTML, { url, touch, navigator });
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const u = String(input);
    if (u === 'data/hub-features.json') return new Response(FEATURES);
    const body = init.body && typeof init.body === 'string' ? JSON.parse(init.body) : init.body;
    calls.push({ url: u, body, init });
    const r = await api(u, body, init);
    return r instanceof Response ? r : new Response(JSON.stringify(r), { status: r?.httpStatus || 200 });
  };
  await import(`../js/ask.js?page=${++loads}`);
  await settle();
  const $ = (id) => dom.document.getElementById(id);
  return { doc: dom.document, calls, $ };
}

afterEach(async () => {
  // Stop anything still running, so its timer doesn't keep the test process alive.
  const button = dom?.document.getElementById('ask-send');
  if (button?.classList.contains('stop')) {
    button.click();
    await settle();
  }
  dom?.restore();
  dom = null;
  delete globalThis.fetch;
});

const send = async ($, text) => {
  type($('ask-input'), text);
  $('ask-send').click();
  await settle();
};

test('#ask= fills the box, sends nothing, and removes the fragment', async () => {
  const { $, calls } = await loadPage({ url: 'https://jamalrizki.github.io/Security-lookup-hub/#ask=Explain%20CVE-2021-44228%3A%20what%20is%20it%3F' });
  assert.equal($('ask-input').value, 'Explain CVE-2021-44228: what is it?');
  assert.equal(calls.length, 0, 'never sent on its own');
  assert.deepEqual(dom.history.log, ['/Security-lookup-hub/'], 'fragment removed with replaceState');
  assert.equal(location.hash, '');
  assert.equal($('ask-count').textContent, '35 / 1,000');
});

test('a bare indicator offers Look it up / Ask anyway and makes no request; Ask anyway sends it', async () => {
  const { $, calls, doc } = await loadPage();
  for (const [q, what] of [['8.8.8.8', 'an IPv4 address'], ['CVE-2021-44228', 'a CVE ID']]) {
    await send($, q);
    assert.equal(calls.length, 0, `${q}: no request`);
    const offer = $('ask-notice');
    assert.match(offer.textContent, new RegExp(`That looks like ${what}\\. Lookup checks it against reputation sources for free\\.`));
    const go = offer.querySelector('a');
    assert.equal(go.textContent, 'Look it up');
    assert.equal(go.href, `./lookup.html#q=${encodeURIComponent(q)}`);
    assert.equal(go.getAttribute('target'), null, 'same tab while there is no thread to lose');
    assert.equal(doc.activeElement, go, 'Look it up is the default');
    assert.equal($('ask-thread').childElementCount, 0);
  }
  const anyway = [...$('ask-notice').querySelectorAll('button')].find((b) => b.textContent === 'Ask anyway');
  anyway.click();
  await settle();
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].body.messages, [{ role: 'user', content: 'CVE-2021-44228' }]);
});

test('a question that contains an indicator is sent; the answer scrolls to its start; New chat appears', async () => {
  const { $, calls, doc } = await loadPage();
  assert.equal($('ask-empty').hidden, false);
  assert.equal($('ask-top').hidden, true);
  await send($, 'is 8.8.8.8 safe to use as DNS?');
  assert.equal(calls.length, 1);
  assert.ok(calls[0].url.endsWith('/api/ask'));
  const answer = $('ask-thread').querySelector('.ask-a');
  assert.ok(answer, 'answer shown');
  assert.equal($('ask-empty').hidden, true, 'intro and examples give way to the thread');
  assert.equal($('ask-top').hidden, false, 'New chat shown');
  const last = doc.scrolledTo.at(-1);
  assert.equal(last.el, answer);
  assert.equal(last.opts.block, 'start', 'the start of the answer, not the end');
  // With a thread on the page, Look up opens Lookup in a new tab so the thread isn't lost.
  const lookUp = answer.querySelector('a.chip');
  assert.equal(lookUp.href, './lookup.html#q=8.8.8.8');
  assert.equal(lookUp.getAttribute('target'), '_blank');
  $('ask-new').click();
  assert.equal($('ask-thread').childElementCount, 0);
  assert.equal($('ask-empty').hidden, false);
});

test('scrolled up while waiting: the page is left where the visitor put it', async () => {
  let release;
  const { $, doc } = await loadPage({ api: () => new Promise((r) => { release = () => r(ANSWER); }) });
  globalThis.scrollY = 900;
  await send($, 'What is DMARC?');
  globalThis.scrollY = 300; // scrolled up to re-read something
  const before = doc.scrolledTo.length;
  release();
  await settle();
  assert.ok($('ask-thread').querySelector('.ask-a'));
  assert.equal(doc.scrolledTo.length, before, 'no scroll');
});

test('Enter sends on desktop; on a touch screen it does not', async () => {
  for (const touch of [false, true]) {
    const { $, calls } = await loadPage({ touch });
    type($('ask-input'), 'What is DMARC?');
    const ev = new Event('keydown', { key: 'Enter' });
    $('ask-input').dispatchEvent(ev);
    await settle();
    assert.equal(calls.length, touch ? 0 : 1, touch ? 'touch: new line' : 'desktop: sent');
    assert.equal(ev.defaultPrevented, !touch);
    dom.restore();
  }
});

test('example chips fill the box without sending', async () => {
  const { $, calls, doc } = await loadPage();
  doc.querySelectorAll('#ask-examples .chip')[2].click();
  assert.equal($('ask-input').value, 'SPF vs DKIM vs DMARC: what does each one stop?');
  assert.equal(calls.length, 0);
});

/* ---------- Phase 18: Stop and elapsed time ---------- */

/** An api handler that never answers until released, and rejects when the page aborts. */
function hanging() {
  const h = { calls: 0 };
  h.api = (url, body, init) => {
    h.calls++;
    return new Promise((resolve, reject) => {
      h.release = (r = ANSWER) => resolve(r);
      init.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    });
  };
  return h;
}

test('Stop: Send becomes Stop; stopping leaves "Stopped." with Retry and Edit and no partial answer', async () => {
  const h = hanging();
  const { $, calls } = await loadPage({ api: h.api });
  await send($, 'What is Kerberoasting?');
  const button = $('ask-send');
  assert.ok(button.classList.contains('stop'));
  assert.equal(button.textContent, 'Stop', 'the word is there for screen readers');
  assert.ok(button.querySelector('.stop-icon'), 'square icon');
  assert.ok(calls[0].init.signal, 'the fetch carries an AbortController signal');
  button.click();
  await settle();
  assert.equal(calls[0].init.signal.aborted, true);
  assert.equal(button.textContent, 'Send');
  const thread = $('ask-thread');
  assert.equal(thread.querySelector('.ask-q').textContent, 'YouWhat is Kerberoasting?', "the visitor's message stays");
  assert.equal(thread.querySelector('.ask-stopped p').textContent, 'Stopped.');
  assert.deepEqual(thread.querySelector('.ask-stopped').querySelectorAll('button').map((b) => b.textContent), ['Retry', 'Edit']);
  assert.equal(thread.querySelector('.ask-a'), null, 'no partial answer');
  assert.equal(thread.querySelector('.ask-thinking'), null);
});

test('Stop: Retry resends the same messages; a stopped turn never joins the history', async () => {
  const h = hanging();
  const { $, calls } = await loadPage({ api: h.api });
  await send($, 'First question');
  $('ask-send').click();
  await settle();
  const retry = $('ask-thread').querySelector('.ask-stopped').querySelectorAll('button')[0];
  retry.click();
  await settle();
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1].body, calls[0].body, 'same messages');
  assert.equal($('ask-thread').querySelector('.ask-stopped'), null);
  // Stop again, then ask something else: the stopped question is not in the history.
  $('ask-send').click();
  await settle();
  await send($, 'Second question');
  assert.deepEqual(calls[2].body.messages, [{ role: 'user', content: 'Second question' }]);
  h.release();
  await settle();
  assert.ok($('ask-thread').querySelector('.ask-a'));
});

test('Stop: Edit puts the question back in the box and removes it from the thread; Esc also stops', async () => {
  const h = hanging();
  const { $, doc } = await loadPage({ api: h.api });
  await send($, 'How does DMARC work?');
  doc.dispatchEvent(new Event('keydown', { key: 'Escape' }));
  await settle();
  const edit = $('ask-thread').querySelector('.ask-stopped').querySelectorAll('button')[1];
  edit.click();
  assert.equal($('ask-input').value, 'How does DMARC work?');
  assert.equal($('ask-thread').childElementCount, 0);
  assert.equal($('ask-empty').hidden, false, 'back to the empty state');
});

test('Enter while a question runs neither sends nor stops', async () => {
  const h = hanging();
  const { $, calls } = await loadPage({ api: h.api });
  await send($, 'What is MFA?');
  type($('ask-input'), 'next one');
  $('ask-input').dispatchEvent(new Event('keydown', { key: 'Enter' }));
  await settle();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.signal.aborted, false);
});

test('the thinking line counts seconds and offers Stop after 40 s', async (t) => {
  t.mock.timers.enable({ apis: ['setInterval', 'Date'], now: 1_000_000 });
  const h = hanging();
  const { $ } = await loadPage({ api: h.api });
  await send($, 'What is SIEM?');
  const line = () => $('ask-thread').querySelector('.ask-thinking');
  assert.match(line().textContent, /^Thinking 0 s$/);
  t.mock.timers.tick(12_000);
  assert.match(line().textContent, /^Thinking 12 s$/);
  assert.equal(line().querySelector('.ask-elapsed').getAttribute('aria-hidden'), 'true', 'the ticking number is not read out every second');
  t.mock.timers.tick(29_000);
  assert.match(line().textContent, /^Thinking 41 s Still working\. You can stop it\.$/);
  h.release();
  await settle();
  assert.equal(line(), null);
});

test('Make it simpler can be stopped too', async () => {
  let simplify;
  const { $, calls } = await loadPage({
    api: (url, body, init) => {
      if (!url.endsWith('/simplify')) return ANSWER;
      return new Promise((resolve, reject) => {
        simplify = init.signal;
        init.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
      });
    },
  });
  await send($, 'is 8.8.8.8 safe to use as DNS?');
  const button = [...$('ask-thread').querySelectorAll('button')].find((b) => b.textContent === 'Make it simpler');
  button.click();
  await settle();
  assert.ok($('ask-send').classList.contains('stop'));
  $('ask-send').click();
  await settle();
  assert.equal(simplify.aborted, true);
  assert.equal(calls.length, 2);
  assert.equal(button.textContent, 'Make it simpler');
  assert.equal(button.disabled, false);
  assert.equal($('ask-thread').querySelector('.ask-simpler').childElementCount, 0, 'nothing partial');
});

test('reduced motion: the dots stop, the timer still counts (CSS)', () => {
  const css = readFileSync(new URL('css/style.css', root), 'utf8');
  assert.match(css, /@media \(prefers-reduced-motion: reduce\) \{\s*\.ask-dots::after \{ animation: none;/);
});
