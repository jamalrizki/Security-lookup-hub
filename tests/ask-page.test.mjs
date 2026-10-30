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
  const cancel = dom?.document.getElementById('ask-cancel');
  if (cancel && !cancel.hidden) cancel.click();
  else if (button?.classList.contains('stop')) button.click();
  await settle();
  dom?.restore();
  dom = null;
  delete globalThis.fetch;
  delete globalThis.MediaRecorder;
  delete globalThis.createImageBitmap;
  delete globalThis.OffscreenCanvas;
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
  assert.equal(button.textContent, 'Stop', 'the word shows next to the square');
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
  const working = $('ask-thread').querySelector('.ask-simpler .ask-thinking');
  assert.ok(working, 'an animated "Simplifying" line shows it is working');
  assert.match(working.textContent, /^Simplifying 0 s$/);
  assert.ok(working.querySelector('.ask-dots'));
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

/* ---------- Phase 19: voice input ---------- */

import { insertAtCursor, pickRecordingType, formatTimer, VOICE_MESSAGES } from '../js/voice.js';

/** A Safari-like recorder (audio/mp4 only) and a microphone that records `bytes`. */
function fakeMic({ deny } = {}) {
  const mic = { asked: 0, tracksStopped: 0, recorder: null };
  class FakeRecorder {
    static isTypeSupported(t) { return t === 'audio/mp4'; }
    constructor(stream, opts) { this.mimeType = opts?.mimeType || ''; this.state = 'inactive'; mic.recorder = this; }
    start() { this.state = 'recording'; }
    stop() {
      this.state = 'inactive';
      this.ondataavailable?.({ data: new Blob([Uint8Array.from([0, 0, 0, 0x20, 0x66, 0x74, 0x79, 0x70])], { type: this.mimeType }) });
      this.onstop?.();
    }
  }
  globalThis.MediaRecorder = FakeRecorder;
  mic.navigator = {
    mediaDevices: {
      getUserMedia(constraints) {
        mic.asked++;
        mic.constraints = constraints;
        if (deny) return Promise.reject(Object.assign(new Error('denied'), { name: deny }));
        return Promise.resolve({ getTracks: () => [{ stop: () => { mic.tracksStopped++; } }] });
      },
    },
  };
  return mic;
}

test('the mic button is hidden without MediaRecorder or getUserMedia', async () => {
  const { $ } = await loadPage();
  assert.equal($('ask-mic').hidden, true, 'no MediaRecorder');
  dom.restore();
  globalThis.MediaRecorder = class {};
  const again = await loadPage({ navigator: {} });
  assert.equal(again.$('ask-mic').hidden, true, 'no getUserMedia (e.g. not a secure page)');
  dom.restore();
  const mic = fakeMic();
  const shown = await loadPage({ navigator: mic.navigator });
  assert.equal(shown.$('ask-mic').hidden, false);
});

test('voice: record, stop, transcribe; the text goes in at the cursor and is never sent', async () => {
  const mic = fakeMic();
  const { $, calls, doc } = await loadPage({
    navigator: mic.navigator,
    api: (url) => (url.endsWith('/api/transcribe') ? { text: 'CVE-2021-44228' } : ANSWER),
  });
  const input = $('ask-input');
  type(input, 'Is in KEV?');
  input.setSelectionRange(3, 3);
  $('ask-mic').click();
  assert.equal(mic.asked, 1, 'getUserMedia called from the tap itself, nothing awaited first (iPhone Safari)');
  assert.equal(mic.constraints.audio.channelCount, 1, 'mono');
  await settle();
  assert.equal(mic.recorder.mimeType, 'audio/mp4', 'the first supported type');
  assert.ok($('ask-mic').classList.contains('recording'));
  assert.equal($('ask-mic').getAttribute('aria-pressed'), 'true');
  assert.equal($('ask-mic').querySelector('.mic-time').textContent, '0:00');
  // While recording: the main button is "Done" (finish), with a separate Cancel, and the box says so.
  assert.equal($('ask-send').textContent, 'Done');
  assert.ok($('ask-send').classList.contains('done'));
  assert.equal($('ask-cancel').hidden, false);
  assert.equal(input.getAttribute('placeholder'), "Recording\u2026 press Done when you've finished");
  assert.ok(input.hasAttribute('readonly'));
  assert.equal($('ask-form').getAttribute('data-busy'), 'record');
  $('ask-send').click(); // Done: stop and transcribe (not discard)
  await settle();
  assert.equal(calls.length, 1);
  assert.ok(calls[0].url.endsWith('/api/transcribe'));
  assert.equal(calls[0].init.headers['content-type'], 'audio/mp4');
  assert.ok(calls[0].body instanceof Blob);
  assert.equal(input.value, 'Is CVE-2021-44228 in KEV?');
  assert.equal(input.selectionStart, 'Is CVE-2021-44228 '.length, 'caret after the inserted text');
  assert.equal(doc.activeElement, input, 'focus back in the box');
  assert.equal($('ask-count').textContent, '25 / 1,000');
  assert.ok(!calls.some((c) => c.url.endsWith('/api/ask')), 'never sent');
  assert.equal(mic.tracksStopped, 1, 'microphone released');
  assert.equal($('ask-mic').classList.contains('recording'), false);
  assert.equal($('ask-send').textContent, 'Send');
  assert.equal($('ask-cancel').hidden, true);
  assert.equal(input.getAttribute('placeholder'), 'Ask AI a security question', 'the box is back to normal');
  assert.equal(input.hasAttribute('readonly'), false);
});

test('voice: the mic button still finishes too; Cancel throws the recording away', async () => {
  const mic = fakeMic();
  const { $, calls } = await loadPage({ navigator: mic.navigator, api: () => ({ text: 'hello' }) });
  $('ask-mic').click();
  await settle();
  $('ask-mic').click();
  await settle();
  assert.equal(calls.length, 1, 'mic again = Done');
  $('ask-mic').click();
  await settle();
  $('ask-cancel').click();
  await settle();
  assert.equal(calls.length, 1, 'Cancel uploads nothing');
  assert.equal(mic.tracksStopped, 2);
  assert.equal($('ask-send').textContent, 'Send');
});

test('voice: while transcribing the box says so, with animated dots, and Send is Stop', async () => {
  const mic = fakeMic();
  let release;
  const { $ } = await loadPage({ navigator: mic.navigator, api: () => new Promise((r) => { release = () => r({ text: 'hi' }); }) });
  $('ask-mic').click();
  await settle();
  $('ask-send').click();
  await settle();
  assert.equal($('ask-input').getAttribute('placeholder'), 'Transcribing\u2026');
  assert.ok($('ask-notice').querySelector('.ask-thinking .ask-dots'), 'animated, like Thinking');
  assert.equal($('ask-send').textContent, 'Stop');
  release();
  await settle();
  assert.equal($('ask-input').value, 'hi');
});

test('voice: Esc cancels a recording and throws it away', async () => {
  const mic = fakeMic();
  const { $, calls, doc } = await loadPage({ navigator: mic.navigator });
  $('ask-mic').click();
  await settle();
  doc.dispatchEvent(new Event('keydown', { key: 'Escape' }));
  await settle();
  assert.equal(calls.length, 0, 'nothing uploaded');
  assert.equal(mic.tracksStopped, 1);
  assert.equal($('ask-mic').classList.contains('recording'), false);
});

test('voice: Stop while transcribing cancels it; errors are plain words', async () => {
  const mic = fakeMic();
  let signal;
  const { $ } = await loadPage({
    navigator: mic.navigator,
    api: (url, body, init) => new Promise((resolve, reject) => {
      signal = init.signal;
      init.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    }),
  });
  $('ask-mic').click();
  await settle();
  $('ask-mic').click();
  await settle();
  assert.match($('ask-notice').textContent, /Transcribing/);
  $('ask-send').click();
  await settle();
  assert.equal(signal.aborted, true);
  assert.equal($('ask-notice').textContent, '');
  assert.equal($('ask-input').value, '');
  dom.restore();

  for (const [reply, message] of [
    [{ text: '', empty: true }, VOICE_MESSAGES.empty],
    [{ httpStatus: 429, error: 'Voice input is used up for now. Type your question instead.' }, 'Voice input is used up for now. Type your question instead.'],
    [{ httpStatus: 502, error: 'x' }, VOICE_MESSAGES.failed],
  ]) {
    const m = fakeMic();
    const page = await loadPage({ navigator: m.navigator, api: () => reply });
    page.$('ask-mic').click();
    await settle();
    page.$('ask-mic').click();
    await settle();
    assert.equal(page.$('ask-notice').textContent, message);
    dom.restore();
  }
  const denied = fakeMic({ deny: 'NotAllowedError' });
  const page = await loadPage({ navigator: denied.navigator });
  page.$('ask-mic').click();
  await settle();
  assert.equal(page.$('ask-notice').textContent, "Microphone access is blocked. Allow it in your browser's site settings.");
});

test('insertAtCursor: spaces as needed, and cut at the limit', () => {
  assert.deepEqual(insertAtCursor('', 0, 0, 'hello', 1000), { value: 'hello', caret: 5, cut: false });
  assert.deepEqual(insertAtCursor('Is in KEV?', 3, 3, 'CVE-1', 1000), { value: 'Is CVE-1 in KEV?', caret: 9, cut: false });
  assert.equal(insertAtCursor('abc', 3, 3, 'def', 1000).value, 'abc def');
  assert.equal(insertAtCursor('replace me', 0, 7, 'swap', 1000).value, 'swap me', 'replaces a selection');
  const full = insertAtCursor('x'.repeat(995), 995, 995, 'a long transcript', 1000);
  assert.equal(full.value.length, 1000);
  assert.equal(full.cut, true);
  assert.equal(formatTimer(7), '0:07');
  assert.equal(formatTimer(60), '1:00');
  assert.equal(pickRecordingType({ isTypeSupported: (t) => t.startsWith('audio/ogg') }), 'audio/ogg;codecs=opus');
  assert.equal(pickRecordingType({ isTypeSupported: () => true }), 'audio/webm;codecs=opus', 'webm first');
  assert.equal(pickRecordingType(undefined), '');
});

/* ---------- Phase 20: one image per question ---------- */

import { prepareImage, scaledSize, sniffImage, IMAGE_MESSAGES, IMAGE_ONLY_QUESTION } from '../js/ask-image.js';

const PNG_HEAD = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const fileOf = (head, size, name = 'shot.png', type = 'image/png') => {
  const bytes = new Uint8Array(size);
  bytes.set(head);
  return new File([bytes], name, { type });
};

/** createImageBitmap and OffscreenCanvas stand-ins: JPEG size from quality (sizes[quality]). */
function fakeCanvas({ width = 3000, height = 2000, sizes = { 0.85: 300_000, 0.7: 200_000 } } = {}) {
  const log = { drawn: [], encodes: [] };
  globalThis.createImageBitmap = async () => ({ width, height, close() {} });
  globalThis.OffscreenCanvas = class {
    constructor(w, h) { this.width = w; this.height = h; log.canvas = [w, h]; }
    getContext() { return { fillRect() {}, drawImage: (b, x, y, w, h) => log.drawn.push([w, h]), set fillStyle(v) {} }; }
    async convertToBlob({ type, quality }) {
      log.encodes.push([type, quality]);
      const bytes = new Uint8Array(sizes[quality]);
      bytes.set([0xff, 0xd8, 0xff]);
      return new Blob([bytes], { type });
    }
  };
  return log;
}

test('prepareImage: scaled to 1,568 px on the long side, JPEG 0.85, lower quality once, then "too large"', async () => {
  const log = fakeCanvas();
  const out = await prepareImage(fileOf(PNG_HEAD, 2000));
  assert.deepEqual(log.canvas, [1568, 1045]);
  assert.deepEqual(log.encodes, [['image/jpeg', 0.85]]);
  assert.equal(out.media_type, 'image/jpeg');
  assert.equal(Buffer.from(out.data, 'base64').length, 300_000);
  assert.equal(Buffer.from(out.data, 'base64')[0], 0xff);

  const twice = fakeCanvas({ sizes: { 0.85: 1.6 * 1024 * 1024, 0.7: 1.2 * 1024 * 1024 } });
  await prepareImage(fileOf(PNG_HEAD, 2000));
  assert.deepEqual(twice.encodes.map((e) => e[1]), [0.85, 0.7], 'quality lowered once');

  fakeCanvas({ sizes: { 0.85: 1.7 * 1024 * 1024, 0.7: 1.6 * 1024 * 1024 } });
  await assert.rejects(prepareImage(fileOf(PNG_HEAD, 2000)), { message: IMAGE_MESSAGES.tooLarge });
  assert.equal(IMAGE_MESSAGES.tooLarge, 'That image is too large.');

  assert.deepEqual(scaledSize(800, 600), { width: 800, height: 600 }, 'never enlarged');
  assert.deepEqual(scaledSize(1000, 4000), { width: 392, height: 1568 });
  assert.equal(sniffImage(Uint8Array.from([...Buffer.from('RIFF'), 0, 0, 0, 0, ...Buffer.from('WEBP')])), 'image/webp');
});

test('images: a 12 MB file, a GIF and an SVG are refused (by size and first bytes, not the name)', async () => {
  fakeCanvas();
  const { $, doc } = await loadPage();
  for (const [file, message] of [
    [fileOf(PNG_HEAD, 12 * 1024 * 1024), IMAGE_MESSAGES.sourceTooLarge],
    [fileOf([...Buffer.from('GIF89a')], 500, 'cat.png', 'image/png'), IMAGE_MESSAGES.wrongType],
    [new File(['<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'], 'x.png', { type: 'image/svg+xml' }), IMAGE_MESSAGES.wrongType],
  ]) {
    $('ask-image').click();
    assert.equal(doc.filePickers.at(-1), $('ask-file'), 'the paperclip opens the file picker');
    $('ask-file').files = [file];
    $('ask-file').dispatchEvent(new Event('change'));
    await settle();
    assert.equal($('ask-notice').textContent, message);
    assert.equal($('ask-attach').hidden, true, 'nothing attached');
  }
  assert.equal($('ask-file').getAttribute('accept'), 'image/png,image/jpeg,image/webp');
});

test('images: paste and drop both attach; the X removes it; a new one replaces the old', async () => {
  fakeCanvas();
  const { $ } = await loadPage();
  const paste = new Event('paste', { clipboardData: { items: [{ kind: 'file', type: 'image/png', getAsFile: () => fileOf(PNG_HEAD, 900) }] } });
  $('ask-input').dispatchEvent(paste);
  await settle();
  assert.equal(paste.defaultPrevented, true);
  assert.equal($('ask-attach').hidden, false);
  const thumb = $('ask-attach').querySelector('img');
  assert.match(thumb.getAttribute('src'), /^blob:/);
  $('ask-attach').querySelector('button').click();
  assert.equal($('ask-attach').hidden, true);
  assert.equal($('ask-attach').childElementCount, 0);

  const textPaste = new Event('paste', { clipboardData: { items: [{ kind: 'string', type: 'text/plain' }] } });
  $('ask-input').dispatchEvent(textPaste);
  assert.equal(textPaste.defaultPrevented, false, 'ordinary text pastes as usual');

  const drop = new Event('drop', { dataTransfer: { files: [fileOf(PNG_HEAD, 900)], types: ['Files'] } });
  $('ask-form').dispatchEvent(drop);
  await settle();
  assert.equal(drop.defaultPrevented, true);
  const first = $('ask-attach').querySelector('img').getAttribute('src');
  $('ask-form').dispatchEvent(new Event('drop', { dataTransfer: { files: [fileOf(PNG_HEAD, 900)], types: ['Files'] } }));
  await settle();
  assert.equal($('ask-attach').querySelectorAll('img').length, 1, 'one image per question');
  assert.notEqual($('ask-attach').querySelector('img').getAttribute('src'), first);
});

test('images: an image alone is a question; only that question carries it; follow-ups are text', async () => {
  fakeCanvas();
  const { $, calls } = await loadPage();
  $('ask-input').dispatchEvent(new Event('paste', { clipboardData: { items: [{ kind: 'file', type: 'image/png', getAsFile: () => fileOf(PNG_HEAD, 900) }] } }));
  await settle();
  $('ask-send').click();
  await settle();
  assert.equal(calls.length, 1);
  const sent = calls[0].body.messages;
  assert.equal(sent.at(-1).content, IMAGE_ONLY_QUESTION);
  assert.equal(IMAGE_ONLY_QUESTION, 'Is this safe? What should I do?');
  assert.equal(sent.at(-1).image.media_type, 'image/jpeg');
  assert.ok(sent.at(-1).image.data.length > 1000);
  assert.ok($('ask-thread').querySelector('.ask-q img.ask-thumb'), 'the thumbnail is on the question in the thread');
  assert.equal($('ask-attach').hidden, true, 'the composer is clear again');

  await send($, 'What should I do if I clicked the link?');
  const follow = calls[1].body.messages;
  assert.equal(follow.length, 3);
  assert.ok(follow.every((m) => !('image' in m)), 'the image is not sent again');
});

test('images: a bare indicator with an image attached is a question, not a lookup', async () => {
  fakeCanvas();
  const { $, calls } = await loadPage();
  $('ask-form').dispatchEvent(new Event('drop', { dataTransfer: { files: [fileOf(PNG_HEAD, 900)], types: ['Files'] } }));
  await settle();
  await send($, 'paypal.com');
  assert.equal(calls.length, 1);
  assert.ok(calls[0].body.messages.at(-1).image);
});

test('the Ask page allows blob: thumbnails and nothing else new in its CSP', () => {
  const csp = /Content-Security-Policy" content="([^"]+)"/.exec(HTML)[1];
  assert.match(csp, /img-src 'self' data: blob: /);
  assert.match(csp, /connect-src 'self' http:\/\/127\.0\.0\.1:8787 https:\/\/security-lookup-hub\.jamal-598\.workers\.dev https:\/\/www\.googletagmanager\.com/);
});
