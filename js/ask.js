// Ask, the home page: a chat with the composer pinned to the bottom. The thread
// lives in a JS variable only: never in browser storage or the URL, so a question
// never lands in history or Analytics (a #ask= fill link is read once and removed).
// Answers are rendered as text nodes (render-answer.js); links come only from the
// Worker's sources and hub lists, re-checked here.

import { decodeJwt } from './analyze/jwt.js';
import { readCertificates } from './analyze/cert.js';
import { parseHeaders } from './extract.js';
import { safeUrl } from './results.js';
import { defang, detect, FILE_EXT } from './detect.js';

export const MAX_QUESTION = 1000;
const MAX_ANSWER = 3000; // the Worker rejects longer earlier answers
export const MAX_HISTORY = 8;
export const HANDOFF_KEY = 'slh-analyze-handoff'; // read by js/analyze/handoff.js

const TOOLS = {
  jwt: 'JWT decoder',
  headers: 'Email-header analyzer',
  cert: 'Certificate viewer',
};

export const PRIVATE_KEY_MESSAGE = "Don't paste private keys anywhere. Treat this key as exposed and replace it.";

export const cvePrompt = (id) => `Explain ${id}: what is it, is it being exploited, and what should I do?`;

const JWT_CANDIDATE = /[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*/g;
const HEADER_START = /^(?:Received|Authentication-Results|Return-Path|Delivered-To|DKIM-Signature|ARC-[A-Za-z-]+|X-[A-Za-z0-9-]+|From|To|Date|Subject|Message-ID):/im;

/**
 * Checked in the browser before anything is sent, using the Analyze tools' own
 * parsers. Returns null (fine to send), { block } (never send), or
 * { tool, name, payload } (offer the Analyze tool instead).
 */
export function preSendCheck(text) {
  const s = String(text);
  if (readCertificates(s).privateKey) return { block: PRIVATE_KEY_MESSAGE };

  for (const [candidate] of s.matchAll(JWT_CANDIDATE)) {
    if (!decodeJwt(candidate).error) return { tool: 'jwt', name: TOOLS.jwt, payload: candidate };
  }

  const start = s.search(HEADER_START);
  if (start >= 0) {
    const block = s.slice(start);
    const h = parseHeaders(block);
    if (h.hops.length >= 2 || h.authHeaders > 0) {
      return { tool: 'headers', name: TOOLS.headers, payload: block };
    }
  }

  const certs = readCertificates(s);
  if (certs.ders?.length) {
    const pem = s.match(/-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----[\s\S]*?-----END (?:X509 |TRUSTED )?CERTIFICATE-----/g).join('\n');
    return { tool: 'cert', name: TOOLS.cert, payload: pem };
  }
  return null;
}

/** The messages sent with a question: the last MAX_HISTORY, earlier answers clipped. */
export function historyForSend(history, question) {
  return [...history, { role: 'user', content: question }]
    .slice(-MAX_HISTORY)
    .map((m) => ({ role: m.role, content: m.role === 'assistant' ? m.content.slice(0, MAX_ANSWER) : m.content }));
}

/** Hub links the page will use: only ids in data/hub-features.json, with that file's href and name. */
export function checkedHub(hub, features) {
  const out = [];
  for (const item of Array.isArray(hub) ? hub : []) {
    const f = features.find((x) => x.id === item?.id);
    if (!f || f.href !== item.href || !/^\.\/[a-z]*(\.html)?(#[a-z-]+)?$/.test(f.href)) continue;
    if (!out.some((o) => o.id === f.id)) out.push({ id: f.id, name: f.name, href: f.href });
  }
  return out;
}

/** The "Answered by" line: the model that actually answered, and how it got there. */
export function answeredBy(body) {
  const model = String(body?.model || 'the AI model');
  const notes = [];
  const fb = body?.fallback;
  if (fb?.reason === 'daily limit') notes.push("today's AI limit (switched to the free model)");
  else if (typeof fb?.from === 'string') notes.push(`free fallback: ${fb.from.replace(/^[a-z]+:/, '')} was ${fb.reason === 'no API key' ? 'not configured' : 'unavailable'}`);
  if (body?.relay?.to === 'openrouter') notes.push('Groq is busy, answered by OpenRouter');
  return `Answered by ${model}${notes.length ? ` (${notes.join('; ')})` : ''}. AI can be wrong: check the sources.`;
}

/** Sources with https URLs only (re-checked here; the Worker already filters). */
export function checkedSources(sources) {
  return (Array.isArray(sources) ? sources : [])
    .map((s) => ({ ...s, url: safeUrl(s?.url) }))
    .filter((s) => s.url)
    .slice(0, 8);
}

/** Ask (the home page) with this text in its box. Ask fills the box and never sends it. */
export const askHref = (text) => `./#ask=${encodeURIComponent(text)}`;

/** The Lookup page, running this lookup. */
export const lookupHref = (value) => `./lookup.html#q=${encodeURIComponent(value)}`;

/** The text of a #ask= fill link (decoded, capped at MAX_QUESTION), or null. */
export function readAskFragment(hash) {
  const h = String(hash || '');
  if (!h.startsWith('#ask=')) return null;
  let text;
  try {
    text = decodeURIComponent(h.slice(5).replace(/\+/g, ' '));
  } catch {
    return null;
  }
  text = text.trim().slice(0, MAX_QUESTION);
  return text || null;
}

const INDICATOR_WORDS = {
  ipv4: 'an IPv4 address', ipv6: 'an IPv6 address', domain: 'a domain', url: 'a URL', email: 'an email address', cve: 'a CVE ID',
};

/**
 * A question that is nothing but one indicator Lookup handles: { type, value, what },
 * else null. "is 8.8.8.8 safe?" is a question; "8.8.8.8" is a lookup.
 */
export function indicatorOnly(text) {
  const d = detect(String(text).trim());
  if (d.error) return null;
  if (d.type === 'hash') return { type: d.type, value: d.value, what: `${d.algorithm === 'MD5' ? 'an' : 'a'} ${d.algorithm} hash` };
  if (!INDICATOR_WORDS[d.type] || (d.type === 'domain' && FILE_EXT.test(d.value))) return null;
  return { type: d.type, value: d.value, what: INDICATOR_WORDS[d.type] };
}

/** Enter sends on desktop (Shift+Enter is a new line); on touch screens Enter is a new line. Ctrl/Cmd+Enter always sends. */
export function enterSends(ev, touch) {
  if (ev.key !== 'Enter' || ev.isComposing) return false;
  if (ev.ctrlKey || ev.metaKey) return true;
  return !touch && !ev.shiftKey && !ev.altKey;
}

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('ask-form')) {
  const { API_BASE } = await import('./config.js');
  const { renderAnswer } = await import('./render-answer.js');
  const { el, $, notice } = await import('./analyze/ui.js');

  let features = [];
  try {
    const r = await fetch('data/hub-features.json');
    if (r.ok) features = (await r.json()).features || [];
  } catch { /* no hub links then */ }

  const input = $('ask-input');
  const send = $('ask-send');
  const count = $('ask-count');
  const thread = $('ask-thread');
  const status = $('ask-notice');
  const touch = globalThis.matchMedia?.('(pointer: coarse)').matches || false;
  const reducedMotion = globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches || false;
  let history = []; // [{ role, content }], this page view only
  // The one thing running (a question, "Make it simpler", ...). While set, Send is
  // Stop and Esc stops it. A stopped request shows nothing partial.
  let active = null; // { controller, kind }

  // The box grows with its text up to about 6 lines (CSS max-height), then scrolls.
  const grow = () => {
    input.style.height = 'auto';
    input.style.height = `${input.scrollHeight}px`;
  };
  const updateCount = () => {
    const n = input.value.length;
    count.textContent = `${n.toLocaleString('en-US')} / ${MAX_QUESTION.toLocaleString('en-US')}`;
    count.classList.toggle('over', n > MAX_QUESTION);
    // Send stays clickable over the limit, so the pre-send check still runs on a pasted
    // key or certificate (both are longer than 1,000 characters) and can warn about it.
    grow();
  };

  // Send turns into Stop (a square; the word is for screen readers) while something runs.
  const begin = (kind) => {
    const controller = new AbortController();
    active = { controller, kind };
    send.classList.add('stop');
    send.replaceChildren(el('span', { class: 'stop-icon', 'aria-hidden': 'true' }), el('span', { class: 'visually-hidden' }, 'Stop'));
    return controller;
  };
  const end = (controller) => {
    if (active?.controller !== controller) return;
    active = null;
    send.classList.remove('stop');
    send.replaceChildren('Send');
  };
  const stop = () => active?.controller.abort();
  send.addEventListener('click', (ev) => {
    if (!active) return;
    ev.preventDefault(); // Stop, not submit
    stop();
  });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape' && active) {
      ev.preventDefault();
      stop();
    }
  });
  input.addEventListener('input', updateCount);

  // The intro and examples show until the first question; "New chat" from then on.
  const updateEmpty = () => {
    const started = thread.childElementCount > 0;
    $('ask-empty').hidden = started;
    $('ask-top').hidden = !started;
  };

  const fill = (text) => {
    input.value = text;
    updateCount();
    input.focus();
  };

  for (const chip of document.querySelectorAll('#ask-examples .chip')) {
    chip.addEventListener('click', () => fill(chip.textContent));
  }

  $('ask-new').addEventListener('click', () => {
    for (const url of threadUrls) URL.revokeObjectURL(url);
    threadUrls = [];
    images.clear();
    history = [];
    thread.replaceChildren();
    status.replaceChildren();
    updateEmpty();
    fill('');
  });

  input.addEventListener('keydown', (ev) => {
    if (enterSends(ev, touch)) {
      ev.preventDefault();
      if (!active) $('ask-form').requestSubmit();
    }
  });

  // One image per question: paperclip, paste or drop. The thread keeps each sent
  // image's object URL (for its thumbnail) until New chat revokes it.
  const { setupImages, IMAGE_ONLY_QUESTION } = await import('./ask-image.js');
  const images = setupImages({
    button: $('ask-image'), fileInput: $('ask-file'), form: $('ask-form'), input, preview: $('ask-attach'), status, el, notice,
    begin, end, isBusy: () => Boolean(active),
  });
  let threadUrls = [];

  // Voice input: the mic records, the Worker transcribes, the text lands at the cursor.
  const { setupVoice } = await import('./voice.js');
  setupVoice({
    button: $('ask-mic'), input, status, apiBase: API_BASE, max: MAX_QUESTION, el, notice,
    begin, end, isBusy: () => Boolean(active), changed: updateCount,
  });

  const openTool = (check) => {
    try {
      sessionStorage.setItem(HANDOFF_KEY, JSON.stringify({ tool: check.tool, text: check.payload, at: Date.now() }));
    } catch { /* the tool opens empty */ }
    location.href = `./analyze.html#${check.tool}`;
  };

  // Lookup is another page. Once there is a thread, it opens in a new tab so the
  // thread (which lives only in this page) isn't lost.
  const lookupLink = (value, text, attrs = {}) => el('a', {
    href: lookupHref(value),
    ...(thread.childElementCount ? { target: '_blank', rel: 'noopener noreferrer' } : {}),
    ...attrs,
  }, text);

  // Answers are long: bring the start of the answer to the top, unless the visitor
  // scrolled up while waiting (then leave the page where they put it).
  let scrollMark = null;
  const markScroll = () => { scrollMark = globalThis.scrollY ?? 0; };
  const showAnswer = (node) => {
    if (scrollMark === null || (globalThis.scrollY ?? 0) >= scrollMark - 40) {
      node.scrollIntoView?.({ block: 'start', behavior: reducedMotion ? 'auto' : 'smooth' });
    }
    scrollMark = null;
  };

  // "Make it simpler": the same answer in plain language (tools off, no new facts),
  // shown under the original with its own "Answered by" line.
  function simplerButton(question, answer) {
    const box = el('div', { class: 'ask-simpler', 'aria-live': 'polite' });
    const button = el('button', { type: 'button', class: 'secondary small' }, 'Make it simpler');
    button.addEventListener('click', async () => {
      if (active) return;
      const controller = begin('simplify');
      button.disabled = true;
      button.textContent = 'Simplifying\u2026';
      let res;
      let r;
      try {
        res = await fetch(`${API_BASE}/api/ask/simplify`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ question, answer: answer.slice(0, MAX_ANSWER) }),
          referrerPolicy: 'no-referrer',
          signal: controller.signal,
        });
        r = await res.json();
      } catch {
        r = { error: 'Ask could not be reached. Try again.' };
      }
      end(controller);
      if (controller.signal.aborted) {
        button.disabled = false;
        button.textContent = 'Make it simpler';
        box.replaceChildren();
        return;
      }
      if (!res?.ok || r.error) {
        button.disabled = false;
        button.textContent = 'Make it simpler';
        box.replaceChildren(notice('warn', String(r.error || 'Ask could not simplify this. Try again.')));
        return;
      }
      button.remove();
      box.replaceChildren(
        el('h4', {}, 'The simple version'),
        el('div', { class: 'ask-text' }, ...renderAnswer(String(r.reply || ''))),
        el('p', { class: 'hint' }, answeredBy(r)));
    });
    return [button, box];
  }

  function answerNode(body, question) {
    const hub = checkedHub(body.hub, features);
    const sources = checkedSources(body.sources);
    const lookups = (Array.isArray(body.lookups) ? body.lookups : []).filter((l) => typeof l?.value === 'string').slice(0, 6);
    const trace = Array.isArray(body.trace) ? body.trace : [];
    const section = (title, ...children) => el('div', { class: 'ask-section' }, el('h4', {}, title), ...children);
    return el('article', { class: 'ask-msg ask-a' },
      el('p', { class: 'ask-who' }, 'Ask'),
      el('div', { class: 'ask-text' }, ...renderAnswer(String(body.reply || ''))),
      hub.length ? section('In the hub', el('div', { class: 'chips' }, ...hub.map((h) => el('a', { class: 'chip', href: h.href }, `${h.name} →`)))) : null,
      lookups.length ? section('Look up', el('div', { class: 'chips' }, ...lookups.map((l) => lookupLink(l.value,
        `Look up ${['url', 'domain', 'email'].includes(l.type) ? defang(l.value) : l.value}`, { class: 'chip' })))) : null,
      sources.length ? section('Sources', el('ol', { class: 'ask-sources' }, ...sources.map((s) => el('li', {},
        el('a', { href: s.url, target: '_blank', rel: 'noopener noreferrer' }, String(s.title || s.domain || s.url)),
        el('span', { class: 'hint' }, ` ${String(s.domain || '')}`))))) : null,
      trace.length ? el('details', { class: 'more ask-trace' },
        el('summary', {}, 'How this was answered'),
        el('ol', { class: 'plain-list' }, ...trace.map((t) => el('li', {},
          el('span', { class: 'mono' }, `${t.tool}(${Object.values(t.args || {}).map((v) => JSON.stringify(v)).join(', ')})`), ' ',
          el('span', { class: `flag ${t.ok ? 'ok' : 'warn'}` }, t.ok ? 'ok' : 'failed'),
          ` ${Number(t.ms) || 0} ms · ${String(t.summary || '')}`,
          t.note ? ` · ${String(t.note)}` : '')))) : null,
      el('p', { class: 'hint' }, answeredBy(body)),
      ...simplerButton(question, String(body.reply || '')));
  }

  // "Stopped." with Retry (the same messages again) and Edit (back into the box, out of
  // the thread). A stopped question never joins the history sent with later questions.
  function stoppedNode(question, asked, image) {
    const retry = el('button', { type: 'button', class: 'secondary small' }, 'Retry');
    const edit = el('button', { type: 'button', class: 'secondary small' }, 'Edit');
    const box = el('div', { class: 'notice warn ask-stopped' }, el('p', {}, 'Stopped.'), el('div', { class: 'row' }, retry, edit));
    retry.addEventListener('click', () => {
      if (active) return;
      box.remove();
      ask(question, asked, image);
    });
    edit.addEventListener('click', () => {
      if (active) return;
      box.remove();
      asked.remove();
      updateEmpty();
      fill(question);
    });
    return box;
  }

  // "Thinking… 12 s", once a second; after 40 s, a nudge that Stop is there.
  function thinkingLine() {
    const started = Date.now();
    const elapsed = el('span', { class: 'ask-elapsed', 'aria-hidden': 'true' });
    const still = el('span', { class: 'ask-still' });
    const line = el('p', { class: 'ask-thinking', role: 'status' }, 'Thinking', el('span', { class: 'ask-dots', 'aria-hidden': 'true' }), ' ', elapsed, still);
    const tick = () => {
      const secs = Math.floor((Date.now() - started) / 1000);
      elapsed.textContent = `${secs} s`;
      if (secs >= 40 && !still.textContent) still.textContent = ' Still working. You can stop it.';
    };
    tick();
    const timer = setInterval(tick, 1000);
    return { line, done: () => { clearInterval(timer); line.remove(); } };
  }

  async function ask(question, asked, image) {
    const controller = begin('ask');
    // The image goes only with the question it was attached to; the history is text.
    const messages = historyForSend(history, question);
    if (image) messages[messages.length - 1].image = { media_type: image.media_type, data: image.data };
    status.replaceChildren();
    const thinking = thinkingLine();
    thread.append(thinking.line);
    thinking.line.scrollIntoView?.({ block: 'nearest' });
    markScroll();
    let res;
    let body;
    try {
      res = await fetch(`${API_BASE}/api/ask`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ messages }),
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      });
      body = await res.json();
    } catch {
      body = { error: 'Ask could not be reached. Check your connection and try again.' };
    }
    thinking.done();
    end(controller);
    if (controller.signal.aborted) {
      thread.append(stoppedNode(question, asked, image));
      return;
    }
    if (!res?.ok || body.error) {
      const retry = el('button', { type: 'button', class: 'secondary small' }, 'Retry');
      const box = notice(res?.status === 429 ? 'bad' : 'warn', String(body.error || 'Ask failed. Try again.'), ' ', retry);
      retry.addEventListener('click', () => {
        if (active) return;
        box.remove();
        ask(question, asked, image);
      });
      thread.append(box);
      return;
    }
    history.push({ role: 'user', content: question }, { role: 'assistant', content: String(body.reply || '') });
    history = history.slice(-MAX_HISTORY);
    const node = answerNode(body, question);
    thread.append(node);
    showAnswer(node);
  }

  function offer(text, ...buttons) {
    status.replaceChildren(el('div', { class: 'notice warn ask-offer' }, el('p', {}, text), el('div', { class: 'row' }, ...buttons)));
    buttons[0].focus();
  }

  function submit(question, { skipCheck = false } = {}) {
    if (!skipCheck) {
      const check = preSendCheck(question);
      if (check?.block) {
        status.replaceChildren(notice('bad', check.block));
        fill('');
        return;
      }
      if (check?.tool) {
        const open = el('button', { type: 'button' }, `Open ${check.name}`);
        const anyway = el('button', { type: 'button', class: 'secondary' }, 'Send anyway');
        open.addEventListener('click', () => openTool(check));
        anyway.addEventListener('click', () => submit(question, { skipCheck: true }));
        offer(`This would be sent to the AI. The ${check.name} reads it without it leaving your browser.`, open, anyway);
        return;
      }
      // Just an indicator: Lookup has better data, and it doesn't spend a paid question.
      const only = images.get() ? null : indicatorOnly(question);
      if (only) {
        const go = lookupLink(only.value, 'Look it up', { class: 'button' });
        const anyway = el('button', { type: 'button', class: 'secondary' }, 'Ask anyway');
        anyway.addEventListener('click', () => submit(question, { skipCheck: true }));
        offer(`That looks like ${only.what}. Lookup checks it against reputation sources for free.`, go, anyway);
        return;
      }
    }
    if (question.length > MAX_QUESTION) {
      status.replaceChildren(notice('warn', `Questions are limited to ${MAX_QUESTION.toLocaleString('en-US')} characters. Shorten it and try again.`));
      return;
    }
    status.replaceChildren();
    const image = images.take();
    if (image) threadUrls.push(image.url);
    const asked = el('div', { class: 'ask-msg ask-q' }, el('p', { class: 'ask-who' }, 'You'),
      image ? el('img', { src: image.url, alt: 'Attached image', class: 'ask-thumb' }) : null,
      el('p', { class: 'ask-q-text' }, question));
    thread.append(asked);
    updateEmpty();
    input.value = '';
    updateCount();
    ask(question, asked, image);
  }

  $('ask-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    // An image on its own is a question too.
    const question = input.value.trim() || (images.get() ? IMAGE_ONLY_QUESTION : '');
    if (!question || active) return;
    submit(question);
  });

  // A #ask= fill link (e.g. "Ask about this CVE" on Lookup): read once, put in the box,
  // never sent, and the fragment removed so it isn't left in the address bar or history.
  // Not focused: on phones that would pop up the keyboard.
  const filled = readAskFragment(location.hash);
  if (location.hash.startsWith('#ask=')) globalThis.history.replaceState(null, '', location.pathname + location.search);
  if (filled) input.value = filled;
  updateCount();
  updateEmpty();
}
