// Ask box on the Lookup page. The thread lives in a JS variable only: never in
// browser storage or the URL fragment, so a question never lands in history or
// Analytics. Answers are rendered as text nodes (render-answer.js); links come
// only from the Worker's sources and hub lists, re-checked here.

import { decodeJwt } from './analyze/jwt.js';
import { readCertificates } from './analyze/cert.js';
import { parseHeaders } from './extract.js';
import { safeUrl } from './results.js';
import { defang } from './detect.js';

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
  let history = []; // [{ role, content }], this page view only
  let busy = false;

  const updateCount = () => {
    const n = input.value.length;
    count.textContent = `${n.toLocaleString('en-US')} / ${MAX_QUESTION.toLocaleString('en-US')}`;
    count.classList.toggle('over', n > MAX_QUESTION);
    // Send stays clickable over the limit, so the pre-send check still runs on a pasted
    // key or certificate (both are longer than 1,000 characters) and can warn about it.
    send.disabled = busy;
  };
  input.addEventListener('input', updateCount);

  for (const chip of document.querySelectorAll('#ask-examples .chip')) {
    chip.addEventListener('click', () => {
      input.value = chip.textContent;
      updateCount();
      input.focus();
    });
  }

  $('ask-new').addEventListener('click', () => {
    history = [];
    thread.replaceChildren();
    status.replaceChildren();
    input.value = '';
    updateCount();
    input.focus();
  });

  // Ctrl/Cmd+Enter sends; plain Enter makes a new line.
  input.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) {
      ev.preventDefault();
      $('ask-form').requestSubmit();
    }
  });

  const openTool = (check) => {
    try {
      sessionStorage.setItem(HANDOFF_KEY, JSON.stringify({ tool: check.tool, text: check.payload, at: Date.now() }));
    } catch { /* the tool opens empty */ }
    location.href = `./analyze.html#${check.tool}`;
  };

  const lookUp = (value) => {
    $('search-input').value = value;
    $('search-form').requestSubmit();
    $('search-input').scrollIntoView({ behavior: 'smooth', block: 'center' });
  };

  // "Make it simpler": the same answer in plain language (tools off, no new facts),
  // shown under the original with its own "Answered by" line.
  function simplerButton(question, answer) {
    const box = el('div', { class: 'ask-simpler', 'aria-live': 'polite' });
    const button = el('button', { type: 'button', class: 'secondary small' }, 'Make it simpler');
    button.addEventListener('click', async () => {
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
        });
        r = await res.json();
      } catch {
        r = { error: 'Ask could not be reached. Try again.' };
      }
      if (!res?.ok || r.error) {
        button.disabled = false;
        button.textContent = 'Make it simpler';
        box.replaceChildren(notice('warn', String(r.error || 'Ask could not simplify this. Try again.')));
        return;
      }
      button.remove();
      box.replaceChildren(
        el('h4', {}, 'In plain words'),
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
      lookups.length ? section('Look up', el('div', { class: 'chips' }, ...lookups.map((l) => {
        const b = el('button', { type: 'button', class: 'chip' }, `Look up ${['url', 'domain', 'email'].includes(l.type) ? defang(l.value) : l.value}`);
        b.addEventListener('click', () => lookUp(l.value));
        return b;
      }))) : null,
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

  async function ask(question) {
    busy = true;
    updateCount();
    status.replaceChildren();
    const thinking = el('p', { class: 'ask-thinking', role: 'status' }, 'Thinking', el('span', { class: 'ask-dots', 'aria-hidden': 'true' }));
    thread.append(thinking);
    let res;
    let body;
    try {
      res = await fetch(`${API_BASE}/api/ask`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ messages: historyForSend(history, question) }),
        referrerPolicy: 'no-referrer',
      });
      body = await res.json();
    } catch {
      body = { error: 'Ask could not be reached. Check your connection and try again.' };
    }
    thinking.remove();
    busy = false;
    updateCount();
    if (!res?.ok || body.error) {
      const retry = el('button', { type: 'button', class: 'secondary small' }, 'Retry');
      const box = notice(res?.status === 429 ? 'bad' : 'warn', String(body.error || 'Ask failed. Try again.'), ' ', retry);
      retry.addEventListener('click', () => { box.remove(); ask(question); });
      thread.append(box);
      return;
    }
    history.push({ role: 'user', content: question }, { role: 'assistant', content: String(body.reply || '') });
    history = history.slice(-MAX_HISTORY);
    thread.append(answerNode(body, question));
  }

  function submit(question, { skipCheck = false } = {}) {
    if (!skipCheck) {
      const check = preSendCheck(question);
      if (check?.block) {
        status.replaceChildren(notice('bad', check.block));
        input.value = '';
        updateCount();
        return;
      }
      if (check?.tool) {
        const open = el('button', { type: 'button' }, `Open ${check.name}`);
        const anyway = el('button', { type: 'button', class: 'secondary' }, 'Send anyway');
        open.addEventListener('click', () => openTool(check));
        anyway.addEventListener('click', () => submit(question, { skipCheck: true }));
        status.replaceChildren(el('div', { class: 'notice warn ask-offer' },
          el('p', {}, `This would be sent to the AI. The ${check.name} reads it without it leaving your browser.`),
          el('div', { class: 'row' }, open, anyway)));
        open.focus();
        return;
      }
    }
    if (question.length > MAX_QUESTION) {
      status.replaceChildren(notice('warn', `Questions are limited to ${MAX_QUESTION.toLocaleString('en-US')} characters. Shorten it and try again.`));
      return;
    }
    status.replaceChildren();
    thread.append(el('div', { class: 'ask-msg ask-q' }, el('p', { class: 'ask-who' }, 'You'), el('p', { class: 'ask-q-text' }, question)));
    input.value = '';
    updateCount();
    ask(question);
  }

  $('ask-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const question = input.value.trim();
    if (!question || busy) return;
    submit(question);
  });

  updateCount();
}
