// "Is this message a scam?" (#message). Paste a text or email; checking it does
// two things. In the browser, warning signs and tactics from data/scam-signs.json
// are matched in code and links go through the link inspector's own inspectUrl().
// Then the message goes to the Worker for an AI read (POST /api/message-check),
// because fixed wording can't catch a scam that words things differently. The AI
// can only raise the verdict: it has no "safe" answer, and combineVerdict() never
// lowers what the code found. No link is ever opened or fetched. Pure functions
// are exported for tests; the page wiring at the bottom only runs in a browser.

import { extractIocs, inspectUrl } from '../extract.js';
import { guidanceUrl } from '../what-now.js';

export const MAX_MESSAGE = 10 * 1024;
export const MAX_LINKS = 10;
export const STRENGTHS = ['strong', 'warning'];

// Invisible characters that can split a word so a keyword check misses it.
const INVISIBLE = /[­͏؜ᅟᅠ឴឵᠋-᠎​-‏‪-‮⁠-⁤⁪-⁯ㅤ︀-️﻿ﾠ]/g;

// Cyrillic and Greek letters that look like Latin ones (NFKC leaves them alone).
const CONFUSABLES = {
  а: 'a', в: 'b', е: 'e', ё: 'e', к: 'k', м: 'm', н: 'h', о: 'o', р: 'p', с: 'c', т: 't', у: 'y', х: 'x',
  і: 'i', ї: 'i', ј: 'j', ѕ: 's', ԁ: 'd', ԛ: 'q', ԝ: 'w', һ: 'h', ӏ: 'l',
  α: 'a', β: 'b', ε: 'e', η: 'n', ι: 'i', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't', υ: 'u', χ: 'x', ω: 'w',
};
const CONFUSABLE_RE = new RegExp(`[${Object.keys(CONFUSABLES).join('')}]`, 'gu');

// Digits and symbols standing in for letters inside a word ("T0ll", "p@y", "Unpa1d").
// "1" can be an i or an l, so both readings are tried.
const LEET_COMMON = { 0: 'o', 3: 'e', 4: 'a', 5: 's', 7: 't', '@': 'a', $: 's' };
const inWord = /(?<=\p{L}[0134578@$]*)[0134578@$](?=[0134578@$]*\p{L})|(?<=\p{L}{2})[0134578@$]\b|\b[0134578@$](?=\p{L}{2})/gu;
const fold = (s, one) => s.replace(inWord, (c) => (c === '1' ? one : c === '8' ? 'b' : LEET_COMMON[c] ?? c));

/** Cleans pasted text for matching and link extraction: NFKC, no invisible characters, straight quotes. */
export function normalise(text) {
  return String(text)
    .normalize('NFKC')
    .replace(INVISIBLE, '')
    .replace(/[‘’‛′`´]/g, "'")
    .replace(/[“”‟″]/g, '"')
    .replace(/[‐-―−]/g, '-')
    .replace(/[ \t  -   　]+/g, ' ');
}

/** The lower-case versions of the text that signs are matched against (as written, and with look-alikes folded). */
export function matchForms(clean) {
  const lower = clean.toLowerCase();
  const latin = lower.replace(CONFUSABLE_RE, (c) => CONFUSABLES[c]);
  return [...new Set([lower, latin, fold(latin, 'i'), fold(latin, 'l')])];
}

/** Compiles the tactic groups. Bad entries are dropped, never thrown. */
export function compileTactics(data) {
  const out = [];
  for (const t of data?.tactics ?? []) {
    if (!t || typeof t.id !== 'string' || typeof t.label !== 'string' || !Array.isArray(t.patterns)) continue;
    try {
      out.push({ id: t.id, label: t.label, patterns: t.patterns.map((p) => new RegExp(p, 'iu')) });
    } catch {
      // As for signs: tests/message-check.test.mjs keeps the real file clean.
    }
  }
  return out;
}

/**
 * The combination rule, on any subject: one tactic means nothing, because real
 * messages ask you to call or mention a fee. A lure with a request is a warning. A
 * threat (something wrong plus a consequence) needs a third tactic to be a warning,
 * and a fourth to be a scam sign.
 */
export function tacticsSign(tactics, forms) {
  const hit = tactics.filter((t) => forms.some((f) => t.patterns.some((re) => re.test(f))));
  const has = (id) => hit.some((t) => t.id === id);
  const threat = has('problem') && has('consequence');
  const reward = has('lure') && has('ask');
  if (!reward && !(threat && hit.length >= 3)) return null;
  const strong = threat && hit.length >= 4;
  return {
    id: 'pressure-tactics',
    strength: strong ? 'strong' : 'warning',
    says: `Combines tactics scammers rely on: ${hit.map((t) => t.label).join('; ')}.`,
    guidance: null,
  };
}

/** Compiles the sign list once. Bad entries (unknown strength, bad pattern) are dropped, never thrown. */
export function compileSigns(data) {
  const out = [];
  for (const s of data?.signs ?? []) {
    if (!s || typeof s.id !== 'string' || !STRENGTHS.includes(s.strength) || typeof s.says !== 'string' || !Array.isArray(s.patterns)) continue;
    try {
      out.push({
        id: s.id,
        strength: s.strength,
        says: s.says,
        patterns: s.patterns.map((p) => new RegExp(p, 'iu')),
        unless: (s.unless ?? []).map((p) => new RegExp(p, 'iu')),
        coveredBy: Array.isArray(s.coveredBy) ? s.coveredBy : [],
        guidance: s.guidance && guidanceUrl(s.guidance.url) ? { by: s.guidance.by, title: s.guidance.title, url: guidanceUrl(s.guidance.url) } : null,
      });
    } catch {
      // A pattern that doesn't compile is skipped; tests/message-check.test.mjs keeps the real file clean.
    }
  }
  return out;
}

/**
 * Links (full URLs, then bare domains) found in the message, each read by the
 * link inspector; never fetched. Returns { links (at most MAX_LINKS), total }.
 */
export function messageLinks(clean, { psl = null, brands = [] } = {}) {
  const { groups } = extractIocs(clean, { psl });
  const urls = (groups.url ?? []).map((u) => u.value);
  const hostsOfUrls = new Set(urls.map((u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } }));
  const bare = (groups.domain ?? []).map((d) => d.value).filter((d) => !hostsOfUrls.has(d));
  const all = [...urls, ...bare];
  const links = all.slice(0, MAX_LINKS).map((value) => {
    const r = inspectUrl(value, { psl, brands });
    return r.error
      ? { value, verdict: 'Unreadable', reasons: [r.error] }
      : { value, url: r.url, host: r.host, registrable: r.registrable, ipHost: r.ipHost, verdict: r.verdict, reasons: r.reasons };
  });
  return { links, total: all.length };
}

/**
 * Checks a pasted message. Returns { error } or
 * { verdict: 'scam' | 'warning' | 'none', signs: [{ id, strength, says, guidance }],
 *   links: [{ value, verdict, reasons, ... }], truncated, linksCapped }.
 * Verdict: any strong sign or a link the inspector calls Suspicious → 'scam';
 * otherwise any warning sign → 'warning'; otherwise 'none'. No score.
 * signs is the compiled list from compileSigns().
 */
export function checkMessage(text, { signs = [], tactics = [], psl = null, brands = [] } = {}) {
  const raw = String(text ?? '');
  if (!raw.trim()) return { error: 'Paste a message to check.' };
  const truncated = raw.length > MAX_MESSAGE;
  const clean = normalise(raw.slice(0, MAX_MESSAGE));
  const forms = matchForms(clean);

  const found = [];
  for (const s of signs) {
    const hit = forms.some((f) => s.patterns.some((re) => re.test(f)));
    if (hit && !forms.some((f) => s.unless.some((re) => re.test(f)))) {
      found.push({ id: s.id, strength: s.strength, says: s.says, guidance: s.guidance, coveredBy: s.coveredBy });
    }
  }
  const pressure = tacticsSign(tactics, forms);
  if (pressure) found.push(pressure);
  // A weaker sign says nothing new once the stronger one it belongs to has matched.
  const hitIds = new Set(found.map((s) => s.id));
  const shown = found.filter((s) => !s.coveredBy?.some((id) => hitIds.has(id))).map(({ coveredBy, ...rest }) => rest);
  shown.sort((a, b) => STRENGTHS.indexOf(a.strength) - STRENGTHS.indexOf(b.strength));

  const { links, total } = messageLinks(clean, { psl, brands });
  const badLink = links.some((l) => l.verdict === 'Suspicious');
  const verdict = shown.some((s) => s.strength === 'strong') || badLink ? 'scam' : shown.length ? 'warning' : 'none';
  return { verdict, signs: shown, links, truncated, linksCapped: total > links.length };
}

export const VERDICT_TEXT = {
  scam: 'Scam signs found',
  warning: 'Some warning signs',
  none: "This check can't clear a message",
};

/** The page's one verdict: the worse of the code check and the AI's read. The AI can only raise it. */
export function combineVerdict(code, ai) {
  if (code === 'scam' || ai === 'likely_scam') return 'scam';
  if (code === 'warning' || ai === 'suspicious') return 'warning';
  return 'none';
}

export const AI_ERROR = "The AI read isn't available right now, so this result is from the code check alone.";

/** Asks the Worker for the AI read: { verdict, reasons, model } or { error }. Never throws, except on Clear (AbortError). */
export async function askAi(message, apiBase, signal) {
  let res;
  let body = null;
  try {
    res = await fetch(`${apiBase}/api/message-check`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: message.slice(0, MAX_MESSAGE).trim() }),
      referrerPolicy: 'no-referrer',
      signal,
    });
    body = await res.json();
  } catch (err) {
    if (err?.name === 'AbortError') throw err;
    return { error: AI_ERROR };
  }
  return res.ok && body?.verdict ? body : { error: AI_ERROR };
}

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('message-form')) {
  const { el, $, notice, lookUpLink, defang } = await import('./ui.js');
  const { ready } = await import('./data.js');
  const { API_BASE } = await import('../config.js');
  let signs = null;
  let tactics = [];
  let signsError = null;
  const signsReady = fetch('data/scam-signs.json')
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
    .then((d) => { signs = compileSigns(d); tactics = compileTactics(d); })
    .catch((err) => { signsError = err.message; });

  const linkRow = (l) => {
    const inspect = el('button', { type: 'button', class: 'secondary small' }, 'Inspect this link');
    inspect.addEventListener('click', () => {
      $('link-input').value = l.value;
      $('link-form').requestSubmit();
      $('link').scrollIntoView({ block: 'start' });
    });
    const target = l.ipHost ? l.host : l.registrable;
    return el('li', {},
      el('span', { class: 'mono' }, defang(l.value)), ' ',
      el('span', { class: `flag ${l.verdict === 'Looks normal' ? 'muted' : 'bad'}` }, l.verdict),
      l.reasons.length ? el('ul', { class: 'plain-list' }, ...l.reasons.map((x) => el('li', { class: 'hint' }, x))) : null,
      el('div', { class: 'row' }, inspect, target ? lookUpLink(target) : null));
  };

  // No "ok" style anywhere: nothing here can show a message is safe.
  const verdictLine = (verdict) => {
    if (verdict === 'scam') return el('p', { class: 'verdict bad' }, el('strong', {}, VERDICT_TEXT.scam));
    if (verdict === 'warning') return el('p', { class: 'verdict warn' }, el('strong', {}, VERDICT_TEXT.warning), ' Real messages can do this too, so check it a way you already trust.');
    return el('p', { class: 'verdict muted' }, el('strong', {}, VERDICT_TEXT.none), ' Neither check found a clear sign, but scams keep changing. Were you expecting this message? If not, contact them a way you already trust.');
  };

  const aiPart = (ai) => {
    if (ai === null) return el('p', { class: 'ask-thinking', role: 'status' }, 'AI is reading the message', el('span', { class: 'ask-dots', 'aria-hidden': 'true' }));
    if (ai.error) return notice('warn', ai.error);
    return el('div', {},
      el('h3', {}, 'What the AI noticed'),
      ai.reasons?.length ? el('ul', { class: 'plain-list' }, ...ai.reasons.map((t) => el('li', {}, t))) : el('p', { class: 'hint' }, 'It found nothing specific to point to, which doesn\u2019t make the message safe.'),
      el('p', { class: 'hint' }, `Read by ${ai.model}. AI can be wrong, and it can't check who really sent this.`));
  };

  const render = (r, listsError, ai) => {
    if (r.error) return [notice('warn', r.error)];
    const parts = [verdictLine(combineVerdict(r.verdict, ai?.verdict))];
    if (r.signs.length) {
      parts.push(el('ul', { class: 'plain-list' }, ...r.signs.map((s) => el('li', {},
        el('span', { class: `flag ${s.strength === 'strong' ? 'bad' : 'warn'}` }, s.strength === 'strong' ? 'Scam sign' : 'Warning'), ' ', s.says,
        s.guidance ? el('span', { class: 'hint' }, ' ', el('a', { href: s.guidance.url, target: '_blank', rel: 'noopener noreferrer' }, s.guidance.title), ` (${s.guidance.by})`) : null))));
    }
    if (r.links.length) {
      parts.push(el('h3', {}, r.linksCapped ? `Links in the message (first ${r.links.length})` : `Links in the message (${r.links.length})`),
        el('p', { class: 'hint' }, 'Read as text by the link inspector. None of them was opened.'),
        el('ul', { class: 'plain-list' }, ...r.links.map(linkRow)));
    }
    if (r.truncated) parts.push(el('p', { class: 'hint' }, 'Only the first 10 KB was checked.'));
    if (listsError) parts.push(notice('warn', 'The domain lists could not load, so look-alike checks on links are off.'));
    parts.splice(1, 0, aiPart(ai));
    return parts;
  };

  let controller = null;

  $('message-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const out = $('message-result');
    controller?.abort();
    const mine = new AbortController();
    controller = mine;
    await signsReady;
    if (!signs) {
      out.replaceChildren(notice('bad', `The list of scam signs could not load (${signsError}). Try reloading the page.`));
      $('message-next').hidden = true;
      return;
    }
    let data = {};
    let listsError = false;
    try {
      data = await ready;
    } catch {
      listsError = true;
    }
    const text = $('message-input').value;
    const r = checkMessage(text, { signs, tactics, ...data });
    // The code check shows at once; the AI's read updates it when it arrives.
    out.replaceChildren(...render(r, listsError, null));
    $('message-next').hidden = Boolean(r.error);
    if (r.error) return;
    try {
      const ai = await askAi(text, API_BASE, mine.signal);
      if (controller === mine) out.replaceChildren(...render(r, listsError, ai));
    } catch {
      // Cleared or replaced: this answer no longer belongs on the page.
    }
  });
  $('message-clear').addEventListener('click', () => {
    controller?.abort();
    controller = null;
    $('message-input').value = '';
    $('message-result').replaceChildren();
    $('message-next').hidden = true;
  });
}
