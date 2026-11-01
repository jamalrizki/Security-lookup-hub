// "Is this message a scam?" (#message). Paste a text or email; warning signs
// from data/scam-signs.json are matched in code, links in the message go
// through the link inspector's own inspectUrl(), and the verdict is decided
// here, never by a model. Nothing pasted leaves the page and no link is ever
// opened or fetched. Pure functions are exported for tests; the page wiring at
// the bottom only runs in a browser.

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
const inWord = /(?<=\p{L})[0134578@$](?=\p{L})|(?<=\p{L}{2})[0134578@$]\b|\b[0134578@$](?=\p{L}{2})/gu;
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
export function checkMessage(text, { signs = [], psl = null, brands = [] } = {}) {
  const raw = String(text ?? '');
  if (!raw.trim()) return { error: 'Paste a message to check.' };
  const truncated = raw.length > MAX_MESSAGE;
  const clean = normalise(raw.slice(0, MAX_MESSAGE));
  const forms = matchForms(clean);

  const found = [];
  for (const s of signs) {
    const hit = forms.some((f) => s.patterns.some((re) => re.test(f)));
    if (hit && !forms.some((f) => s.unless.some((re) => re.test(f)))) {
      found.push({ id: s.id, strength: s.strength, says: s.says, guidance: s.guidance });
    }
  }
  found.sort((a, b) => STRENGTHS.indexOf(a.strength) - STRENGTHS.indexOf(b.strength));

  const { links, total } = messageLinks(clean, { psl, brands });
  const badLink = links.some((l) => l.verdict === 'Suspicious');
  const verdict = found.some((s) => s.strength === 'strong') || badLink ? 'scam' : found.length ? 'warning' : 'none';
  return { verdict, signs: found, links, truncated, linksCapped: total > links.length };
}

export const VERDICT_TEXT = {
  scam: 'Scam signs found',
  warning: 'Some warning signs',
  none: 'No known scam signs found',
};

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('message-form')) {
  const { el, $, notice, lookUpLink, defang } = await import('./ui.js');
  const { ready } = await import('./data.js');
  let signs = null;
  let signsError = null;
  const signsReady = fetch('data/scam-signs.json')
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
    .then((d) => { signs = compileSigns(d); })
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

  const render = (r, listsError) => {
    if (r.error) return [notice('warn', r.error)];
    const parts = [];
    if (r.verdict === 'scam') parts.push(el('p', { class: 'verdict bad' }, el('strong', {}, VERDICT_TEXT.scam)));
    else if (r.verdict === 'warning') parts.push(el('p', { class: 'verdict warn' }, el('strong', {}, VERDICT_TEXT.warning), ' Real messages can do this too, so check it a way you already trust.'));
    else parts.push(el('p', { class: 'verdict ok' }, el('strong', {}, VERDICT_TEXT.none), ' That doesn’t make it safe: new scams use new wording.'));
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
    return parts;
  };

  $('message-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const out = $('message-result');
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
    const r = checkMessage($('message-input').value, { signs, ...data });
    out.replaceChildren(...render(r, listsError));
    $('message-next').hidden = Boolean(r.error);
  });
  $('message-clear').addEventListener('click', () => {
    $('message-input').value = '';
    $('message-result').replaceChildren();
    $('message-next').hidden = true;
  });
}
