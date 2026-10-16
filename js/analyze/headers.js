// Email-header analyzer (#headers). Headers contain your own address; they are
// parsed here in the browser and never sent anywhere.

import { parseHeaders, MAX_HEADERS } from '../extract.js';
import { ready } from './data.js';
import { el, $, notice, rows, lookUpLink, defang } from './ui.js';

const RESULT_KIND = { pass: 'ok', fail: 'bad', softfail: 'warn', neutral: 'warn', none: 'warn', temperror: 'warn', permerror: 'bad', policy: 'warn' };

function delay(s) {
  if (s == null) return '';
  if (s < 0) return 'clock skew (earlier than previous hop)';
  if (s < 60) return `+${s}s`;
  if (s < 3600) return `+${Math.round(s / 60)} min`;
  return `+${(s / 3600).toFixed(1)} h`;
}

function authRow(method, results) {
  if (!results?.length) return [method.toUpperCase(), el('span', { class: 'hint' }, 'not reported')];
  return [method.toUpperCase(), el('span', {}, ...results.flatMap((r, i) => [
    i ? ', ' : null,
    el('span', { class: `flag ${RESULT_KIND[r.result] || 'muted'}` }, r.result),
    r.domain ? ` ${r.domain}` : '',
  ]))];
}

async function analyze() {
  const raw = $('headers-input').value;
  const out = $('headers-result');
  if (!raw.trim()) {
    out.replaceChildren();
    return;
  }
  let psl = null;
  try {
    ({ psl } = await ready);
  } catch { /* domain comparisons fall back to exact matches */ }
  const h = parseHeaders(raw, { psl });
  if (!h.headers) {
    out.replaceChildren(notice('warn', 'No headers found. Paste the raw headers ("Show original" in Gmail, "View source" in Outlook).'));
    return;
  }
  const parts = [];
  if (raw.length > MAX_HEADERS) parts.push(notice('warn', `Only the first ${MAX_HEADERS / 1024} KB were read.`));
  parts.push(rows([
    ['Subject', h.subject],
    ['From', h.from],
    ['Reply-To', h.replyTo],
    ['Return-Path', h.returnPath],
    ['Message-ID domain', h.messageId],
    ['Date', h.date],
  ]));
  parts.push(h.mismatches.length
    ? el('div', { class: 'verdict warn' }, el('strong', {}, 'Mismatches'), el('ul', { class: 'plain-list' }, ...h.mismatches.map((m) => el('li', {}, m))))
    : el('p', { class: 'verdict ok' }, 'From, Reply-To, Return-Path and Message-ID domains agree.'));

  parts.push(el('h3', {}, 'Authentication'),
    el('p', { class: 'hint' }, h.authHeaders
      ? `From the topmost Authentication-Results header (added by the receiving provider)${h.authHeaders > 1 ? `; ${h.authHeaders - 1} more further down may have been added by other servers` : ''}.`
      : 'No Authentication-Results header. Your provider adds it on delivery; it may be missing if these headers were copied from a sent message.'),
    rows([authRow('spf', h.auth.spf), authRow('dkim', h.auth.dkim), authRow('dmarc', h.auth.dmarc)]));

  if (h.hops.length) {
    parts.push(el('h3', {}, `Delivery path (${h.hops.length} hops, oldest first)`),
      el('p', { class: 'hint' }, 'Only the last few hops (added by your own mail provider) can be trusted. Lower ones were written by servers you don’t control and can be forged.'),
      el('ol', { class: 'hops' }, ...h.hops.map((hop, i) => el('li', {},
        el('div', {}, el('span', { class: 'mono' }, hop.from || '?'), ' → ', el('span', { class: 'mono' }, hop.by || '?')),
        el('div', { class: 'hint' },
          hop.ip ? el('span', { class: 'mono' }, hop.ip) : null,
          hop.ip && hop.publicIp ? lookUpLink(hop.ip) : hop.ip ? ' (private)' : null,
          hop.time ? ` · ${new Date(hop.time).toUTCString()}` : '',
          i ? ` · ${delay(hop.delaySeconds)}` : '')))));
  }

  const g = h.iocs.groups;
  const found = [...(g.ipv4 || []), ...(g.ipv6 || []), ...(g.domain || [])];
  if (found.length) {
    parts.push(el('h3', {}, 'Public IPs and domains in the path'),
      el('ul', { class: 'plain-list' }, ...found.map((i) => el('li', {}, el('span', { class: 'mono' }, defang(i.value)), ' ', lookUpLink(i.value)))));
  }
  out.replaceChildren(...parts);
}

$('headers-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  analyze();
});
