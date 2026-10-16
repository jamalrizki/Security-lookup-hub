// IOC extractor (#ioc). Runs in the browser; only a "Look up" click on one
// value leaves the page. There is deliberately no "look up all": VirusTotal
// allows 4 lookups a minute for the whole site.

import { extractIocs, toCsv, MAX_TEXT } from '../extract.js';
import { ready } from './data.js';
import { el, $, notice, lookUpLink, copyButton, download, defang } from './ui.js';

const TYPES = [
  ['url', 'URLs', 'URL'], ['domain', 'Domains', 'domain'], ['ipv4', 'IPv4 addresses', 'IPv4 address'], ['ipv6', 'IPv6 addresses', 'IPv6 address'],
  ['email', 'Email addresses', 'email address'], ['hash', 'Hashes', 'hash'], ['cve', 'CVE IDs', 'CVE ID'],
];
const show = (type, v) => (['url', 'domain', 'email'].includes(type) ? defang(v) : v);

let last = null;

function groupTable(type, label, items) {
  return el('details', { class: 'ioc-group', open: true },
    el('summary', {}, `${label} (${items.length})`),
    el('table', { class: 'ioc-table' },
      el('thead', {}, el('tr', {}, el('th', {}, 'Value'), el('th', {}, 'Count'), el('th', {}, ''))),
      el('tbody', {}, ...items.map((i) => el('tr', {},
        el('td', { class: 'mono' }, show(type, i.value), i.note ? el('span', { class: 'flag warn' }, i.note) : null),
        el('td', {}, String(i.count)),
        el('td', { class: 'actions' }, lookUpLink(i.value), copyButton(() => i.value)))))));
}

function topList(label, items, type) {
  const top = [...items].sort((a, b) => b.count - a.count).slice(0, 10);
  return el('div', {}, el('h3', {}, label), top.length
    ? el('ol', { class: 'plain-list' }, ...top.map((i) => el('li', { class: 'mono' }, `${show(type, i.value)} × ${i.count}`)))
    : el('p', { class: 'hint' }, 'None'));
}

async function run() {
  const out = $('ioc-result');
  const text = $('ioc-input').value;
  if (!text.trim()) {
    out.replaceChildren();
    return;
  }
  let psl = null;
  try {
    ({ psl } = await ready);
  } catch {
    out.replaceChildren(notice('warn', 'The domain list could not load, so file names like report.txt may show up as domains.'));
  }
  const logMode = $('ioc-log').checked;
  const r = extractIocs(text, { psl, lineFilter: logMode ? $('ioc-filter').value : '' });
  last = r;
  const parts = [];
  if (text.length > MAX_TEXT) parts.push(notice('warn', `Only the first ${MAX_TEXT / 1024} KB were scanned.`));
  const counts = TYPES.filter(([t]) => r.groups[t]).map(([t, many, one]) => (r.groups[t].length === 1 ? `1 ${one}` : `${r.groups[t].length} ${many.replace(/^(?!URL|IPv|CVE)\w/, (c) => c.toLowerCase())}`));
  parts.push(el('p', {}, r.total ? `Found ${counts.join(', ')}.` : 'No indicators found.'));
  if (r.dropped.length) {
    const byReason = {};
    for (const d of r.dropped) byReason[d.kind] = (byReason[d.kind] || 0) + 1;
    parts.push(el('details', { class: 'more' },
      el('summary', {}, `Left out ${r.dropped.length}: ${Object.entries(byReason).map(([k, v]) => `${v} \u00d7 ${k}`).join('; ')}`),
      el('ul', { class: 'mono-list' }, ...r.dropped.slice(0, 200).map((d) => el('li', {}, `${d.value} — ${d.reason}`)))));
  }
  if (r.total) {
    parts.push(el('div', { class: 'row' },
      copyButton(() => TYPES.flatMap(([t]) => (r.groups[t] || []).map((i) => show(t, i.value))).join('\n'), 'Copy all (defanged)'),
      (() => {
        const b = el('button', { type: 'button', class: 'secondary small' }, 'Download CSV');
        b.addEventListener('click', () => download('iocs.csv', toCsv([['type', 'value', 'count', 'note'],
          ...TYPES.flatMap(([t]) => (r.groups[t] || []).map((i) => [t, i.value, i.count, i.note || '']))])));
        return b;
      })()));
  }
  if (logMode && r.total) {
    parts.push(el('div', { class: 'tools pair' },
      topList('Top IPs', [...(r.groups.ipv4 || []), ...(r.groups.ipv6 || [])], 'ip'),
      topList('Top domains', r.groups.domain || [], 'domain')));
  }
  for (const [t, l] of TYPES) if (r.groups[t]) parts.push(groupTable(t, l, r.groups[t]));
  out.replaceChildren(...parts);
}

$('ioc-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  run();
});
$('ioc-log').addEventListener('change', () => {
  $('ioc-filter-row').hidden = !$('ioc-log').checked;
});
$('ioc-clear').addEventListener('click', () => {
  $('ioc-input').value = '';
  $('ioc-result').replaceChildren();
  last = null;
});

/** Lets other tools (the file analyzer's strings) hand text to the extractor. */
export function sendToExtractor(text) {
  $('ioc-input').value = text;
  location.hash = 'ioc';
  run();
}
export const lastResult = () => last;
