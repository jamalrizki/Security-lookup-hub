// News page: one request to /api/news (a snapshot the Worker's cron job keeps
// in KV). Filter lives in the URL fragment (#filter=kev). All text via textContent.

import { API_BASE } from './config.js';

const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

const FILTERS = [
  ['all', 'All'],
  ['advisories', 'Advisories'],
  ['kev', 'KEV'],
  ['news', 'News'],
];
const STALE_MS = 3 * 3600 * 1000; // hourly refresh; three missed runs is stale

function ago(iso) {
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms)) return '';
  const min = Math.round(ms / 60000);
  if (min < 1) return 'just now';
  if (min < 60) return `${min} min ago`;
  const h = Math.round(min / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

function when(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return el('time', { datetime: d.toISOString(), title: d.toUTCString() }, ago(iso));
}

// Links come from the Worker, which only keeps https links on each publisher's
// own domain; this re-checks before linking.
function safe(href) {
  try {
    const u = new URL(href);
    return u.protocol === 'https:' && !u.username ? u.href : null;
  } catch {
    return null;
  }
}

const KIND = { kev: 'KEV', advisories: 'Advisory', news: 'News' };

function itemRow(item, sources) {
  const href = safe(item.link);
  const title = href ? el('a', { href, target: '_blank', rel: 'noopener noreferrer' }, item.title) : el('span', {}, item.title);
  const publisher = sources[item.source]?.name || item.source;
  const body = el('div', { class: 'news-body' },
    el('h3', { class: 'news-title' }, title),
    el('div', { class: 'news-source' }, publisher));
  if (item.cve) {
    body.append(el('p', { class: 'kev-line' },
      el('a', { href: `./#q=${encodeURIComponent(item.cve)}`, class: 'mono' }, item.cve),
      ` \u00b7 ${[item.vendor, item.product].filter(Boolean).join(' ')}`,
      item.ransomware ? el('span', { class: 'flag bad' }, 'Ransomware use') : null));
  }
  if (item.summary) body.append(el('p', { class: 'news-summary' }, item.summary));
  return el('li', { class: 'news-row' },
    el('span', { class: `news-tag ${item.filter}` }, KIND[item.filter] || item.filter),
    body,
    el('span', { class: 'news-age' }, when(item.date)));
}

let data;
let filter = 'all';

function render() {
  const sources = data.sources || {};
  const items = Object.values(sources).flatMap((s) => s.items || [])
    .sort((a, b) => String(b.date || '').localeCompare(String(a.date || '')));
  const count = (key) => (key === 'all' ? items.length : items.filter((i) => i.filter === key).length);

  $('news-filters').replaceChildren(...FILTERS.map(([key, label]) => {
    const b = el('button', { type: 'button', class: 'chip', 'aria-pressed': String(filter === key) }, label, el('span', { class: 'chip-count' }, String(count(key))));
    b.addEventListener('click', () => { location.hash = key === 'all' ? '' : `filter=${key}`; });
    return b;
  }));

  const shown = filter === 'all' ? items : items.filter((i) => i.filter === filter);
  if (data.pending) {
    $('news-list').replaceChildren(el('p', { class: 'notice warn' }, 'First update runs within the hour.'));
  } else {
    $('news-list').replaceChildren(shown.length
      ? el('ul', { class: 'rows' }, ...shown.map((i) => itemRow(i, sources)))
      : el('p', { class: 'empty' }, 'Nothing here yet.'));
  }

  $('news-status').replaceChildren(...Object.values(sources).map((s) => {
    const stale = !s.ok || !s.fetchedAt || Date.now() - Date.parse(s.fetchedAt) > STALE_MS;
    return el('span', { class: stale ? 'stale' : '' },
      `${s.name}: ${s.fetchedAt ? `last updated ${ago(s.fetchedAt)}` : 'not updated yet'}${stale ? ' (stale)' : ''}. `);
  }), 'Headlines and links only; read the full story on each publisher’s site.');
}

function readHash() {
  const f = new URLSearchParams(location.hash.slice(1)).get('filter');
  filter = FILTERS.some(([k]) => k === f) ? f : 'all';
}

try {
  const res = await fetch(`${API_BASE}/api/news`, { referrerPolicy: 'no-referrer' });
  data = await res.json();
  if (data.error) throw new Error(data.error);
  readHash();
  render();
  window.addEventListener('hashchange', () => { readHash(); render(); });
} catch (err) {
  $('news-list').replaceChildren(el('p', { class: 'notice warn' }, `Could not load the news: ${err.message}`));
}
