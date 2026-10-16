// CVEs page: keyword search over NVD via the Worker. The search lives in the
// URL fragment (#q=fortinet&severity=HIGH) so results can be shared.

import { validateCveSearch } from './detect.js';
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

const SEVERITY_KIND = { CRITICAL: 'bad', HIGH: 'bad', MEDIUM: 'warn', LOW: 'ok' };
const notice = (kind, text) => el('p', { class: `notice ${kind}` }, text);

function row(r) {
  const sev = r.severity ? `${r.severity[0]}${r.severity.slice(1).toLowerCase()}` : null;
  return el('li', { class: 'cve-row' },
    el('div', { class: 'cve-head' },
      el('a', { href: `./#q=${encodeURIComponent(r.id)}`, class: 'mono' }, r.id),
      sev ? el('span', { class: `flag ${SEVERITY_KIND[r.severity] || 'muted'}` }, `${sev} ${r.score}`) : el('span', { class: 'flag muted' }, 'No score yet'),
      el('span', { class: 'hint' }, r.published)),
    el('p', {}, r.summary));
}

let run = 0;
async function search(q, severity) {
  const out = $('cve-results');
  const v = validateCveSearch(q, severity);
  if (v.error) {
    out.replaceChildren(notice('warn', v.error));
    return;
  }
  const mine = ++run;
  out.replaceChildren(el('p', { class: 'hint' }, 'Searching NVD…'));
  const params = new URLSearchParams({ q: v.keyword });
  if (v.severity) params.set('severity', v.severity);
  let body;
  try {
    const res = await fetch(`${API_BASE}/api/cve-search?${params}`, { referrerPolicy: 'no-referrer' });
    body = await res.json();
  } catch {
    body = { error: 'The search service could not be reached.' };
  }
  if (mine !== run) return;
  if (body.error) {
    out.replaceChildren(notice('warn', body.error));
    return;
  }
  if (!body.total) {
    out.replaceChildren(el('p', {}, `No NVD matches for “${v.keyword}”.`));
    return;
  }
  out.replaceChildren(
    el('p', { class: 'hint' }, `Showing the ${body.results.length} newest of ${body.total.toLocaleString()} matches${body.cached ? ' (cached)' : ''}.`),
    el('ul', { class: 'cve-list' }, ...body.results.map(row)),
  );
}

function fromHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  const q = p.get('q');
  if (!q) return;
  $('cve-q').value = q;
  $('cve-sev').value = (p.get('severity') || '').toUpperCase();
  search(q, p.get('severity'));
}

$('cve-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  const params = new URLSearchParams({ q: $('cve-q').value.trim() });
  if ($('cve-sev').value) params.set('severity', $('cve-sev').value);
  if (location.hash.slice(1) === params.toString()) search($('cve-q').value, $('cve-sev').value);
  else location.hash = params.toString(); // triggers hashchange -> search
});
window.addEventListener('hashchange', fromHash);
fromHash();
