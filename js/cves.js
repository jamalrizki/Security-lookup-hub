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
  const sev = (r.severity || '').toLowerCase();
  const href = `./#q=${encodeURIComponent(r.id)}`;
  return el('li', { class: 'cve-row' },
    el('span', { class: `cve-score sev-${sev || 'none'}` }, r.score != null ? String(r.score) : '\u2014'),
    el('div', { class: 'cve-id' },
      el('strong', { class: 'mono' }, r.id),
      el('span', { class: `sev-${sev || 'none'}` }, sev ? `${sev} \u00b7 ${r.published}` : `No score yet \u00b7 ${r.published}`)),
    el('p', { class: 'cve-desc' }, r.summary),
    el('a', { class: 'cve-go', href }, 'Look up \u2192'));
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
    el('ul', { class: 'rows' }, ...body.results.map(row)),
  );
}

// Severity is a segmented control: one radio per level, "" for any.
const getSev = () => document.querySelector('input[name="cve-sev"]:checked')?.value || '';
function setSev(v) {
  const want = String(v || '').toUpperCase();
  const box = document.querySelector(`input[name="cve-sev"][value="${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(want) ? want : ''}"]`);
  if (box) box.checked = true;
}

function fromHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  const q = p.get('q');
  if (!q) return;
  $('cve-q').value = q;
  setSev(p.get('severity'));
  search(q, p.get('severity'));
}

$('cve-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  const params = new URLSearchParams({ q: $('cve-q').value.trim() });
  if (getSev()) params.set('severity', getSev());
  if (location.hash.slice(1) === params.toString()) search($('cve-q').value, getSev());
  else location.hash = params.toString(); // triggers hashchange -> search
});
window.addEventListener('hashchange', fromHash);
fromHash();
