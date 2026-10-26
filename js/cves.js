// CVEs page: keyword search over NVD via the Worker. The search lives in the
// URL fragment (#q=fortinet&severity=HIGH) so results can be shared.

import { validateCveSearch } from './detect.js';
import { API_BASE } from './config.js';
import { cveIdsFromText, priorityRow, sortRows, factsLine, rowsToCsv, MAX_CVES } from './patch-priority.js';
import { download } from './analyze/ui.js';
import { summaryLine, rowDetail, rowLabel, NOT_LISTED_NOTE } from './kev-search.js';

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

// ---------- Patch priority list ----------
// Paste CVE IDs (or any text containing them); each one goes through the normal
// /api/lookup, one at a time, and the list is ranked in code (js/patch-priority.js).

const VERDICT_CLASS = {
  'Exploited in the wild: patch urgently': 'sev-critical',
  'High priority': 'sev-critical',
  'Patch soon': 'sev-high',
  'Patch on your normal cycle': 'sev-medium',
  'Low priority': 'sev-low',
};

function prioRow(r, i) {
  const sev = (r.cvss?.severity || '').toLowerCase();
  // The facts line already shows KEV, EPSS and CVSS; only "High priority" has a reason it doesn't (EPSS 10%+, or remote no-login no-click).
  const reasons = r.verdict === 'High priority' && r.reasons.length ? ` — ${r.reasons.join('; ')}` : '';
  const gaps = r.error ? ` (${r.error})` : r.missing.length ? ` (unavailable right now: ${r.missing.join(', ')})` : '';
  return el('li', { class: 'cve-row' },
    el('span', { class: `cve-score sev-${sev || 'none'}` }, r.cvss ? String(r.cvss.score) : '—'),
    el('div', { class: 'cve-id' },
      el('strong', { class: 'mono' }, `${i + 1}. ${r.id}`),
      el('span', { class: VERDICT_CLASS[r.verdict] || 'sev-none' }, r.verdict)),
    el('p', { class: 'cve-desc' }, `${factsLine(r)}${reasons}${gaps}`),
    el('a', { class: 'cve-go', href: `./#q=${encodeURIComponent(r.id)}` }, 'Look up →'));
}

async function lookupCve(id) {
  try {
    const res = await fetch(`${API_BASE}/api/lookup?q=${encodeURIComponent(id)}`, { referrerPolicy: 'no-referrer' });
    return await res.json();
  } catch {
    return { error: 'The lookup service could not be reached.' };
  }
}

let prioRun = 0;
async function rank(text) {
  const out = $('prio-results');
  const { ids, extra, invalid } = cveIdsFromText(text);
  if (!ids.length) {
    out.replaceChildren(notice('warn', invalid.length
      ? `No valid CVE IDs found (${invalid.slice(0, 3).join(', ')} ${invalid.length === 1 ? "isn't" : "aren't"} valid). CVE IDs look like CVE-2021-44228.`
      : 'No CVE IDs found. Paste IDs like CVE-2021-44228, or text that contains them.'));
    return;
  }
  const mine = ++prioRun;
  const rows = [];
  for (const [i, id] of ids.entries()) {
    out.replaceChildren(el('p', { class: 'hint' }, `Checking ${id} (${i + 1} of ${ids.length})…`));
    const body = await lookupCve(id);
    if (mine !== prioRun) return;
    rows.push(priorityRow(id, body));
  }
  const sorted = sortRows(rows);
  const csvButton = el('button', { type: 'button', class: 'secondary' }, 'Download CSV');
  csvButton.addEventListener('click', () => download('patch-priority.csv', rowsToCsv(sorted)));
  out.replaceChildren(...[
    extra ? notice('warn', `Only the first ${MAX_CVES} CVE IDs were checked; ${extra} more ${extra === 1 ? 'was' : 'were'} left out. Run them as a second list in a minute.`) : null,
    invalid.length ? el('p', { class: 'hint' }, `Skipped ${invalid.length} invalid ID${invalid.length === 1 ? '' : 's'}: ${invalid.slice(0, 5).join(', ')}.`) : null,
    el('p', { class: 'hint' }, 'Most urgent first. The order is the hub’s rule of thumb, decided in code: CISA KEV first, then EPSS, then CVSS. It is not a vendor rating, and it doesn’t know which products you run.'),
    el('ul', { class: 'rows' }, ...sorted.map(prioRow)),
    el('div', { class: 'row' }, csvButton),
  ].filter(Boolean)); // replaceChildren would print a null as the text "null"
}

$('prio-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  rank($('prio-text').value);
});

// ---------- Exploited in my products (CISA KEV by vendor or product) ----------
// GET /api/kev-search filters the KEV file the Worker already holds; counts and
// order are decided there in code. "Rank these" hands the newest IDs to the
// patch priority list above.

function kevRow(r) {
  return el('li', { class: 'cve-row' },
    el('span', { class: 'cve-score sev-critical' }, 'KEV'),
    el('div', { class: 'cve-id' },
      el('strong', { class: 'mono' }, r.id),
      el('span', { class: r.ransomware ? 'sev-critical' : 'sev-high' }, rowLabel(r))),
    el('p', { class: 'cve-desc' }, rowDetail(r)),
    el('a', { class: 'cve-go', href: `./#q=${encodeURIComponent(r.id)}` }, 'Look up →'));
}

let kevRun = 0;
async function kevList(q) {
  const out = $('kev-results');
  const v = validateCveSearch(q);
  if (v.error) {
    out.replaceChildren(notice('warn', v.error));
    return;
  }
  const mine = ++kevRun;
  out.replaceChildren(el('p', { class: 'hint' }, 'Checking the CISA KEV catalog…'));
  let body;
  try {
    const res = await fetch(`${API_BASE}/api/kev-search?${new URLSearchParams({ q: v.keyword })}`, { referrerPolicy: 'no-referrer' });
    body = await res.json();
  } catch {
    body = { error: 'The search service could not be reached.' };
  }
  if (mine !== kevRun) return;
  if (body.error || !Array.isArray(body.results)) {
    out.replaceChildren(notice('warn', body.error || 'The search failed. Try again later.'));
    return;
  }
  const parts = [el('p', {}, summaryLine(body)), el('p', { class: 'hint' }, NOT_LISTED_NOTE)];
  if (body.results.length) {
    const ids = body.results.map((r) => r.id).slice(0, MAX_CVES);
    const rankButton = el('button', { type: 'button', class: 'secondary' },
      body.results.length > MAX_CVES ? `Rank the ${MAX_CVES} newest →` : 'Rank these →');
    rankButton.addEventListener('click', () => {
      $('prio-text').value = ids.join(', ');
      document.getElementById('priority').scrollIntoView();
      rank($('prio-text').value);
    });
    // Button above the list: up to 50 rows would push it off screen.
    parts.push(el('div', { class: 'row' }, rankButton), el('ul', { class: 'rows' }, ...body.results.map(kevRow)));
  }
  out.replaceChildren(...parts);
}

$('kev-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  kevList($('kev-q').value);
});
