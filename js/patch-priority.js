// Patch-priority list for the CVEs page: pulls CVE IDs out of pasted text and
// ranks the Worker's lookup results. DOM-free so it can be tested in Node.
//
// The order is decided here, in code, never by a model:
//   1. the hub's priority verdict (the Worker's cveVerdict(): Rejected; in CISA KEV;
//      EPSS >= 10% or a critical remote no-login no-click flaw; then CVSS severity),
//   2. within the same verdict: known ransomware use, then higher EPSS, then higher
//      CVSS, then the CVE ID (so the order is stable).

import { normalizeCveId } from './detect.js';
import { toCsv } from './extract.js';

/** At most this many CVEs per list: NVD allows the whole site 8 keyless calls a minute. */
export const MAX_CVES = 8;
/** Pasted text is cut at this length before scanning (a long scan report is fine). */
export const MAX_TEXT = 50_000;

// Same loose shape as the IOC extractor: copy-paste dashes, underscores or spaces.
const CVE_RE = /\bCVE[\s‐-―−_-]*\d{4}[\s‐-―−_-]*\d{4,19}\b/gi;

/**
 * CVE IDs in the text, normalised and de-duplicated in order of first appearance.
 * Returns { ids, extra, invalid }: ids is capped at max, extra counts the unique
 * IDs left out, invalid lists the CVE-looking strings that aren't valid IDs.
 */
export function cveIdsFromText(text, max = MAX_CVES, now = new Date()) {
  const seen = new Set();
  const invalid = new Set();
  for (const m of String(text ?? '').slice(0, MAX_TEXT).matchAll(CVE_RE)) {
    const c = normalizeCveId(m[0], now);
    if (c?.value) seen.add(c.value);
    else invalid.add(m[0]);
  }
  const all = [...seen];
  return { ids: all.slice(0, max), extra: Math.max(0, all.length - max), invalid: [...invalid] };
}

export const VERDICT_ORDER = [
  'Exploited in the wild: patch urgently',
  'High priority',
  'Patch soon',
  'Patch on your normal cycle',
  'Low priority',
  'No score yet',
  'Not enough data',
  'Rejected: not a valid vulnerability',
];
const rankOf = (v) => {
  const i = VERDICT_ORDER.indexOf(v);
  return i === -1 ? VERDICT_ORDER.indexOf('Not enough data') : i;
};

/** Pulls the facts for one row out of a /api/lookup body (or an error). */
export function priorityRow(id, body) {
  if (!body || body.error || !Array.isArray(body.sources)) {
    return { id, verdict: 'Not enough data', reasons: [], kev: null, epss: null, cvss: null, missing: ['NVD', 'CISA KEV', 'FIRST EPSS'], error: body?.error || 'The lookup failed.' };
  }
  const ok = Object.fromEntries(body.sources.filter((s) => s.status === 'ok').map((s) => [s.id, s.data]));
  const missing = body.sources.filter((s) => s.status !== 'ok').map((s) => s.name);
  const c = ok.nvd?.cvss;
  return {
    id,
    verdict: body.priority?.verdict || 'Not enough data',
    reasons: Array.isArray(body.priority?.reasons) ? body.priority.reasons : [],
    kev: ok.kev ? { inKev: Boolean(ok.kev.inKev), dateAdded: ok.kev.dateAdded || null, dueDate: ok.kev.dueDate || null, ransomware: Boolean(ok.kev.ransomware) } : null,
    epss: Number.isFinite(ok.epss?.epss) ? ok.epss.epss : null,
    cvss: c && Number.isFinite(c.baseScore) ? { score: c.baseScore, severity: (c.severity || '').toUpperCase() || null } : null,
    missing,
  };
}

const desc = (a, b) => (b ?? -1) - (a ?? -1);

/** Sorted copy of the rows, most urgent first. */
export function sortRows(rows) {
  return [...rows].sort((a, b) => rankOf(a.verdict) - rankOf(b.verdict)
    || Number(Boolean(b.kev?.ransomware)) - Number(Boolean(a.kev?.ransomware))
    || desc(a.epss, b.epss)
    || desc(a.cvss?.score, b.cvss?.score)
    || a.id.localeCompare(b.id));
}

/** EPSS as a short percentage: "12.3%", or two decimals under 1%. */
export const epssText = (f) => (f == null ? 'unknown' : `${(f * 100).toFixed(f < 0.01 ? 2 : 1)}%`);

/** One plain line of facts for a row. */
export function factsLine(r) {
  const kev = r.kev == null ? 'KEV: unknown'
    : r.kev.inKev ? `In CISA KEV since ${r.kev.dateAdded || '?'}${r.kev.ransomware ? ' (ransomware use known)' : ''}`
      : 'Not in CISA KEV';
  const cvss = r.cvss ? `CVSS ${r.cvss.score}${r.cvss.severity ? ` ${r.cvss.severity.toLowerCase()}` : ''}` : 'no CVSS score';
  return `${kev} · EPSS ${epssText(r.epss)} · ${cvss}`;
}

/** CSV of the ranked list, for a ticket or spreadsheet (cells made formula-safe by toCsv). */
export function rowsToCsv(sorted) {
  return toCsv([
    ['rank', 'cve', 'hub_priority', 'in_kev', 'kev_date_added', 'kev_due_date', 'ransomware', 'epss', 'cvss', 'severity', 'unavailable'],
    ...sorted.map((r, i) => [
      i + 1, r.id, r.verdict,
      r.kev == null ? '' : r.kev.inKev ? 'yes' : 'no',
      r.kev?.dateAdded || '', r.kev?.dueDate || '',
      r.kev == null ? '' : r.kev.ransomware ? 'known' : '',
      r.epss == null ? '' : r.epss.toFixed(4),
      r.cvss?.score ?? '', r.cvss?.severity || '',
      r.missing.join('; '),
    ]),
  ]);
}
