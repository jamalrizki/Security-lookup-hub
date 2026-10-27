// DMARC report viewer (#dmarc). Reads a DMARC aggregate report (the XML that
// mailbox providers send to a domain's rua= address) locally with the
// browser's DOMParser. Totals, alignment percentages and the readiness line
// are computed here from the report; nothing is sent anywhere. Accepts the
// RFC 7489 format (no namespace, or the old dmarc.org one) and RFC 9990's
// urn:ietf:params:xml:ns:dmarc-2.0, and tolerates missing optional fields,
// since many reporters don't follow the format closely.

import { lookupable } from './nmap.js';

export const MAX_DMARC = 10 * 1024 * 1024;
/** A failing source counts as "real volume" at this share of all messages or more. */
export const REAL_VOLUME = 0.01;
/** Table rows shown at once (largest sources first); totals always use every row. */
export const MAX_ROWS_SHOWN = 500;

/** Refuses oversized input, compressed files and XML that declares entities or a DTD subset. */
export function checkDmarcXml(text) {
  if (text.length > MAX_DMARC) return 'That is more than 10 MB.';
  if (/^(\x1f[\x8b\ufffd]|PK\x03\x04)/.test(text)) return 'That is a compressed report (.gz or .zip). Unzip it first and drop the .xml inside.';
  if (/<!ENTITY/i.test(text) || /<!DOCTYPE[^>]*\[/i.test(text)) return 'This XML declares entities, which DMARC reports never do, so it was not read.';
  return null;
}

const RESULTS = new Set(['pass', 'fail', 'none', 'neutral', 'softfail', 'temperror', 'permerror', 'policy']);
const DISPOSITIONS = new Set(['none', 'quarantine', 'reject']);

// Children by local name, so namespaced (RFC 9990) and plain reports read the same.
const kids = (node, name) => (node ? [...node.children].filter((c) => (c.localName || c.nodeName) === name) : []);
const kid = (node, name) => kids(node, name)[0] || null;
const text = (node, max = 253) => {
  const t = node?.textContent?.trim();
  return t ? t.slice(0, max) : null;
};
const result = (node) => {
  const t = text(node, 20)?.toLowerCase();
  return t ? (RESULTS.has(t) ? t : 'other') : null;
};
const epoch = (node) => {
  const t = text(node, 20);
  return t && /^\d{1,12}$/.test(t) ? new Date(Number(t) * 1000) : null;
};

/**
 * Turns a parsed report Document into plain objects.
 * Returns { error } or { meta, policy, records, skipped }.
 */
export function readDmarc(doc) {
  const root = doc?.documentElement;
  if (!root || (root.localName || root.nodeName) !== 'feedback') return { error: 'That is XML, but not a DMARC aggregate report (no <feedback> root).' };

  const md = kid(root, 'report_metadata');
  const range = kid(md, 'date_range');
  const meta = {
    namespace: root.namespaceURI || null,
    org: text(kid(md, 'org_name'), 200),
    email: text(kid(md, 'email'), 200),
    id: text(kid(md, 'report_id'), 200),
    begin: epoch(kid(range, 'begin')),
    end: epoch(kid(range, 'end')),
  };
  const pp = kid(root, 'policy_published');
  const pct = text(kid(pp, 'pct'), 4);
  const p = text(kid(pp, 'p'), 20)?.toLowerCase();
  const policy = {
    domain: text(kid(pp, 'domain')),
    p: DISPOSITIONS.has(p) ? p : null,
    sp: text(kid(pp, 'sp'), 20),
    adkim: text(kid(pp, 'adkim'), 2),
    aspf: text(kid(pp, 'aspf'), 2),
    pct: pct && /^\d{1,3}$/.test(pct) && Number(pct) <= 100 ? Number(pct) : null,
    testing: text(kid(pp, 'testing'), 2)?.toLowerCase() === 'y',
  };

  const records = [];
  let skipped = 0;
  for (const rec of kids(root, 'record')) {
    const row = kid(rec, 'row');
    const pe = kid(row, 'policy_evaluated');
    const count = text(kid(row, 'count'), 40); // longer than any safe integer, so truncation can't make a bad count look valid
    const ip = text(kid(row, 'source_ip'), 45);
    // Counts must be non-negative whole numbers; a row without one can't be totalled.
    if (!count || !/^\d+$/.test(count) || !Number.isSafeInteger(Number(count))) { skipped++; continue; }
    const ar = kid(rec, 'auth_results');
    const disp = text(kid(pe, 'disposition'), 20)?.toLowerCase();
    records.push({
      ip,
      count: Number(count),
      disposition: DISPOSITIONS.has(disp) ? disp : null,
      dkimAligned: result(kid(pe, 'dkim')) === 'pass',
      spfAligned: result(kid(pe, 'spf')) === 'pass',
      headerFrom: text(kid(kid(rec, 'identifiers'), 'header_from')),
      dkim: kids(ar, 'dkim').slice(0, 10).map((d) => ({ domain: text(kid(d, 'domain')), selector: text(kid(d, 'selector'), 100), result: result(kid(d, 'result')) })),
      spf: kids(ar, 'spf').slice(0, 10).map((s) => ({ domain: text(kid(s, 'domain')), result: result(kid(s, 'result')) })),
    });
  }
  return { meta, policy, records, skipped };
}

/** Parses report text. Returns { error } or the readDmarc result. */
export function parseDmarc(text, Parser = globalThis.DOMParser) {
  const bad = checkDmarcXml(text);
  if (bad) return { error: bad };
  const doc = new Parser().parseFromString(text, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) return { error: 'That is not well-formed XML.' };
  return readDmarc(doc);
}

/** A record passes DMARC when SPF or DKIM passed and aligned with the From domain. */
export const passes = (r) => r.dkimAligned || r.spfAligned;

/** Totals and failing sources (grouped by IP, largest first). */
export function summarize(report) {
  const total = report.records.reduce((n, r) => n + r.count, 0);
  const passed = report.records.filter(passes).reduce((n, r) => n + r.count, 0);
  const bySource = new Map();
  for (const r of report.records) {
    if (passes(r) || !r.count) continue;
    const key = r.ip || '(no IP)';
    const s = bySource.get(key) || { ip: key, count: 0, spfFail: false, noDkim: true };
    s.count += r.count;
    if (r.spf.some((x) => x.result && x.result !== 'pass')) s.spfFail = true;
    if (r.dkim.some((x) => x.result)) s.noDkim = false;
    bySource.set(key, s);
  }
  const failing = [...bySource.values()].sort((a, b) => b.count - a.count || a.ip.localeCompare(b.ip));
  const sources = new Set(report.records.map((r) => r.ip || '(no IP)')).size;
  return { total, passed, failed: total - passed, pct: total ? Math.floor((passed / total) * 1000) / 10 : null, sources, failing };
}

/** The next policy step after the published one. */
export function nextStep(policy) {
  const pct = policy.pct ?? 100;
  if (policy.p === 'reject') return pct < 100 ? `raise pct from ${pct} to 100` : null;
  if (policy.p === 'quarantine') return pct < 100 ? `raise pct from ${pct} to 100` : 'move to p=reject';
  return 'move to p=quarantine';
}

/**
 * The readiness line, decided only from the report and the fixed constants above.
 * Returns { level: 'ok' | 'warn' | 'bad' | 'muted', text }.
 */
export function readiness(report, sum = summarize(report)) {
  if (!sum.total) return { level: 'muted', text: 'This report has no messages, so there is nothing to judge yet.' };
  const step = nextStep(report.policy);
  const real = sum.failing.filter((s) => s.count / sum.total >= REAL_VOLUME);
  const n = real.length;
  if (n) {
    const who = `${n} source${n === 1 ? '' : 's'} send${n === 1 ? 's' : ''} real volume (at least ${REAL_VOLUME * 100}% of messages) and fail${n === 1 ? 's' : ''} both checks`;
    if (!step) return { level: 'warn', text: `Already at p=reject, so receivers that honor DMARC block this mail. ${who}: if any of them is a service you use, fix its SPF or DKIM.` };
    return { level: 'bad', text: `Not ready to ${step} yet: ${who}. Find out what ${n === 1 ? 'it is' : 'they are'} first: a mail service of yours to fix, or someone spoofing you.` };
  }
  if (sum.failed) {
    const tail = step ? `Check them, then ${step}.` : 'Policy is already at full p=reject.';
    return { level: 'warn', text: `Close: everything sending real volume passes. ${sum.failed} message${sum.failed === 1 ? '' : 's'} from small sources failed. ${tail}` };
  }
  return step
    ? { level: 'ok', text: `Every message passed DMARC. If other reporters agree over a couple of weeks, ${step}.` }
    : { level: 'ok', text: 'Every message passed DMARC, and the policy is already at full p=reject.' };
}

const fmtDate = (d) => (d ? d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : '?');

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('dmarc-file')) {
  const { el, $, notice, lookUpLink, rows } = await import('./ui.js');
  const resultFlag = (ok, label) => el('span', { class: `flag ${ok ? 'ok' : 'bad'}` }, label);
  const raw = (list) => list.map((x) => `${x.result || '?'}${x.domain ? ` (${x.domain})` : ''}`).join(', ') || 'none';

  const show = (report) => {
    const out = $('dmarc-result');
    if (report.error) { out.replaceChildren(notice('warn', report.error)); return; }
    const sum = summarize(report);
    const ready = readiness(report, sum);
    const { meta, policy } = report;
    const list = [...report.records].sort((a, b) => b.count - a.count).slice(0, MAX_ROWS_SHOWN);
    out.replaceChildren(...[
      rows([
        ['Reporter', [meta.org, meta.email].filter(Boolean).join(' · ') || '?'],
        ['Period', `${fmtDate(meta.begin)} → ${fmtDate(meta.end)}`],
        ['Domain', policy.domain],
        ['Published policy', `p=${policy.p || '?'}${policy.sp ? `, sp=${policy.sp}` : ''}${policy.pct != null ? `, pct=${policy.pct}` : ''}${policy.testing ? ', testing' : ''}`],
      ]),
      el('p', {}, sum.total
        ? `${sum.total.toLocaleString('en-US')} message${sum.total === 1 ? '' : 's'} from ${sum.sources} source${sum.sources === 1 ? '' : 's'}: ${sum.pct}% passed DMARC. ${sum.failing.length} source${sum.failing.length === 1 ? '' : 's'} failing.`
        : 'No messages in this report.'),
      sum.failing.length ? el('p', { class: 'hint' }, 'Failing: ', sum.failing.slice(0, 5).map((s) => `${s.ip} (${s.count} msg${s.count === 1 ? '' : 's'}${s.spfFail ? ', SPF fail' : ''}${s.noDkim ? ', no DKIM' : ''})`).join('; '), sum.failing.length > 5 ? '…' : '') : null,
      notice(ready.level === 'muted' ? 'warn' : ready.level, ready.text),
      report.skipped ? el('p', { class: 'hint' }, `${report.skipped} row${report.skipped === 1 ? '' : 's'} without a valid message count ${report.skipped === 1 ? 'was' : 'were'} left out.`) : null,
      list.length < report.records.length ? el('p', { class: 'hint' }, `Showing the ${list.length} largest of ${report.records.length} rows; the totals above count all of them.`) : null,
      list.length ? el('table', { class: 'ioc-table dmarc-table' },
        el('thead', {}, el('tr', {}, ...['Source IP', 'Msgs', 'SPF', 'DKIM', 'Applied'].map((t) => el('th', {}, t)))),
        el('tbody', {}, ...list.map((r) => el('tr', {},
          el('td', { class: 'mono' }, r.ip || '?', r.ip && lookupable(r.ip) ? lookUpLink(r.ip) : null),
          el('td', {}, String(r.count)),
          el('td', {}, resultFlag(r.spfAligned, r.spfAligned ? 'pass' : 'fail'), el('div', { class: 'hint' }, `raw: ${raw(r.spf)}`)),
          el('td', {}, resultFlag(r.dkimAligned, r.dkimAligned ? 'pass' : 'fail'), el('div', { class: 'hint' }, `raw: ${raw(r.dkim)}`)),
          el('td', {}, r.disposition || '?'))))) : null,
    ].filter(Boolean)); // native replaceChildren would print a null as text
  };

  const load = async (file) => {
    if (!file) return;
    if (file.size > MAX_DMARC) { $('dmarc-result').replaceChildren(notice('warn', 'That file is more than 10 MB.')); return; }
    show(parseDmarc(await file.text()));
  };

  $('dmarc-file').addEventListener('change', (ev) => load(ev.target.files[0]));
  $('dmarc-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const t = $('dmarc-input').value.trim();
    if (t) show(parseDmarc(t));
  });
  const drop = $('dmarc-drop');
  drop.addEventListener('dragover', (ev) => { ev.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (ev) => {
    ev.preventDefault();
    drop.classList.remove('over');
    load(ev.dataTransfer.files[0]);
  });
}
