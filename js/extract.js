// Shared, DOM-free logic for the Analyze tools: refanging, IOC extraction,
// registrable domains (Public Suffix List), punycode, lookalike checks, URL
// inspection and email-header parsing. Everything runs in the browser; nothing
// pasted is sent anywhere. Tests import this module directly.

import { detect, refang, parseIPv4, parseIPv6, ipv4Reserved, ipv6Reserved, normalizeCveId } from './detect.js';

// ---------- Refanging whole texts ----------

/** detect.js's refang() works on one indicator; this rewrites defanged IOCs anywhere in a text. */
export function refangText(text) {
  return text
    .replace(/\bhxxp(s?)(\[:\]|:)\/\//gi, 'http$1://')
    .replace(/\bfxp:\/\//gi, 'ftp://')
    .replace(/\[(\.|dot)\]|\((\.|dot)\)|\{\.\}/gi, '.')
    .replace(/\[:\/\/\]/g, '://')
    .replace(/\[(@|at)\]|\((at)\)/gi, '@');
}

// ---------- Public Suffix List ----------

/** Parses public_suffix_list.dat (ICANN and private sections) into rule sets. */
export function parsePsl(text) {
  const rules = new Set();
  const wild = new Set();
  const except = new Set();
  for (const line of text.split('\n')) {
    const rule = line.trim().split(/\s/)[0];
    if (!rule || rule.startsWith('//')) continue;
    const r = toAscii(rule.toLowerCase());
    if (r.startsWith('!')) except.add(r.slice(1));
    else if (r.startsWith('*.')) wild.add(r.slice(2));
    else rules.add(r);
  }
  return { rules, wild, except };
}

/**
 * The public suffix and registrable domain ("eTLD+1") of a hostname, or
 * { suffix, registrable: null } when the host is itself a suffix. Returns null
 * if no PSL rule matches (an unknown TLD).
 */
export function registrableDomain(host, psl) {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  let suffixLen = 0;
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join('.');
    const parent = labels.slice(i + 1).join('.');
    if (psl.except.has(candidate)) { suffixLen = labels.length - i - 1; break; }
    if (psl.rules.has(candidate) || (parent && psl.wild.has(parent))) { suffixLen = labels.length - i; break; }
  }
  if (!suffixLen) return null;
  const suffix = labels.slice(-suffixLen).join('.');
  const registrable = labels.length > suffixLen ? labels.slice(-suffixLen - 1).join('.') : null;
  return { suffix, registrable, subdomain: labels.slice(0, Math.max(0, labels.length - suffixLen - 1)).join('.') };
}

// ---------- Punycode (RFC 3492) ----------

const BASE = 36;
const adapt = (delta, numPoints, first) => {
  let d = first ? Math.floor(delta / 700) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  for (; d > 455; k += BASE) d = Math.floor(d / 35);
  return Math.floor(k + (36 * d) / (d + 38));
};

function punyDecode(input) {
  const out = [];
  const b = input.lastIndexOf('-');
  for (let j = 0; j < Math.max(b, 0); j++) out.push(input.charCodeAt(j));
  let n = 128;
  let bias = 72;
  let i = 0;
  for (let idx = b > 0 ? b + 1 : 0; idx < input.length;) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new Error('bad punycode');
      const c = input.charCodeAt(idx++);
      const digit = c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : BASE;
      if (digit >= BASE) throw new Error('bad punycode');
      i += digit * w;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    if (n > 0x10ffff) throw new Error('bad punycode');
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

/** xn-- labels to Unicode; invalid punycode is left as is. */
export function toUnicode(host) {
  return host.split('.').map((l) => {
    if (!/^xn--/i.test(l)) return l;
    try {
      return punyDecode(l.slice(4).toLowerCase());
    } catch {
      return l;
    }
  }).join('.');
}

/** Unicode hostname to punycode, via the URL parser. */
export function toAscii(host) {
  if (!/[^\x00-\x7f]/.test(host)) return host;
  try {
    return new URL(`http://${host.replace(/^\*\./, 'wildcard.')}`).hostname.replace(/^wildcard\./, host.startsWith('*.') ? '*.' : '');
  } catch {
    return host;
  }
}

// ---------- IOC extraction ----------

export const MAX_TEXT = 500 * 1024;

// TLDs that are also common file extensions: "invoice.zip" may be a file, not a domain.
const FILE_TLDS = new Set(['zip', 'mov', 'py', 'sh', 'pl', 'rs', 'md', 'cs', 'ps', 'ai', 'so', 'gz', 'sc', 'mp', 'mobi', 'pdf', 'doc', 'app', 'dev', 'run', 'cc', 'cv', 'js', 'ts', 'io', 'ml', 'ws']);

const RE = {
  url: /\b(?:https?|ftp):\/\/[^\s<>"'`{}|\\^]+/gi,
  email: /\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]{1,62}\b/gi,
  cve: /\bCVE[\s‐-―−_-]*\d{4}[\s‐-―−_-]*\d{4,19}\b/gi,
  hash: /\b[a-f0-9]{32}(?:[a-f0-9]{8})?(?:[a-f0-9]{24})?\b/gi,
  ipv4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  // Not touching other word characters or colons; a trailing sentence full stop is fine.
  ipv6: /(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}(?:[0-9a-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})(?![\w:]|\.\w)/gi,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z][a-z0-9-]{1,62}|xn--[a-z0-9-]{1,59})\b/gi,
};

const trimUrl = (u) => u.replace(/[.,;:!?)\]}'"]+$/, '');

/**
 * Extracts indicators from free text. Returns
 * { groups: { type: [{ value, count, note? }] }, dropped: [{ value, reason, kind, count }], total }.
 * options.psl rejects domains with unknown TLDs (file names like report.txt);
 * options.lineFilter keeps only lines containing that substring (log mode).
 */
export function extractIocs(input, { psl = null, lineFilter = '' } = {}) {
  let text = String(input).slice(0, MAX_TEXT);
  if (lineFilter) {
    const f = lineFilter.toLowerCase();
    text = text.split(/\r?\n/).filter((l) => l.toLowerCase().includes(f)).join('\n');
  }
  text = refangText(text);

  const found = new Map(); // "type value" -> { type, value, count, note }
  const dropped = new Map();
  const add = (type, value, note) => {
    const key = `${type} ${value}`;
    const e = found.get(key) || { type, value, count: 0, note };
    e.count += 1;
    found.set(key, e);
  };
  // kind groups drops for a short summary; reason is the full explanation.
  const drop = (value, reason, kind) => {
    const e = dropped.get(value) || { value, reason, kind, count: 0 };
    e.count += 1;
    dropped.set(value, e);
  };

  // URLs and emails first, then blank them so their hosts aren't counted again as bare domains.
  let rest = text.replace(RE.url, (m) => {
    const u = trimUrl(m);
    const d = detect(u);
    if (d.type === 'url' && !d.error) add('url', d.value);
    else drop(u, d.error || 'not a valid URL', d.error && /not public/.test(d.error) ? 'URL to a private or internal host' : 'invalid');
    return ' '.repeat(m.length);
  });
  rest = rest.replace(RE.email, (m) => {
    const d = detect(m);
    if (d.type === 'email' && !d.error) {
      if (!psl || registrableDomain(m.split('@')[1], psl)) add('email', d.value);
      else drop(m, 'not a real top-level domain', 'unknown top-level domain');
    } else drop(m, d.error || 'not a valid email address', 'invalid');
    return ' '.repeat(m.length);
  });
  rest = rest.replace(RE.cve, (m) => {
    const c = normalizeCveId(m);
    if (c?.value) add('cve', c.value);
    else drop(m, c?.error || 'not a valid CVE ID', 'invalid');
    return ' ';
  });
  for (const m of rest.matchAll(RE.hash)) {
    if ([32, 40, 64].includes(m[0].length)) add('hash', m[0].toLowerCase(), { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' }[m[0].length]);
  }
  rest = rest.replace(RE.ipv6, (m) => {
    const groups = parseIPv6(m);
    if (!groups) return m;
    const reason = ipv6Reserved(groups);
    if (reason) drop(m.toLowerCase(), reason, 'private or reserved IP');
    else add('ipv6', m.toLowerCase());
    return ' '.repeat(m.length);
  });
  rest = rest.replace(RE.ipv4, (m) => {
    const o = parseIPv4(m);
    if (!o) return m;
    const reason = ipv4Reserved(o);
    if (reason) drop(m, reason, 'private or reserved IP');
    else add('ipv4', m);
    return ' '.repeat(m.length);
  });
  for (const m of rest.matchAll(RE.domain)) {
    const value = m[0].toLowerCase();
    if (/^\d+(\.\d+)+$/.test(value)) continue; // version numbers
    const d = detect(value);
    if (d.type !== 'domain') continue;
    if (d.error) { drop(value, d.error, 'internal name'); continue; }
    const tld = value.slice(value.lastIndexOf('.') + 1);
    if (psl && !registrableDomain(value, psl)?.registrable) { drop(value, 'not a real top-level domain (probably a file name)', 'file name, not a domain'); continue; }
    // "invoice.zip", "setup.py": a single label before a TLD that is also a file extension.
    const note = FILE_TLDS.has(tld) && value.split('.').length === 2 ? `may be a file name (.${tld} is also a file extension)` : undefined;
    add('domain', value, note);
  }

  const groups = {};
  for (const e of found.values()) (groups[e.type] ||= []).push({ value: e.value, count: e.count, ...(e.note ? { note: e.note } : {}) });
  for (const list of Object.values(groups)) list.sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
  return { groups, dropped: [...dropped.values()], total: found.size };
}

// ---------- Access logs (IOC extractor, log mode) ----------

// Apache/nginx "common" and "combined" formats:
//   host ident user [10/Oct/2026:13:55:36 +0000] "GET /path?q HTTP/1.1" 200 2326 "referer" "user agent"
const ACCESS_LINE = /^(\S+) \S+ \S+ \[([^\]]{1,40})\] "([^"]*)" (\d{3}) (?:\d+|-)(?: "(?:[^"\\]|\\.)*" "((?:[^"\\]|\\.)*)")?/;
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
export const MAX_AGENT = 120;
const MAX_PATH = 200;

/** "10/Oct/2026:13:55:36 +0000" -> epoch ms, or NaN. */
function logTime(s) {
  const m = /^(\d{2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/.exec(s);
  if (!m || !(m[2] in MONTHS)) return NaN;
  const offset = (m[7] === '-' ? -1 : 1) * (Number(m[8]) * 60 + Number(m[9])) * 60_000;
  return Date.UTC(Number(m[3]), MONTHS[m[2]], Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6])) - offset;
}

const top = (map, n = 10) => [...map].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]))).slice(0, n).map(([value, count]) => ({ value, count }));

/**
 * Counts from an access log, or null when most non-empty lines aren't in the
 * common/combined format (log mode then works as before). Paths lose their query
 * string; user agents are cut to 120 characters. Same text limit and line filter
 * as extractIocs.
 */
export function parseAccessLog(input, { lineFilter = '' } = {}) {
  let lines = String(input).slice(0, MAX_TEXT).split(/\r?\n/).filter((l) => l.trim());
  if (lineFilter) {
    const f = lineFilter.toLowerCase();
    lines = lines.filter((l) => l.toLowerCase().includes(f));
  }
  if (!lines.length) return null;
  const statuses = new Map();
  const paths = new Map();
  const agents = new Map();
  let matched = 0;
  let first = null;
  let last = null;
  for (const line of lines) {
    const m = ACCESS_LINE.exec(line);
    if (!m) continue;
    matched += 1;
    const t = logTime(m[2]);
    if (!Number.isNaN(t)) {
      if (!first || t < first.t) first = { t, text: m[2] };
      if (!last || t > last.t) last = { t, text: m[2] };
    }
    statuses.set(m[4], (statuses.get(m[4]) || 0) + 1);
    const target = m[3].split(' ')[1];
    if (target) {
      const path = target.split('?')[0].slice(0, MAX_PATH);
      paths.set(path, (paths.get(path) || 0) + 1);
    }
    if (m[5] !== undefined) {
      const agent = m[5].slice(0, MAX_AGENT);
      agents.set(agent, (agents.get(agent) || 0) + 1);
    }
  }
  if (matched * 2 <= lines.length) return null;
  return {
    lines: lines.length,
    matched,
    first: first?.text || null,
    last: last?.text || null,
    statuses: top(statuses),
    paths: top(paths),
    agents: top(agents),
  };
}

/** CSV with a header row; every field quoted, and formula-leading cells neutralised for spreadsheets. */
export function toCsv(rows) {
  const cell = (v) => {
    let s = String(v ?? '');
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
    return `"${s.replace(/"/g, '""')}"`;
  };
  return rows.map((r) => r.map(cell).join(',')).join('\r\n');
}

// ---------- Lookalike detection ----------

// A curated map of characters that look like ASCII letters, not all of Unicode.
const CONFUSABLES = {
  // Cyrillic
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'і': 'i', 'ї': 'i', 'ј': 'j', 'к': 'k', 'ӏ': 'l', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c',
  'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w', 'ү': 'y',
  // Greek
  'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ϲ': 'c', 'ω': 'w',
  // Latin look-alikes and digits
  'ɡ': 'g', 'ı': 'i', 'ł': 'l', 'ɩ': 'i', 'ɑ': 'a', 'ȷ': 'j', '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't',
  'à': 'a', 'á': 'a', 'â': 'a', 'ä': 'a', 'å': 'a', 'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e', 'ì': 'i', 'í': 'i', 'î': 'i', 'ï': 'i',
  'ò': 'o', 'ó': 'o', 'ô': 'o', 'ö': 'o', 'ø': 'o', 'ù': 'u', 'ú': 'u', 'û': 'u', 'ü': 'u', 'ç': 'c', 'ñ': 'n', 'ý': 'y',
};

/** Maps a label to the ASCII it imitates: Cyrillic "раураl" and "paypa1" both become "paypal". */
export function skeleton(label) {
  return [...label.toLowerCase()].map((c) => CONFUSABLES[c] ?? c).join('').replace(/rn/g, 'm').replace(/vv/g, 'w');
}

export function editDistance(a, b) {
  if (Math.abs(a.length - b.length) > 3) return 99;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length];
}

const scriptsOf = (label) => {
  const s = new Set();
  for (const c of label) {
    if (/[a-z]/i.test(c)) s.add('Latin');
    else if (/[Ѐ-ӿ]/.test(c)) s.add('Cyrillic');
    else if (/[Ͱ-Ͽ]/.test(c)) s.add('Greek');
  }
  return s;
};

/**
 * Brand impersonation checks on a host. brands: [{ name, label, domains }].
 * Edit distance allowed: 2 for brand labels of 6+ characters, 1 for 4-5, and
 * none (look-alike characters only) for 3 or fewer: any distance on "ups" or
 * "ibm" would match most short names. A domain that belongs to any listed
 * brand is never flagged (ups.com is one letter from usps).
 */
export function lookalikes(host, psl, brands) {
  const reasons = [];
  const pd = registrableDomain(host, psl);
  if (!pd?.registrable) return reasons;
  const registrable = pd.registrable;
  const first = toUnicode(registrable.slice(0, -pd.suffix.length - 1));
  const sub = toUnicode(pd.subdomain || '');
  if (brands.some((b) => b.domains.includes(registrable))) return reasons; // a listed brand's own domain
  for (const b of brands) {
    const skel = skeleton(first);
    const max = b.label.length >= 6 ? 2 : b.label.length >= 4 ? 1 : 0;
    if (first !== b.label && skel === b.label) reasons.push(`"${first}" imitates ${b.name} using look-alike characters`);
    else if (first === b.label) reasons.push(`Uses the ${b.name} name on ${registrable}, which isn't one of ${b.name}'s listed domains`);
    else if (max && editDistance(skel, b.label) <= max) reasons.push(`"${first}" is one or two letters away from ${b.name} (${b.label})`);
    else if (b.label.length >= 5 && skel.includes(b.label)) reasons.push(`The domain name contains "${b.label}" (${b.name}) but isn't ${b.name}'s`);
    const subLabels = sub ? sub.split('.') : [];
    if (subLabels.some((l) => skeleton(l) === b.label) || b.domains.some((d) => sub === d || sub.endsWith(`.${d}`) || sub.startsWith(`${d}.`))) {
      reasons.push(`${b.name}'s name appears only in the subdomain; the real domain is ${registrable}`);
    }
  }
  return [...new Set(reasons)];
}

// ---------- URL inspection ----------

export const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 's.id', 'lnkd.in', 'bl.ink', 'v.gd', 'qrco.de'];
const REDIRECT_PARAMS = new Set(['url', 'redirect', 'redirect_uri', 'redirect_url', 'next', 'u', 'dest', 'destination', 'target', 'continue', 'return', 'returnurl', 'return_to', 'goto', 'r', 'link']);

/** Percent-decodes up to 3 layers. Returns the layers (first is the input). */
export function decodeLayers(s, max = 3) {
  const layers = [s];
  for (let i = 0; i < max; i++) {
    let next;
    try {
      next = decodeURIComponent(layers[layers.length - 1].replace(/\+/g, ' '));
    } catch {
      break;
    }
    if (next === layers[layers.length - 1]) break;
    layers.push(next);
  }
  return layers;
}

/** Decodes Base64 / Base64url that turns out to be mostly printable UTF-8 text, else null. */
export function maybeBase64(value) {
  const v = value.trim();
  if (v.length < 12 || v.length > 8192 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(v) || /^[a-z]+$|^\d+$/i.test(v)) return null;
  try {
    let s = v.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    s += '='.repeat((4 - (s.length % 4)) % 4);
    const bytes = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const printable = [...text].filter((c) => c >= ' ' || c === '\n' || c === '\t').length;
    return text.length >= 6 && printable / text.length > 0.95 ? text : null;
  } catch {
    return null;
  }
}

const looksLikeUrl = (s) => /^(?:https?:)?\/\/[^\s/]+\.[^\s/]+/i.test(refangText(s.trim()));

/**
 * Inspects one URL without fetching it. Returns { error } or
 * { url, scheme, host, hostUnicode, registrable, port, userinfo, ipHost, punycode,
 *   mixedScripts, shortener, path, query, params, nested, reasons, notes, verdict }.
 */
export function inspectUrl(raw, { psl, brands = [] } = {}) {
  let input = refangText(refang(String(raw).trim()));
  const notes = [];
  if (!/^[a-z][a-z0-9+.-]*:/i.test(input)) {
    if (input.startsWith('//')) input = `https:${input}`;
    else {
      input = `https://${input}`;
      notes.push('No scheme was given, so https:// was assumed.');
    }
  }
  let u;
  try {
    u = new URL(input);
  } catch {
    return { error: 'That is not a URL the browser can parse.' };
  }
  if (!['http:', 'https:'].includes(u.protocol)) {
    return { error: `${u.protocol} URLs aren't web links${u.protocol === 'javascript:' || u.protocol === 'data:' ? ' and can run code or carry content directly; treat this as hostile' : ''}.` };
  }

  const reasons = [];
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const ipHost = Boolean(parseIPv4(host) || parseIPv6(host));
  const hostUnicode = ipHost ? host : toUnicode(host);
  const punycode = !ipHost && host.split('.').some((l) => l.startsWith('xn--'));
  const pd = ipHost || !psl ? null : registrableDomain(host, psl);
  const userinfo = u.username || u.password ? decodeLayers(`${u.username}${u.password ? `:${u.password}` : ''}`).pop() : null;

  if (userinfo) reasons.push(`Text before "@" ("${userinfo}") is not where the link goes; the real host is ${hostUnicode}`);
  if (ipHost) reasons.push('The host is a bare IP address, not a domain name');
  if (u.port) reasons.push(`Non-standard port ${u.port}`);
  const mixed = [];
  if (!ipHost) {
    for (const label of hostUnicode.split('.')) {
      const s = scriptsOf(label);
      if (s.size > 1) mixed.push(`${label} (${[...s].join(' + ')})`);
    }
  }
  if (mixed.length) reasons.push(`Mixes alphabets in one name: ${mixed.join(', ')}`);
  if (punycode && !mixed.length) notes.push(`Internationalised domain: ${host} displays as ${hostUnicode}.`);
  if (!ipHost && psl) {
    if (!pd) reasons.push('The top-level domain is not a real public suffix');
    else reasons.push(...lookalikes(host, psl, brands));
  }
  const shortener = pd?.registrable && SHORTENERS.includes(pd.registrable) ? pd.registrable : SHORTENERS.includes(host) ? host : null;
  if (shortener) reasons.push(`${shortener} is a link shortener: the destination can't be seen without opening it`);
  if (u.protocol === 'http:') notes.push('Not HTTPS: anything sent to this page travels unencrypted.');

  const pathLayers = decodeLayers(u.pathname);
  const queryLayers = decodeLayers(u.search.slice(1));
  if (pathLayers.length > 2 || queryLayers.length > 2) reasons.push(`Encoded ${Math.max(pathLayers.length, queryLayers.length) - 1} times over, a common way to hide what a link contains`);

  const params = [];
  const nested = [];
  for (const [name, value] of new URLSearchParams(u.search)) {
    const decoded = decodeLayers(value).pop();
    const b64 = maybeBase64(decoded);
    const isRedirectName = REDIRECT_PARAMS.has(name.toLowerCase());
    const candidate = [decoded, b64].find((v) => v && looksLikeUrl(v));
    if (candidate) nested.push({ param: name, url: candidate.trim() });
    params.push({ name, value: decoded.slice(0, 500), base64: b64 ? b64.slice(0, 500) : null, redirect: Boolean(candidate) || (isRedirectName && Boolean(decoded)) });
  }
  if (nested.length) reasons.push(`Redirects to another URL (parameter ${nested.map((n) => `"${n.param}"`).join(', ')}), which can hide the real destination`);

  return {
    url: u.href,
    scheme: u.protocol.slice(0, -1),
    host,
    hostUnicode,
    registrable: pd?.registrable ?? null,
    suffix: pd?.suffix ?? null,
    port: u.port || null,
    userinfo,
    ipHost,
    punycode,
    shortener,
    path: { raw: u.pathname, decoded: pathLayers[pathLayers.length - 1], layers: pathLayers.length - 1 },
    query: { raw: u.search, decoded: queryLayers[queryLayers.length - 1], layers: queryLayers.length - 1 },
    params,
    nested,
    reasons,
    notes,
    verdict: reasons.length ? 'Suspicious' : 'Looks normal',
  };
}

// ---------- Email headers ----------

export const MAX_HEADERS = 200 * 1024;

/** Decodes RFC 2047 encoded words (=?UTF-8?B?...?= and =?UTF-8?Q?...?=) for display. */
export function decodeMimeWords(v) {
  if (!v) return v;
  return v.replace(/=\?([\w-]+)\?([bq])\?([^?]*)\?=(\s+(?==\?))?/gi, (m, charset, enc, data) => {
    try {
      const bytes = enc.toLowerCase() === 'b'
        ? Uint8Array.from(atob(data), (c) => c.charCodeAt(0))
        : Uint8Array.from(data.replace(/_/g, ' ').replace(/=([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))), (c) => c.charCodeAt(0));
      return new TextDecoder(charset.toLowerCase(), { fatal: false }).decode(bytes);
    } catch {
      return m;
    }
  });
}

const addrDomain = (v) => (/[\w.+-]+@([a-z0-9.-]+\.[a-z]{2,})/i.exec(v || '')?.[1] || '').toLowerCase() || null;

function parseReceived(value) {
  const from = /\bfrom\s+([^\s;()]+)/i.exec(value)?.[1] || null;
  const by = /\bby\s+([^\s;()]+)/i.exec(value)?.[1] || null;
  // "from HELO (rdns [IP])": the bracketed IP inside the parentheses is what the
  // receiving server saw; a bracket right after "from" is only the sender's HELO claim.
  const seen = /\bfrom\s+\S+\s+\(([^)]*)\)/i.exec(value)?.[1] || '';
  const ipMatch = /\[(?:IPv6:)?([0-9a-f:.]+)\]/i.exec(seen) || /\[(?:IPv6:)?([0-9a-f:.]+)\]/i.exec(value) || /\(([0-9a-f:.]{7,})\)/i.exec(value);
  let ip = null;
  if (ipMatch) {
    const c = ipMatch[1];
    if (parseIPv4(c) || parseIPv6(c)) ip = c.toLowerCase();
  }
  const semi = value.lastIndexOf(';');
  const t = semi >= 0 ? Date.parse(value.slice(semi + 1).trim().replace(/\s*\([^)]*\)\s*$/, '')) : NaN;
  const isPublic = ip ? !(parseIPv4(ip) ? ipv4Reserved(parseIPv4(ip)) : ipv6Reserved(parseIPv6(ip))) : false;
  return { from, by, ip, publicIp: isPublic, time: Number.isFinite(t) ? new Date(t).toISOString() : null };
}

/** Pulls method=result pairs and their checked domains out of Authentication-Results. */
export function parseAuthResults(value) {
  const out = {};
  for (const part of value.split(';').slice(1)) {
    const m = /^\s*(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)/i.exec(part);
    if (!m) continue;
    const method = m[1].toLowerCase();
    const prop = (name) => new RegExp(`\\b${name}\\s*=\\s*"?([^\\s;"]+)`, 'i').exec(part)?.[1]?.toLowerCase() || null;
    const domain = method === 'spf' ? (prop('smtp.mailfrom') || '').split('@').pop() || prop('smtp.helo')
      : method === 'dkim' ? prop('header.d') || (prop('header.i') || '').split('@').pop() || null
        : method === 'dmarc' ? prop('header.from') : null;
    (out[method] ||= []).push({ result: m[2].toLowerCase(), domain: domain || null });
  }
  return out;
}

/**
 * Parses raw email headers (only the header block; a body after the first blank
 * line is ignored). Returns headers, hops (oldest first, with delays),
 * addresses, authentication results, mismatches and extracted indicators.
 */
export function parseHeaders(raw, { psl = null } = {}) {
  const text = String(raw).slice(0, MAX_HEADERS).replace(/\r\n?/g, '\n');
  const block = text.split(/\n\s*\n/)[0];
  const headers = [];
  for (const line of block.split('\n')) {
    if (/^[ \t]/.test(line) && headers.length) headers[headers.length - 1].value += ` ${line.trim()}`;
    else {
      const m = /^([!-9;-~]+):\s?(.*)$/.exec(line);
      if (m) headers.push({ name: m[1], value: m[2].trim() });
    }
  }
  const all = (name) => headers.filter((h) => h.name.toLowerCase() === name);
  const one = (name) => all(name)[0]?.value ?? null;

  // Received headers are prepended by each server: the first is the newest.
  const hops = all('received').map((h) => parseReceived(h.value)).reverse();
  hops.forEach((h, i) => {
    const prev = hops[i - 1];
    h.delaySeconds = prev?.time && h.time ? Math.round((Date.parse(h.time) - Date.parse(prev.time)) / 1000) : null;
  });

  const site = (d) => (d && psl ? registrableDomain(d, psl)?.registrable || d : d);
  const fromDomain = addrDomain(one('from'));
  const replyTo = addrDomain(one('reply-to'));
  const returnPath = addrDomain(one('return-path'));
  const messageId = /@([^>\s]+)>?/.exec(one('message-id') || '')?.[1]?.toLowerCase() || null;
  const mismatches = [];
  if (fromDomain && replyTo && site(fromDomain) !== site(replyTo)) mismatches.push(`Replies go to ${replyTo}, not the sender's domain ${fromDomain}`);
  if (fromDomain && returnPath && site(fromDomain) !== site(returnPath)) mismatches.push(`Bounces go to ${returnPath} (Return-Path), not ${fromDomain}`);
  if (fromDomain && messageId && site(fromDomain) !== site(messageId)) mismatches.push(`The Message-ID was created by ${messageId}, not ${fromDomain}`);
  // Which fields the comparison could actually use, so "no mismatch" is never claimed about missing ones.
  const fields = { From: fromDomain, 'Reply-To': replyTo, 'Return-Path': returnPath, 'Message-ID': messageId };
  const present = Object.keys(fields).filter((k) => fields[k]);
  const missing = Object.keys(fields).filter((k) => !fields[k]);

  // The topmost Authentication-Results is the one your own provider added.
  const authRaw = one('authentication-results');
  const auth = authRaw ? parseAuthResults(authRaw) : {};

  const iocText = [...all('received'), ...all('x-originating-ip'), ...all('x-sender-ip')].map((h) => h.value).join('\n');
  const iocs = extractIocs(iocText, { psl });

  return {
    headers: headers.length,
    subject: decodeMimeWords(one('subject')),
    date: one('date'),
    from: decodeMimeWords(one('from')),
    fromDomain,
    replyTo,
    returnPath,
    messageId,
    hops,
    auth,
    authHeaders: all('authentication-results').length,
    mismatches,
    present,
    missing,
    iocs,
  };
}
