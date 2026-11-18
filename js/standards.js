// "What does this standard ask for?" (Reference page, #standards): search over data/standards.json.
// Pure functions only, so tests can run them without a page.

import { isHubHref } from './what-now.js';

// Official framework pages may only link to these hosts, over https.
export const STANDARD_HOSTS = ['www.nist.gov', 'www.cisecurity.org'];

/** The URL as a safe link target, or null if it isn't https on an allowed host. */
export function standardUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && STANDARD_HOSTS.includes(u.hostname) && !u.username && !u.password && !u.port ? u.href : null;
  } catch {
    return null;
  }
}

export const CSF_FUNCTIONS = ['GV', 'ID', 'PR', 'DE', 'RS', 'RC'];
export const CIS_COUNT = 18;

const CIS_NUM = /^(?:cis(?:\s*controls?)?|control)?[\s:#-]*(\d{1,3})$/;
// "pr", "csf pr", "nist csf pr.aa", "PR.AA-01" (a subcategory finds its category).
const CSF_CODE = /^(?:(?:nist\s*)?csf[\s:-]*)?(gv|id|pr|de|rs|rc)(?:\.([a-z]{2})(?:[\s-]\d{1,2})?)?$/;
const FRAMEWORK_WORDS = {
  csf: ['csf', 'nist csf', 'nist', 'csf 2.0', 'nist csf 2.0', 'cybersecurity framework', 'nist cybersecurity framework'],
  cis: ['cis', 'cis controls', 'cis control', 'cis critical security controls', 'cis v8', 'cis v8.1', 'cis controls v8.1'],
};

/**
 * Search the standards list.
 *   ""                         -> kind 'all': every item, in data order
 *   "cis", "nist csf"          -> kind 'framework': every item of that framework
 *   "7", "cis 7", "control 7"  -> kind 'cis': that CIS control (error when not 1-18)
 *   "pr", "csf pr", "pr.aa"    -> kind 'csf': that CSF function; with a category code, `category` is set
 *                                 (error when the category isn't one of CSF 2.0's)
 *   "logging"                  -> kind 'text': items whose name matches, then search words, then category
 *                                 names, then the plain sentence, then the auditor line
 * Text after 60 characters is ignored; regex characters are plain text.
 */
export function searchStandards(data, query) {
  const items = data?.items || [];
  const raw = String(query ?? '').trim().toLowerCase().replace(/\s+/g, ' ').slice(0, 60);
  if (!raw) return { kind: 'all', items: [...items] };

  for (const [fw, words] of Object.entries(FRAMEWORK_WORDS)) {
    if (words.includes(raw)) return { kind: 'framework', framework: fw, items: items.filter((i) => i.framework === fw) };
  }

  let m = raw.match(CIS_NUM);
  if (m) {
    const n = Number(m[1]);
    if (n < 1 || n > CIS_COUNT) return { kind: 'cis', num: n, items: [], error: `CIS Controls v8.1 has ${CIS_COUNT} controls, numbered 1 to ${CIS_COUNT}.` };
    return { kind: 'cis', num: n, items: items.filter((i) => i.framework === 'cis' && i.num === String(n)) };
  }

  m = raw.match(CSF_CODE);
  if (m) {
    const fn = m[1].toUpperCase();
    const found = items.filter((i) => i.framework === 'csf' && i.num === fn);
    if (!m[2]) return { kind: 'csf', function: fn, items: found };
    const code = `${fn}.${m[2].toUpperCase()}`;
    const category = found.flatMap((i) => i.categories || []).find((c) => c.code === code) || null;
    if (!category) return { kind: 'csf', function: fn, code, items: [], error: `${code} is not a CSF 2.0 category.` };
    return { kind: 'csf', function: fn, code, category, items: found };
  }

  if (raw.length < 3) return { kind: 'text', items: [] };
  const has = (s) => String(s || '').toLowerCase().includes(raw);
  const rank = (i) => {
    if (has(i.name)) return 0;
    if ((i.tags || []).some(has)) return 1;
    if ((i.categories || []).some((c) => has(c.name))) return 2;
    if (has(i.plain)) return 3;
    if (has(i.evidence)) return 4;
    return -1;
  };
  const found = items
    .map((i, n) => [rank(i), n, i])
    .filter(([r]) => r >= 0)
    .sort((x, y) => x[0] - y[0] || x[1] - y[1])
    .map(([, , i]) => i);
  return { kind: 'text', items: found };
}

/** Checks one item's shape against the framework list; returns a list of problems (empty when fine). */
export function standardProblems(item, frameworkIds = ['csf', 'cis']) {
  const out = [];
  if (!frameworkIds.includes(item.framework)) out.push('framework must be a listed framework id');
  for (const k of ['num', 'name', 'plain', 'evidence']) if (typeof item[k] !== 'string' || !item[k].trim()) out.push(`${k} missing`);
  if (typeof item.name === 'string' && (item.name.length > 80 || /\.$/.test(item.name))) out.push('name must be the official short name: 80 characters max, no full stop');
  for (const k of ['plain', 'evidence']) {
    if (typeof item[k] === 'string' && item[k].length > 160) out.push(`${k} over 160 characters`);
    if (typeof item[k] === 'string' && !/\.$/.test(item[k])) out.push(`${k} must end with a full stop`);
  }
  if (item.framework === 'csf' && !CSF_FUNCTIONS.includes(item.num)) out.push('a CSF item num must be a function code (GV, ID, PR, DE, RS, RC)');
  if (item.framework === 'cis' && !/^(?:[1-9]|1[0-8])$/.test(item.num)) out.push('a CIS item num must be 1 to 18');
  if (!Array.isArray(item.tags) || !item.tags.length || !item.tags.every((t) => typeof t === 'string' && t === t.toLowerCase() && t.trim() === t && t.length >= 2)) {
    out.push('tags must be a non-empty list of lower-case search words');
  }
  if (item.framework === 'csf') {
    const cats = item.categories;
    if (!Array.isArray(cats) || !cats.length) out.push('a CSF function needs its categories');
    else for (const c of cats) {
      if (typeof c?.code !== 'string' || !c.code.startsWith(`${item.num}.`) || !/^[A-Z]{2}\.[A-Z]{2}$/.test(c.code)) out.push(`category code ${c?.code} must be ${item.num}.XX`);
      if (typeof c?.name !== 'string' || !c.name.trim()) out.push(`category ${c?.code} needs a name`);
    }
  } else if ('categories' in item) out.push('only CSF functions have categories');
  if (!Array.isArray(item.hub)) out.push('hub must be a list (may be empty)');
  else for (const h of item.hub) {
    if (typeof h?.label !== 'string' || !h.label.trim()) out.push('hub link needs a label');
    if (!isHubHref(h?.href)) out.push(`hub link ${h?.href} must be a relative link to a hub page`);
  }
  const known = new Set(['framework', 'num', 'name', 'plain', 'evidence', 'tags', 'categories', 'hub']);
  for (const k of Object.keys(item)) if (!known.has(k)) out.push(`unknown field ${k}`);
  return out;
}

/** Short label for an item's key column: "CSF PR" or "CIS 7". */
export const standardKey = (item) => `${item.framework === 'csf' ? 'CSF' : 'CIS'} ${item.num}`;
