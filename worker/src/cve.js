// CVE sources: NVD (record, CVSS, products), CISA KEV (exploited in the wild),
// FIRST EPSS (exploitation probability), plus NVD keyword search.
//
// Ported from CVE Explainer (github.com/jamalrizki/cve-explainer, worker/src/tools.js):
// the parsing, CVSS translation, CWE names, KEV loading and the newest-first
// search workaround are copied, not shared. Its MCP and chat code is left out.
// Here the hub decides in code which CVE to look up, so the model never
// chooses (or mistypes) the ID.

import { getJson } from './http.js';

const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
// CISA's own feed first; the cisagov/kev-data GitHub repo is CISA's official mirror of the same file.
export const KEV_URLS = [
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
];
const KEV_TTL_MS = 60 * 60 * 1000;
const KEV_MAX_BYTES = 4_000_000; // ~1.8 MB in Oct 2026; getJson's default cap is 1 MB
const FETCH_TIMEOUT_MS = 10000;
const SEARCH_WINDOW = 20; // how many of the newest NVD matches the search looks at
const SEARCH_LIMIT = 10;
export const CVE_TTL = 6 * 3600; // KEV and EPSS change daily

// Word for word from CVE Explainer.
export const NOT_IN_KEV =
  "Not in CISA's KEV catalog. That means CISA has no confirmed evidence of exploitation to list; " +
  'it does not prove the CVE is safe or unexploited.';

// ---------- NVD access ----------

// NVD keys are UUIDs. Anything else is ignored rather than sent: CVE Explainer
// once nearly sent another service's key to NVD.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const nvdKey = (env = {}) => (UUID.test(env.NVD_API_KEY || '') ? env.NVD_API_KEY : null);
// NVD allows 5 requests per rolling 30 s without a key, 50 with one.
export const nvdPerMinute = (env) => (nvdKey(env) ? 80 : 8);

/**
 * NVD answers an unknown CVE with 200 and no results, so a 404 always means a
 * problem. An invalid or not-yet-activated key gets "404, message: Invalid
 * apiKey."; then retry without the key so lookups keep working keyless.
 */
async function nvdFetch(url, env) {
  const key = nvdKey(env);
  const opts = { timeout: FETCH_TIMEOUT_MS, rateLimitStatuses: [403, 429] };
  let r = await getJson(url, { ...opts, headers: key ? { apiKey: key } : {} });
  if (r.status === 404 && key && /api ?key/i.test(r.message || '')) r = await getJson(url, opts);
  if (r.status === 404) throw new Error(`NVD HTTP 404${r.message ? `: ${r.message}` : ''}`);
  return r;
}

const busy = { status: 'skipped', message: 'NVD’s free rate limit is in use. Try again in a minute.' };

// ---------- NVD record ----------

export function englishText(list, maxLen) {
  const entry = (list || []).find((d) => d.lang === 'en') || (list || [])[0];
  const text = (entry?.value || '').replace(/\s+/g, ' ').trim();
  return text.length > maxLen ? `${text.slice(0, maxLen)}…` : text;
}

export function statusNotes(cve) {
  const notes = [];
  const status = cve.vulnStatus || '';
  if (/reject/i.test(status)) notes.push('This CVE was REJECTED (withdrawn). It is not a valid vulnerability record.');
  else if (/awaiting|received|undergoing/i.test(status)) {
    notes.push('NVD has not finished analyzing this CVE yet, so scores and affected-product data may be missing or provisional.');
  } else if (/deferred/i.test(status)) notes.push('NVD has deferred analysis of this CVE, so its data may be incomplete.');
  return notes;
}

const CVSS_PREFERENCE = ['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2'];

/**
 * Chooses one score to report. NVD's own ("Primary") analysis beats a
 * vendor/CNA ("Secondary") score; among equals, newer CVSS 3.x versions win.
 */
export function pickCvss(metrics = {}) {
  const candidates = [];
  for (const key of CVSS_PREFERENCE) {
    for (const m of Array.isArray(metrics[key]) ? metrics[key] : []) candidates.push({ key, m });
  }
  const best = candidates.find((c) => c.m.type === 'Primary') || candidates[0];
  if (!best) return null;
  const { key, m } = best;
  const d = m.cvssData || {};
  return {
    version: d.version,
    baseScore: d.baseScore,
    severity: d.baseSeverity || m.baseSeverity || null,
    vector: d.vectorString,
    scoredBy: m.type === 'Primary' ? 'NVD' : `${m.source} (vendor/CNA)`,
    // Raw fields for the priority rule (network, no privileges, no interaction).
    attackVector: d.attackVector || null,
    privilegesRequired: d.privilegesRequired || null,
    userInteraction: d.userInteraction || null,
    plainEnglish: key === 'cvssMetricV2' ? [] : describeCvss(d),
  };
}

const ATTACK_VECTOR = {
  NETWORK: 'Can be attacked remotely over the network',
  ADJACENT_NETWORK: 'Attacker must be on the same local network segment',
  ADJACENT: 'Attacker must be on the same local network segment',
  LOCAL: 'Attacker needs local access to the machine',
  PHYSICAL: 'Attacker needs physical access to the device',
};
const COMPLEXITY = {
  LOW: 'Easy to exploit; no special conditions needed',
  HIGH: "Harder to exploit; depends on conditions outside the attacker's control",
};
const PRIVILEGES = {
  NONE: 'No login or privileges needed',
  LOW: 'Needs a basic user account',
  HIGH: 'Needs an administrator-level account',
};
const INTERACTION = {
  NONE: 'No user has to do anything',
  REQUIRED: 'A user has to take an action (open a file, click a link)',
  PASSIVE: 'A user is involved only passively',
  ACTIVE: 'A user has to take a deliberate action',
};
const IMPACT = { NONE: 'none', LOW: 'limited', HIGH: 'high' };

export function describeCvss(d) {
  const out = [];
  const add = (table, value) => table[value] && out.push(table[value]);
  add(ATTACK_VECTOR, d.attackVector);
  add(COMPLEXITY, d.attackComplexity);
  add(PRIVILEGES, d.privilegesRequired);
  add(INTERACTION, d.userInteraction);
  if (d.attackRequirements === 'PRESENT') out.push('Exploitation depends on specific deployment conditions');
  if (d.scope === 'CHANGED') out.push('Can affect resources beyond the vulnerable component');
  // CVSS v3.x names these confidentialityImpact; v4.0 names them vulnConfidentialityImpact.
  const c = d.confidentialityImpact ?? d.vulnConfidentialityImpact;
  const i = d.integrityImpact ?? d.vulnIntegrityImpact;
  const a = d.availabilityImpact ?? d.vulnAvailabilityImpact;
  if (c || i || a) {
    out.push(`Impact: data exposure ${IMPACT[c] ?? 'unknown'}, data tampering ${IMPACT[i] ?? 'unknown'}, `
      + `service disruption ${IMPACT[a] ?? 'unknown'}`);
  }
  return out;
}

export const CWE_NAMES = {
  'CWE-20': 'Improper Input Validation',
  'CWE-22': 'Path Traversal',
  'CWE-74': 'Injection',
  'CWE-77': 'Command Injection',
  'CWE-78': 'OS Command Injection',
  'CWE-79': 'Cross-site Scripting (XSS)',
  'CWE-89': 'SQL Injection',
  'CWE-94': 'Code Injection',
  'CWE-119': 'Memory Buffer Bounds Error',
  'CWE-125': 'Out-of-bounds Read',
  'CWE-190': 'Integer Overflow or Wraparound',
  'CWE-200': 'Exposure of Sensitive Information',
  'CWE-269': 'Improper Privilege Management',
  'CWE-287': 'Improper Authentication',
  'CWE-306': 'Missing Authentication for Critical Function',
  'CWE-352': 'Cross-Site Request Forgery (CSRF)',
  'CWE-400': 'Uncontrolled Resource Consumption',
  'CWE-416': 'Use After Free',
  'CWE-434': 'Unrestricted File Upload',
  'CWE-476': 'NULL Pointer Dereference',
  'CWE-502': 'Deserialization of Untrusted Data',
  'CWE-601': 'Open Redirect',
  'CWE-611': 'XML External Entity (XXE)',
  'CWE-787': 'Out-of-bounds Write',
  'CWE-798': 'Hard-coded Credentials',
  'CWE-862': 'Missing Authorization',
  'CWE-863': 'Incorrect Authorization',
  'CWE-917': 'Expression Language Injection',
  'CWE-918': 'Server-Side Request Forgery (SSRF)',
  'CWE-1321': 'Prototype Pollution',
  'NVD-CWE-Other': "Other (not in NVD's CWE list)",
  'NVD-CWE-noinfo': 'Insufficient information',
};

export function weaknessList(weaknesses = []) {
  const ids = new Set();
  for (const w of weaknesses) for (const d of w.description || []) if (d.value) ids.add(d.value);
  return [...ids].map((id) => ({ id, name: CWE_NAMES[id] ?? null }));
}

// cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:...  (part: a=application, o=OS, h=hardware)
export function parseCpe(criteria) {
  const p = String(criteria || '').split(':');
  if (p.length < 6 || p[0] !== 'cpe') return null;
  const type = { a: 'application', o: 'operating system', h: 'hardware' }[p[2]] || p[2];
  return { type, vendor: p[3], product: p[4], version: p[5], update: p[6] };
}

export function versionRange(match, cpe) {
  const parts = [];
  if (match.versionStartIncluding) parts.push(`>= ${match.versionStartIncluding}`);
  if (match.versionStartExcluding) parts.push(`> ${match.versionStartExcluding}`);
  if (match.versionEndIncluding) parts.push(`<= ${match.versionEndIncluding}`);
  if (match.versionEndExcluding) parts.push(`< ${match.versionEndExcluding}`);
  if (parts.length) return parts.join(', ');
  if (cpe.version === '*') return 'any version';
  if (cpe.version === '-') return 'unspecified version';
  const update = cpe.update && cpe.update !== '*' && cpe.update !== '-' ? ` ${cpe.update}` : '';
  return `${cpe.version}${update}`;
}

export function affectedProducts(configurations = []) {
  const seen = new Set();
  const out = [];
  for (const config of configurations) {
    for (const node of config.nodes || []) {
      for (const match of node.cpeMatch || []) {
        if (!match.vulnerable) continue;
        const cpe = parseCpe(match.criteria);
        if (!cpe) continue;
        const versions = versionRange(match, cpe);
        const key = `${cpe.vendor}|${cpe.product}|${versions}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ vendor: cpe.vendor, product: cpe.product, type: cpe.type, versions });
      }
    }
  }
  return out;
}

export function topReferences(references = [], limit) {
  const weight = (tags = []) => (tags.includes('Patch') || tags.includes('Vendor Advisory') ? 3
    : tags.includes('Mitigation') ? 2 : tags.includes('Exploit') ? 1 : 0);
  return [...references]
    .map((r) => ({ url: r.url, tags: r.tags || [] }))
    .sort((a, b) => weight(b.tags) - weight(a.tags))
    .slice(0, limit);
}

export function parseNvdCve(cve) {
  const affected = affectedProducts(cve.configurations);
  const full = englishText(cve.descriptions, 100000);
  return {
    id: cve.id,
    status: cve.vulnStatus || null,
    published: cve.published?.slice(0, 10) ?? null,
    modified: cve.lastModified?.slice(0, 10) ?? null,
    description: full.length > 600 ? `${full.slice(0, 600)}…` : full,
    descriptionTruncated: full.length > 600,
    cvss: pickCvss(cve.metrics),
    weaknesses: weaknessList(cve.weaknesses),
    affected: affected.slice(0, 8),
    affectedTotal: affected.length,
    references: topReferences(cve.references, 6),
    notes: statusNotes(cve),
  };
}

async function nvd(id, tools) {
  if (!(await tools.allow('nvd', nvdPerMinute(tools.env)))) return busy;
  const r = await nvdFetch(`${NVD_URL}?cveId=${encodeURIComponent(id)}`, tools.env);
  const cve = r.json?.vulnerabilities?.[0]?.cve;
  if (!cve) return { status: 'empty', message: `NVD has no record of ${id}. It may not exist, or it may be too new to appear yet.` };
  return { status: 'ok', data: parseNvdCve(cve) };
}

// ---------- CISA KEV ----------

// Module-level cache: lives as long as this Worker isolate, so most requests
// skip both the download and the parse. Holds a Map of CVE ID -> entry.
let kevCache = { entries: null, released: null, at: 0 };

export function _resetKevCache() {
  kevCache = { entries: null, released: null, at: 0 };
}

export async function loadKev() {
  if (kevCache.entries && Date.now() - kevCache.at < KEV_TTL_MS) return kevCache;
  let lastError;
  for (const url of KEV_URLS) {
    try {
      const r = await getJson(url, {
        timeout: FETCH_TIMEOUT_MS,
        maxBytes: KEV_MAX_BYTES,
        cf: { cacheTtl: 3600, cacheEverything: true }, // edge-cache the ~1.8 MB file
      });
      if (!Array.isArray(r.json?.vulnerabilities)) throw new Error('unexpected KEV file format');
      kevCache = {
        entries: new Map(r.json.vulnerabilities.map((v) => [v.cveID, v])),
        released: r.json.dateReleased?.slice(0, 10) ?? null,
        at: Date.now(),
      };
      return kevCache;
    } catch (err) {
      lastError = err;
    }
  }
  throw new Error(`could not load the CISA KEV catalog (${lastError.message})`);
}

const clip = (t, n) => (t.length > n ? `${t.slice(0, n).replace(/\s+\S*$/, '')}\u2026` : t);

export function kevEntry(entry, released) {
  if (!entry) return { inKev: false, catalogReleased: released, message: NOT_IN_KEV };
  return {
    inKev: true,
    vendorProject: entry.vendorProject || null,
    product: entry.product || null,
    name: (entry.vulnerabilityName || '').trim(),
    dateAdded: entry.dateAdded || null,
    dueDate: entry.dueDate || null,
    requiredAction: clip(entry.requiredAction || '', 160),
    ransomware: entry.knownRansomwareCampaignUse === 'Known',
    catalogReleased: released,
  };
}

async function kev(id) {
  const { entries, released } = await loadKev();
  return { status: 'ok', data: kevEntry(entries.get(id), released) };
}

// ---------- KEV search by vendor or product ----------

export const KEV_SEARCH_LIMIT = 50;
export const KEV_RECENT_DAYS = 90;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const day = (s) => (typeof s === 'string' && DATE.test(s) ? s : null);

/**
 * Every KEV entry whose vendor or product (CISA's names) contains the keyword,
 * case-insensitively; "ivanti connect" matches vendor Ivanti + product Connect
 * Secure. Newest added first. Counts are over all matches, rows are capped.
 * keyword must already be validated (validateCveSearch).
 */
export function kevSearch(entries, released, keyword, now = new Date()) {
  const q = keyword.toLowerCase().replace(/\s+/g, ' ').trim();
  const since = new Date(now.getTime() - KEV_RECENT_DAYS * 86_400_000).toISOString().slice(0, 10);
  const matches = [];
  for (const e of entries.values()) {
    const hay = `${e.vendorProject || ''} ${e.product || ''}`.toLowerCase().replace(/\s+/g, ' ');
    if (hay.includes(q)) matches.push(e);
  }
  matches.sort((a, b) => (day(b.dateAdded) || '').localeCompare(day(a.dateAdded) || '') || String(b.cveID).localeCompare(String(a.cveID)));
  return {
    keyword,
    catalogReleased: released,
    total: matches.length,
    recent: matches.filter((e) => (day(e.dateAdded) || '') >= since).length,
    recentDays: KEV_RECENT_DAYS,
    ransomware: matches.filter((e) => e.knownRansomwareCampaignUse === 'Known').length,
    results: matches.slice(0, KEV_SEARCH_LIMIT).map((e) => ({
      id: String(e.cveID || ''),
      vendorProject: String(e.vendorProject || ''),
      product: String(e.product || ''),
      name: clip(String(e.vulnerabilityName || '').trim(), 160),
      dateAdded: day(e.dateAdded),
      dueDate: day(e.dueDate),
      ransomware: e.knownRansomwareCampaignUse === 'Known',
      description: clip(String(e.shortDescription || '').trim(), 300),
      requiredAction: clip(String(e.requiredAction || '').trim(), 160),
    })),
  };
}

// ---------- FIRST EPSS ----------

export function formatPercent(fraction) {
  const pct = fraction * 100;
  return `${pct < 1 ? pct.toFixed(2) : pct.toFixed(1)}%`;
}

export function parseEpss(json) {
  const row = json?.data?.[0];
  if (!row) return null;
  const score = Number(row.epss);
  const percentile = Number(row.percentile);
  return {
    epss: score,
    percentile,
    scoreDate: row.date || null,
    meaning: `Estimated ${formatPercent(score)} chance of exploitation activity in the next 30 days; `
      + `riskier than ${formatPercent(percentile)} of all scored CVEs.`,
  };
}

async function epss(id) {
  const r = await getJson(`${EPSS_URL}?cve=${encodeURIComponent(id)}`, { timeout: FETCH_TIMEOUT_MS });
  const data = parseEpss(r.json);
  if (!data) return { status: 'empty', message: 'FIRST has no EPSS score for this CVE yet. Brand-new CVEs can take a day or more to appear.' };
  return { status: 'ok', data };
}

// ---------- Keyword search ----------

export { validateCveSearch as validateSearch } from '../../js/detect.js';

/**
 * NVD lists matches OLDEST first and cannot sort. So: one request to count the
 * matches, then fetch the last page, which holds the newest. At most two requests.
 */
export async function searchCves({ keyword, severity }, tools) {
  let base = `${NVD_URL}?keywordSearch=${encodeURIComponent(keyword)}`;
  if (severity) base += `&cvssV3Severity=${severity}`;
  const perMinute = nvdPerMinute(tools.env);

  if (!(await tools.allow('nvd', perMinute))) return { skipped: true };
  const count = await nvdFetch(`${base}&resultsPerPage=1`, tools.env);
  const total = count.json?.totalResults ?? 0;
  if (!total) return { total: 0, results: [] };

  if (!(await tools.allow('nvd', perMinute))) return { skipped: true };
  const page = await nvdFetch(`${base}&resultsPerPage=${SEARCH_WINDOW}&startIndex=${Math.max(0, total - SEARCH_WINDOW)}`, tools.env);
  const results = (page.json?.vulnerabilities || [])
    .map(({ cve }) => {
      const cvss = pickCvss(cve.metrics);
      return {
        id: cve.id,
        published: cve.published?.slice(0, 10) ?? '',
        severity: cvss?.severity ?? null,
        score: cvss?.baseScore ?? null,
        summary: englishText(cve.descriptions, 200),
      };
    })
    .sort((a, b) => b.published.localeCompare(a.published))
    .slice(0, SEARCH_LIMIT);
  return { total, results };
}

// ---------- Registry ----------

export const CVE_SOURCES = {
  nvd: { name: 'NVD', quota: 'nvd', ttl: CVE_TTL, run: nvd, link: (id) => `https://nvd.nist.gov/vuln/detail/${id}` },
  kev: { name: 'CISA KEV', ttl: CVE_TTL, run: kev, link: (id) => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(id)}` },
  epss: { name: 'FIRST EPSS', ttl: CVE_TTL, run: epss, link: () => 'https://www.first.org/epss/' },
};
