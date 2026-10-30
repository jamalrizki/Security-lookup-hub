// Sources that need a free API key (Worker secrets): VirusTotal, AbuseIPDB,
// and abuse.ch (MalwareBazaar, URLhaus). All free tiers are non-commercial.

import { getJson } from './http.js';
import NAMES from '../../data/source-names.json' with { type: 'json' };

const unix = (s) => (s ? new Date(s * 1000).toISOString() : null);
// abuse.ch dates look like "2024-01-31 12:34:56" (UTC).
const abuseDate = (s) => (s ? new Date(`${s.replace(/ UTC$/, '').replace(' ', 'T')}Z`).toISOString() : null);
const base64url = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// ---------- VirusTotal ----------

/** Turns last_analysis_stats into counts and a coarse verdict. */
export function vtVerdict(stats = {}) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const engines = malicious + suspicious + (stats.undetected || 0) + (stats.harmless || 0);
  const verdict = malicious >= 3 ? 'malicious' : malicious + suspicious > 0 ? 'suspicious' : engines ? 'clean' : 'unknown';
  return { malicious, suspicious, engines, verdict };
}

export function parseVt(kind, j) {
  const a = j.data?.attributes || {};
  const out = { ...vtVerdict(a.last_analysis_stats), reputation: a.reputation ?? null, lastAnalysis: unix(a.last_analysis_date) };
  if (kind === 'file') {
    const ptc = a.popular_threat_classification || {};
    Object.assign(out, {
      name: a.meaningful_name || a.names?.[0] || null,
      fileType: a.type_description || null,
      size: a.size ?? null,
      label: ptc.suggested_threat_label || null,
      families: (ptc.popular_threat_name || []).map((x) => x.value).slice(0, 5),
      categories: (ptc.popular_threat_category || []).map((x) => x.value).slice(0, 5),
      firstSeen: unix(a.first_submission_date),
      tags: (a.tags || []).slice(0, 15),
    });
  } else if (kind === 'domain') {
    Object.assign(out, { categories: [...new Set(Object.values(a.categories || {}))].slice(0, 6) });
  } else if (kind === 'ip') {
    Object.assign(out, { asOwner: a.as_owner || null, asn: a.asn ?? null, country: a.country || null });
  } else if (kind === 'url') {
    Object.assign(out, { finalUrl: a.last_final_url || null, title: a.title || null, categories: [...new Set(Object.values(a.categories || {}))].slice(0, 6) });
  }
  return out;
}

const VT_PATHS = {
  file: (h) => ['files', h, `https://www.virustotal.com/gui/file/${h}`],
  domain: (d) => ['domains', d, `https://www.virustotal.com/gui/domain/${d}`],
  ip: (ip) => ['ip_addresses', ip, `https://www.virustotal.com/gui/ip-address/${ip}`],
  // URL ids are the unpadded base64url of the URL; the GUI uses the SHA-256 id returned in data.id.
  url: (u) => ['urls', base64url(u), null],
};

function virusTotal(kind) {
  return async (value, tools) => {
    // Free tier is 4 requests/minute for the whole site; leave room before VT refuses.
    if (!(await tools.allow('VT_API_KEY', 4))) {
      return { status: 'skipped', message: 'VirusTotal’s free limit (4 lookups a minute) is in use. Try again in a minute.' };
    }
    const [path, id, link] = VT_PATHS[kind](value);
    const r = await getJson(`https://www.virustotal.com/api/v3/${path}/${id}`, { headers: { 'x-apikey': tools.env.VT_API_KEY } });
    if (r.status === 404) return { status: 'empty', message: 'VirusTotal has never seen this.' };
    const gui = link || `https://www.virustotal.com/gui/url/${r.json.data?.id}`;
    return { status: 'ok', data: parseVt(kind, r.json), link: gui };
  };
}

// ---------- AbuseIPDB ----------

export function parseAbuseIpdb(j) {
  const d = j.data || {};
  return {
    score: d.abuseConfidenceScore ?? 0,
    reports: d.totalReports ?? 0,
    reporters: d.numDistinctUsers ?? 0,
    lastReported: d.lastReportedAt || null,
    isp: d.isp || null,
    domain: d.domain || null,
    usageType: d.usageType || null,
    country: d.countryCode || null,
    isTor: Boolean(d.isTor),
    isWhitelisted: d.isWhitelisted ?? null,
  };
}

async function abuseIpdb(ip, tools) {
  const r = await getJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
    headers: { Key: tools.env.ABUSEIPDB_API_KEY },
  });
  const data = parseAbuseIpdb(r.json);
  return { status: data.reports ? 'ok' : 'empty', data, message: data.reports ? undefined : 'No abuse reports in the last 90 days.' };
}

// ---------- abuse.ch: MalwareBazaar and URLhaus ----------

function abuseChPost(url, params, tools) {
  return getJson(url, {
    method: 'POST',
    body: new URLSearchParams(params),
    headers: { 'Auth-Key': tools.env.ABUSECH_AUTH_KEY, 'content-type': 'application/x-www-form-urlencoded' },
  });
}

const NOT_FOUND = ['hash_not_found', 'no_results'];

export function parseBazaar(j) {
  const s = j.data?.[0] || {};
  return {
    sha256: s.sha256_hash || null,
    family: s.signature || null,
    fileName: s.file_name || null,
    fileType: s.file_type || null,
    firstSeen: abuseDate(s.first_seen),
    lastSeen: abuseDate(s.last_seen),
    tags: (s.tags || []).slice(0, 15),
    deliveryMethod: s.delivery_method || null,
  };
}

async function malwareBazaar(hash, tools) {
  const r = await abuseChPost('https://mb-api.abuse.ch/api/v1/', { query: 'get_info', hash }, tools);
  const q = r.json?.query_status;
  if (NOT_FOUND.includes(q)) return { status: 'empty', message: 'Not a known malware sample in MalwareBazaar.' };
  if (q !== 'ok') throw new Error(q || 'unexpected response');
  const data = parseBazaar(r.json);
  return { status: 'ok', data, link: data.sha256 ? `https://bazaar.abuse.ch/sample/${data.sha256}/` : undefined };
}

const urlEntry = (u) => ({ url: u.url, status: u.url_status, threat: u.threat, added: abuseDate(u.date_added), tags: u.tags || [] });

export function parseUrlhaus(kind, j) {
  if (kind === 'url') {
    return { status: j.url_status, threat: j.threat, added: abuseDate(j.date_added), tags: j.tags || [], blacklists: j.blacklists || {} };
  }
  if (kind === 'host') {
    return { urlCount: Number(j.url_count) || 0, firstSeen: abuseDate(j.firstseen), blacklists: j.blacklists || {}, urls: (j.urls || []).slice(0, 25).map(urlEntry) };
  }
  return { family: j.signature || null, fileType: j.file_type || null, firstSeen: abuseDate(j.firstseen), urlCount: Number(j.url_count) || 0, urls: (j.urls || []).slice(0, 25).map((u) => ({ url: u.url, status: u.url_status, added: abuseDate(u.firstseen) })) };
}

function urlhaus(kind) {
  const endpoint = { url: 'url', host: 'host', payload: 'payload' }[kind];
  return async (value, tools) => {
    let params = { [kind]: value };
    if (kind === 'payload') {
      if (value.length === 40) return { status: 'skipped', message: 'URLhaus only looks up MD5 and SHA-256 hashes.' };
      params = { [value.length === 32 ? 'md5_hash' : 'sha256_hash']: value };
    }
    const r = await abuseChPost(`https://urlhaus-api.abuse.ch/v1/${endpoint}/`, params, tools);
    const q = r.json?.query_status;
    if (NOT_FOUND.includes(q)) return { status: 'empty', message: 'Not listed in URLhaus.' };
    if (q !== 'ok') throw new Error(q || 'unexpected response');
    return { status: 'ok', data: parseUrlhaus(kind, r.json), link: r.json.urlhaus_reference || undefined };
  };
}

// ---------- Registry ----------

const e = encodeURIComponent;

export const KEYED_SOURCES = {
  vtFile: { name: NAMES.vtFile, key: 'VT_API_KEY', run: virusTotal('file'), link: (h) => `https://www.virustotal.com/gui/file/${h}` },
  vtDomain: { name: NAMES.vtDomain, key: 'VT_API_KEY', run: virusTotal('domain'), link: (d) => `https://www.virustotal.com/gui/domain/${d}` },
  vtIp: { name: NAMES.vtIp, key: 'VT_API_KEY', run: virusTotal('ip'), link: (ip) => `https://www.virustotal.com/gui/ip-address/${ip}` },
  vtUrl: { name: NAMES.vtUrl, key: 'VT_API_KEY', run: virusTotal('url'), link: (u) => `https://www.virustotal.com/gui/search/${e(e(u))}` },
  abuseipdb: { name: NAMES.abuseipdb, key: 'ABUSEIPDB_API_KEY', run: abuseIpdb, link: (ip) => `https://www.abuseipdb.com/check/${ip}` },
  bazaar: { name: NAMES.bazaar, key: 'ABUSECH_AUTH_KEY', run: malwareBazaar, link: (h) => `https://bazaar.abuse.ch/browse.php?search=${e(h)}` },
  urlhausUrl: { name: NAMES.urlhausUrl, key: 'ABUSECH_AUTH_KEY', run: urlhaus('url'), link: (u) => `https://urlhaus.abuse.ch/browse.php?search=${e(u)}` },
  urlhausHost: { name: NAMES.urlhausHost, key: 'ABUSECH_AUTH_KEY', run: urlhaus('host'), link: (h) => `https://urlhaus.abuse.ch/browse.php?search=${e(h)}` },
  urlhausPayload: { name: NAMES.urlhausPayload, key: 'ABUSECH_AUTH_KEY', run: urlhaus('payload'), link: (h) => `https://urlhaus.abuse.ch/browse.php?search=${e(h)}` },
};
