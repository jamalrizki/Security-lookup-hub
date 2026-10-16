// Lookup sources. Each source asks a third-party database about the indicator;
// none of them ever connects to the indicator itself.
//
// A source's run(value, tools) returns { status, data?, message?, link? } where
// status is "ok" (found something), "empty" (source answered, nothing known),
// "error", or "skipped" (rate limit or missing key). Keyed sources live in
// keyed.js. Parsers are exported so they can be tested on saved responses.

import { getJson } from './http.js';
import { KEYED_SOURCES } from './keyed.js';
import { CVE_SOURCES } from './cve.js';

const DAY = 86_400_000;
const vcardName = (entity) => entity?.vcardArray?.[1]?.find((v) => v[0] === 'fn')?.[3] || null;
const eventDate = (events, action) => events?.find((e) => e.eventAction === action)?.eventDate || null;

// ---------- Domain registration (RDAP) ----------

export function parseDomainRdap(j, now = Date.now()) {
  const registered = eventDate(j.events, 'registration');
  const registrar = (j.entities || []).find((e) => e.roles?.includes('registrar'));
  const ageDays = registered ? Math.floor((now - Date.parse(registered)) / DAY) : null;
  return {
    domain: (j.ldhName || '').toLowerCase(),
    registered,
    expires: eventDate(j.events, 'expiration'),
    updated: eventDate(j.events, 'last changed'),
    ageDays,
    newlyRegistered: ageDays !== null && ageDays < 30,
    registrar: vcardName(registrar),
    status: j.status || [],
    nameservers: (j.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean),
  };
}

async function rdapDomain(domain) {
  // RDAP only knows registered domains, so walk up from a subdomain
  // (a.b.example.co.uk -> b.example.co.uk -> example.co.uk) until one answers.
  const labels = domain.split('.');
  for (let i = 0; i <= Math.min(labels.length - 2, 3); i++) {
    const name = labels.slice(i).join('.');
    const r = await getJson(`https://rdap.org/domain/${name}`, { accept: 'application/rdap+json' });
    if (r.json) return { status: 'ok', data: parseDomainRdap(r.json) };
  }
  return { status: 'empty', message: 'No registration record found. The domain may be unregistered, or its registry may not support RDAP.' };
}

// ---------- DNS (Cloudflare DNS over HTTPS) ----------

const DNS_TYPES = { 1: 'A', 28: 'AAAA', 15: 'MX', 2: 'NS', 16: 'TXT', 5: 'CNAME' };
const unquote = (s) => s.replace(/^"|"$/g, '').replace(/" "/g, '');

export function parseDns(answers) {
  const records = {};
  for (const [type, j] of Object.entries(answers)) {
    if (type === 'DMARC') continue;
    records[type] = (j.Answer || []).filter((a) => DNS_TYPES[a.type] === type).map((a) => (type === 'TXT' ? unquote(a.data) : a.data.replace(/\.$/, '')));
  }
  const spf = (records.TXT || []).filter((t) => /^v=spf1\b/i.test(t));
  const dmarc = (answers.DMARC?.Answer || []).map((a) => unquote(a.data)).filter((t) => /^v=DMARC1\b/i.test(t));
  const policy = dmarc[0]?.match(/\bp=(\w+)/i)?.[1]?.toLowerCase() || null;
  return {
    records,
    spf: spf[0] || null,
    spfMultiple: spf.length > 1,
    dmarc: dmarc[0] || null,
    dmarcPolicy: policy,
  };
}

async function dns(domain) {
  const ask = (name, type) => getJson(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    { accept: 'application/dns-json' },
  ).then((r) => r.json || {});
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT'];
  const results = await Promise.all([...types.map((t) => ask(domain, t)), ask(`_dmarc.${domain}`, 'TXT')]);
  const answers = Object.fromEntries(types.map((t, i) => [t, results[i]]));
  answers.DMARC = results[types.length];
  if (answers.A.Status === 3) return { status: 'empty', message: 'The domain does not exist in DNS (NXDOMAIN).' };
  return { status: 'ok', data: parseDns(answers) };
}

// ---------- Certificates (crt.sh, Cert Spotter fallback) ----------

const MAX_NAMES = 200;

function summariseNames(names, domain) {
  const suffix = `.${domain}`;
  const set = new Set();
  for (const raw of names) {
    for (const n of String(raw).toLowerCase().split('\n')) {
      const name = n.trim().replace(/^\*\./, '');
      if (name === domain || name.endsWith(suffix)) set.add(name);
    }
  }
  const all = [...set].sort();
  return { total: all.length, names: all.slice(0, MAX_NAMES), truncated: all.length > MAX_NAMES };
}

export function parseCrtSh(rows, domain) {
  return { source: 'crt.sh', certificates: rows.length, ...summariseNames(rows.map((r) => r.name_value), domain) };
}

export function parseCertSpotter(rows, domain) {
  return { source: 'Cert Spotter', certificates: rows.length, firstPageOnly: true, ...summariseNames(rows.flatMap((r) => r.dns_names || []), domain) };
}

async function certificates(domain) {
  let crtError;
  try {
    const r = await getJson(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json&exclude=expired&deduplicate=Y`, { timeout: 7000 });
    if (r.status === 413) {
      return { status: 'ok', data: { source: 'crt.sh', tooMany: true, total: null, names: [] } };
    }
    if (r.json) {
      const data = parseCrtSh(r.json, domain);
      return data.total ? { status: 'ok', data } : { status: 'empty', message: 'No unexpired certificates found.' };
    }
  } catch (err) {
    crtError = err.message;
  }
  // crt.sh is often slow or down; Cert Spotter allows a few keyless queries per hour.
  const r = await getJson(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`);
  if (!r.json) throw new Error(`crt.sh ${crtError || 'unavailable'}; Cert Spotter HTTP ${r.status}`);
  const data = parseCertSpotter(r.json, domain);
  return data.total ? { status: 'ok', data } : { status: 'empty', message: 'No unexpired certificates found.' };
}

// ---------- IP: Shodan InternetDB ----------

export function parseInternetDb(j) {
  return {
    ports: j.ports || [],
    hostnames: j.hostnames || [],
    vulns: j.vulns || [],
    cpes: j.cpes || [],
    tags: j.tags || [],
  };
}

async function internetDb(ip) {
  const r = await getJson(`https://internetdb.shodan.io/${ip}`);
  if (r.status === 404) return { status: 'empty', message: 'Shodan has no data on this IP (no open ports seen in recent scans).' };
  return { status: 'ok', data: parseInternetDb(r.json) };
}

// ---------- IP: network owner (RDAP) ----------

export function parseIpRdap(j) {
  const org = (j.entities || []).find((e) => e.roles?.some((r) => r === 'registrant' || r === 'administrative'));
  const cidrs = (j.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`);
  return {
    network: j.name || null,
    handle: j.handle || null,
    owner: vcardName(org),
    country: j.country || null,
    range: j.startAddress && j.endAddress ? `${j.startAddress} - ${j.endAddress}` : null,
    cidrs,
    asns: j.arin_originas0_originautnums || [],
    registry: (j.port43 || '').replace(/^whois\./, '').replace(/\.net$|\.org$/, '').toUpperCase() || null,
  };
}

async function rdapIp(ip) {
  const r = await getJson(`https://rdap.org/ip/${ip}`, { accept: 'application/rdap+json' });
  if (!r.json) return { status: 'empty', message: 'No registry record found for this address.' };
  return { status: 'ok', data: parseIpRdap(r.json) };
}

// ---------- Registry ----------

export const SOURCES = {
  rdap: { name: 'Domain registration (RDAP)', run: rdapDomain, link: (d) => `https://lookup.icann.org/en/lookup?name=${encodeURIComponent(d)}` },
  dns: { name: 'DNS records', run: dns, link: (d) => `https://mxtoolbox.com/SuperTool.aspx?action=${encodeURIComponent(`mx:${d}`)}&run=toolpage` },
  certs: { name: 'Certificates', run: certificates, link: (d) => `https://crt.sh/?q=${encodeURIComponent(d)}` },
  internetdb: { name: 'Shodan InternetDB', run: internetDb, link: (ip) => `https://www.shodan.io/host/${ip}` },
  ipowner: { name: 'Network owner (RDAP)', run: rdapIp, link: (ip) => `https://ipinfo.io/${ip}` },
  ...KEYED_SOURCES,
  ...CVE_SOURCES,
};

/** Which sources run for each detected type, and on which value. Verdict sources first. */
export function plan(detected) {
  const run = (ids, value) => ids.map((id) => ({ id, value }));
  const forDomain = (d) => run(['vtDomain', 'urlhausHost', 'rdap', 'dns', 'certs'], d);
  const forIp = (ip) => run(['abuseipdb', 'vtIp', 'urlhausHost', 'internetdb', 'ipowner'], ip);
  switch (detected.type) {
    case 'cve': return run(['nvd', 'kev', 'epss'], detected.value);
    case 'hash': return run(['vtFile', 'bazaar', 'urlhausPayload'], detected.value);
    case 'domain': return forDomain(detected.value);
    case 'ipv4':
    case 'ipv6': return forIp(detected.value);
    case 'url': {
      // One VirusTotal call per search: the URL itself, not its host as well.
      const host = detected.host.replace(/^\[|\]$/g, '');
      const hostSources = /^[\d.]+$|:/.test(host)
        ? run(['abuseipdb', 'internetdb', 'ipowner'], host)
        : run(['rdap', 'dns', 'certs'], host);
      return [...run(['vtUrl', 'urlhausUrl'], detected.value), ...hostSources];
    }
    case 'email': return run(['dns'], detected.value.split('@')[1]);
    default: return [];
  }
}
