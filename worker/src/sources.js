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

// ----- Email security: SPF, DMARC, DKIM, null MX, grade -----

/** SPF details from the top record. includes aren't expanded, so lookups is a minimum. */
export function parseSpf(record) {
  if (!record) return null;
  const terms = record.split(/\s+/).slice(1);
  const all = terms.map((t) => /^([+\-~?]?)all$/i.exec(t)).find(Boolean);
  const qualifier = all ? (all[1] || '+') : null;
  const lookups = terms.filter((t) => /^[+\-~?]?(include:|a\b|a:|a\/|mx\b|mx:|mx\/|ptr\b|ptr:|exists:)/i.test(t) || /^redirect=/i.test(t)).length;
  return {
    all: qualifier ? `${qualifier}all` : null,
    allMeaning: { '-': 'strict: others are rejected', '~': 'soft: others are marked suspicious', '?': 'neutral: no opinion on others', '+': 'dangerous: anyone may send as this domain' }[qualifier] || 'no "all" mechanism',
    ptr: terms.some((t) => /^[+\-~?]?ptr\b/i.test(t)),
    redirect: terms.find((t) => /^redirect=/i.test(t))?.slice(9) || null,
    lookups,
  };
}

/** DMARC tags, with the RFC 7489 defaults filled in. */
export function parseDmarc(record) {
  if (!record) return null;
  const tags = {};
  for (const part of record.split(';')) {
    const m = /^\s*([a-z]+)\s*=\s*(.*?)\s*$/i.exec(part);
    if (m) tags[m[1].toLowerCase()] = m[2];
  }
  const pct = /^\d{1,3}$/.test(tags.pct || '') ? Math.min(Number(tags.pct), 100) : 100;
  return {
    p: (tags.p || '').toLowerCase() || null,
    sp: (tags.sp || '').toLowerCase() || null,
    pct,
    adkim: (tags.adkim || 'r').toLowerCase() === 's' ? 'strict' : 'relaxed',
    aspf: (tags.aspf || 'r').toLowerCase() === 's' ? 'strict' : 'relaxed',
    rua: Boolean(tags.rua),
  };
}

/** A DKIM key record: present, revoked (empty p=) or missing. */
export function parseDkim(records, selector) {
  if (!selector) return null;
  const rec = records.find((t) => /(^|;)\s*p\s*=/i.test(t) || /^v=DKIM1/i.test(t));
  if (!rec) return { selector, found: false };
  const p = /(?:^|;)\s*p\s*=\s*([^;]*)/i.exec(rec)?.[1]?.replace(/\s+/g, '') ?? '';
  const k = (/(?:^|;)\s*k\s*=\s*([^;\s]*)/i.exec(rec)?.[1] || 'rsa').toLowerCase();
  // An RSA public key's DER is roughly modulus bytes + ~38; good enough for 1024 vs 2048 vs 4096.
  const bytes = Math.floor((p.replace(/=+$/, '').length * 3) / 4);
  const bits = k === 'rsa' && bytes > 60 ? Math.round(((bytes - 38) * 8) / 1024) * 1024 : null;
  return { selector, found: true, revoked: p === '', keyType: k, keyBits: bits };
}

/**
 * Spoofing grade, decided in code:
 *  Protected: SPF -all or ~all, and DMARC quarantine/reject at 100%.
 *  Easy to spoof: no DMARC, p=none, no SPF, or SPF +all.
 *  Partly protected: anything in between.
 */
export function emailGrade({ spf, dmarc, nullMx, spfMultiple }) {
  const reasons = [];
  const policy = dmarc ? (dmarc.inherited && dmarc.sp ? dmarc.sp : dmarc.p) : null;
  if (!spf) reasons.push('No SPF record');
  else if (spfMultiple) reasons.push('More than one SPF record, which makes SPF invalid');
  else if (spf.all === '+all') reasons.push('SPF ends in +all, so anyone may send as this domain');
  else if (!spf.all && spf.redirect) reasons.push(`SPF hands its policy to ${spf.redirect} (redirect=), which isn't expanded here`);
  else if (spf.all === '?all' || !spf.all) reasons.push(`SPF ${spf.all ? 'ends in ?all (neutral)' : 'has no "all" mechanism'}, so it doesn't reject other senders`);
  if (!dmarc) reasons.push('No DMARC record');
  else if (!policy || policy === 'none') reasons.push('DMARC policy is p=none: spoofed mail is reported, not blocked');
  else if (dmarc.pct < 100) reasons.push(`DMARC ${policy} applies to only ${dmarc.pct}% of failing mail`);
  if (spf?.lookups > 10) reasons.push(`SPF uses at least ${spf.lookups} DNS lookups; more than 10 makes it fail`);

  // A redirect= delegates the whole policy; it's given the benefit of the doubt since it isn't expanded.
  const spfOk = spf && !spfMultiple && (spf.all === '-all' || spf.all === '~all' || (!spf.all && Boolean(spf.redirect)));
  const dmarcOk = dmarc && (policy === 'quarantine' || policy === 'reject') && dmarc.pct === 100;
  const easy = !dmarc || !policy || policy === 'none' || !spf || spf.all === '+all' || spfMultiple;
  const grade = spfOk && dmarcOk && spf.lookups <= 10 ? 'Protected' : easy ? 'Easy to spoof' : 'Partly protected';
  if (grade === 'Protected') reasons.push(`SPF ${spf.all || `via ${spf.redirect}`} and DMARC p=${policy}${nullMx ? ', and a null MX says it accepts no mail' : ''}`);
  return { grade, reasons };
}

const DNS_TYPES = { 1: 'A', 28: 'AAAA', 15: 'MX', 2: 'NS', 16: 'TXT', 5: 'CNAME' };
const unquote = (s) => s.replace(/^"|"$/g, '').replace(/" "/g, '');
const txt = (j) => (j?.Answer || []).filter((a) => a.type === 16).map((a) => unquote(a.data));

/**
 * answers: DoH JSON per type (A, AAAA, MX, NS, TXT), plus DMARC (and dmarcFrom
 * when it came from a parent domain) and DKIM when a selector was given.
 */
export function parseDns(answers, { domain = null, dmarcFrom = null, selector = null } = {}) {
  const records = {};
  for (const type of ['A', 'AAAA', 'MX', 'NS', 'TXT']) {
    if (!answers[type]) continue;
    records[type] = (answers[type].Answer || []).filter((a) => DNS_TYPES[a.type] === type).map((a) => (type === 'TXT' ? unquote(a.data) : a.data.replace(/\.$/, '')));
  }
  const spfRecords = (records.TXT || []).filter((t) => /^v=spf1\b/i.test(t));
  const dmarcRecords = txt(answers.DMARC).filter((t) => /^v=DMARC1\b/i.test(t));
  const mx = records.MX || [];
  // RFC 7505 null MX: a single "0 ." record.
  const nullMx = mx.length === 1 && /^0\s*\.?$/.test(mx[0].trim());
  const spf = parseSpf(spfRecords[0]);
  const dmarc = parseDmarc(dmarcRecords[0]);
  if (dmarc && dmarcFrom && dmarcFrom !== domain) Object.assign(dmarc, { inherited: true, from: dmarcFrom });
  const email = emailGrade({ spf, dmarc, nullMx, spfMultiple: spfRecords.length > 1 });
  return {
    records,
    spf: spfRecords[0] || null,
    spfMultiple: spfRecords.length > 1,
    spfDetails: spf,
    dmarc: dmarcRecords[0] || null,
    dmarcPolicy: dmarc?.p ?? null,
    dmarcDetails: dmarc,
    nullMx,
    noMx: !mx.length,
    dkim: parseDkim(txt(answers.DKIM), selector),
    emailGrade: email.grade,
    emailReasons: email.reasons,
    // A domain that sends no mail can still be spoofed unless it says so.
    parkedAdvice: !mx.length && email.grade !== 'Protected',
  };
}

/** DKIM selectors: DNS labels (letters, digits, -, _) joined by dots; 63 per label, 100 in all. */
export function validSelector(sel) {
  return typeof sel === 'string' && sel.length <= 100 && sel.split('.').every((l) => /^[A-Za-z0-9_-]{1,63}$/.test(l));
}

async function dns(domain, tools, opts = {}) {
  const ask = (name, type) => getJson(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    { accept: 'application/dns-json' },
  ).then((r) => r.json || {});
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT'];
  const selector = validSelector(opts.selector) ? opts.selector : null;
  const results = await Promise.all([
    ...types.map((t) => ask(domain, t)),
    ask(`_dmarc.${domain}`, 'TXT'),
    selector ? ask(`${selector}._domainkey.${domain}`, 'TXT') : null,
  ]);
  const answers = Object.fromEntries(types.map((t, i) => [t, results[i]]));
  if (answers.A.Status === 3) return { status: 'empty', message: 'The domain does not exist in DNS (NXDOMAIN).' };
  answers.DMARC = results[types.length];
  answers.DKIM = results[types.length + 1];

  // Receivers apply the organisational domain's DMARC policy (its sp=) to
  // subdomains. Without a Public Suffix List here, walk up to two parents.
  let dmarcFrom = domain;
  const labels = domain.split('.');
  for (let i = 1; i <= 2 && labels.length - i >= 2 && !txt(answers.DMARC).some((t) => /^v=DMARC1\b/i.test(t)); i++) {
    dmarcFrom = labels.slice(i).join('.');
    answers.DMARC = await ask(`_dmarc.${dmarcFrom}`, 'TXT');
  }
  return { status: 'ok', data: parseDns(answers, { domain, dmarcFrom, selector }) };
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
