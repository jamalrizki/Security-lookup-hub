// Result cards for Worker lookups. Source data is attacker-influenced (hostnames,
// TXT records, certificate names), so everything is inserted as text and
// nothing from a feed becomes a link except CVE IDs, which are validated first.

import { defang } from './detect.js';

const fmtDate = (iso) => (iso ? new Date(iso).toISOString().slice(0, 10) : '—');

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

const extLink = (href, ...children) => el('a', { href, target: '_blank', rel: 'noopener noreferrer' }, ...children);
const flag = (kind, text) => el('span', { class: `flag ${kind}` }, text);

function rows(pairs) {
  return el('dl', { class: 'facts' }, ...pairs.filter(Boolean).flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v ?? '—')]));
}

function list(items, empty = 'None') {
  if (!items?.length) return el('span', { class: 'hint' }, empty);
  return el('span', { class: 'mono' }, items.join(', '));
}

function moreList(label, items) {
  if (!items.length) return null;
  return el('details', { class: 'more' }, el('summary', {}, `${label} (${items.length})`),
    el('ul', { class: 'mono-list' }, ...items.map((n) => el('li', {}, n))));
}

const RENDER = {
  rdap(d) {
    const age = d.ageDays == null ? null : d.ageDays < 365 ? `${d.ageDays} days` : `${(d.ageDays / 365).toFixed(1)} years`;
    return [
      d.newlyRegistered ? el('p', { class: 'notice bad' }, el('strong', {}, 'Newly registered. '), 'Domains under 30 days old are a common phishing signal.') : null,
      rows([
        ['Domain', d.domain],
        ['Registered', d.registered ? `${fmtDate(d.registered)} (${age} ago)` : null],
        ['Expires', fmtDate(d.expires)],
        ['Registrar', d.registrar],
        ['Name servers', list(d.nameservers)],
      ]),
      moreList('Registry status', d.status),
    ];
  },

  dns(d) {
    const r = d.records;
    const dmarc = !d.dmarc ? flag('bad', 'Missing')
      : d.dmarcPolicy === 'none' ? flag('warn', 'p=none (monitor only)')
        : flag('ok', `p=${d.dmarcPolicy}`);
    return [
      rows([
        ['SPF', d.spf ? (d.spfMultiple ? flag('warn', 'Multiple records (invalid)') : flag('ok', 'Present')) : flag('bad', 'Missing')],
        ['DMARC', dmarc],
        ['A', list(r.A)],
        ['AAAA', list(r.AAAA)],
        ['MX', list(r.MX)],
        ['NS', list(r.NS)],
      ]),
      moreList('TXT records', r.TXT || []),
      d.spf ? el('p', { class: 'mono small' }, d.spf) : null,
    ];
  },

  certs(d) {
    if (d.tooMany) return [el('p', {}, 'Too many certificates to summarise here. Open the full list on crt.sh.')];
    return [
      rows([
        ['Names found', `${d.total}${d.firstPageOnly ? '+' : ''}`],
        ['Certificates', `${d.certificates}${d.firstPageOnly ? ' (first page)' : ''}`],
        ['Data from', d.source],
      ]),
      moreList('Hostnames on certificates', d.names),
      d.truncated ? el('p', { class: 'hint' }, `Showing the first ${d.names.length}.`) : null,
    ];
  },

  internetdb(d) {
    const cves = d.vulns.filter((v) => /^CVE-\d{4}-\d{4,}$/.test(v));
    return [
      d.tags.includes('scanner') ? el('p', { class: 'notice warn' }, 'Tagged as a scanner: likely internet background noise.') : null,
      rows([
        ['Open ports', list(d.ports.map(String), 'None seen')],
        ['Known CVEs', cves.length ? el('span', {}, ...cves.slice(0, 20).flatMap((c, i) => [i ? ', ' : null, extLink(`https://nvd.nist.gov/vuln/detail/${c}`, c)])) : el('span', { class: 'hint' }, 'None listed')],
        ['Tags', list(d.tags)],
        ['Hostnames', list(d.hostnames.slice(0, 10))],
      ]),
      cves.length > 20 ? el('p', { class: 'hint' }, `Plus ${cves.length - 20} more CVEs on Shodan.`) : null,
      moreList('Software (CPE)', d.cpes),
      el('p', { class: 'hint' }, 'From Shodan’s passive scan data, which can be days or weeks old.'),
    ];
  },

  ipowner(d) {
    return [rows([
      ['Owner', d.owner],
      ['Network', d.network],
      ['Range', d.cidrs.length ? list(d.cidrs) : d.range],
      d.asns.length ? ['ASN', list(d.asns.map((a) => `AS${a}`))] : null,
      ['Registry', d.registry],
      d.country ? ['Country', d.country] : null,
    ])];
  },
};

// ---------- Keyed sources ----------

const VERDICT = {
  malicious: ['bad', 'Malicious'],
  suspicious: ['warn', 'Suspicious'],
  clean: ['ok', 'No detections'],
  unknown: ['muted', 'Not analysed'],
};

function vt(d, extra) {
  const [kind, text] = VERDICT[d.verdict] || VERDICT.unknown;
  return [
    el('p', { class: `verdict ${kind}` }, el('strong', {}, `${d.malicious} / ${d.engines}`), ` engines flag this \u2014 ${text.toLowerCase()}`),
    rows([...extra, d.suspicious ? ['Suspicious', String(d.suspicious)] : null, ['Last analysed', fmtDate(d.lastAnalysis)]]),
  ];
}

const blacklisted = (b = {}) => Object.entries(b).filter(([, v]) => v && v !== 'not listed').map(([k, v]) => `${k}: ${v}`);

function urlTable(urls) {
  if (!urls?.length) return null;
  return el('details', { class: 'more' }, el('summary', {}, `Malicious URLs (${urls.length} shown, defanged)`),
    el('ul', { class: 'mono-list' }, ...urls.map((u) =>
      el('li', {}, defang(u.url), el('span', { class: 'hint' }, ` \u2014 ${u.status || '?'}${u.threat ? `, ${u.threat}` : ''}, ${fmtDate(u.added)}`)))));
}

Object.assign(RENDER, {
  vtFile: (d) => [
    ...vt(d, [
      d.label ? ['Threat label', el('strong', {}, d.label)] : null,
      d.families.length ? ['Families', list(d.families)] : null,
      ['File name', d.name],
      ['Type', d.fileType],
      ['First seen', fmtDate(d.firstSeen)],
    ]),
    d.tags.length ? el('div', { class: 'ref-meta' }, ...d.tags.map((t) => el('span', { class: 'badge' }, t))) : null,
  ],
  vtDomain: (d) => vt(d, [d.categories.length ? ['Categories', list(d.categories)] : null, ['Reputation', String(d.reputation ?? '\u2014')]]),
  vtIp: (d) => vt(d, [['AS owner', d.asOwner], d.asn ? ['ASN', `AS${d.asn}`] : null, ['Country', d.country]]),
  vtUrl: (d) => vt(d, [d.title ? ['Page title', d.title] : null, d.finalUrl ? ['Final URL', el('span', { class: 'mono' }, defang(d.finalUrl))] : null, d.categories.length ? ['Categories', list(d.categories)] : null]),

  abuseipdb(d) {
    const kind = d.score >= 75 ? 'bad' : d.score >= 25 ? 'warn' : 'ok';
    return [
      el('p', { class: `verdict ${kind}` }, el('strong', {}, `${d.score}%`), ' abuse confidence'),
      rows([
        ['Reports (90 days)', `${d.reports} from ${d.reporters} users`],
        ['Last reported', fmtDate(d.lastReported)],
        ['ISP', d.isp],
        ['Usage', d.usageType],
        ['Country', d.country],
        d.isTor ? ['Tor exit node', flag('warn', 'Yes')] : null,
      ]),
    ];
  },

  bazaar: (d) => [
    el('p', { class: 'verdict bad' }, el('strong', {}, 'Known malware'), d.family ? ` \u2014 ${d.family}` : ''),
    rows([['File name', d.fileName], ['Type', d.fileType], ['First seen', fmtDate(d.firstSeen)], ['Last seen', fmtDate(d.lastSeen)], d.deliveryMethod ? ['Delivered by', d.deliveryMethod] : null]),
    d.tags.length ? el('div', { class: 'ref-meta' }, ...d.tags.map((t) => el('span', { class: 'badge' }, t))) : null,
  ],

  urlhausUrl: (d) => [
    el('p', { class: 'verdict bad' }, el('strong', {}, 'Listed as malicious'), ` \u2014 ${d.threat || 'malware'}`),
    rows([['Status', d.status === 'online' ? flag('bad', 'Online now') : d.status], ['Added', fmtDate(d.added)], d.tags.length ? ['Tags', list(d.tags)] : null, blacklisted(d.blacklists).length ? ['Blocklists', list(blacklisted(d.blacklists))] : null]),
  ],
  // A host listing means malware was served from it, not that the host is
  // malicious: GitHub, Google Drive and Discord all carry thousands.
  urlhausHost: (d) => [
    el('p', { class: 'verdict warn' }, el('strong', {}, `${d.urlCount.toLocaleString()} malware URL${d.urlCount === 1 ? '' : 's'}`), ` ${d.urlCount === 1 ? 'has' : 'have'} been served from this host`),
    el('p', { class: 'hint' }, 'This means the host has been used to deliver malware. Big file-sharing and code-hosting sites are abused this way constantly, so it does not by itself make the host malicious. Check the URLs below and the blocklists.'),
    rows([['First seen', fmtDate(d.firstSeen)], blacklisted(d.blacklists).length ? ['Blocklists', list(blacklisted(d.blacklists))] : null]),
    urlTable(d.urls),
  ],
  urlhausPayload: (d) => [
    el('p', { class: 'verdict bad' }, el('strong', {}, 'Distributed by malware URLs'), d.family ? ` \u2014 ${d.family}` : ''),
    rows([['Type', d.fileType], ['First seen', fmtDate(d.firstSeen)], ['Seen on', `${d.urlCount.toLocaleString()} URL${d.urlCount === 1 ? '' : 's'}`]]),
    urlTable(d.urls),
  ],
});

const STATUS = { ok: ['ok', 'Found'], empty: ['muted', 'No data'], error: ['warn', 'Unavailable'], skipped: ['warn', 'Skipped'] };
// A "found" result from a threat feed is bad news, not good news.
const LISTED = new Set(['bazaar', 'urlhausUrl', 'urlhausHost', 'urlhausPayload']);

export function sourceCard(s) {
  const [kind, text] = s.status === 'ok' && s.id.startsWith('vt') ? VERDICT[s.data.verdict] || VERDICT.unknown
    : s.status === 'ok' && s.id === 'urlhausHost' ? ['warn', 'Used for malware']
      : s.status === 'ok' && LISTED.has(s.id) ? ['bad', 'Listed']
    : s.status === 'empty' && LISTED.has(s.id) ? ['ok', 'Not listed']
      : STATUS[s.status] || ['muted', s.status];
  const body = s.status === 'ok' && RENDER[s.id] ? RENDER[s.id](s.data) : [el('p', { class: 'hint' }, s.message || '')];
  const sourceHost = new URL(s.link).hostname.replace(/^www\./, '');
  return el('article', { class: 'card' },
    el('header', {}, el('h3', {}, s.name), flag(kind, text)),
    ...body,
    el('footer', {},
      extLink(s.link, `Full report on ${sourceHost} →`),
      s.checkedAt ? el('span', { class: 'hint' }, `${s.cached ? 'Cached, checked' : 'Checked'} ${fmtDate(s.checkedAt)}`) : null));
}
