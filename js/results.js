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
// Opens the hub's own lookup for an indicator (same tab; the page reacts to #q=).
export const hubLink = (value, text = value) => el('a', { href: `./lookup.html#q=${encodeURIComponent(value)}` }, text);

/** Returns the URL if it is https with no userinfo, else null. Feed data decides these links. */
export function safeUrl(raw) {
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' && !u.username && !u.password ? u.href : null;
  } catch {
    return null;
  }
}
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
    const spf = d.spfDetails;
    const dm = d.dmarcDetails;
    const policy = dm ? (dm.inherited && dm.sp ? dm.sp : dm.p) : null;
    const spfFlag = !d.spf ? flag('bad', 'Missing')
      : d.spfMultiple ? flag('bad', 'Multiple records (invalid)')
        : flag({ '-all': 'ok', '~all': 'ok', '?all': 'warn', '+all': 'bad' }[spf.all] || 'warn', spf.all || 'no "all"');
    const dmarcFlag = !dm ? flag('bad', 'Missing')
      : !policy || policy === 'none' ? flag('warn', 'p=none (monitor only)')
        : flag(dm.pct < 100 ? 'warn' : 'ok', `p=${policy}${dm.pct < 100 ? ` at ${dm.pct}%` : ''}`);
    const dkim = !d.dkim ? el('span', { class: 'hint' }, 'Add a selector above to check')
      : !d.dkim.found ? flag('warn', `No key at ${d.dkim.selector}`)
        : d.dkim.revoked ? flag('warn', `${d.dkim.selector}: revoked (empty key)`)
          : flag('ok', `${d.dkim.selector}: ${d.dkim.keyType.toUpperCase()}${d.dkim.keyBits ? ` ~${d.dkim.keyBits}-bit` : ''}`);
    const gradeKind = { Protected: 'ok', 'Partly protected': 'warn', 'Easy to spoof': 'bad' }[d.emailGrade] || 'muted';
    return [
      d.emailGrade ? el('div', { class: `verdict ${gradeKind}` },
        el('span', { class: 'hint' }, 'Email spoofing: '), el('strong', {}, d.emailGrade),
        el('ul', { class: 'plain-list' }, ...d.emailReasons.map((x) => el('li', {}, x)))) : null,
      d.nullMx ? el('p', { class: 'notice ok' }, 'Null MX: this domain says it accepts no email.') : null,
      d.parkedAdvice ? el('p', { class: 'hint' }, 'No mail servers (MX) are set. If this domain never sends mail, publish a null MX (0 .), "v=spf1 -all" and a DMARC p=reject record so nobody can send mail pretending to be it.') : null,
      rows([
        ['SPF', spfFlag],
        spf ? ['SPF lookups', `${spf.lookups}${spf.lookups ? '+' : ''} of 10${spf.ptr ? '; uses ptr (deprecated)' : ''}`] : null,
        ['DMARC', dmarcFlag],
        dm ? ['DMARC details', `${dm.inherited ? `inherited from ${dm.from}; ` : ''}alignment DKIM ${dm.adkim}, SPF ${dm.aspf}; reports ${dm.rua ? 'on' : 'off'}${dm.sp && !dm.inherited ? `; subdomains p=${dm.sp}` : ''}`] : null,
        ['DKIM', dkim],
        ['A', list(r.A)],
        ['AAAA', list(r.AAAA)],
        ['MX', d.nullMx ? 'Null MX (accepts no mail)' : list(r.MX)],
        ['NS', list(r.NS)],
      ]),
      spf && spf.lookups ? el('p', { class: 'hint' }, 'Includes aren\u2019t expanded here, so the real number of SPF lookups is at least this; SPF fails above 10.') : null,
      moreList('TXT records', r.TXT || []),
      d.spf ? el('p', { class: 'mono small' }, d.spf) : null,
      d.dmarc ? el('p', { class: 'mono small' }, d.dmarc) : null,
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
        ['Known CVEs', cves.length ? el('span', {}, ...cves.slice(0, 20).flatMap((c, i) => [i ? ', ' : null, hubLink(c)])) : el('span', { class: 'hint' }, 'None listed')],
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

// ---------- CVE sources ----------

const SEVERITY_KIND = { CRITICAL: 'bad', HIGH: 'bad', MEDIUM: 'warn', LOW: 'ok' };

Object.assign(RENDER, {
  nvd(d) {
    const c = d.cvss;
    const sev = (c?.severity || '').toUpperCase();
    const refs = d.references.map((r) => {
      const href = safeUrl(r.url);
      const label = r.tags.length ? ` (${r.tags.slice(0, 2).join(', ')})` : '';
      // Non-https or userinfo URLs are shown as text, never linked.
      return el('li', {}, href ? extLink(href, new URL(href).hostname) : el('span', { class: 'mono' }, defang(r.url)), el('span', { class: 'hint' }, label));
    });
    return [
      ...d.notes.map((n) => el('p', { class: 'notice warn' }, n)),
      c ? el('p', { class: `verdict ${SEVERITY_KIND[sev] || 'muted'}` }, el('strong', {}, `${sev ? `${sev[0]}${sev.slice(1).toLowerCase()} ` : ''}${c.baseScore}`), ` \u2014 CVSS ${c.version}, scored by ${c.scoredBy}`)
        : el('p', { class: 'verdict muted' }, 'No CVSS score yet'),
      c?.plainEnglish.length ? el('ul', { class: 'plain-list' }, ...c.plainEnglish.map((l) => el('li', {}, l))) : null,
      el('p', {}, d.description, d.descriptionTruncated ? el('span', { class: 'hint' }, ' (more on NVD)') : null),
      rows([
        d.weaknesses.length ? ['Weakness', list(d.weaknesses.map((w) => (w.name ? `${w.name} (${w.id})` : w.id)))] : null,
        ['Published', d.published],
        ['Modified', d.modified],
        ['Status', d.status],
      ]),
      d.affected.length ? el('details', { class: 'more' }, el('summary', {}, `Affected products (${d.affectedTotal > d.affected.length ? `${d.affected.length} of ${d.affectedTotal}` : d.affected.length})`),
        el('ul', { class: 'mono-list' }, ...d.affected.map((a) => el('li', {}, `${a.vendor} ${a.product}: ${a.versions}`)))) : null,
      refs.length ? el('details', { class: 'more' }, el('summary', {}, `References (${refs.length})`), el('ul', { class: 'plain-list' }, ...refs)) : null,
    ];
  },

  kev(d) {
    if (!d.inKev) return [el('p', { class: 'verdict muted' }, el('strong', {}, 'Not in KEV')), el('p', { class: 'hint' }, d.message)];
    return [
      el('p', { class: 'verdict bad' }, el('strong', {}, 'Exploited in the wild'), ' \u2014 listed in CISA KEV'),
      rows([
        ['Vulnerability', d.name],
        ['Product', [d.vendorProject, d.product].filter(Boolean).join(' ')],
        ['Date added', d.dateAdded],
        ['CISA due date', d.dueDate],
        ['Ransomware use', d.ransomware ? flag('bad', 'Known') : 'Not known'],
        ['Required action', d.requiredAction],
      ]),
    ];
  },

  epss(d) {
    const kind = d.epss >= 0.1 ? 'bad' : d.epss >= 0.01 ? 'warn' : 'ok';
    return [
      el('p', { class: `verdict ${kind}` }, el('strong', {}, `${(d.epss * 100).toFixed(d.epss < 0.01 ? 2 : 1)}%`), ' chance of exploitation in 30 days'),
      el('p', {}, d.meaning),
      rows([['Percentile', `${(d.percentile * 100).toFixed(1)}`], ['Score date', d.scoreDate]]),
    ];
  },
});

const PRIORITY_KIND = {
  'Rejected: not a valid vulnerability': 'muted',
  'Exploited in the wild: patch urgently': 'bad',
  'High priority': 'bad',
  'Patch soon': 'warn',
  'Patch on your normal cycle': 'ok',
  'Low priority': 'ok',
};

/** The rule-of-thumb priority strip shown above CVE cards. */
export function priorityStrip(p) {
  return el('div', { class: `priority verdict ${PRIORITY_KIND[p.verdict] || 'muted'}` },
    el('span', { class: 'hint' }, 'Priority (rule of thumb): '),
    el('strong', {}, p.verdict),
    p.reasons.length ? el('span', {}, ` \u2014 ${p.reasons.join('; ')}`) : null);
}

const STATUS = { ok: ['ok', 'Found'], empty: ['muted', 'No data'], error: ['warn', 'Unavailable'], skipped: ['warn', 'Skipped'] };
// A "found" result from a threat feed is bad news, not good news.
const LISTED = new Set(['bazaar', 'urlhausUrl', 'urlhausHost', 'urlhausPayload']);

export function sourceCard(s) {
  const [kind, text] = s.status === 'ok' && s.id === 'kev' ? (s.data.inKev ? ['bad', 'In KEV'] : ['muted', 'Not in KEV'])
    : s.status === 'ok' && s.id.startsWith('vt') ? VERDICT[s.data.verdict] || VERDICT.unknown
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
