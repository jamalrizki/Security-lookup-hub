// Result cards for Worker lookups. Source data is attacker-influenced (hostnames,
// TXT records, certificate names), so everything is inserted as text and
// nothing from a feed becomes a link except CVE IDs, which are validated first.

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

const STATUS = { ok: ['ok', 'Found'], empty: ['muted', 'No data'], error: ['warn', 'Unavailable'] };

export function sourceCard(s) {
  const [kind, text] = STATUS[s.status] || ['muted', s.status];
  const body = s.status === 'ok' && RENDER[s.id] ? RENDER[s.id](s.data) : [el('p', { class: 'hint' }, s.message || '')];
  const sourceHost = new URL(s.link).hostname.replace(/^www\./, '');
  return el('article', { class: 'card' },
    el('header', {}, el('h3', {}, s.name), flag(kind, text)),
    ...body,
    el('footer', {},
      extLink(s.link, `Full report on ${sourceHost} →`),
      s.checkedAt ? el('span', { class: 'hint' }, `${s.cached ? 'Cached, checked' : 'Checked'} ${fmtDate(s.checkedAt)}`) : null));
}
