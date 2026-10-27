// Nmap viewer (#nmap). Reads Nmap XML (-oX) locally with the browser's
// DOMParser and shows a filterable host/port table. Private IPs are expected
// in scan results and shown, but only public addresses get a Look up link.

import { detect, normalizeCveId } from '../detect.js';

export const MAX_NMAP = 20 * 1024 * 1024;

/**
 * Refuses XML that declares entities or an internal DTD subset: real Nmap
 * output never does, and it is how entity-expansion ("billion laughs") and
 * external-entity tricks work.
 */
export function checkXml(text) {
  if (text.length > MAX_NMAP) return 'That is more than 20 MB.';
  if (/<!ENTITY/i.test(text) || /<!DOCTYPE[^>]*\[/i.test(text)) return 'This XML declares entities, which Nmap output never does, so it was not read.';
  return null;
}

/** Unique CVE IDs mentioned in script output, normalised. */
export function cvesIn(text) {
  const out = new Set();
  for (const m of String(text).matchAll(/\bCVE[-_ ]?\d{4}[-_ ]?\d{4,19}\b/gi)) {
    const c = normalizeCveId(m[0]);
    if (c?.value) out.add(c.value);
  }
  return [...out];
}

/** Only addresses the hub can look up (public IPs) get a Look up link. */
export const lookupable = (addr) => {
  const d = detect(addr);
  return (d.type === 'ipv4' || d.type === 'ipv6') && !d.error;
};

/** Parses Nmap XML into plain objects. Returns { error } or { scan, hosts, stats }. */
export function parseNmap(text, Parser = globalThis.DOMParser) {
  const bad = checkXml(text);
  if (bad) return { error: bad };
  const doc = new Parser().parseFromString(text, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) return { error: 'That is not well-formed XML.' };
  const root = doc.documentElement;
  if (!root || root.nodeName !== 'nmaprun') return { error: 'That is XML, but not Nmap output (no <nmaprun> root). Save scans with -oX.' };

  const attr = (el, name) => el?.getAttribute(name) ?? null;
  const hosts = [...root.getElementsByTagName('host')].map((h) => {
    const addrs = [...h.getElementsByTagName('address')];
    const ip = addrs.find((a) => /^ipv[46]$/.test(attr(a, 'addrtype')));
    const mac = addrs.find((a) => attr(a, 'addrtype') === 'mac');
    const ports = [...h.getElementsByTagName('port')].map((p) => {
      const svc = p.getElementsByTagName('service')[0];
      const scripts = [...p.getElementsByTagName('script')].map((s) => ({ id: attr(s, 'id'), output: (attr(s, 'output') || '').slice(0, 4000) }));
      return {
        proto: attr(p, 'protocol'),
        port: Number(attr(p, 'portid')),
        state: attr(p.getElementsByTagName('state')[0], 'state'),
        service: attr(svc, 'name'),
        product: [attr(svc, 'product'), attr(svc, 'version'), attr(svc, 'extrainfo') ? `(${attr(svc, 'extrainfo')})` : null].filter(Boolean).join(' '),
        scripts,
        cves: cvesIn(scripts.map((s) => s.output).join('\n')),
      };
    });
    return {
      addr: attr(ip, 'addr'),
      mac: attr(mac, 'addr'),
      vendor: attr(mac, 'vendor'),
      state: attr(h.getElementsByTagName('status')[0], 'state'),
      hostnames: [...h.getElementsByTagName('hostname')].map((n) => attr(n, 'name')).filter(Boolean),
      ports,
    };
  });
  const finished = root.getElementsByTagName('finished')[0];
  return {
    scan: { args: attr(root, 'args'), version: attr(root, 'version'), started: attr(root, 'startstr'), summary: attr(finished, 'summary') },
    hosts,
    stats: {
      up: hosts.filter((h) => h.state === 'up').length,
      down: hosts.filter((h) => h.state === 'down').length,
      openPorts: hosts.reduce((n, h) => n + h.ports.filter((p) => p.state === 'open').length, 0),
    },
  };
}

/** Rows for the table after filters: port number, service substring, open-only. */
export function filterRows(result, { port = '', service = '', openOnly = false } = {}) {
  const svc = service.trim().toLowerCase();
  const rows = [];
  for (const h of result.hosts) {
    for (const p of h.ports) {
      if (port && String(p.port) !== String(port).trim()) continue;
      if (svc && !`${p.service || ''} ${p.product || ''}`.toLowerCase().includes(svc)) continue;
      if (openOnly && p.state !== 'open') continue;
      rows.push({ host: h, port: p });
    }
  }
  return rows;
}

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('nmap-file')) {
  const { el, $, notice, lookUpLink } = await import('./ui.js');
  let result = null;

  const renderTable = () => {
    const rows = filterRows(result, { port: $('nmap-port').value, service: $('nmap-service').value, openOnly: $('nmap-open').checked });
    const counts = {};
    for (const { port } of rows) if (port.state === 'open') counts[port.service || 'unknown'] = (counts[port.service || 'unknown'] || 0) + 1;
    $('nmap-table').replaceChildren(
      el('p', { class: 'hint' }, `${rows.length} port rows shown. Open by service: ${Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(', ') || 'none'}.`),
      el('table', { class: 'ioc-table nmap-table' },
        el('thead', {}, el('tr', {}, ...['Host', 'Port', 'State', 'Service', 'Version'].map((t) => el('th', {}, t)))),
        el('tbody', {}, ...rows.map(({ host, port }) => el('tr', {},
          el('td', { class: 'mono' }, host.addr || '?', host.hostnames.length ? el('div', { class: 'hint' }, host.hostnames.join(', ')) : null,
            host.addr && lookupable(host.addr) ? lookUpLink(host.addr) : null),
          el('td', { class: 'mono' }, `${port.port}/${port.proto}`),
          el('td', {}, el('span', { class: `flag ${port.state === 'open' ? 'ok' : 'muted'}` }, port.state || '?')),
          el('td', {}, port.service || ''),
          el('td', {}, port.product || '', port.cves.length ? el('div', { class: 'cve-links' }, ...port.cves.flatMap((c, i) => [i ? ', ' : null, el('a', { href: `./lookup.html#q=${c}`, class: 'mono' }, c)])) : null))))));
  };

  const load = async (file) => {
    const out = $('nmap-result');
    if (!file) return;
    if (file.size > MAX_NMAP) { out.replaceChildren(notice('warn', 'That file is more than 20 MB.')); return; }
    result = parseNmap(await file.text());
    if (result.error) { out.replaceChildren(notice('warn', result.error)); return; }
    const s = result.stats;
    out.replaceChildren(
      el('p', {}, `${s.up} host${s.up === 1 ? '' : 's'} up, ${s.down} down, ${s.openPorts} open port${s.openPorts === 1 ? '' : 's'}.`),
      result.scan.args ? el('p', { class: 'hint mono' }, result.scan.args) : null,
      el('div', { class: 'row' },
        el('input', { id: 'nmap-port', type: 'text', inputmode: 'numeric', placeholder: 'Port, e.g. 22', 'aria-label': 'Filter by port' }),
        el('input', { id: 'nmap-service', type: 'text', placeholder: 'Service or product', 'aria-label': 'Filter by service' }),
        el('label', { class: 'inline' }, el('input', { id: 'nmap-open', type: 'checkbox', checked: true }), ' Open only')),
      el('div', { id: 'nmap-table' }),
    );
    for (const id of ['nmap-port', 'nmap-service', 'nmap-open']) $(id).addEventListener('input', renderTable);
    renderTable();
  };

  $('nmap-file').addEventListener('change', (ev) => load(ev.target.files[0]));
  const drop = $('nmap-drop');
  drop.addEventListener('dragover', (ev) => { ev.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (ev) => {
    ev.preventDefault();
    drop.classList.remove('over');
    load(ev.dataTransfer.files[0]);
  });
}
