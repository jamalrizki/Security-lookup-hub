// Subnet calculator (#subnet). IPv4 and IPv6 (BigInt), plus "is this IP in
// this range?". Pure functions are exported for tests; the page wiring at the
// bottom only runs in a browser.

import { parseIPv4, parseIPv6, detect } from '../detect.js';

const v4ToBig = (o) => o.reduce((n, x) => (n << 8n) | BigInt(x), 0n);
const v6ToBig = (g) => g.reduce((n, x) => (n << 16n) | BigInt(x), 0n);
const bigToV4 = (n) => [24n, 16n, 8n, 0n].map((s) => Number((n >> s) & 0xffn)).join('.');

/** RFC 5952 text form: lowercase, longest run of 2+ zero groups as "::". */
export function formatIPv6(n) {
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  let best = -1;
  let bestLen = 1;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (best < 0) return hex.join(':');
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLen).join(':')}`;
}

/** Parses "ip/prefix" (IPv4 also accepts a dotted netmask). Returns { version, addr, prefix } or { error }. */
export function parseCidr(input) {
  const s = String(input).trim();
  const [ip, rawPrefix, extra] = s.split('/');
  if (extra !== undefined) return { error: 'Use one "/" between the address and the prefix.' };
  const v4 = parseIPv4(ip);
  const v6 = v4 ? null : parseIPv6(ip);
  if (!v4 && !v6) return { error: 'That is not an IPv4 or IPv6 address.' };
  const max = v4 ? 32 : 128;
  let prefix = max;
  if (rawPrefix !== undefined) {
    if (/^\d{1,3}$/.test(rawPrefix)) prefix = Number(rawPrefix);
    else if (v4 && parseIPv4(rawPrefix)) {
      const m = v4ToBig(parseIPv4(rawPrefix));
      const bits = m.toString(2).padStart(32, '0');
      if (!/^1*0*$/.test(bits)) return { error: 'That netmask has gaps; masks are a run of 1s then 0s (e.g. 255.255.255.0).' };
      prefix = bits.indexOf('0') === -1 ? 32 : bits.indexOf('0');
    } else return { error: `The prefix must be a number from 0 to ${max}.` };
    if (prefix > max) return { error: `The prefix must be a number from 0 to ${max}.` };
  }
  return { version: v4 ? 4 : 6, addr: v4 ? v4ToBig(v4) : v6ToBig(v6), prefix };
}

/** Everything about a subnet. Host counts follow RFC 3021 for /31 and treat /32 as a single host. */
export function subnetInfo(input) {
  const c = parseCidr(input);
  if (c.error) return c;
  const bits = c.version === 4 ? 32n : 128n;
  const size = 1n << (bits - BigInt(c.prefix));
  const mask = ((1n << bits) - 1n) ^ (size - 1n);
  const network = c.addr & mask;
  const last = network | (size - 1n);
  const hostBitsSet = c.addr !== network;
  if (c.version === 6) {
    return {
      version: 6, prefix: c.prefix, network: `${formatIPv6(network)}/${c.prefix}`,
      first: formatIPv6(network), last: formatIPv6(last), count: size.toString(), hostBitsSet,
    };
  }
  const p = c.prefix;
  const usable = p === 32 ? 1n : p === 31 ? 2n : size - 2n;
  return {
    version: 4,
    prefix: p,
    network: `${bigToV4(network)}/${p}`,
    netmask: bigToV4(mask),
    wildcard: bigToV4(((1n << 32n) - 1n) ^ mask),
    // /31 point-to-point links (RFC 3021) and /32 single hosts have no broadcast address.
    broadcast: p >= 31 ? null : bigToV4(last),
    firstHost: p >= 31 ? bigToV4(network) : bigToV4(network + 1n),
    lastHost: p >= 31 ? bigToV4(last) : bigToV4(last - 1n),
    total: size.toString(),
    usable: usable.toString(),
    hostBitsSet,
  };
}

/** Is ip inside cidr? Returns true/false, or { error }. */
export function inRange(cidr, ip) {
  const c = parseCidr(cidr);
  if (c.error) return c;
  const t = parseCidr(ip.split('/')[0]);
  if (t.error) return t;
  if (t.version !== c.version) return { error: `Mixing IPv${c.version} and IPv${t.version}.` };
  const bits = c.version === 4 ? 32n : 128n;
  const mask = ((1n << bits) - 1n) ^ ((1n << (bits - BigInt(c.prefix))) - 1n);
  return (t.addr & mask) === (c.addr & mask);
}

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('subnet-form')) {
  const { el, $, notice, rows } = await import('./ui.js');
  const show = () => {
    const out = $('subnet-result');
    const q = $('subnet-input').value.trim();
    if (!q) { out.replaceChildren(); return; }
    const r = subnetInfo(q);
    if (r.error) { out.replaceChildren(notice('warn', r.error)); return; }
    const parts = [];
    if (r.hostBitsSet) parts.push(el('p', { class: 'hint' }, `That address has host bits set; the network is ${r.network}.`));
    parts.push(r.version === 4
      ? rows([
        ['Network', el('span', { class: 'mono' }, r.network)],
        ['Netmask', el('span', { class: 'mono' }, r.netmask)],
        ['Wildcard', el('span', { class: 'mono' }, r.wildcard)],
        ['Broadcast', r.broadcast ? el('span', { class: 'mono' }, r.broadcast) : (r.prefix === 31 ? 'none (/31 point-to-point link, RFC 3021)' : 'none (single host)')],
        ['First host', el('span', { class: 'mono' }, r.firstHost)],
        ['Last host', el('span', { class: 'mono' }, r.lastHost)],
        ['Usable hosts', Number(r.usable).toLocaleString()],
        ['Total addresses', Number(r.total).toLocaleString()],
      ])
      : rows([
        ['Network', el('span', { class: 'mono' }, r.network)],
        ['First address', el('span', { class: 'mono' }, r.first)],
        ['Last address', el('span', { class: 'mono' }, r.last)],
        ['Addresses', el('span', { class: 'mono' }, BigInt(r.count).toLocaleString())],
      ]));
    const check = $('subnet-check').value.trim();
    if (check) {
      const inside = inRange(q, check);
      parts.push(inside.error ? notice('warn', inside.error)
        : el('p', { class: `verdict ${inside ? 'ok' : 'muted'}` }, el('strong', {}, check), inside ? ' is in this range.' : ' is not in this range.'));
    }
    out.replaceChildren(...parts);
  };
  $('subnet-form').addEventListener('submit', (ev) => { ev.preventDefault(); show(); });

  // Known provider ranges: the "Is this IP in it?" address, else the range's own address.
  $('subnet-provider').addEventListener('click', async () => {
    const out = $('subnet-provider-result');
    const ip = ($('subnet-check').value.trim() || $('subnet-input').value.trim()).split('/')[0];
    const d = detect(ip);
    if (d.type !== 'ipv4' && d.type !== 'ipv6') { out.replaceChildren(notice('warn', 'Type an IPv4 or IPv6 address first.')); return; }
    // Private and other non-public addresses are answered without downloading anything.
    if (d.error) { out.replaceChildren(el('p', { class: 'verdict muted' }, 'Private address: not on the internet.')); return; }
    const { providerRanges } = await import('./provider-ranges.js');
    const { classify, shortLabel } = await import('../ranges.js');
    const button = $('subnet-provider');
    button.disabled = true;
    out.replaceChildren(el('p', { class: 'hint' }, 'Downloading the provider lists\u2026'));
    try {
      const lists = await providerRanges();
      const c = classify(lists, d.value);
      out.replaceChildren(el('p', { class: `verdict ${c.tor ? 'warn' : 'muted'}` }, el('strong', {}, d.value), ': ', shortLabel(c), '.'));
    } catch (err) {
      out.replaceChildren(notice('warn', err.message));
    } finally {
      button.disabled = false;
    }
  });
  $('subnet-input').addEventListener('input', show);
  $('subnet-check').addEventListener('input', show);
}
