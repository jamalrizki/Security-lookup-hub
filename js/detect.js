// Input detection and validation. Pure functions with no DOM access, so the
// Worker (phase 3) can import the same rules and reject the same inputs.

const REFANG_RULES = [
  [/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.'],
  [/\[:\]|\[:\/\/\]/g, (m) => m.slice(1, -1)],
  [/\[@\]|\[at\]|\(at\)/gi, '@'],
  [/^hxxp/i, 'http'],
  [/^fxp/i, 'ftp'],
];

/** Undo common defanging (hxxp, [.], [at]) so pasted IOCs are recognised. */
export function refang(input) {
  let s = String(input).trim();
  for (const [re, rep] of REFANG_RULES) s = s.replace(re, rep);
  return s;
}

/** Make a URL or domain unclickable for display: hxxps://bad[.]example */
export function defang(input) {
  return String(input).replace(/^http/i, (m) => (m[0] === 'H' ? 'HXXP' : 'hxxp')).replace(/\./g, '[.]');
}

// ---------- IPv4 ----------

export function parseIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const octets = m.slice(1).map((o) => {
    // Leading zeros are rejected: some resolvers read "010" as octal.
    if (o.length > 1 && o[0] === '0') return NaN;
    return Number(o);
  });
  return octets.every((o) => o >= 0 && o <= 255) ? octets : null;
}

const V4_RESERVED = [
  ['0.0.0.0', 8, '"this network" (0.0.0.0/8)'],
  ['10.0.0.0', 8, 'private (10.0.0.0/8)'],
  ['100.64.0.0', 10, 'carrier-grade NAT (100.64.0.0/10)'],
  ['127.0.0.0', 8, 'loopback (127.0.0.0/8)'],
  ['169.254.0.0', 16, 'link-local (169.254.0.0/16)'],
  ['172.16.0.0', 12, 'private (172.16.0.0/12)'],
  ['192.0.0.0', 24, 'IETF protocol assignments (192.0.0.0/24)'],
  ['192.0.2.0', 24, 'documentation (TEST-NET-1)'],
  ['192.88.99.0', 24, 'deprecated 6to4 relay'],
  ['192.168.0.0', 16, 'private (192.168.0.0/16)'],
  ['198.18.0.0', 15, 'benchmarking (198.18.0.0/15)'],
  ['198.51.100.0', 24, 'documentation (TEST-NET-2)'],
  ['203.0.113.0', 24, 'documentation (TEST-NET-3)'],
  ['224.0.0.0', 4, 'multicast (224.0.0.0/4)'],
  ['240.0.0.0', 4, 'reserved (240.0.0.0/4)'],
].map(([base, bits, label]) => ({ base: v4ToInt(parseIPv4(base)), mask: maskBits(bits), label }));

function v4ToInt(o) {
  return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
}

function maskBits(bits) {
  return bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
}

/** Returns a reason string if the address is not publicly routable, else null. */
export function ipv4Reserved(octets) {
  const n = v4ToInt(octets);
  for (const r of V4_RESERVED) if (((n & r.mask) >>> 0) === r.base) return r.label;
  return null;
}

// ---------- IPv6 ----------

/** Parses an IPv6 address into eight 16-bit groups, or returns null. */
export function parseIPv6(input) {
  const s = input.replace(/^\[|\]$/g, '');
  if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return null;

  let head = s;
  let tail = [];
  const lastColon = s.lastIndexOf(':');
  if (s.slice(lastColon + 1).includes('.')) {
    const v4 = parseIPv4(s.slice(lastColon + 1));
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    head = s.slice(0, lastColon + 1);
    if (!head.endsWith('::')) head = head.slice(0, -1);
  }

  const halves = head.split('::');
  if (halves.length > 2) return null;
  const split = (p) => (p === '' ? [] : p.split(':'));
  const left = split(halves[0]);
  const right = halves.length === 2 ? split(halves[1]) : [];
  if (![...left, ...right].every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return null;

  const hex = (g) => parseInt(g, 16);
  const count = left.length + right.length + tail.length;
  if (halves.length === 2) {
    if (count > 7) return null;
    return [...left.map(hex), ...new Array(8 - count).fill(0), ...right.map(hex), ...tail];
  }
  return count === 8 ? [...left.map(hex), ...tail] : null;
}

/** Returns a reason string if the address is not global unicast, else null. */
export function ipv6Reserved(g) {
  const zeroUpTo = (n) => g.slice(0, n).every((x) => x === 0);
  if (zeroUpTo(8)) return 'unspecified (::)';
  if (zeroUpTo(7) && g[7] === 1) return 'loopback (::1)';
  if (zeroUpTo(5) && g[5] === 0xffff) {
    const v4 = [g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff];
    return ipv4Reserved(v4) ? `IPv4-mapped ${ipv4Reserved(v4)}` : null;
  }
  if ((g[0] & 0xfe00) === 0xfc00) return 'unique local (fc00::/7)';
  if ((g[0] & 0xffc0) === 0xfe80) return 'link-local (fe80::/10)';
  if ((g[0] & 0xff00) === 0xff00) return 'multicast (ff00::/8)';
  if (g[0] === 0x2001 && g[1] === 0x0db8) return 'documentation (2001:db8::/32)';
  if (g[0] === 0x2001 && g[1] === 0x0002 && g[2] === 0) return 'benchmarking (2001:2::/48)';
  if ((g[0] & 0xe000) !== 0x2000) return 'not global unicast (outside 2000::/3)';
  return null;
}

// ---------- Domains ----------

// Names that only make sense inside a private network, or are reserved by RFC 6761.
const INTERNAL_SUFFIXES = [
  'localhost', 'local', 'localdomain', 'internal', 'intranet', 'lan', 'home',
  'corp', 'home.arpa', 'test', 'invalid', 'onion',
];

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

/** Lowercases, punycodes and strips a trailing dot. Returns null if unparseable. */
export function normaliseDomain(input) {
  if (/[/?#@:\\\s%]/.test(input)) return null;
  let host;
  try {
    host = new URL(`http://${input}`).hostname;
  } catch {
    return null;
  }
  // URL() accepts "a/b" or "user@host"; insist the whole input was the host.
  if (host.replace(/\.$/, '') !== input.toLowerCase().replace(/\.$/, '') && !/[^\x00-\x7f]/.test(input)) {
    return null;
  }
  return host.replace(/\.$/, '');
}

/** Returns { value } for a valid public domain, { error } otherwise, or null if it isn't domain-shaped. */
export function checkDomain(input) {
  const d = normaliseDomain(input);
  if (!d || (!d.includes('.') && !INTERNAL_SUFFIXES.includes(d))) return null;
  const internal = INTERNAL_SUFFIXES.find((s) => d === s || d.endsWith(`.${s}`));
  if (internal) return { value: d, error: `".${internal}" names are internal or reserved, not public domains.` };
  if (d.length > 253) return { value: d, error: 'Domain is longer than 253 characters.' };
  const labels = d.split('.');
  if (!labels.every((l) => LABEL_RE.test(l))) return null;
  if (!TLD_RE.test(labels[labels.length - 1])) return null;
  return { value: d };
}

// ---------- Hashes ----------

const HEX_HASHES = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' };

/**
 * Lists the likely algorithms for a hash string, most likely first.
 * Format-based only: a 32-hex string could be MD5, NTLM or MD4 and nothing in
 * the string itself can tell them apart.
 */
export function identifyHash(input) {
  const s = input.trim();
  const out = [];
  const add = (name, note = '') => out.push({ name, note });

  const prefixed = [
    [/^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$/, 'bcrypt', 'Cost factor is the number after the second $.'],
    [/^\$argon2(id|i|d)\$/, 'Argon2', 'Variant, memory and iteration settings are in the string.'],
    [/^\$y\$/, 'yescrypt', 'Default on recent Debian, Ubuntu and Fedora /etc/shadow.'],
    [/^\$7\$/, 'scrypt (crypt format)', ''],
    [/^\$6\$/, 'SHA-512 crypt', 'Linux /etc/shadow ($6$).'],
    [/^\$5\$/, 'SHA-256 crypt', 'Linux /etc/shadow ($5$).'],
    [/^\$1\$/, 'MD5 crypt', 'Old Linux and Cisco "type 5" format.'],
    [/^\$apr1\$/, 'Apache MD5 (apr1)', 'Used in .htpasswd files.'],
    [/^\$[PH]\$[./A-Za-z0-9]{31}$/, 'phpass', 'WordPress, phpBB and Drupal 7.'],
    [/^pbkdf2_sha256\$\d+\$/, 'Django PBKDF2-SHA256', ''],
    [/^\{SSHA\}/i, 'LDAP salted SHA-1 (SSHA)', ''],
    [/^\{SHA\}/i, 'LDAP SHA-1', 'Base64 of a raw SHA-1 digest.'],
    [/^\*[0-9A-F]{40}$/i, 'MySQL 4.1+ (double SHA-1)', ''],
  ];
  for (const [re, name, note] of prefixed) if (re.test(s)) add(name, note);
  if (out.length) return out;

  // hash:salt pairs, e.g. from older web apps
  const [main, salt] = s.split(':');
  const hex = /^[0-9a-f]+$/i.test(main) ? main : null;
  if (hex && salt !== undefined && s.split(':').length === 2) {
    const base = identifyHash(hex);
    return base.map((b) => ({ name: `${b.name} with salt`, note: 'hash:salt format.' }));
  }
  if (!hex || salt !== undefined) return out;

  switch (hex.length) {
    case 8: add('CRC32', 'A checksum, not a cryptographic hash.'); add('Adler-32'); break;
    case 16: add('MySQL 3.x (OLD_PASSWORD)'); add('Half of an LM hash'); break;
    case 32:
      add('MD5', 'Most common 32-character hash.');
      add('NTLM', 'Windows password hash (MD4 of the UTF-16LE password). Same length as MD5.');
      add('MD4');
      add('LM', 'Legacy Windows; uppercase hex, often AAD3B435B51404EE… when unused.');
      break;
    case 40: add('SHA-1'); add('RIPEMD-160'); break;
    case 56: add('SHA-224'); add('SHA3-224'); break;
    case 64: add('SHA-256'); add('SHA3-256'); add('BLAKE2s-256'); break;
    case 96: add('SHA-384'); add('SHA3-384'); break;
    case 128: add('SHA-512'); add('SHA3-512'); add('BLAKE2b-512'); add('Whirlpool'); break;
    default: break;
  }
  return out;
}

// ---------- CVE IDs ----------

// Any case, with the dash variants copy-paste produces (hyphen, non-breaking
// hyphen, en/em dash, minus sign), underscores or spaces. Same rule as CVE Explainer.
const CVE_LOOSE = /^CVE[\s\u2010-\u2015\u2212_-]*(\d{4})[\s\u2010-\u2015\u2212_-]*(\d{4,19})$/i;
export const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,19}$/;

/**
 * Normalises a CVE ID to CVE-YYYY-NNNN... Returns { value } or { error }, or
 * null when the input doesn't start like a CVE ID at all.
 */
export function normalizeCveId(input, now = new Date()) {
  const s = String(input).trim();
  if (!/^CVE[\s\u2010-\u2015\u2212_-]*\d/i.test(s)) return null;
  const m = CVE_LOOSE.exec(s);
  if (!m) return { error: 'CVE IDs look like CVE-2021-44228: a 4-digit year, then at least 4 digits.' };
  const year = Number(m[1]);
  const maxYear = now.getUTCFullYear() + 1;
  if (year < 1999 || year > maxYear) return { error: `CVE years run from 1999 to ${maxYear}; ${year} isn't valid.` };
  return { value: `CVE-${m[1]}-${m[2]}` };
}

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/** CVE keyword search rules, shared by the CVEs page and the Worker. Returns { keyword, severity } or { error }. */
export function validateCveSearch(q, severity) {
  const keyword = String(q ?? '').trim().replace(/\s+/g, ' ');
  if (keyword.length < 2 || keyword.length > 60) return { error: 'Search for 2 to 60 characters.' };
  if (!/^[A-Za-z0-9 ._-]+$/.test(keyword)) return { error: 'Use letters, digits, spaces, dots, dashes and underscores only.' };
  const sev = String(severity ?? '').trim().toUpperCase();
  if (sev && !SEVERITIES.includes(sev)) return { error: 'Severity must be Low, Medium, High or Critical.' };
  return { keyword, severity: sev || null };
}

// ---------- Top-level detection ----------

/**
 * Works out what kind of indicator was pasted.
 * Returns { type, value, label } on success, or { type, value, error } when the
 * input is recognisable but not something we will look up (private IPs etc.).
 * type is one of: cve, hash, ipv4, ipv6, domain, url, email, unknown, empty.
 */
export function detect(raw) {
  const s = refang(raw);
  if (!s) return { type: 'empty', value: '' };

  // Before the domain/hash rules: checked first so "CVE-2021-44228" is never a hostname.
  const cve = normalizeCveId(s);
  if (cve) return cve.error ? { type: 'cve', value: s, error: cve.error } : { type: 'cve', value: cve.value, label: 'CVE ID' };

  if (/^https?:\/\//i.test(s)) {
    let u;
    try {
      u = new URL(s);
    } catch {
      return { type: 'unknown', value: s, error: 'That looks like a URL but could not be parsed.' };
    }
    const hostCheck = detect(u.hostname);
    if (hostCheck.error) return { type: 'url', value: u.href, host: u.hostname, error: `The URL's host is not public. ${hostCheck.error}` };
    if (!['domain', 'ipv4', 'ipv6'].includes(hostCheck.type)) {
      return { type: 'unknown', value: s, error: 'The URL host is not a valid domain or IP address.' };
    }
    return { type: 'url', value: u.href, host: hostCheck.value, label: 'URL' };
  }

  if (/^[^\s@]+@[^\s@]+$/.test(s)) {
    const domain = checkDomain(s.split('@')[1]);
    if (domain && !domain.error) return { type: 'email', value: s.toLowerCase(), label: 'Email address' };
    return { type: 'unknown', value: s, error: 'That looks like an email address, but the domain part is not valid.' };
  }

  if (/^[0-9a-f]+$/i.test(s) && HEX_HASHES[s.length]) {
    return { type: 'hash', value: s.toLowerCase(), label: `${HEX_HASHES[s.length]} hash`, algorithm: HEX_HASHES[s.length] };
  }

  const v4 = parseIPv4(s);
  if (v4) {
    const reserved = ipv4Reserved(v4);
    const value = v4.join('.');
    return reserved
      ? { type: 'ipv4', value, error: `This is a ${reserved} address, so there is nothing public to look up.` }
      : { type: 'ipv4', value, label: 'IPv4 address' };
  }

  const v6 = parseIPv6(s);
  if (v6) {
    const reserved = ipv6Reserved(v6);
    const value = s.replace(/^\[|\]$/g, '').toLowerCase();
    return reserved
      ? { type: 'ipv6', value, error: `This is a ${reserved} address, so there is nothing public to look up.` }
      : { type: 'ipv6', value, label: 'IPv6 address' };
  }

  const domain = checkDomain(s);
  if (domain) {
    return domain.error
      ? { type: 'domain', value: domain.value, error: domain.error }
      : { type: 'domain', value: domain.value, label: 'Domain' };
  }

  if (/^[0-9a-f]{8,}$/i.test(s) || identifyHash(s).length) {
    return { type: 'unknown', value: s, error: 'Looks like a hash, but only MD5, SHA-1 and SHA-256 can be looked up. Try the hash identifier below.' };
  }
  return { type: 'unknown', value: s, error: 'Not recognised as a hash, IP, domain, URL or email. To check a password, use the password field.' };
}
