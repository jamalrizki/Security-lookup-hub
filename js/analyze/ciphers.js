// Cipher suite decoder (#ciphers). Paste suite names (IANA "TLS_…" or OpenSSL
// "ECDHE-RSA-…"), hex codes, a colon-separated OpenSSL string or Nmap
// ssl-enum-ciphers output. Each name is split into its parts and graded in
// code: no model, nothing sent. Only names in the IANA registry copy
// (data/cipher-suites.json) are graded, so a typo is "not recognized", never a
// guess.

export const MAX_INPUT = 64 * 1024;
export const MAX_SUITES = 200;

export const SOURCES = {
  rfc9325: { label: 'RFC 9325: TLS recommendations (IETF, 2022)', url: 'https://www.rfc-editor.org/rfc/rfc9325' },
  rfc10015: { label: 'RFC 10015: obsolete key exchanges in TLS 1.2 (IETF, 2026)', url: 'https://www.rfc-editor.org/rfc/rfc10015' },
  rfc7465: { label: 'RFC 7465: RC4 prohibited in TLS', url: 'https://www.rfc-editor.org/rfc/rfc7465' },
  iana: { label: 'IANA TLS cipher suite registry', url: 'https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml' },
  nist: { label: 'NIST SP 800-52 Rev. 2: TLS guidelines', url: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final' },
};

/** Every reason a grade can give. The text is the hub's own words. */
export const REASONS = {
  'null-cipher': { grade: 'insecure', text: 'No encryption: anyone on the path can read the traffic.', source: 'rfc9325' },
  'integrity-only': { grade: 'insecure', text: 'Integrity only, no encryption (meant for a few industrial uses, never for websites).', source: 'iana' },
  anon: { grade: 'insecure', text: 'No server authentication: anyone in the middle can pretend to be the server.', source: 'rfc9325' },
  export: { grade: 'insecure', text: 'Export-grade: crypto weakened on purpose in the 1990s, broken by attacks such as FREAK and Logjam.', source: 'rfc9325' },
  rc4: { grade: 'insecure', text: 'RC4 has known biases that leak data; TLS forbids it.', source: 'rfc7465' },
  'tiny-key': { grade: 'insecure', text: 'A 56-bit or shorter key can be brute-forced.', source: 'rfc9325' },
  '64bit-block': { grade: 'insecure', text: '64-bit block cipher: the Sweet32 attack recovers data from long connections.', source: 'rfc9325' },
  md5: { grade: 'insecure', text: 'MD5 is a broken hash; only obsolete suites use it.', source: 'rfc9325' },
  rsa: { grade: 'weak', text: 'RSA key exchange: no forward secrecy, so a stolen server key decrypts recorded traffic. TLS 1.2 must no longer use it.', source: 'rfc10015' },
  'rsa-psk': { grade: 'weak', text: 'RSA key transport: no forward secrecy, so a stolen server key decrypts recorded traffic.', source: 'iana' },
  'static-dh': { grade: 'weak', text: 'Static Diffie-Hellman: no forward secrecy. TLS 1.2 must no longer use it.', source: 'rfc10015' },
  'static-ecdh': { grade: 'weak', text: 'Static ECDH: no forward secrecy. TLS 1.2 should no longer use it.', source: 'rfc10015' },
  dhe: { grade: 'weak', text: 'Finite-field DHE: TLS 1.2 must no longer use it (2026). Use ECDHE instead.', source: 'rfc10015' },
  psk: { grade: 'weak', text: 'Pre-shared key with no ephemeral exchange: no forward secrecy.', source: 'rfc9325' },
  cbc: { grade: 'weak', text: 'CBC mode: the older design behind padding-oracle attacks such as Lucky13. Prefer GCM or ChaCha20-Poly1305.', source: 'rfc9325' },
  ccm8: { grade: 'weak', text: 'Short 8-byte integrity tag; not recommended for general use.', source: 'iana' },
  'iana-discouraged': { grade: 'weak', text: 'The IANA registry marks this suite as discouraged.', source: 'iana' },
};

export const GRADE_TEXT = {
  insecure: 'Insecure',
  weak: 'Weak',
  ok: 'OK',
  signal: 'Not a cipher',
  'not-graded': 'Not graded',
  unknown: 'Not recognized',
};

export const REC_TEXT = { Y: 'Recommended', N: 'Not recommended', D: 'Discouraged' };

// Key exchange part of a TLS 1.2-and-earlier IANA name (before _WITH_).
const KX = {
  RSA: { kx: 'RSA key transport', auth: 'RSA', fs: false, family: 'rsa' },
  DH_RSA: { kx: 'Static DH', auth: 'RSA', fs: false, family: 'static-dh' },
  DH_DSS: { kx: 'Static DH', auth: 'DSA', fs: false, family: 'static-dh' },
  DHE_RSA: { kx: 'DHE (ephemeral)', auth: 'RSA', fs: true, family: 'dhe' },
  DHE_DSS: { kx: 'DHE (ephemeral)', auth: 'DSA', fs: true, family: 'dhe' },
  DH_ANON: { kx: 'DH (anonymous)', auth: 'None', fs: true, family: 'anon' },
  ECDH_RSA: { kx: 'Static ECDH', auth: 'RSA', fs: false, family: 'static-ecdh' },
  ECDH_ECDSA: { kx: 'Static ECDH', auth: 'ECDSA', fs: false, family: 'static-ecdh' },
  ECDHE_RSA: { kx: 'ECDHE (ephemeral)', auth: 'RSA', fs: true, family: 'ecdhe' },
  ECDHE_ECDSA: { kx: 'ECDHE (ephemeral)', auth: 'ECDSA', fs: true, family: 'ecdhe' },
  ECDH_ANON: { kx: 'ECDH (anonymous)', auth: 'None', fs: true, family: 'anon' },
  PSK: { kx: 'Pre-shared key', auth: 'Pre-shared key', fs: false, family: 'psk' },
  DHE_PSK: { kx: 'DHE + pre-shared key', auth: 'Pre-shared key', fs: true, family: 'dhe' },
  PSK_DHE: { kx: 'DHE + pre-shared key', auth: 'Pre-shared key', fs: true, family: 'dhe' },
  ECDHE_PSK: { kx: 'ECDHE + pre-shared key', auth: 'Pre-shared key', fs: true, family: 'ecdhe' },
  RSA_PSK: { kx: 'RSA + pre-shared key', auth: 'Pre-shared key and RSA', fs: false, family: 'rsa-psk' },
  NULL: { kx: 'None', auth: 'None', fs: false, family: 'anon' },
};

// Bulk cipher part (after _WITH_), longest names first when matching.
const CIPHERS = {
  NULL: { cipher: 'None', mode: '—', family: 'null' },
  RC4_40: { cipher: 'RC4, 40-bit', mode: 'Stream', family: 'rc4' },
  RC4_128: { cipher: 'RC4, 128-bit', mode: 'Stream', family: 'rc4' },
  RC2_CBC_40: { cipher: 'RC2, 40-bit', mode: 'CBC', family: 'tiny-key' },
  DES40_CBC: { cipher: 'DES, 40-bit', mode: 'CBC', family: 'tiny-key' },
  DES_CBC_40: { cipher: 'DES, 40-bit', mode: 'CBC', family: 'tiny-key' },
  DES_CBC: { cipher: 'DES, 56-bit', mode: 'CBC', family: 'tiny-key' },
  '3DES_EDE_CBC': { cipher: 'Triple DES', mode: 'CBC', family: '64bit-block' },
  IDEA_CBC: { cipher: 'IDEA', mode: 'CBC', family: '64bit-block' },
  SEED_CBC: { cipher: 'SEED', mode: 'CBC', family: 'cbc' },
  CHACHA20_POLY1305: { cipher: 'ChaCha20', mode: 'Poly1305 (AEAD)', family: 'aead' },
};
for (const name of ['AES', 'CAMELLIA', 'ARIA']) {
  const label = name === 'AES' ? 'AES' : name[0] + name.slice(1).toLowerCase();
  for (const bits of ['128', '256']) {
    CIPHERS[`${name}_${bits}_CBC`] = { cipher: `${label}-${bits}`, mode: 'CBC', family: 'cbc' };
    CIPHERS[`${name}_${bits}_GCM`] = { cipher: `${label}-${bits}`, mode: 'GCM (AEAD)', family: 'aead' };
  }
}
for (const bits of ['128', '256']) {
  CIPHERS[`AES_${bits}_CCM`] = { cipher: `AES-${bits}`, mode: 'CCM (AEAD)', family: 'aead' };
  CIPHERS[`AES_${bits}_CCM_8`] = { cipher: `AES-${bits}`, mode: 'CCM, 8-byte tag (AEAD)', family: 'ccm8' };
}
const CIPHER_KEYS = Object.keys(CIPHERS).sort((a, b) => b.length - a.length);

const MACS = { SHA: 'HMAC-SHA1', SHA256: 'HMAC-SHA256', SHA384: 'HMAC-SHA384', MD5: 'HMAC-MD5', NULL: 'None' };

const TLS13 = {
  TLS_AES_128_GCM_SHA256: 'AES_128_GCM',
  TLS_AES_256_GCM_SHA384: 'AES_256_GCM',
  TLS_CHACHA20_POLY1305_SHA256: 'CHACHA20_POLY1305',
  TLS_AES_128_CCM_SHA256: 'AES_128_CCM',
  TLS_AES_128_CCM_8_SHA256: 'AES_128_CCM_8',
};
const INTEGRITY_ONLY = new Set(['TLS_SHA256_SHA256', 'TLS_SHA384_SHA384']);
const SIGNALS = new Set(['TLS_EMPTY_RENEGOTIATION_INFO_SCSV', 'TLS_FALLBACK_SCSV']);

/** Builds lookups from data/cipher-suites.json: by upper-case name and by 4-digit hex code. */
export function buildRegistry(data) {
  const byName = new Map();
  const byCode = new Map();
  for (const s of data?.suites || []) {
    byName.set(s.name.toUpperCase(), s);
    byCode.set(s.code.replace(/0x|,/gi, '').toUpperCase(), s);
  }
  return { byName, byCode };
}

/**
 * Splits an IANA name into its parts. Returns null for names this decoder
 * doesn't model (Kerberos, SRP, GOST, SM4, ECCPWD, Ascon, AEGIS…).
 */
export function partsOf(ianaName) {
  const name = String(ianaName).toUpperCase();
  if (SIGNALS.has(name)) return { signal: true };
  if (INTEGRITY_ONLY.has(name)) {
    return { version: 'TLS 1.3', kx: 'Chosen separately', auth: 'From the certificate', fs: true, kxFamily: 'tls13', cipher: 'None', mode: '—', cipherFamily: 'integrity-only', mac: `HMAC-${name.slice(4, 10)}` };
  }
  if (TLS13[name]) {
    const c = CIPHERS[TLS13[name]];
    return { version: 'TLS 1.3', kx: 'Chosen separately (always ephemeral)', auth: 'From the certificate', fs: true, kxFamily: 'tls13', cipher: c.cipher, mode: c.mode, cipherFamily: c.family, mac: 'Built into the cipher (AEAD)' };
  }
  const m = /^TLS_([A-Z0-9_]+?)(_EXPORT)?_WITH_([A-Z0-9_]+)$/.exec(name);
  if (!m) return null;
  const kx = KX[m[1]];
  if (!kx) return null;
  const right = m[3];
  const key = CIPHER_KEYS.find((k) => right === k || right.startsWith(`${k}_`));
  if (!key) return null;
  const macKey = right.slice(key.length + 1);
  const c = CIPHERS[key];
  const aead = c.family === 'aead' || c.family === 'ccm8';
  if (macKey && !MACS[macKey]) return null;
  return {
    version: 'TLS 1.2 or earlier',
    kx: kx.kx,
    auth: kx.auth,
    fs: kx.fs,
    kxFamily: kx.family,
    export: Boolean(m[2]),
    cipher: c.cipher,
    mode: c.mode,
    cipherFamily: c.family,
    mac: aead ? 'Built into the cipher (AEAD)' : MACS[macKey] || 'None',
    macFamily: macKey === 'MD5' ? 'md5' : null,
  };
}

/** Grade and reasons for a registry suite, decided in code from its parts. */
export function gradeSuite(suite) {
  const parts = partsOf(suite.name);
  if (!parts) {
    // A family this decoder doesn't model: IANA's own "discouraged" still counts.
    return suite.rec === 'D'
      ? { grade: 'weak', parts: null, reasons: [{ id: 'iana-discouraged', ...REASONS['iana-discouraged'] }] }
      : { grade: 'not-graded', parts: null, reasons: [] };
  }
  if (parts.signal) return { grade: 'signal', parts: null, reasons: [] };
  const ids = [];
  if (parts.cipherFamily === 'integrity-only') ids.push('integrity-only');
  if (parts.cipherFamily === 'null') ids.push('null-cipher');
  if (parts.kxFamily === 'anon') ids.push('anon');
  if (parts.export) ids.push('export');
  if (['rc4', 'tiny-key', '64bit-block'].includes(parts.cipherFamily)) ids.push(parts.cipherFamily);
  if (parts.macFamily === 'md5') ids.push('md5');
  if (['rsa', 'rsa-psk', 'static-dh', 'static-ecdh', 'dhe', 'psk'].includes(parts.kxFamily)) ids.push(parts.kxFamily);
  if (parts.mode === 'CBC' && !ids.includes('tiny-key') && !ids.includes('64bit-block')) ids.push('cbc');
  if (parts.cipherFamily === 'ccm8') ids.push('ccm8');
  let grade = ids.some((id) => REASONS[id].grade === 'insecure') ? 'insecure' : ids.length ? 'weak' : 'ok';
  if (grade === 'ok' && suite.rec === 'D') {
    ids.push('iana-discouraged');
    grade = 'weak';
  }
  return { grade, parts, reasons: ids.map((id) => ({ id, ...REASONS[id] })) };
}

// OpenSSL names → IANA names. Key exchange prefixes, longest first.
const OSSL_KX = [
  ['ECDHE-ECDSA', 'ECDHE_ECDSA'], ['ECDHE-RSA', 'ECDHE_RSA'], ['ECDHE-PSK', 'ECDHE_PSK'],
  ['ECDH-ECDSA', 'ECDH_ECDSA'], ['ECDH-RSA', 'ECDH_RSA'],
  ['EDH-RSA', 'DHE_RSA'], ['EDH-DSS', 'DHE_DSS'], ['DHE-RSA', 'DHE_RSA'], ['DHE-DSS', 'DHE_DSS'], ['DHE-PSK', 'DHE_PSK'],
  ['DH-RSA', 'DH_RSA'], ['DH-DSS', 'DH_DSS'], ['RSA-PSK', 'RSA_PSK'],
  ['AECDH', 'ECDH_anon'], ['ADH', 'DH_anon'], ['PSK', 'PSK'],
  ['ECDHE', 'ECDHE_RSA'], // OpenSSL's ARIA names: ECDHE-ARIA128-GCM-SHA256
];
const OSSL_CIPHERS = [
  ['CHACHA20-POLY1305', 'CHACHA20_POLY1305'],
  ['AES128-CCM8', 'AES_128_CCM_8'], ['AES256-CCM8', 'AES_256_CCM_8'],
  ['AES128-CCM', 'AES_128_CCM'], ['AES256-CCM', 'AES_256_CCM'],
  ['AES128-GCM', 'AES_128_GCM'], ['AES256-GCM', 'AES_256_GCM'],
  ['AES128-CBC', 'AES_128_CBC'], ['AES256-CBC', 'AES_256_CBC'],
  ['ARIA128-GCM', 'ARIA_128_GCM'], ['ARIA256-GCM', 'ARIA_256_GCM'],
  ['3DES-EDE-CBC', '3DES_EDE_CBC'], ['DES-CBC3', '3DES_EDE_CBC'],
  ['CAMELLIA128', 'CAMELLIA_128_CBC'], ['CAMELLIA256', 'CAMELLIA_256_CBC'],
  ['AES128', 'AES_128_CBC'], ['AES256', 'AES_256_CBC'],
  ['IDEA-CBC', 'IDEA_CBC'], ['RC2-CBC', 'RC2_CBC_40'], ['DES-CBC', 'DES_CBC'],
  ['SEED', 'SEED_CBC'], ['RC4', 'RC4_128'], ['NULL', 'NULL'],
];
const EXPORT_CIPHER = { DES_CBC: 'DES40_CBC', RC4_128: 'RC4_40', RC2_CBC_40: 'RC2_CBC_40' };

/** The IANA name an OpenSSL name stands for, or null. Checked against the registry by the caller. */
export function opensslToIana(name) {
  let rest = String(name).toUpperCase();
  let exp = false;
  if (rest.startsWith('EXP-')) {
    exp = true;
    rest = rest.slice(4);
  }
  let kx = 'RSA';
  const pre = OSSL_KX.find(([p]) => rest.startsWith(`${p}-`));
  if (pre) {
    kx = pre[1];
    rest = rest.slice(pre[0].length + 1);
  }
  const c = OSSL_CIPHERS.find(([p]) => rest === p || rest.startsWith(`${p}-`));
  if (!c) return null;
  let cipher = c[1];
  if (exp) {
    if (!EXPORT_CIPHER[cipher]) return null;
    cipher = EXPORT_CIPHER[cipher];
  } else if (cipher === 'RC2_CBC_40') return null;
  let mac = rest.slice(c[0].length + 1);
  if (cipher === 'CHACHA20_POLY1305' && !mac) mac = 'SHA256';
  if (mac && !MACS[mac]) return null;
  return `TLS_${kx}${exp ? '_EXPORT' : ''}_WITH_${cipher}${mac ? `_${mac}` : ''}`;
}

const OSSL_HINT = /(AES|CHACHA20|DES|RC4|RC2|NULL|CAMELLIA|ARIA|SEED|IDEA)/;

/** Pulls suite-like tokens out of pasted text: IANA/Java names, OpenSSL names, hex codes. */
export function tokensOf(input) {
  const text = String(input).slice(0, MAX_INPUT).replace(/0x([0-9a-f]{2})\s*,\s*0x([0-9a-f]{2})/gi, '0x$1$2');
  const out = [];
  const seen = new Set();
  for (let raw of text.split(/[\s,:;|]+/)) {
    raw = raw.replace(/^[("'[{<]+|[)"'\]}>.]+$/g, '');
    const up = raw.toUpperCase();
    let kind = null;
    if (/^(TLS|SSL)_[A-Z0-9_]+$/.test(up)) kind = 'iana';
    else if (/^0X[0-9A-F]{4}$/.test(up)) kind = 'code';
    else if (/^[A-Z0-9]+(-[A-Z0-9]+)+$/.test(up) && OSSL_HINT.test(up)) kind = 'openssl';
    if (!kind || seen.has(up)) continue;
    seen.add(up);
    out.push({ input: raw, kind });
    if (out.length >= MAX_SUITES) break;
  }
  return out;
}

/** Decodes one token against the registry. */
export function decodeOne({ input, kind }, registry) {
  const up = input.toUpperCase();
  let suite = null;
  if (kind === 'code') suite = registry.byCode.get(up.slice(2)) || null;
  else if (kind === 'iana') suite = registry.byName.get(up.replace(/^SSL_/, 'TLS_')) || null;
  else {
    suite = registry.byName.get(up) || null; // TLS 1.3 names look the same in OpenSSL
    const iana = suite ? null : opensslToIana(up);
    if (iana) suite = registry.byName.get(iana.toUpperCase()) || registry.byName.get(iana.toUpperCase().replace('TLS_DHE_PSK_', 'TLS_PSK_DHE_')) || null;
  }
  if (!suite) return { input, kind, suite: null, grade: 'unknown', parts: null, reasons: [] };
  return { input, kind, suite, ...gradeSuite(suite) };
}

const ORDER = ['insecure', 'weak', 'ok', 'signal', 'not-graded', 'unknown'];

/** Decodes pasted text. Returns { results (worst first), counts, turnOff, truncated } or { error }. */
export function decodeSuites(input, registry) {
  const text = String(input ?? '');
  if (!text.trim()) return { error: 'Paste one or more cipher suite names.' };
  const tokens = tokensOf(text);
  if (!tokens.length) return { error: 'No cipher suite names found. Try a name like TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 or ECDHE-RSA-AES128-GCM-SHA256.' };
  const results = tokens.map((t) => decodeOne(t, registry))
    .map((r, i) => ({ ...r, i }))
    .sort((a, b) => ORDER.indexOf(a.grade) - ORDER.indexOf(b.grade) || a.i - b.i)
    .map(({ i, ...r }) => r);
  const counts = Object.fromEntries(ORDER.map((g) => [g, results.filter((r) => r.grade === g).length]));
  const turnOff = results.filter((r) => r.grade === 'insecure' || r.grade === 'weak').map((r) => r.suite.name);
  return { results, counts, turnOff, truncated: tokens.length >= MAX_SUITES || text.length > MAX_INPUT };
}

export const EXAMPLE = [
  'TLS_AES_128_GCM_SHA256',
  'ECDHE-RSA-AES128-GCM-SHA256',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
  'TLS_RSA_WITH_AES_128_GCM_SHA256',
  'DHE-RSA-AES256-GCM-SHA384',
  'DES-CBC3-SHA',
  'TLS_RSA_WITH_RC4_128_SHA',
  '0xC02C',
].join('\n');

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('ciphers-form')) {
  const { el, $, notice, copyButton, rows } = await import('./ui.js');
  const KIND = { insecure: 'bad', weak: 'warn', ok: 'ok', signal: 'muted', 'not-graded': 'muted', unknown: 'muted' };
  let registry = null;
  const loading = fetch('data/cipher-suites.json')
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
    .then((data) => { registry = buildRegistry(data); })
    .catch(() => { registry = null; });

  const why = (r) => {
    if (r.grade === 'unknown') return el('p', {}, 'Not in the IANA registry. Check the spelling: the hub does not guess.');
    if (r.grade === 'signal') return el('p', {}, 'A signal clients send, not a real cipher. Normal to see in a list.');
    if (r.grade === 'not-graded') return el('p', {}, 'A rare family the hub does not grade. IANA\'s status is shown.');
    if (!r.reasons.length) return el('p', {}, 'Forward secrecy and an AEAD cipher: nothing to fix.');
    return el('ul', { class: 'plain-list' }, ...r.reasons.map((x) => el('li', {}, x.text)));
  };
  const item = (r) => el('details', { class: 'ioc-group', open: r.grade === 'insecure' || r.grade === 'weak' },
    el('summary', {}, el('code', {}, r.suite ? r.suite.name : r.input), ' ', el('span', { class: `flag ${KIND[r.grade]}` }, GRADE_TEXT[r.grade])),
    why(r),
    r.suite ? rows([
      r.kind !== 'iana' ? ['You pasted', r.input] : null,
      r.parts ? ['Key exchange', r.parts.kx] : null,
      r.parts ? ['Authentication', r.parts.auth] : null,
      r.parts ? ['Cipher', r.parts.cipher] : null,
      r.parts ? ['Mode', r.parts.mode] : null,
      r.parts ? ['Integrity', r.parts.mac] : null,
      ['IANA status', REC_TEXT[r.suite.rec]],
      ['Code', r.suite.code],
    ]) : null,
  );

  const show = async () => {
    const out = $('ciphers-result');
    const raw = $('ciphers-input').value;
    if (!raw.trim()) { out.replaceChildren(); return; }
    await loading;
    if (!registry) { out.replaceChildren(notice('warn', 'The cipher suite list did not load. Reload the page and try again.')); return; }
    const r = decodeSuites(raw, registry);
    if (r.error) { out.replaceChildren(notice('warn', r.error)); return; }
    const c = r.counts;
    const summary = [
      c.insecure && `${c.insecure} insecure`, c.weak && `${c.weak} weak`, c.ok && `${c.ok} OK`,
      c.signal && `${c.signal} signal`, c['not-graded'] && `${c['not-graded']} not graded`, c.unknown && `${c.unknown} not recognized`,
    ].filter(Boolean).join(' · ');
    const used = new Set(r.results.flatMap((x) => x.reasons.map((y) => y.source)));
    out.replaceChildren(...[
      el('p', { class: `notice ${c.insecure ? 'bad' : c.weak || !c.ok ? 'warn' : 'ok'}` }, el('strong', {}, summary), r.turnOff.length ? ` Turn off the ${r.turnOff.length} insecure or weak suite${r.turnOff.length === 1 ? '' : 's'} if your clients don't need them.` : ''),
      r.truncated ? notice('warn', `Only the first ${MAX_SUITES} names were read.`) : null,
      r.turnOff.length ? el('div', { class: 'row' }, copyButton(() => r.turnOff.join('\n'), 'Copy the turn-off list')) : null,
      ...r.results.map(item),
      used.size ? el('p', { class: 'hint' }, 'Rules from: ', ...[...used].flatMap((k, i) => [i ? ' · ' : '', el('a', { href: SOURCES[k].url, target: '_blank', rel: 'noopener noreferrer' }, SOURCES[k].label)])) : null,
    ].filter(Boolean)); // a real DOM prints a null child as the text "null"
  };
  $('ciphers-form').addEventListener('submit', (ev) => { ev.preventDefault(); show(); });
  $('ciphers-example').addEventListener('click', () => { $('ciphers-input').value = EXAMPLE; show(); });
  $('ciphers-clear').addEventListener('click', () => { $('ciphers-input').value = ''; $('ciphers-result').replaceChildren(); });
}
