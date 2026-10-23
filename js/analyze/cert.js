// Certificate viewer (#cert). A minimal DER / X.509 parser written here (the
// CSP allows no CDN libraries). It reads certificates only: pasted text that
// contains a private key is refused, never parsed.

const OIDS = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
  '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC',
};
const SIG_ALGS = {
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption (broken)',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption (weak)',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1 (weak)',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
};
const CURVES = { '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521', '1.3.132.0.10': 'secp256k1' };
const MAX_INPUT = 1024 * 1024;

// ---------- DER reading ----------

/** Reads one tag-length-value at offset. Throws on anything malformed. */
function tlv(b, off) {
  if (off + 2 > b.length) throw new Error('truncated');
  const tag = b[off];
  let len = b[off + 1];
  let start = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('unsupported length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[start + i];
    start += n;
  }
  const end = start + len;
  if (end > b.length) throw new Error('length runs past the end');
  return { tag, start, end, len };
}

function children(b, node) {
  const out = [];
  for (let off = node.start; off < node.end;) {
    const c = tlv(b, off);
    out.push(c);
    off = c.end;
  }
  return out;
}

function oid(b, node) {
  const v = b.subarray(node.start, node.end);
  const parts = [Math.floor(v[0] / 40), v[0] % 40];
  let n = 0;
  for (let i = 1; i < v.length; i++) {
    n = n * 128 + (v[i] & 0x7f);
    if (!(v[i] & 0x80)) { parts.push(n); n = 0; }
  }
  return parts.join('.');
}

function str(b, node) {
  const v = b.subarray(node.start, node.end);
  if (node.tag === 0x1e) { // BMPString: UTF-16BE
    let s = '';
    for (let i = 0; i + 1 < v.length; i += 2) s += String.fromCharCode((v[i] << 8) | v[i + 1]);
    return s;
  }
  return new TextDecoder(node.tag === 0x0c ? 'utf-8' : 'latin1').decode(v);
}

function time(b, node) {
  const s = str(b, node);
  const m = node.tag === 0x17
    ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s)
    : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/.exec(s);
  if (!m) return null;
  let year = Number(m[1]);
  if (node.tag === 0x17) year += year >= 50 ? 1900 : 2000; // RFC 5280 UTCTime rule
  return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] || 0))).toISOString();
}

function name(b, node) {
  const parts = [];
  for (const set of children(b, node)) {
    for (const atv of children(b, set)) {
      const [type, value] = children(b, atv);
      const key = OIDS[oid(b, type)] || oid(b, type);
      parts.push([key, str(b, value)]);
    }
  }
  return parts;
}

const sameBytes = (b, x, y) => x.end - x.start === y.end - y.start && b.subarray(x.start, x.end).every((v, i) => v === b[y.start + i]);

function intBits(b, node) {
  let i = node.start;
  while (i < node.end && b[i] === 0) i++;
  if (i === node.end) return 0;
  return (node.end - i - 1) * 8 + (32 - Math.clz32(b[i]));
}

function publicKey(b, spki) {
  const [alg, bits] = children(b, spki);
  const [algOid, params] = children(b, alg);
  const id = oid(b, algOid);
  if (id === '1.2.840.113549.1.1.1') {
    // BIT STRING: one "unused bits" byte, then SEQUENCE { modulus, exponent }.
    const seq = tlv(b, bits.start + 1);
    const [modulus] = children(b, seq);
    return { type: 'RSA', bits: intBits(b, modulus) };
  }
  if (id === '1.2.840.10045.2.1') {
    const curve = params && params.tag === 0x06 ? CURVES[oid(b, params)] || oid(b, params) : 'unknown curve';
    const size = { 'P-256': 256, 'P-384': 384, 'P-521': 521, secp256k1: 256 }[curve] || null;
    return { type: `EC ${curve}`, bits: size };
  }
  if (id === '1.3.101.112') return { type: 'Ed25519', bits: 256 };
  if (id === '1.3.101.113') return { type: 'Ed448', bits: 456 };
  return { type: id, bits: null };
}

function sans(b, octet) {
  const out = [];
  const seq = tlv(b, octet.start);
  for (const g of children(b, seq)) {
    const v = b.subarray(g.start, g.end);
    if (g.tag === 0x82) out.push(`DNS:${new TextDecoder('latin1').decode(v)}`);
    else if (g.tag === 0x81) out.push(`email:${new TextDecoder('latin1').decode(v)}`);
    else if (g.tag === 0x86) out.push(`URI:${new TextDecoder('latin1').decode(v)}`);
    else if (g.tag === 0x87 && v.length === 4) out.push(`IP:${[...v].join('.')}`);
    else if (g.tag === 0x87 && v.length === 16) out.push(`IP:${[...Array(8)].map((_, i) => ((v[i * 2] << 8) | v[i * 2 + 1]).toString(16)).join(':')}`);
  }
  return out;
}

/** Parses one DER certificate. Returns the fields, or throws. */
export function parseCertificate(der, now = Date.now()) {
  const b = der instanceof Uint8Array ? der : new Uint8Array(der);
  const cert = tlv(b, 0);
  if (cert.tag !== 0x30 || cert.end !== b.length) throw new Error('not a single DER certificate');
  const [tbs, sigAlg] = children(b, cert);
  let fields = children(b, tbs);
  let version = 1;
  if (fields[0].tag === 0xa0) {
    version = b[tlv(b, fields[0].start).start] + 1;
    fields = fields.slice(1);
  }
  const [serial, , issuerN, validity, subjectN, spki, ...rest] = fields;
  const [nb, na] = children(b, validity);
  const notBefore = time(b, nb);
  const notAfter = time(b, na);

  let altNames = [];
  let isCA = false;
  const extsNode = rest.find((n) => n.tag === 0xa3);
  if (extsNode) {
    for (const ext of children(b, tlv(b, extsNode.start))) {
      const parts = children(b, ext);
      const id = oid(b, parts[0]);
      const value = parts[parts.length - 1]; // OCTET STRING (critical flag may sit between)
      if (id === '2.5.29.17') altNames = sans(b, value);
      if (id === '2.5.29.19') {
        const bc = children(b, tlv(b, value.start));
        isCA = Boolean(bc[0] && bc[0].tag === 0x01 && b[bc[0].start] !== 0);
      }
    }
  }
  const serialHex = [...b.subarray(serial.start, serial.end)].map((x) => x.toString(16).padStart(2, '0')).join(':');
  const sigId = oid(b, children(b, sigAlg)[0]);
  return {
    version,
    serial: serialHex,
    subject: name(b, subjectN),
    issuer: name(b, issuerN),
    selfSigned: sameBytes(b, subjectN, issuerN),
    notBefore,
    notAfter,
    expired: Boolean(notAfter && Date.parse(notAfter) < now),
    notYetValid: Boolean(notBefore && Date.parse(notBefore) > now),
    key: publicKey(b, spki),
    signatureAlgorithm: SIG_ALGS[sigId] || sigId,
    sans: altNames,
    isCA,
  };
}

/**
 * Splits pasted text or file bytes into DER certificates. Returns { ders } or
 * { error }. Anything containing a private key is refused outright.
 */
export function readCertificates(input) {
  if (typeof input === 'string') {
    if (input.length > MAX_INPUT) return { error: 'That is more than 1 MB; paste one certificate or a short chain.' };
    if (/PRIVATE KEY/.test(input)) return { privateKey: true };
    const blocks = [...input.matchAll(/-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----([\s\S]*?)-----END (?:X509 |TRUSTED )?CERTIFICATE-----/g)];
    if (!blocks.length) return { error: 'No "-----BEGIN CERTIFICATE-----" block found. Paste a PEM certificate or drop a .cer/.crt/.der file.' };
    try {
      return { ders: blocks.slice(0, 10).map((m) => Uint8Array.from(atob(m[1].replace(/\s+/g, '')), (c) => c.charCodeAt(0))) };
    } catch {
      return { error: 'The certificate block is not valid Base64.' };
    }
  }
  const bytes = new Uint8Array(input);
  if (bytes.length > MAX_INPUT) return { error: 'That file is more than 1 MB.' };
  const head = new TextDecoder('latin1').decode(bytes.subarray(0, Math.min(bytes.length, MAX_INPUT)));
  if (head.includes('-----BEGIN')) return readCertificates(head); // a PEM saved as .crt
  return { ders: [bytes] };
}

export async function sha256Fingerprint(der) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', der));
  return [...h].map((x) => x.toString(16).padStart(2, '0')).join('');
}

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('cert-form')) {
  const { el, $, notice, rows } = await import('./ui.js');
  const dn = (parts) => parts.map(([k, v]) => `${k}=${v}`).join(', ') || '(empty)';
  const date = (iso) => (iso ? new Date(iso).toUTCString() : '—');

  const show = async (input) => {
    const out = $('cert-result');
    const r = readCertificates(input);
    if (r.privateKey) {
      out.replaceChildren(notice('bad', el('strong', {}, 'That contains a PRIVATE KEY, so it was not read. '),
        'If it is a real key, treat it as exposed: anyone who has seen it can impersonate the server. Replace the key and have the certificate reissued, and paste only the certificate here.'));
      $('cert-input').value = '';
      return;
    }
    if (r.error) { out.replaceChildren(notice('warn', r.error)); return; }
    const cards = [];
    for (const [i, der] of r.ders.entries()) {
      let c;
      try {
        c = parseCertificate(der);
      } catch (err) {
        cards.push(notice('warn', `Certificate ${i + 1} could not be parsed (${err.message}).`));
        continue;
      }
      const fp = await sha256Fingerprint(der);
      const flags = [
        c.expired ? el('span', { class: 'flag bad' }, 'Expired') : null,
        c.notYetValid ? el('span', { class: 'flag warn' }, 'Not yet valid') : null,
        !c.expired && !c.notYetValid ? el('span', { class: 'flag ok' }, 'In date') : null,
        c.selfSigned ? el('span', { class: 'flag warn' }, 'Self-signed') : null,
        c.isCA ? el('span', { class: 'flag muted' }, 'CA certificate') : null,
        /weak|broken/.test(c.signatureAlgorithm) ? el('span', { class: 'flag bad' }, 'Weak signature') : null,
      ];
      cards.push(el('article', { class: 'card' },
        el('header', {}, el('h3', {}, r.ders.length > 1 ? `Certificate ${i + 1}` : 'Certificate'), el('span', { class: 'ref-meta' }, ...flags)),
        rows([
          ['Subject', el('span', { class: 'mono' }, dn(c.subject))],
          ['Issuer', el('span', { class: 'mono' }, dn(c.issuer))],
          ['Valid from', date(c.notBefore)],
          ['Valid until', date(c.notAfter)],
          ['Alternative names', c.sans.length ? el('span', { class: 'mono' }, c.sans.join(', ')) : 'none'],
          ['Key', `${c.key.type}${c.key.bits ? `, ${c.key.bits} bits` : ''}`],
          ['Signature', c.signatureAlgorithm],
          ['Serial', el('span', { class: 'mono' }, c.serial)],
          ['SHA-256', el('span', { class: 'mono' }, fp)],
        ]),
        el('p', { class: 'hint' }, el('a', { href: `https://crt.sh/?q=${fp}`, target: '_blank', rel: 'noopener noreferrer' }, 'Find it in certificate-transparency logs (crt.sh) →'))));
    }
    out.replaceChildren(el('div', { class: 'cards' }, ...cards));
  };

  $('cert-form').addEventListener('submit', (ev) => { ev.preventDefault(); show($('cert-input').value); });
  $('cert-file').addEventListener('change', async (ev) => {
    const f = ev.target.files[0];
    if (f) show(await f.arrayBuffer());
  });
  const drop = $('cert-drop');
  drop.addEventListener('dragover', (ev) => { ev.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  const { receiveHandoff } = await import('./handoff.js');
  receiveHandoff('cert', show);
  drop.addEventListener('drop', async (ev) => {
    ev.preventDefault();
    drop.classList.remove('over');
    const f = ev.dataTransfer.files[0];
    if (f) show(await f.arrayBuffer());
  });
}
