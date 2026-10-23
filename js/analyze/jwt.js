// JWT decoder (#jwt). Decodes header and payload locally. It never verifies
// the signature and never sends the token anywhere.

const MAX_TOKEN = 64 * 1024;

function b64urlJson(part) {
  let s = part.replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error('not Base64url');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0)));
  return JSON.parse(text);
}

const TIME_CLAIMS = { exp: 'Expires', nbf: 'Not valid before', iat: 'Issued' };

/** Returns { header, payload, signatureLength, warnings, times } or { error }. */
export function decodeJwt(input, now = Date.now()) {
  const token = String(input).trim().replace(/^Bearer\s+/i, '');
  if (!token) return { error: 'Paste a token.' };
  if (token.length > MAX_TOKEN) return { error: 'That is too long to be a normal token (64 KB limit).' };
  const parts = token.split('.');
  if (parts.length === 5) return { error: 'This is an encrypted token (JWE, five parts). Its payload can only be read with the key.' };
  if (parts.length !== 3) return { error: `A JWT has three parts separated by dots; this has ${parts.length}.` };
  let header;
  let payload;
  try {
    header = b64urlJson(parts[0]);
  } catch {
    return { error: 'The header (first part) is not Base64url-encoded JSON.' };
  }
  try {
    payload = b64urlJson(parts[1]);
  } catch {
    return { error: 'The payload (second part) is not Base64url-encoded JSON.' };
  }
  if (typeof header !== 'object' || header === null || Array.isArray(header)) return { error: 'The header is not a JSON object.' };

  const warnings = [];
  const alg = String(header.alg ?? '');
  if (!alg || alg.toLowerCase() === 'none') warnings.push('alg is "none": this token is unsigned, and anyone can change it. A server that accepts it is vulnerable.');
  if (alg.toLowerCase() === 'none' && parts[2]) warnings.push('It also carries a signature, which "none" says to ignore.');
  if (alg && alg.toLowerCase() !== 'none' && !parts[2]) warnings.push(`alg is ${alg} but the signature part is empty.`);
  if (header.jku || header.x5u) warnings.push('The header points to a key URL (jku/x5u). Servers must not fetch keys from URLs a token chooses.');

  const times = [];
  if (payload && typeof payload === 'object') {
    for (const [claim, label] of Object.entries(TIME_CLAIMS)) {
      const v = payload[claim];
      if (v === undefined) continue;
      if (typeof v !== 'number' || !Number.isFinite(v)) {
        times.push({ claim, label, value: v, status: 'not a number' });
        continue;
      }
      const ms = v * 1000;
      const date = Number.isFinite(new Date(ms).getTime()) ? new Date(ms).toISOString() : null;
      let status = null;
      if (claim === 'exp') status = ms < now ? 'expired' : 'not expired';
      if (claim === 'nbf') status = ms > now ? 'not yet valid' : 'valid';
      if (claim === 'iat' && ms > now + 60000) status = 'in the future';
      times.push({ claim, label, value: v, date, status });
    }
  }
  return { header, payload, signatureLength: parts[2].length, warnings, times };
}

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('jwt-form')) {
  const { el, $, notice, rows } = await import('./ui.js');
  const KIND = { expired: 'bad', 'not yet valid': 'warn', 'in the future': 'warn', 'not a number': 'warn', 'not expired': 'ok', valid: 'ok' };
  const show = () => {
    const out = $('jwt-result');
    const raw = $('jwt-input').value;
    if (!raw.trim()) { out.replaceChildren(); return; }
    const r = decodeJwt(raw);
    if (r.error) { out.replaceChildren(notice('warn', r.error)); return; }
    out.replaceChildren(
      el('p', { class: 'notice warn' }, el('strong', {}, 'Decoded, not verified.'), ' The signature is not checked, so nothing here proves who issued the token.'),
      ...r.warnings.map((w) => notice('bad', w)),
      r.times.length ? rows(r.times.map((t) => [
        `${t.label} (${t.claim})`,
        el('span', {}, t.date ? new Date(t.date).toUTCString() : String(t.value), t.status ? el('span', { class: `flag ${KIND[t.status] || 'muted'}` }, t.status) : null),
      ])) : null,
      el('h3', {}, 'Header'),
      el('pre', { class: 'json' }, JSON.stringify(r.header, null, 2)),
      el('h3', {}, 'Payload'),
      el('pre', { class: 'json' }, JSON.stringify(r.payload, null, 2)),
      el('p', { class: 'hint' }, `Signature: ${r.signatureLength} characters (not shown or checked).`),
    );
  };
  $('jwt-form').addEventListener('submit', (ev) => { ev.preventDefault(); show(); });
  $('jwt-input').addEventListener('input', show);
  const { receiveHandoff } = await import('./handoff.js');
  receiveHandoff('jwt', show);
}
