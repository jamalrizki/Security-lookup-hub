// Cipher suite decoder (Analyze #ciphers): names split into parts and graded in
// code, only names in the IANA registry copy (data/cipher-suites.json) accepted,
// nothing sent anywhere.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { installDom, settle } from './helpers/dom.mjs';
import {
  buildRegistry, partsOf, gradeSuite, opensslToIana, tokensOf, decodeOne, decodeSuites,
  REASONS, SOURCES, GRADE_TEXT, REC_TEXT, EXAMPLE, MAX_SUITES, MAX_INPUT,
} from '../js/analyze/ciphers.js';

const root = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, root), 'utf8');
const DATA = JSON.parse(read('data/cipher-suites.json'));
const reg = buildRegistry(DATA);
const grade = (name) => decodeSuites(name, reg).results[0];
const ids = (r) => r.reasons.map((x) => x.id).sort();

test('the registry copy has the right shape: unique names and codes, Y/N/D only, the core suites present', () => {
  assert.match(DATA.updated, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(DATA.suites.length > 300);
  const names = new Set();
  const codes = new Set();
  for (const s of DATA.suites) {
    assert.deepEqual(Object.keys(s).sort(), ['code', 'name', 'rec']);
    assert.match(s.code, /^0x[0-9A-F]{2},0x[0-9A-F]{2}$/, s.name);
    assert.match(s.name, /^TLS_[A-Za-z0-9_]+$/, s.name);
    assert.ok(['Y', 'N', 'D'].includes(s.rec), s.name);
    assert.ok(!names.has(s.name) && !codes.has(s.code), `duplicate ${s.name}`);
    names.add(s.name);
    codes.add(s.code);
  }
  const byName = Object.fromEntries(DATA.suites.map((s) => [s.name, s]));
  assert.equal(byName.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.code, '0xC0,0x2F');
  assert.equal(byName.TLS_AES_128_GCM_SHA256.code, '0x13,0x01');
  assert.equal(byName.TLS_RSA_WITH_3DES_EDE_CBC_SHA.code, '0x00,0x0A');
  assert.equal(byName.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.code, '0xCC,0xA8');
});

test('the code grades agree with IANA: every Recommended suite is OK, every Discouraged one is weak or insecure', () => {
  for (const s of DATA.suites) {
    const g = gradeSuite(s);
    if (s.rec === 'Y') assert.equal(g.grade, 'ok', s.name);
    if (s.rec === 'D') assert.ok(['weak', 'insecure'].includes(g.grade), `${s.name}: ${g.grade}`);
    if (g.grade === 'insecure') assert.ok(g.reasons.some((x) => x.grade === 'insecure'), s.name);
  }
});

test('each insecure rule fires on the suite it is for', () => {
  const cases = {
    TLS_RSA_WITH_NULL_SHA256: 'null-cipher',
    TLS_SHA256_SHA256: 'integrity-only',
    TLS_DH_anon_WITH_AES_128_GCM_SHA256: 'anon',
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA: 'anon',
    TLS_RSA_EXPORT_WITH_RC4_40_MD5: 'export',
    TLS_ECDHE_RSA_WITH_RC4_128_SHA: 'rc4',
    TLS_DHE_RSA_WITH_DES_CBC_SHA: 'tiny-key',
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: '64bit-block',
    TLS_RSA_WITH_IDEA_CBC_SHA: '64bit-block',
    TLS_RSA_WITH_RC4_128_MD5: 'md5',
  };
  for (const [name, id] of Object.entries(cases)) {
    const r = grade(name);
    assert.equal(r.grade, 'insecure', name);
    assert.ok(ids(r).includes(id), `${name}: ${ids(r)}`);
  }
  // 3DES with ECDHE is still insecure even though IANA only says N (not D).
  assert.equal(grade('TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA').suite.rec, 'N');
});

test('weak rules: no forward secrecy, finite-field DHE, CBC, CCM_8, PSK', () => {
  assert.deepEqual(ids(grade('TLS_RSA_WITH_AES_128_GCM_SHA256')), ['rsa']);
  assert.deepEqual(ids(grade('TLS_RSA_WITH_AES_256_CBC_SHA')), ['cbc', 'rsa']);
  assert.deepEqual(ids(grade('TLS_DH_RSA_WITH_AES_128_GCM_SHA256')), ['static-dh']);
  assert.deepEqual(ids(grade('TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256')), ['static-ecdh']);
  assert.deepEqual(ids(grade('TLS_DHE_RSA_WITH_AES_256_GCM_SHA384')), ['dhe']);
  assert.deepEqual(ids(grade('TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256')), ['dhe']);
  assert.deepEqual(ids(grade('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256')), ['cbc']);
  assert.deepEqual(ids(grade('TLS_AES_128_CCM_8_SHA256')), ['ccm8']);
  assert.deepEqual(ids(grade('TLS_PSK_WITH_AES_128_GCM_SHA256')), ['psk']);
  assert.deepEqual(ids(grade('TLS_RSA_PSK_WITH_AES_128_GCM_SHA256')), ['rsa-psk']);
  assert.deepEqual(ids(grade('TLS_PSK_DHE_WITH_AES_128_CCM_8')), ['ccm8', 'dhe']);
  for (const n of ['TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'TLS_AES_128_CCM_8_SHA256']) assert.equal(grade(n).grade, 'weak', n);
});

test('OK suites: TLS 1.3 and ECDHE with an AEAD cipher', () => {
  for (const n of ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM']) {
    const r = grade(n);
    assert.equal(r.grade, 'ok', n);
    assert.deepEqual(r.reasons, []);
    assert.equal(r.parts.fs, true);
  }
});

test('parts of a name', () => {
  assert.deepEqual(
    (({ version, kx, auth, cipher, mode, mac }) => ({ version, kx, auth, cipher, mode, mac }))(partsOf('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256')),
    { version: 'TLS 1.2 or earlier', kx: 'ECDHE (ephemeral)', auth: 'RSA', cipher: 'AES-128', mode: 'GCM (AEAD)', mac: 'Built into the cipher (AEAD)' },
  );
  const cbc = partsOf('TLS_RSA_WITH_AES_256_CBC_SHA');
  assert.equal(cbc.kx, 'RSA key transport');
  assert.equal(cbc.mode, 'CBC');
  assert.equal(cbc.mac, 'HMAC-SHA1');
  assert.equal(cbc.fs, false);
  assert.equal(partsOf('TLS_AES_256_GCM_SHA384').version, 'TLS 1.3');
  assert.equal(partsOf('TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384').cipher, 'Camellia-256');
  assert.equal(partsOf('TLS_RSA_EXPORT_WITH_DES40_CBC_SHA').export, true);
  assert.equal(partsOf('TLS_SHA384_SHA384').mac, 'HMAC-SHA384');
  assert.deepEqual(partsOf('TLS_FALLBACK_SCSV'), { signal: true });
  for (const n of ['TLS_KRB5_WITH_3DES_EDE_CBC_SHA', 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA', 'TLS_AEGIS_256_SHA512', 'TLS_SM4_GCM_SM3', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_MD99', 'nonsense']) assert.equal(partsOf(n), null, n);
});

test('families the decoder does not model: "not graded" unless IANA discourages them', () => {
  const krb = grade('TLS_KRB5_WITH_3DES_EDE_CBC_SHA'); // IANA: N
  assert.equal(krb.grade, 'not-graded');
  assert.equal(krb.parts, null);
  const krbD = grade('TLS_KRB5_WITH_RC4_128_SHA'); // IANA: D
  assert.equal(krbD.grade, 'weak');
  assert.deepEqual(ids(krbD), ['iana-discouraged']);
  assert.equal(grade('TLS_EMPTY_RENEGOTIATION_INFO_SCSV').grade, 'signal');
});

test('OpenSSL names map to IANA names', () => {
  const cases = {
    'ECDHE-RSA-AES128-GCM-SHA256': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'ECDHE-ECDSA-CHACHA20-POLY1305': 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    'ECDHE-RSA-AES256-SHA384': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'AES128-SHA': 'TLS_RSA_WITH_AES_128_CBC_SHA',
    'DES-CBC3-SHA': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'EDH-RSA-DES-CBC3-SHA': 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
    'EXP-RC4-MD5': 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
    'EXP-EDH-RSA-DES-CBC-SHA': 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
    'ADH-AES256-GCM-SHA384': 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
    'AECDH-AES128-SHA': 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
    'ECDHE-ECDSA-AES128-CCM8': 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8',
    'PSK-AES128-CBC-SHA256': 'TLS_PSK_WITH_AES_128_CBC_SHA256',
    'ECDHE-ARIA128-GCM-SHA256': 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
    'CAMELLIA256-SHA': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
  };
  for (const [ossl, iana] of Object.entries(cases)) assert.equal(opensslToIana(ossl), iana, ossl);
  for (const bad of ['RC2-CBC-MD5', 'EXP-AES128-SHA', 'AES128-SHA999', 'FOO-BAR', 'ECDHE-RSA']) assert.equal(opensslToIana(bad), null, bad);
  // IANA spells DHE-PSK CCM_8 suites "PSK_DHE".
  assert.equal(decodeOne({ input: 'DHE-PSK-AES128-CCM8', kind: 'openssl' }, reg).suite.name, 'TLS_PSK_DHE_WITH_AES_128_CCM_8');
  // TLS 1.3 names are the same in OpenSSL.
  assert.equal(decodeOne({ input: 'TLS_AES_128_GCM_SHA256', kind: 'openssl' }, reg).suite.code, '0x13,0x01');
});

test('pasted text: OpenSSL strings, Nmap output, hex codes, Java names; duplicates and junk dropped', () => {
  const nmap = `| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|_  least strength: C`;
  assert.deepEqual(tokensOf(nmap).map((t) => t.input), ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA']);
  assert.deepEqual(tokensOf('ECDHE-RSA-AES128-GCM-SHA256:!aNULL:HIGH:+3DES:DES-CBC3-SHA:ecdhe-rsa-aes128-gcm-sha256').map((t) => [t.input, t.kind]), [
    ['ECDHE-RSA-AES128-GCM-SHA256', 'openssl'], ['DES-CBC3-SHA', 'openssl'],
  ]);
  assert.deepEqual(tokensOf('0xC0,0x2F and 0x009C, also a well-known e-mail').map((t) => [t.input, t.kind]), [['0xC02F', 'code'], ['0x009C', 'code']]);
  const r = decodeSuites('0xC0,0x2F\nSSL_RSA_WITH_RC4_128_MD5\ntls_dh_anon_with_aes_128_cbc_sha', reg);
  assert.deepEqual(r.results.map((x) => [x.suite.name, x.grade]), [
    ['TLS_RSA_WITH_RC4_128_MD5', 'insecure'],
    ['TLS_DH_anon_WITH_AES_128_CBC_SHA', 'insecure'],
    ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'ok'],
  ]);
});

test('unknown names are "not recognized", never guessed; empty or junk input gets a plain message', () => {
  for (const n of ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA999', 'ECDHE-RSA-AES512-GCM-SHA256', 'TLS_MADE_UP', '0xFFFF']) {
    const r = grade(n);
    assert.equal(r.grade, 'unknown', n);
    assert.equal(r.suite, null);
  }
  assert.match(decodeSuites('   ', reg).error, /Paste/);
  assert.match(decodeSuites('hello world', reg).error, /No cipher suite names found/);
});

test('results: worst first, counts, a turn-off list, and caps', () => {
  const r = decodeSuites(EXAMPLE, reg);
  assert.deepEqual(r.results.map((x) => x.grade), ['insecure', 'insecure', 'weak', 'weak', 'weak', 'ok', 'ok', 'ok']);
  assert.deepEqual(r.counts, { insecure: 2, weak: 3, ok: 3, signal: 0, 'not-graded': 0, unknown: 0 });
  assert.deepEqual(r.turnOff, ['TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384']);
  assert.equal(r.truncated, false);
  const many = DATA.suites.map((s) => s.name).join('\n');
  const big = decodeSuites(many, reg);
  assert.equal(big.results.length, MAX_SUITES);
  assert.equal(big.truncated, true);
  assert.ok(tokensOf(`${'x'.repeat(MAX_INPUT)} TLS_AES_128_GCM_SHA256`).length === 0, 'text past the input cap is not read');
});

test('every reason has a grade, plain text and a known https source; labels exist for every grade and IANA value', () => {
  for (const [id, r] of Object.entries(REASONS)) {
    assert.ok(['insecure', 'weak'].includes(r.grade), id);
    assert.ok(r.text.length > 20 && r.text.length < 160, id);
    assert.ok(SOURCES[r.source], `${id}: ${r.source}`);
  }
  for (const s of Object.values(SOURCES)) assert.match(s.url, /^https:\/\/(www\.rfc-editor\.org|www\.iana\.org|csrc\.nist\.gov)\//);
  for (const g of ['insecure', 'weak', 'ok', 'signal', 'not-graded', 'unknown']) assert.ok(GRADE_TEXT[g]);
  for (const v of ['Y', 'N', 'D']) assert.ok(REC_TEXT[v]);
});

test('the Analyze page has the decoder, loads the module, and the module stays local', () => {
  const html = read('analyze.html');
  for (const id of ['ciphers', 'ciphers-form', 'ciphers-input', 'ciphers-example', 'ciphers-clear', 'ciphers-result']) assert.ok(html.includes(`id="${id}"`), id);
  assert.ok(html.includes('<script type="module" src="js/analyze/ciphers.js"></script>'));
  assert.ok(html.includes('<a href="#ciphers">'));
  const src = read('js/analyze/ciphers.js');
  assert.ok(!/innerHTML|localStorage|sessionStorage/.test(src), 'textContent only, no storage');
  assert.deepEqual([...src.matchAll(/fetch\(([^)]*)\)/g)].map((m) => m[1]), ["'data/cipher-suites.json'"], 'the only request is the bundled list');
});

test('in the page: Decode shows the summary and graded suites; Try an example and Clear work; nothing leaves', async () => {
  const dom = installDom(read('analyze.html'), { url: 'https://jamalrizki.github.io/Security-lookup-hub/analyze.html' });
  const requests = [];
  globalThis.fetch = async (input) => {
    const u = String(input);
    requests.push(u);
    if (u.startsWith('data/')) return new Response(read(u));
    return new Response('no', { status: 500 });
  };
  try {
    await import('../js/analyze/ciphers.js?page=1');
    await settle();
    const $ = (id) => dom.document.getElementById(id);
    $('ciphers-input').value = 'DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256';
    $('ciphers-form').requestSubmit();
    await settle();
    const out = $('ciphers-result').textContent;
    assert.match(out, /1 insecure · 1 OK/);
    assert.match(out, /TLS_RSA_WITH_3DES_EDE_CBC_SHA/);
    assert.match(out, /You pasted/);
    assert.match(out, /Sweet32/);
    assert.match(out, /Discouraged/);
    assert.match(out, /Copy the turn-off list/);
    assert.match(out, /Rules from: /);
    $('ciphers-example').click();
    await settle();
    assert.match($('ciphers-result').textContent, /2 insecure · 3 weak · 3 OK/);
    $('ciphers-clear').click();
    assert.equal($('ciphers-input').value, '');
    assert.equal($('ciphers-result').textContent, '');
    $('ciphers-input').value = 'TLS_NOT_A_SUITE';
    $('ciphers-form').requestSubmit();
    await settle();
    assert.match($('ciphers-result').textContent, /1 not recognized/);
    assert.match($('ciphers-result').textContent, /does not guess/);
    assert.deepEqual(requests, ['data/cipher-suites.json']);
  } finally {
    dom.restore();
    delete globalThis.fetch;
  }
});
