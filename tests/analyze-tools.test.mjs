// JWT decoder and file analyzer (pure functions; the page wiring only runs in a browser).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeJwt } from '../js/analyze/jwt.js';
import { sniffType, extensionWarnings, extractStrings } from '../js/analyze/file.js';

const b64url = (obj) => Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj)).toString('base64url');
const jwt = (header, payload, sig = 'c2lnbmF0dXJl') => `${b64url(header)}.${b64url(payload)}.${sig}`;
const NOW = Date.parse('2026-10-15T12:00:00Z');

/* ---------- JWT ---------- */

test('decodes header and payload, with time claims as dates and statuses', () => {
  const t = jwt({ alg: 'HS256', typ: 'JWT' }, { sub: '123', name: 'Jo', iat: 1760000000, exp: 1760003600, nbf: 1900000000 });
  const r = decodeJwt(`Bearer ${t}`, NOW);
  assert.deepEqual(r.header, { alg: 'HS256', typ: 'JWT' });
  assert.equal(r.payload.name, 'Jo');
  assert.deepEqual(r.warnings, []);
  const byClaim = Object.fromEntries(r.times.map((x) => [x.claim, x]));
  assert.equal(byClaim.exp.status, 'expired');
  assert.equal(byClaim.exp.date, '2025-10-09T09:53:20.000Z');
  assert.equal(byClaim.nbf.status, 'not yet valid');
  assert.equal(byClaim.iat.status, null);
});

test('flags alg none, empty signatures and key URLs', () => {
  const none = decodeJwt(`${b64url({ alg: 'none' })}.${b64url({ admin: true })}.`, NOW);
  assert.match(none.warnings[0], /unsigned/);
  const NONE = decodeJwt(jwt({ alg: 'NoNe' }, {}), NOW);
  assert.equal(NONE.warnings.length, 2, 'case-insensitive, and a signature that "none" ignores');
  assert.match(decodeJwt(`${b64url({ alg: 'RS256' })}.${b64url({})}.`, NOW).warnings[0], /signature part is empty/);
  assert.match(decodeJwt(jwt({ alg: 'RS256', jku: 'https://evil.example/keys' }, {}), NOW).warnings[0], /jku/);
});

test('rejects malformed, encrypted and oversized tokens without throwing', () => {
  assert.match(decodeJwt('a.b', NOW).error, /three parts/);
  assert.match(decodeJwt('a.b.c.d.e', NOW).error, /encrypted/);
  assert.match(decodeJwt('!!!.e30.x', NOW).error, /header/);
  assert.match(decodeJwt(`${b64url({ alg: 'HS256' })}.${b64url('not json <script>')}.x`, NOW).error, /payload/);
  assert.match(decodeJwt(`${b64url('[1,2]')}.${b64url({})}.x`, NOW).error, /not a JSON object/);
  assert.match(decodeJwt('x'.repeat(70000), NOW).error, /too long/);
  assert.match(decodeJwt('   ', NOW).error, /Paste/);
  const weird = decodeJwt(jwt({ alg: 'HS256' }, { exp: 'tomorrow', html: '<img src=x onerror=alert(1)>' }), NOW);
  assert.equal(weird.times[0].status, 'not a number');
  assert.equal(weird.payload.html, '<img src=x onerror=alert(1)>', 'kept as data; the page shows it as text');
});

/* ---------- File type ---------- */

const bytes = (...parts) => {
  const arr = [];
  for (const p of parts) arr.push(...(typeof p === 'string' ? [...p].map((c) => c.charCodeAt(0)) : p));
  return Uint8Array.from(arr);
};

function peFile() {
  const b = new Uint8Array(0x100);
  b.set([0x4d, 0x5a]);
  b[0x3c] = 0x80;
  b.set([0x50, 0x45, 0, 0], 0x80);
  return b;
}

test('magic bytes: executables', () => {
  assert.equal(sniffType(peFile()).label, 'Windows executable (PE)');
  assert.equal(sniffType(bytes([0x4d, 0x5a], new Array(100).fill(0))).label, 'DOS/MZ executable');
  assert.equal(sniffType(bytes([0x7f], 'ELF', [2, 1, 1])).type, 'elf');
  assert.equal(sniffType(bytes([0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1])).type, 'macho');
  assert.equal(sniffType(bytes([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2])).label, 'macOS universal executable (fat Mach-O)');
  assert.equal(sniffType(bytes([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x3d])).type, 'class', 'Java class shares the magic');
  assert.equal(sniffType(bytes('#!/usr/bin/env python3\nprint(1)')).label, 'Script (python3)');
  assert.equal(sniffType(bytes('#!/bin/bash\necho')).label, 'Script (bash)');
});

test('magic bytes: documents, archives, images, unknown', () => {
  assert.equal(sniffType(bytes('%PDF-1.7\n')).type, 'pdf');
  assert.equal(sniffType(bytes([0x50, 0x4b, 3, 4], '....[Content_Types].xml....word/document.xml')).type, 'docx');
  assert.equal(sniffType(bytes([0x50, 0x4b, 3, 4], '....xl/workbook.xml')).type, 'xlsx');
  assert.equal(sniffType(bytes([0x50, 0x4b, 3, 4], '....AndroidManifest.xml')).type, 'apk');
  assert.equal(sniffType(bytes([0x50, 0x4b, 3, 4], '....readme.txt')).type, 'zip');
  assert.equal(sniffType(bytes([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])).type, 'ole');
  assert.equal(sniffType(bytes([0x89], 'PNG', [0x0d, 0x0a, 0x1a, 0x0a])).type, 'png');
  assert.equal(sniffType(bytes([0xff, 0xd8, 0xff, 0xe0])).type, 'jpeg');
  assert.equal(sniffType(bytes('GIF89a')).type, 'gif');
  assert.equal(sniffType(bytes('hello world')), null);
  assert.equal(sniffType(new Uint8Array(0)), null);
});

test('extension mismatches and double extensions', () => {
  assert.deepEqual(extensionWarnings('setup.exe', sniffType(peFile())), []);
  assert.match(extensionWarnings('invoice.pdf', sniffType(peFile()))[0], /Windows executable.*\.pdf/);
  const dbl = extensionWarnings('invoice.pdf.exe', sniffType(peFile()));
  assert.match(dbl[0], /Double extension/);
  assert.equal(dbl.length, 1, '.exe matches the PE content');
  assert.deepEqual(extensionWarnings('report.docx', sniffType(bytes([0x50, 0x4b, 3, 4], 'word/'))), []);
  assert.match(extensionWarnings('photo.jpg', sniffType(bytes('%PDF-1.4')))[0], /PDF document/);
  assert.deepEqual(extensionWarnings('notes.txt', null), [], 'unknown content: nothing to compare');
});

test('strings: ASCII and UTF-16LE runs of 6+, capped', () => {
  const utf16 = [...'cmd.exe /c whoami'].flatMap((c) => [c.charCodeAt(0), 0]);
  const b = bytes([0, 1, 2], 'http://evil.example.net/a', [0, 0xff], 'short', [0], 'kernel32.dll', [0], utf16, [0, 0]);
  const s = extractStrings(b);
  assert.ok(s.includes('http://evil.example.net/a'));
  assert.ok(s.includes('kernel32.dll'));
  assert.ok(!s.includes('short'), 'under 6 characters');
  // The byte pair before it ("l\0" from kernel32.dll) is valid UTF-16 too, so the run may start early.
  assert.ok(s.some((x) => x.endsWith('cmd.exe /c whoami')), 'UTF-16LE');
  const many = bytes(...Array.from({ length: 6000 }, (_, i) => `string${i}\0`));
  assert.equal(extractStrings(many).length, 5000);
});
