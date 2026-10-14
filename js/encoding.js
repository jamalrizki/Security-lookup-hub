// Encode/decode helpers for the decoder tool: Base64, URL encoding and hex.
// All text is treated as UTF-8. Decoders throw an Error with a readable message.

import { toHex } from './md5.js';

const enc = new TextEncoder();

function bytesToText(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`Decoded bytes are not valid UTF-8 text. As hex: ${toHex(bytes)}`);
  }
}

export function base64Encode(text) {
  let bin = '';
  for (const b of enc.encode(text)) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Accepts standard and URL-safe Base64, with or without padding or line breaks. */
export function base64Decode(input) {
  let s = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error('Input contains characters that are not Base64.');
  s = s.replace(/=+$/, '');
  if (s.length % 4 === 1) throw new Error('Base64 input has an invalid length.');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s);
  return bytesToText(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

export function urlEncode(text) {
  return encodeURIComponent(text);
}

/** Decodes %XX sequences; "+" is also read as a space, as in form data. */
export function urlDecode(input) {
  try {
    return decodeURIComponent(input.replace(/\+/g, ' '));
  } catch {
    throw new Error('Input has a malformed % escape sequence.');
  }
}

export function hexEncode(text) {
  return toHex(enc.encode(text));
}

/** Accepts "48656c6c6f", "48 65 6c", "48:65:6c", "0x48 0x65" and "\x48\x65". */
export function hexDecode(input) {
  const s = input.replace(/0x|\\x/gi, '').replace(/[\s:,-]/g, '');
  if (!/^[0-9a-f]*$/i.test(s)) throw new Error('Input contains characters that are not hex.');
  if (s.length % 2) throw new Error('Hex input has an odd number of digits.');
  const bytes = new Uint8Array(s.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return bytesToText(bytes);
}

export const CODECS = {
  base64: { label: 'Base64', encode: base64Encode, decode: base64Decode },
  url: { label: 'URL encoding', encode: urlEncode, decode: urlDecode },
  hex: { label: 'Hex', encode: hexEncode, decode: hexDecode },
};
