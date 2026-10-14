// Pwned Passwords range check (k-anonymity). Only the first 5 hex characters
// of the SHA-1 hash leave the browser; the match happens locally.

import { toHex } from './md5.js';

/** Returns how many times the password appears in Pwned Passwords. */
export async function checkPassword(password) {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  const hash = toHex(new Uint8Array(digest)).toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' },
    referrerPolicy: 'no-referrer',
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`Have I Been Pwned returned HTTP ${res.status}`);
  for (const line of (await res.text()).split('\n')) {
    const [s, count] = line.trim().split(':');
    // Padding rows have a count of 0 and never match a real hash.
    if (s === suffix) return Number(count);
  }
  return 0;
}
