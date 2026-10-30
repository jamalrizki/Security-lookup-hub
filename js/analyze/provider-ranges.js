// The public Tor / cloud provider lists for the subnet calculator and the IOC
// extractor's log mode. Downloaded from GET /api/ranges once per page visit, and
// only after a button click; the IPs being checked never leave the browser
// (the request carries no parameters). Matching is js/ranges.js, the same code
// the Worker's network source uses.

import { API_BASE } from '../config.js';
import { classify, NOT_LISTED } from '../ranges.js';

export const RANGES_NOTE = 'Downloads the public provider lists once; the IP you typed stays in your browser.';
export const PENDING = "The provider lists haven't been downloaded by the hub yet. Try again in a few hours.";
export const UNREACHABLE = 'The provider lists could not be downloaded. Try again in a moment.';

let loading = null;

/** The lists, downloaded on the first call and kept for the page visit. Rejects with a plain message. */
export function providerRanges() {
  loading ||= (async () => {
    let body;
    try {
      const res = await fetch(`${API_BASE}/api/ranges`, { referrerPolicy: 'no-referrer' });
      body = res.ok ? await res.json() : null;
    } catch {
      body = null;
    }
    if (!body || body.error) throw new Error(UNREACHABLE);
    if (body.pending) throw new Error(PENDING);
    return body;
  })();
  // A failure isn't kept, so a later click can try again.
  loading.catch(() => { loading = null; });
  return loading;
}

/** For tests: forget the downloaded lists. */
export function resetProviderRanges() {
  loading = null;
}

/** A row label for the Top IPs list: provider name, "Tor", or '' when in none. */
export function rowLabel(lists, ip) {
  const c = classify(lists, ip);
  if (!c) return '';
  return [c.tor ? 'Tor' : null, c.provider?.name].filter(Boolean).join(', ');
}

export { NOT_LISTED };
