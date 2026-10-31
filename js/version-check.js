// "Is my version affected?" on the NVD card: compares a version the visitor types with
// the affected ranges NVD lists. DOM-free, tested in Node. The verdict is decided here,
// in code; nothing is sent anywhere.
//
// Input is the card's `affected` list from the Worker: { vendor, product, type, versions },
// where `versions` is the text built by versionRange() in worker/src/cve.js:
//   ">= 2.0, < 2.15.0"   (any of >=, >, <=, <, joined by ", ")
//   "any version"         (cpe version *)
//   "unspecified version" (cpe version -)
//   "1.2.3" or "1.2.3 sp1" (one exact version, optionally with an update level)
// tests/version-check.test.mjs feeds versionRange()'s real output through parseRange()
// so the two stay in step.

export const MAX_VERSION_LENGTH = 40;
const VERSION_RE = /^[0-9][0-9A-Za-z.\-_+]*$/;

/** Cleans what the visitor typed: trims, drops a leading v ("v2.14.1"). Returns null if it isn't a version. */
export function cleanVersion(raw) {
  const s = String(raw ?? '').trim().replace(/^v(?=\d)/i, '');
  if (!s || s.length > MAX_VERSION_LENGTH || !VERSION_RE.test(s)) return null;
  return s;
}

// Pre-release words sort below the release they belong to (2.15.0-rc1 < 2.15.0).
// Single letters are NOT pre-releases: OpenSSL's 1.0.1a comes after 1.0.1.
const PRE = /^(?:alpha|beta|rc|pre|preview|dev|snapshot|milestone)$/i;

function tokens(v) {
  // "2.15.0-rc1" -> [2, 15, 0, "rc", 1]; letters and digits split apart.
  return String(v).toLowerCase().split(/[.\-_+]/).flatMap((part) => part.match(/\d+|[a-z]+/g) || [])
    .map((t) => (/^\d+$/.test(t) ? Number(t) : t));
}

/** -1, 0 or 1. Numbers compare as numbers, missing trailing zeros are equal, pre-release words sort lower. */
export function compareVersions(a, b) {
  const x = tokens(a);
  const y = tokens(b);
  const n = Math.max(x.length, y.length);
  const isPre = (t) => typeof t === 'string' && PRE.test(t);
  for (let i = 0; i < n; i += 1) {
    let p = x[i];
    let q = y[i];
    // A missing part counts as 0 next to a number (2.15 = 2.15.0), and as "the release"
    // next to a word: above a pre-release (2.15.0 > 2.15.0-rc1), below a letter (1.0.1 < 1.0.1a).
    if (p === undefined) {
      if (typeof q === 'number') p = 0;
      else return isPre(q) ? 1 : -1;
    }
    if (q === undefined) {
      if (typeof p === 'number') q = 0;
      else return isPre(p) ? -1 : 1;
    }
    if (p === q) continue;
    if (typeof p === 'number' && typeof q === 'number') return p < q ? -1 : 1;
    if (typeof p === 'number') return 1; // a number outranks a word in the same place
    if (typeof q === 'number') return -1;
    if (isPre(p) !== isPre(q)) return isPre(p) ? -1 : 1;
    return p < q ? -1 : 1;
  }
  return 0;
}

/** Parses one `versions` text into { kind: 'range'|'any'|'unknown'|'exact', ... }. */
export function parseRange(text) {
  const s = String(text ?? '').trim();
  if (s === 'any version') return { kind: 'any' };
  if (s === 'unspecified version' || !s) return { kind: 'unknown' };
  if (/^(?:>=|>|<=|<) /.test(s)) {
    const bounds = [];
    for (const part of s.split(', ')) {
      const m = /^(>=|>|<=|<) (\S+)$/.exec(part);
      if (!m) return { kind: 'unknown' };
      bounds.push({ op: m[1], version: m[2] });
    }
    return { kind: 'range', bounds };
  }
  const [version, ...update] = s.split(' ');
  return { kind: 'exact', version, update: update.join(' ') || null };
}

const OPS = {
  '>=': (c) => c >= 0, '>': (c) => c > 0, '<=': (c) => c <= 0, '<': (c) => c < 0,
};

/** Does one parsed range include the version? true, false, or null (can't tell). */
export function inRange(version, range) {
  if (range.kind === 'any') return true;
  if (range.kind === 'unknown') return null;
  if (range.kind === 'exact') {
    if (!range.update) return compareVersions(version, range.version) === 0;
    // "2.0 beta9": typing 2.0-beta9 matches; plain 2.0 might be a different build.
    if (compareVersions(version, `${range.version}.${range.update}`) === 0) return true;
    return compareVersions(version, range.version) === 0 ? null : false;
  }
  return range.bounds.every((b) => OPS[b.op](compareVersions(version, b.version)));
}

/** Distinct "vendor product" choices from the affected list, in first-seen order. */
export function productChoices(affected = []) {
  const seen = new Map();
  for (const a of affected) {
    const key = `${a.vendor}|${a.product}`;
    if (!seen.has(key)) seen.set(key, { key, label: `${a.vendor} ${a.product}`.replace(/_/g, ' ') });
  }
  return [...seen.values()];
}

/**
 * The verdict. `affected` and `affectedTotal` come straight from the NVD card;
 * `productKey` is one of productChoices()' keys.
 * Returns { verdict: 'affected'|'not-listed'|'cant-tell'|'invalid', text, matches, notes }.
 */
export function checkVersion(affected, affectedTotal, productKey, rawVersion) {
  const version = cleanVersion(rawVersion);
  if (!version) {
    return { verdict: 'invalid', text: 'Type a version number, such as 2.14.1.', matches: [], notes: [] };
  }
  const rows = (affected || []).filter((a) => `${a.vendor}|${a.product}` === productKey);
  if (!rows.length) {
    return { verdict: 'invalid', text: 'Pick a product from the list.', matches: [], notes: [] };
  }
  const label = productChoices(rows)[0].label;
  const notes = [];
  const matches = [];
  let unknown = 0;
  for (const row of rows) {
    const range = parseRange(row.versions);
    const hit = inRange(version, range);
    if (hit === true) matches.push(row.versions);
    else if (hit === null) {
      unknown += 1;
      if (range.kind === 'exact') notes.push(`NVD lists ${row.versions} specifically: check your update or service-pack level.`);
    }
  }
  const partial = (affectedTotal || 0) > (affected || []).length;
  if (partial) notes.push(`NVD lists ${affectedTotal} affected ranges for this CVE and the hub shows the first ${affected.length}, so check the full list on NVD.`);

  if (matches.length) {
    return {
      verdict: 'affected',
      text: `${version} is inside a range NVD lists as affected for ${label} (${matches.join('; ')}). Plan to update to a fixed version from the vendor's advisory.`,
      matches,
      notes,
    };
  }
  if (unknown || partial) {
    return {
      verdict: 'cant-tell',
      text: unknown
        ? `NVD lists some ${label} entries without a version number or only for a specific update level, so the hub can't tell whether ${version} is affected. Check the vendor's advisory.`
        : `${version} isn't in the ranges shown here, but NVD has more ranges than the hub received. Check the full list on NVD.`,
      matches,
      notes,
    };
  }
  return {
    verdict: 'not-listed',
    text: `${version} is outside every range NVD lists for ${label}. That's a good sign, not a guarantee: vendors sometimes backport fixes or list more versions in their own advisory.`,
    matches,
    notes,
  };
}
