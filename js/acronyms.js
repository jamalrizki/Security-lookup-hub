// Security acronyms (Reference page, #acronyms): search over data/acronyms.json.
// Pure functions only, so tests can run them without a page.

/** Lower case, letters and digits only: "PCI DSS" -> "pcidss", "S/MIME" -> "smime", "ATT&CK" -> "attck". */
export const acronymKey = (s) => String(s ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');

/**
 * Search the acronym list.
 *   ""              -> { results: [], kind: 'empty' }
 *   "xss", "S/MIME" -> exact acronym matches first (every meaning, list order),
 *                      then acronyms that start with it, then matches in the full name,
 *                      then matches in the plain sentence.
 *   "phishing"      -> { results: [], kind: 'text' } when nothing matches.
 * Text after 60 characters is ignored; regex characters are plain text.
 */
export function searchAcronyms(list, query) {
  const raw = String(query ?? '').trim().toLowerCase().slice(0, 60);
  const key = acronymKey(raw);
  if (!raw) return { results: [], kind: 'empty' };
  const rank = (a) => {
    const k = acronymKey(a.acronym);
    if (key && k === key) return 0;
    if (key && k.startsWith(key)) return 1;
    if (raw.length >= 3 && a.full.toLowerCase().includes(raw)) return 2;
    if (raw.length >= 3 && a.plain.toLowerCase().includes(raw)) return 3;
    return -1;
  };
  const results = list
    .map((a, i) => [rank(a), i, a])
    .filter(([r]) => r >= 0)
    .sort((x, y) => x[0] - y[0] || x[1] - y[1])
    .map(([, , a]) => a);
  return { results, kind: 'text', exact: results.filter((a) => acronymKey(a.acronym) === key).length };
}

/** Checks one entry's shape; returns a list of problems (empty when fine). */
export function acronymProblems(a) {
  const out = [];
  for (const k of ['acronym', 'full', 'plain']) if (typeof a[k] !== 'string' || !a[k].trim()) out.push(`${k} missing`);
  if (typeof a.acronym === 'string' && (a.acronym.length > 10 || !acronymKey(a.acronym))) out.push('acronym must be 1-10 characters with a letter or digit');
  if (typeof a.full === 'string' && a.full.length > 80) out.push('full over 80 characters');
  if (typeof a.plain === 'string' && a.plain.length > 140) out.push('plain over 140 characters');
  if (typeof a.plain === 'string' && !/[.]$/.test(a.plain)) out.push('plain must end with a full stop');
  const known = new Set(['acronym', 'full', 'plain']);
  for (const k of Object.keys(a)) if (!known.has(k)) out.push(`unknown field ${k}`);
  return out;
}
