// Plain-language rewrites must not add facts. These checks run in code on the
// rewrite: any sentence that brings in a CVE ID, a link or a number that its
// source didn't have is deleted. Used by Explain's "In plain English" (source:
// the facts JSON) and Ask's "Make it simpler" (source: the original answer).

const CVE = /CVE[\s‐-―−_-]*(\d{4})[\s‐-―−_-]*(\d{4,19})/gi;
const URL_RE = /\b(?:https?|hxxps?):\/\/[^\s)\]]+|\b[\w-]+(?:\[\.\]|\.)(?:com|org|net|gov|io|dev|edu|mil|uk|au|example)\/[^\s)\]]*/gi;
// Numbers as written: 9.8, 11.6%, 1,500, 2026. Dates are split into their parts.
const NUMBER = /\d[\d,]*(?:\.\d+)?/g;

const cveIds = (text) => new Set([...String(text).matchAll(CVE)].map((m) => `CVE-${m[1]}-${m[2]}`));
const urls = (text) => new Set((String(text).match(URL_RE) || []).map((u) => u.toLowerCase().replace(/^hxxp/, 'http').replace(/\[\.\]/g, '.').replace(/[.,;:!?]+$/, '')));
const numbers = (text) => (String(text).match(NUMBER) || []).map((n) => Number(n.replace(/,/g, ''))).filter(Number.isFinite);

/**
 * True if the number is supported by the source: small counts (0-10) are free,
 * anything else must match a source number, allowing for rounding (11.6 -> 12).
 */
function supported(n, sourceNumbers) {
  if (Number.isInteger(n) && n <= 10) return true;
  return sourceNumbers.some((s) => Math.abs(s - n) <= 0.51);
}

/** What in this sentence its source doesn't have: { cves, urls, numbers }. */
export function newFacts(sentence, source) {
  const srcCves = cveIds(source);
  const srcUrls = urls(source);
  const srcNumbers = numbers(source);
  const sentenceCves = cveIds(sentence);
  // A CVE ID's digits are checked as the ID, not as numbers.
  const withoutIds = String(sentence).replace(CVE, ' ').replace(URL_RE, ' ');
  return {
    cves: [...sentenceCves].filter((id) => !srcCves.has(id)),
    urls: [...urls(sentence)].filter((u) => !srcUrls.has(u)),
    numbers: numbers(withoutIds).filter((n) => !supported(n, srcNumbers)),
  };
}

// A sentence ends at . ! or ? followed by a space or the end of the line, so the dots
// inside a link, a version (8.3.36) or a score (9.8) don't split it.
const splitSentences = (line) => line.split(/(?<=[.!?]["')\]]*)\s+(?=\S)/).map((s, i, all) => (i < all.length - 1 ? `${s} ` : s));

/** Deletes every sentence that adds a CVE ID, link or number the source doesn't have. */
export function keepSourceFacts(text, source) {
  const kept = String(text).split('\n').map((line) => {
    if (!line.trim()) return { blank: true, text: '' };
    const sents = splitSentences(line).filter((s) => {
      const f = newFacts(s, source);
      return !f.cves.length && !f.urls.length && !f.numbers.length;
    });
    return { blank: false, text: sents.join('').trimEnd() };
  });
  return kept
    .filter((l) => l.blank || l.text.trim().replace(/^[-*]$/, ''))
    .map((l) => l.text)
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}
