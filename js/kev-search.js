// "Exploited in my products" (cves.html#kev): text for the results of
// GET /api/kev-search. DOM-free so tests/kev-search.test.mjs can run it in Node.
// Every number here comes from the Worker's kevSearch(), which counts CISA's
// KEV file in code; nothing is estimated.

const plural = (n, one, many) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;

export const NOT_LISTED_NOTE =
  'Not being listed here does not make a product safe: KEV only holds CVEs CISA has confirmed evidence of exploitation for. '
  + 'If nothing shows up, try the vendor name alone, or the parent company if the product was bought.';

/** One line: how many matched, how many recent, how many ransomware-linked. */
export function summaryLine(body) {
  const released = body.catalogReleased ? ` (catalog released ${body.catalogReleased})` : '';
  if (!body.total) return `No CISA KEV entries match “${body.keyword}”${released}.`;
  const head = `${plural(body.total, 'exploited vulnerability', 'exploited vulnerabilities')} in CISA’s KEV catalog for “${body.keyword}”${released}.`;
  const recent = `${plural(body.recent, 'added', 'added')} in the last ${body.recentDays} days, ${plural(body.ransomware, 'linked', 'linked')} to ransomware.`;
  const shown = body.results.length < body.total ? ` Showing the ${body.results.length} newest.` : '';
  return `${head} ${recent}${shown}`;
}

/** The detail line under a row. CISA's text, labelled as CISA's. */
export function rowDetail(r) {
  const parts = [];
  if (r.name) parts.push(`${r.name}.`);
  if (r.description) parts.push(r.description);
  if (r.dueDate) parts.push(`CISA due date: ${r.dueDate} (the deadline for US federal agencies).`);
  if (r.ransomware) parts.push('Known ransomware use.');
  if (r.requiredAction) parts.push(`CISA’s required action: ${r.requiredAction}`);
  return parts.join(' ');
}

/** "Ivanti Connect Secure · added 2026-10-01" */
export const rowLabel = (r) => `${[r.vendorProject, r.product].filter(Boolean).join(' ')}${r.dateAdded ? ` · added ${r.dateAdded}` : ''}`;
