// Lookup's type buttons. data/lookup-types.json holds one entry per button and
// data/source-names.json the sources' display names (the Worker reads the same
// file), so the "Checks:" line can't drift from what the Worker runs; a test
// compares each entry with the Worker's plan().

export const DEFAULT_TYPE = 'myip';

/** The button for a detect() type: IPv4 and IPv6 share "IP address". */
export function buttonFor(detectedType) {
  if (detectedType === 'ipv4' || detectedType === 'ipv6') return 'ip';
  return ['domain', 'url', 'hash', 'email', 'cve'].includes(detectedType) ? detectedType : null;
}

const join = (ids, names) => [...new Set(ids.map((id) => names[id] || id))].join(', ');

/** "Checks: AbuseIPDB, VirusTotal, …" for one type entry. */
export function checksText(type, names) {
  if (!type) return '';
  if (type.hostSources) {
    return `Checks: ${join(type.sources, names)}, then the host: ${join(type.hostSources.domain, names)} (or for an IP host: ${join(type.hostSources.ip, names)}).`;
  }
  return `Checks: ${join(type.sources, names)}.`;
}

/**
 * The message for input detect() couldn't place. detect()'s catch-all message
 * names every type, so the selected type's own sentence replaces it; its more
 * specific messages ("looks like an email, but…") are kept.
 */
export function invalidMessage(type, detected) {
  if (type?.invalid && /^Not recognised as/.test(detected.error || '')) return type.invalid;
  return detected.error;
}
