// Ports and protocols (Reference page, #ports): search over data/ports.json.
// Pure functions only, so tests can run them without a page.

const PROTOS = new Set(['TCP', 'UDP', 'TCP/UDP']);

/** Does an entry's transport include the asked one ("tcp" matches "TCP/UDP")? */
function protoIncludes(entry, proto) {
  return !proto || entry.proto.split('/').includes(proto.toUpperCase());
}

/**
 * Search the port list.
 *   ""                 -> { results: all, kind: 'all' }
 *   "443", "53/udp"    -> { results: entries on that port (and transport), kind: 'port' }
 *   "70000"            -> { results: [], error: 'Ports go from 0 to 65535.' }
 *   "ssh", "mail"      -> { results: name matches first, then other text matches, kind: 'text' }
 * Results keep port order within each rank.
 */
export function searchPorts(ports, query) {
  const q = String(query ?? '').trim().toLowerCase().slice(0, 60);
  if (!q) return { results: ports.slice(), kind: 'all' };
  const num = q.match(/^(?:port\s*)?(\d{1,6})(?:\s*\/\s*(tcp|udp))?$/);
  if (num) {
    const port = Number(num[1]);
    if (port > 65535) return { results: [], kind: 'port', error: 'Ports go from 0 to 65535.' };
    return { results: ports.filter((p) => p.port === port && protoIncludes(p, num[2])), kind: 'port', port };
  }
  const rank = (p) => {
    const name = p.name.toLowerCase();
    if (name === q) return 0;
    if (name.startsWith(q)) return 1;
    if (name.includes(q) || p.full.toLowerCase().includes(q)) return 2;
    if (p.use.toLowerCase().includes(q)) return 3;
    return -1;
  };
  const results = ports
    .map((p) => [rank(p), p])
    .filter(([r]) => r >= 0)
    .sort((a, b) => a[0] - b[0] || a[1].port - b[1].port)
    .map(([, p]) => p);
  return { results, kind: 'text' };
}

/** "443/TCP" */
export const portLabel = (p) => `${p.port}/${p.proto}`;

/** The encrypted versions of an entry, as "993 IMAPS" strings, from the list itself. */
export function secureVersions(ports, entry) {
  return (entry.secure || []).map((n) => {
    const alt = ports.find((p) => p.port === n);
    return alt ? `${alt.port} ${alt.name}` : null;
  }).filter(Boolean);
}

/** Checks one entry's shape; returns a list of problems (empty when fine). */
export function entryProblems(p) {
  const out = [];
  if (!Number.isInteger(p.port) || p.port < 0 || p.port > 65535) out.push('port must be 0-65535');
  if (!PROTOS.has(p.proto)) out.push('proto must be TCP, UDP or TCP/UDP');
  for (const k of ['name', 'full', 'use']) if (typeof p[k] !== 'string' || !p[k].trim()) out.push(`${k} missing`);
  if (typeof p.name === 'string' && p.name.length > 20) out.push('name over 20 characters');
  if (typeof p.use === 'string' && p.use.length > 140) out.push('use over 140 characters');
  if ('secure' in p && (!Array.isArray(p.secure) || !p.secure.every(Number.isInteger))) out.push('secure must be a list of ports');
  for (const k of ['exposed', 'default']) if (k in p && p[k] !== true) out.push(`${k} is only ever true`);
  const known = new Set(['port', 'proto', 'name', 'full', 'use', 'secure', 'exposed', 'default']);
  for (const k of Object.keys(p)) if (!known.has(k)) out.push(`unknown field ${k}`);
  return out;
}
