// Windows event IDs (Reference page, #events): search over data/events.json.
// Pure functions only, so tests can run them without a page.

// Microsoft Learn links may only point here, over https.
export const EVENT_DOC_HOST = 'learn.microsoft.com';

/** A link to Microsoft's page for an event (or for the logon-type / status tables), or null if it isn't safe. */
export function eventDocUrl(docBase, id) {
  if (!Number.isInteger(id) || id < 1 || id > 99999) return null;
  try {
    const u = new URL(`${docBase}${id}`);
    if (u.protocol !== 'https:' || u.hostname !== EVENT_DOC_HOST || u.username || u.password || u.port || u.search || u.hash) return null;
    return u.pathname.endsWith(`/event-${id}`) ? u.href : null;
  } catch {
    return null;
  }
}

/** The page Microsoft documents an event on (domain-group events share the local-group page). */
export const eventPageId = (e) => e.page ?? e.id;

/**
 * A 4625 status code as Windows writes it ("0xC000006A"), or null.
 * Accepts upper or lower case and an optional 0x; anything but exactly 8 hex digits is refused.
 * Without 0x it needs a letter A-F, so an 8-digit decimal number is not read as a status code.
 */
export function normalizeStatus(s) {
  const m = String(s ?? '').trim().match(/^(0x)?([0-9a-f]{8})$/i);
  if (!m || (!m[1] && !/[a-f]/i.test(m[2]))) return null;
  return `0x${m[2].toUpperCase()}`;
}

const EVENT_ID = /^(?:event(?:\s*id)?|eventid|id)?[\s:#-]*(\d{1,6})$/;
const LOGON_TYPE = /^(?:logon\s*type|type)[\s:#-]*(\d{1,3})$/;

/**
 * Search the event list.
 *   ""                       -> kind 'empty'
 *   "4625", "event id 4625"  -> kind 'id': that event (empty when not listed; error when not a valid ID)
 *   "0xC000006A", "c000006a" -> kind 'status': that 4625 status code (status null when not listed)
 *   "logon type 10", "10"    -> kind 'logon-type': that logon type (empty when there is no such type)
 *   "locked out"             -> kind 'text': events whose name matches, then the plain sentence, then "why it matters";
 *                               plus logon types and status codes whose text matches.
 * Text after 60 characters is ignored; regex characters are plain text.
 */
export function searchEvents(data, query) {
  const events = data?.events || [];
  const logonTypes = data?.logonTypes || [];
  const statusCodes = data?.statusCodes || [];
  const raw = String(query ?? '').trim().toLowerCase().replace(/\s+/g, ' ').slice(0, 60);
  const none = { events: [], logonTypes: [], statuses: [] };
  if (!raw) return { kind: 'empty', ...none };

  const code = normalizeStatus(raw);
  if (code) return { kind: 'status', ...none, code, statuses: statusCodes.filter((s) => s.code === code) };

  let m = raw.match(LOGON_TYPE) || raw.match(/^(\d{1,2})$/);
  if (m) {
    const t = Number(m[1]);
    return { kind: 'logon-type', ...none, type: t, logonTypes: logonTypes.filter((l) => l.type === t) };
  }

  m = raw.match(EVENT_ID);
  if (m) {
    const id = Number(m[1]);
    if (id < 1 || id > 65535) return { kind: 'id', ...none, id, error: 'Windows event IDs are numbers from 1 to 65535.' };
    return { kind: 'id', ...none, id, events: events.filter((e) => e.id === id) };
  }

  if (raw.length < 3) return { kind: 'text', ...none };
  const rank = (e) => {
    if (e.name.toLowerCase().includes(raw)) return 0;
    if (e.plain.toLowerCase().includes(raw)) return 1;
    if (e.why.toLowerCase().includes(raw)) return 2;
    return -1;
  };
  const found = events
    .map((e, i) => [rank(e), i, e])
    .filter(([r]) => r >= 0)
    .sort((x, y) => x[0] - y[0] || x[1] - y[1])
    .map(([, , e]) => e);
  return {
    kind: 'text',
    events: found,
    logonTypes: logonTypes.filter((l) => `${l.name} ${l.plain}`.toLowerCase().includes(raw)),
    statuses: statusCodes.filter((s) => `${s.plain} ${s.why || ''}`.toLowerCase().includes(raw)),
  };
}

/** Checks one event entry's shape; returns a list of problems (empty when fine). */
export function eventProblems(e) {
  const out = [];
  if (e.log !== 'Security') out.push('log must be "Security" in this list');
  if (!Number.isInteger(e.id) || e.id < 1 || e.id > 65535) out.push('id must be a whole number from 1 to 65535');
  for (const k of ['category', 'name', 'plain', 'why']) if (typeof e[k] !== 'string' || !e[k].trim()) out.push(`${k} missing`);
  if (typeof e.name === 'string' && (e.name.length > 80 || !/\.$/.test(e.name))) out.push('name must be Microsoft\'s title: 80 characters max, ending with a full stop');
  for (const k of ['plain', 'why']) {
    if (typeof e[k] === 'string' && e[k].length > 160) out.push(`${k} over 160 characters`);
    if (typeof e[k] === 'string' && !/[.]$/.test(e[k])) out.push(`${k} must end with a full stop`);
  }
  if ('page' in e && (!Number.isInteger(e.page) || e.page === e.id)) out.push('page must be another event ID');
  const known = new Set(['log', 'id', 'category', 'name', 'plain', 'why', 'page']);
  for (const k of Object.keys(e)) if (!known.has(k)) out.push(`unknown field ${k}`);
  return out;
}
