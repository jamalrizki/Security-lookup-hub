// Ports practice (Reference page, #ports-practice). Random questions for
// Network+/Security+ students, built from data/ports.json, so the quiz and the
// "Ports and protocols" list above it can never disagree. No AI, no network
// beyond the same data file, no storage: the session score lives in a variable.
// Pure functions are exported for tests; startPortsDrill() wires the page.

import { seeded, cryptoRand } from './analyze/subnet-drill.js';

export { seeded, cryptoRand };

export const KINDS = ['port', 'name', 'transport', 'secure'];
export const MAX_ANSWER = 40;

// Ports that certification objectives (Network+, Security+) ask about most.
// "Exam ports only" limits questions to these; otherwise they come up 3x as often.
export const EXAM_PORTS = [
  20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 137, 138, 139, 143, 161, 162,
  389, 443, 445, 465, 514, 587, 636, 993, 995, 1433, 1812, 1813, 3306, 3389, 5060, 5061,
];

// Other names a student may fairly give for "what runs on port N?". The list's
// name and full name (and anything in its brackets) are accepted already.
export const ALIASES = {
  20: ['ftp'],
  21: ['ftp control'],
  111: ['portmap', 'portmapper', 'sunrpc', 'rpc'],
  135: ['rpc', 'msrpc', 'microsoft rpc', 'dcom'],
  137: ['netbios'],
  138: ['netbios'],
  139: ['netbios'],
  162: ['snmp', 'snmp trap'],
  443: ['http over ssl', 'tls', 'ssl'],
  465: ['smtp over tls', 'smtp over ssl'],
  587: ['smtp', 'smtp submission', 'mail submission'],
  853: ['dns over tls'],
  989: ['ftps', 'ftps data'],
  1433: ['sql server', 'mssql', 'microsoft sql'],
  1521: ['oracle db', 'oracle tns'],
  1813: ['radius', 'radius accounting'],
  3268: ['global catalog'],
  3269: ['global catalog', 'global catalog ssl'],
  3306: ['mariadb'],
  4500: ['nat t', 'ipsec', 'ipsec nat t'],
  5353: ['multicast dns', 'bonjour'],
  5432: ['postgres'],
  5900: ['rfb'],
  5985: ['winrm http'],
  5986: ['winrm', 'winrm over https'],
  6443: ['kubernetes', 'k8s', 'kube api'],
  6514: ['syslog over tls', 'syslog'],
  8080: ['http', 'http alternate', 'http proxy', 'alternate http'],
  9200: ['elastic'],
  27017: ['mongo'],
};

// How a service is named in a question when its list name alone would be
// unclear ("Which port does Submission use?").
export const SUBJECT = {
  20: 'FTP data (active mode)',
  21: 'FTP control',
  67: 'a DHCP server',
  68: 'a DHCP client',
  162: 'SNMP traps',
  587: 'SMTP mail submission',
  1813: 'RADIUS accounting',
  3268: 'the Active Directory Global Catalog',
  3269: 'the Active Directory Global Catalog over TLS',
  8080: 'alternate HTTP (HTTP-Alt)',
};

// Words dropped before comparing names, so "RDP protocol" or "the SMB service" count.
const FILLER = new Set(['the', 'a', 'an', 'protocol', 'service', 'server', 'port']);

/** "MS-SQL", "ms sql", "MS SQL protocol" -> "mssql". */
export function normName(s) {
  return String(s ?? '')
    .toLowerCase()
    .replace(/\+/g, 'plus')
    .split(/[^a-z0-9]+/)
    .filter((w) => w && !FILLER.has(w))
    .join('');
}

/** Every normalised name accepted for an entry. */
export function acceptedNames(p) {
  const out = new Set([normName(p.name), normName(p.full)]);
  const outer = p.full.replace(/\([^)]*\)/g, ' ');
  out.add(normName(outer));
  for (const part of outer.split('/')) out.add(normName(part));
  for (const [, inner] of p.full.matchAll(/\(([^)]*)\)/g)) {
    for (const part of inner.split(/,|\/|\band\b|\bor\b|\balso\b/)) out.add(normName(part));
  }
  for (const a of ALIASES[p.port] || []) out.add(normName(a));
  out.delete('');
  // Bracket words that only describe the entry ("data", "server", "HTTP") are not names on their own.
  for (const w of ['data', 'client', 'control', 'http', 'https', 'ldap', 'ipsec', 'unencrypted']) {
    if (normName(p.name) !== w && !(ALIASES[p.port] || []).map(normName).includes(w)) out.delete(w);
  }
  return out;
}

const pick = (rand, list) => list[Math.floor(rand() * list.length)];
const subject = (p) => SUBJECT[p.port] || p.name;
const transportWord = (p) => (p.proto === 'TCP/UDP' ? 'both' : p.proto);

/** Entries the drill can ask about: all, or only EXAM_PORTS. */
export function pool(ports, examOnly = false) {
  return examOnly ? ports.filter((p) => EXAM_PORTS.includes(p.port)) : ports.slice();
}

function pickEntry(rand, entries) {
  const weight = (p) => (EXAM_PORTS.includes(p.port) ? 3 : 1);
  const total = entries.reduce((s, p) => s + weight(p), 0);
  let r = rand() * total;
  for (const p of entries) { r -= weight(p); if (r < 0) return p; }
  return entries[entries.length - 1];
}

/**
 * Makes one question from the port list. kinds limits which kinds can come up.
 * Returns { kind, entry, prompt, answer, ports? } where answer is shown on a miss.
 */
export function makeQuestion(rand, ports, { kinds = KINDS, examOnly = false } = {}) {
  const entries = pool(ports, examOnly);
  if (!entries.length) return null;
  const allowed = kinds.filter((k) => KINDS.includes(k));
  let kind = pick(rand, allowed.length ? allowed : KINDS);
  let entry = pickEntry(rand, kind === 'secure' ? entries.filter((p) => p.secure?.length) : entries);
  if (!entry) { kind = 'port'; entry = pickEntry(rand, entries); }
  const q = { kind, entry };
  const usually = entry.default ? 'usually ' : '';

  if (kind === 'port') {
    // Every listed port with the same name counts (DHCP is 67 and 68), unless the
    // question names one side of it ("a DHCP server").
    q.ports = SUBJECT[entry.port] ? [entry.port] : ports.filter((p) => p.name === entry.name).map((p) => p.port);
    q.prompt = `Which port does ${subject(entry)} ${usually}use?`;
    q.answer = q.ports.join(' or ');
  } else if (kind === 'name') {
    q.prompt = `What ${usually || 'normally '}runs on port ${entry.port} (${entry.proto})?`;
    q.answer = entry.name === entry.full ? entry.name : `${entry.name} (${entry.full})`;
  } else if (kind === 'transport') {
    q.prompt = `Does ${subject(entry)} on port ${entry.port} use TCP, UDP or both?`;
    q.answer = entry.proto === 'TCP/UDP' ? 'both (TCP and UDP)' : entry.proto;
  } else {
    q.ports = entry.secure.slice();
    q.prompt = `${entry.name} uses port ${entry.port} and is not encrypted. Which port is its encrypted version?`;
    q.answer = q.ports.map((n) => {
      const alt = ports.find((p) => p.port === n);
      return alt ? `${n} (${alt.name})` : String(n);
    }).join(' or ');
  }
  return q;
}

/**
 * Grades an answer. Returns { status: 'correct' | 'wrong' | 'invalid', message }.
 * 'invalid' (empty, too long, a word where a port number is asked) never
 * counts against the student.
 */
export function checkAnswer(q, input) {
  const raw = String(input ?? '').trim();
  if (!raw) return { status: 'invalid', message: 'Type an answer first.' };
  if (raw.length > MAX_ANSWER) return { status: 'invalid', message: `That answer is too long (${MAX_ANSWER} characters max).` };
  const ok = (good) => ({ status: good ? 'correct' : 'wrong', message: good ? 'Correct.' : `Not quite. The answer is ${q.answer}.` });

  if (q.kind === 'port' || q.kind === 'secure') {
    const m = /^(?:port\s*)?(\d{1,5})(?:\s*\/\s*(tcp|udp))?$/i.exec(raw);
    if (!m) return { status: 'invalid', message: 'Answer with a port number, like 443.' };
    const n = Number(m[1]);
    if (n > 65535) return { status: 'invalid', message: 'Ports go from 0 to 65535.' };
    return ok(q.ports.includes(n));
  }
  if (q.kind === 'transport') {
    const t = raw.toLowerCase().replace(/\s+/g, ' ');
    let said = null;
    if (/^(both|tcp ?(\/|and|&|\+|,) ?udp|udp ?(\/|and|&|\+|,) ?tcp)$/.test(t)) said = 'both';
    else if (t === 'tcp') said = 'TCP';
    else if (t === 'udp') said = 'UDP';
    if (!said) return { status: 'invalid', message: 'Answer TCP, UDP or both.' };
    return ok(said === transportWord(q.entry));
  }
  if (/^\d+$/.test(raw)) return { status: 'invalid', message: 'Answer with the service name, like SSH.' };
  return ok(acceptedNames(q.entry).has(normName(raw)));
}

/** One plain line about the entry, shown after an answer (from the list's own text). */
export function explain(ports, q) {
  const p = q.entry;
  const secure = (p.secure || []).map((n) => ports.find((x) => x.port === n)).filter(Boolean)
    .map((x) => `${x.port} ${x.name}`);
  return [
    `${p.port}/${p.proto} ${p.name}${p.full === p.name ? '' : `: ${p.full}`}. ${p.use}`,
    secure.length ? `Encrypted version: ${secure.join(' or ')}.` : null,
    p.default ? 'A common default, not its official IANA assignment.' : null,
    p.exposed ? 'Should normally not be reachable from the internet.' : null,
  ].filter(Boolean).join(' ');
}

// ---------- Page wiring ----------

/**
 * Wires #ports-practice. el/$ come from the caller so this file needs no DOM
 * of its own; showInList(port) fills the list's search box.
 */
export function startPortsDrill(ports, { el, $, showInList }) {
  if (!$('pdrill-form') || !ports.length) return;
  const score = { right: 0, answered: 0 };
  let q = null;
  let done = false;

  const showScore = () => {
    $('pdrill-score').textContent = score.answered ? `${score.right} / ${score.answered} this session` : '';
  };
  const detail = () => el('p', { class: 'hint' }, explain(ports, q));
  const next = () => {
    q = makeQuestion(cryptoRand, ports, { examOnly: $('pdrill-exam').checked });
    done = false;
    $('pdrill-question').textContent = q ? q.prompt : 'No questions available.';
    $('pdrill-answer').value = '';
    $('pdrill-result').replaceChildren();
  };

  $('pdrill-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    if (!q) return;
    const r = checkAnswer(q, $('pdrill-answer').value);
    if (r.status === 'invalid') { $('pdrill-result').replaceChildren(el('p', { class: 'notice warn' }, r.message)); return; }
    // Only the first real attempt at a question counts towards the score.
    if (!done) { score.answered++; if (r.status === 'correct') score.right++; done = true; }
    $('pdrill-result').replaceChildren(
      el('p', { class: `verdict ${r.status === 'correct' ? 'ok' : 'bad'}` }, r.status === 'correct' ? '✔ ' : '✘ ', r.message),
      detail(),
    );
    showScore();
  });
  $('pdrill-reveal').addEventListener('click', () => {
    if (!q) return;
    done = true; // revealed answers don't score
    $('pdrill-result').replaceChildren(el('p', { class: 'verdict muted' }, `The answer is ${q.answer}.`), detail());
  });
  $('pdrill-next').addEventListener('click', () => { next(); $('pdrill-answer').focus(); });
  $('pdrill-exam').addEventListener('change', () => next());
  $('pdrill-show').addEventListener('click', () => { if (q) showInList(q.entry.port); });
  next();
}
