// CVSS practice (Study page, #cvss-practice). Exam-style multiple-choice
// questions on CVSS v3.1 for CySA+, Security+ and PenTest+ students: what a
// metric value means, which value fits a scenario, which severity a vector
// gets, which of four findings scores highest, and the severity bands.
// Every score is computed here with FIRST's published v3.1 equations
// (https://www.first.org/cvss/v3.1/specification-document, section 7), never
// written by hand or by a model. The bank is built from a fixed seed, so it is
// the same on every visit and the tests check every question in it. No AI, no
// network, no storage. Pure functions are exported for tests.

import { seeded } from './analyze/subnet-drill.js';

export const METRICS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

// Each metric: its name and, per value, the value's name and one plain line.
export const META = {
  AV: { name: 'Attack Vector', values: {
    N: ['Network', 'the attacker can exploit it remotely, across the internet or other routed networks'],
    A: ['Adjacent', 'the attacker must be on the same local network segment, such as the same Wi-Fi, Bluetooth range or VLAN'],
    L: ['Local', 'the attacker needs local access, such as a shell on the machine, or a user opening a malicious file'],
    P: ['Physical', 'the attacker must physically touch or handle the device'],
  } },
  AC: { name: 'Attack Complexity', values: {
    L: ['Low', 'no special conditions: the attack works reliably, every time'],
    H: ['High', 'success depends on conditions outside the attacker’s control, such as winning a race condition or a man-in-the-middle position'],
  } },
  PR: { name: 'Privileges Required', values: {
    N: ['None', 'the attacker needs no account or login at all'],
    L: ['Low', 'the attacker needs an ordinary user account'],
    H: ['High', 'the attacker needs an administrator or other highly privileged account'],
  } },
  UI: { name: 'User Interaction', values: {
    N: ['None', 'the attack works without any user doing anything'],
    R: ['Required', 'a user must take some action, such as clicking a link or opening a file'],
  } },
  S: { name: 'Scope', values: {
    U: ['Unchanged', 'the impact stays within the vulnerable component’s own security authority'],
    C: ['Changed', 'the impact reaches past the vulnerable component, for example escaping a VM or a browser sandbox'],
  } },
  C: { name: 'Confidentiality', values: {
    H: ['High', 'total loss of confidentiality: the attacker can read all data, or critical data such as passwords'],
    L: ['Low', 'some data can be read, but the attacker doesn’t control what or how much'],
    N: ['None', 'no loss of confidentiality'],
  } },
  I: { name: 'Integrity', values: {
    H: ['High', 'total loss of integrity: the attacker can change any data, or critical data'],
    L: ['Low', 'some data can be changed, but the attacker doesn’t control what, and the effect is limited'],
    N: ['None', 'no loss of integrity'],
  } },
  A: { name: 'Availability', values: {
    H: ['High', 'total loss of availability: the attacker can fully shut the component down'],
    L: ['Low', 'reduced performance or interruptions, but not a full outage'],
    N: ['None', 'no loss of availability'],
  } },
};

// FIRST CVSS v3.1 weights (specification section 7.4).
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

/** The v3.1 Roundup: the smallest one-decimal number >= x, with the spec's float guard. */
export function roundup(x) {
  const n = Math.round(x * 100000);
  return n % 10000 === 0 ? n / 100000 : (Math.floor(n / 10000) + 1) / 10;
}

/** Parses "CVSS:3.1/AV:N/…" (or the bare metrics) into { AV: 'N', … }, or null if not a full, legal base vector. */
export function parseVector(text) {
  const s = String(text ?? '').trim();
  if (s.length > 60) return null;
  const parts = s.replace(/^CVSS:3\.[01]\//, '').split('/');
  if (parts.length !== METRICS.length) return null;
  const out = {};
  for (const p of parts) {
    const [k, v, extra] = p.split(':');
    if (extra !== undefined || !META[k] || k in out || !(v in META[k].values)) return null;
    out[k] = v;
  }
  return out;
}

/** "CVSS:3.1/AV:N/AC:L/…" for a metrics object. */
export const vectorString = (m) => `CVSS:3.1/${METRICS.map((k) => `${k}:${m[k]}`).join('/')}`;

/** Severity band for a base score (v3.x qualitative rating scale). */
export function severity(score) {
  if (score === 0) return 'None';
  if (score < 4) return 'Low';
  if (score < 7) return 'Medium';
  if (score < 9) return 'High';
  return 'Critical';
}
export const SEVERITIES = ['None', 'Low', 'Medium', 'High', 'Critical'];

/** Base score with its working: { score, severity, impact, exploitability }, or null for an invalid vector. */
export function baseScore(vector) {
  const m = typeof vector === 'string' ? parseVector(vector) : vector;
  if (!m || METRICS.some((k) => !(m[k] in (META[k]?.values || {})))) return null;
  const changed = m.S === 'C';
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exploitability = 8.22 * W.AV[m.AV] * W.AC[m.AC] * W.PR[changed ? 'C' : 'U'][m.PR] * W.UI[m.UI];
  let score = 0;
  if (impact > 0) score = roundup(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10));
  return { score, severity: severity(score), impact: Math.round(impact * 100) / 100, exploitability: Math.round(exploitability * 100) / 100 };
}

const one = (n) => n.toFixed(1);
const working = (r) => `Impact ${r.impact.toFixed(2)}, Exploitability ${r.exploitability.toFixed(2)}`;

// ---------- Question bank ----------

function shuffle(rand, arr) {
  const out = arr.slice();
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/** A question with `right` and three wrong options, shuffled; the answer index follows the right option. */
function mc(rand, q, right, wrong, why) {
  const options = shuffle(rand, [right, ...wrong.slice(0, 3)]);
  return { q, options, answer: options.indexOf(right), why };
}

const randomVector = (rand) => Object.fromEntries(METRICS.map((k) => {
  const vals = Object.keys(META[k].values);
  return [k, vals[Math.floor(rand() * vals.length)]];
}));

// Scenarios an exam describes in words, and the metric value each one points to.
export const SCENARIOS = [
  ['AV', 'N', 'A flaw in a web server can be triggered by anyone who can send it an HTTP request from the internet.'],
  ['AV', 'N', 'A remote attacker can exploit an exposed VPN appliance’s login page from anywhere.'],
  ['AV', 'A', 'The attacker must be connected to the same Wi-Fi network as the victim’s laptop.'],
  ['AV', 'A', 'The flaw is in a Bluetooth stack and can only be reached from within radio range.'],
  ['AV', 'L', 'The attacker must already have a shell on the server to run the vulnerable command.'],
  ['AV', 'L', 'The victim has to open a malicious document on their own computer for the flaw to be reached.'],
  ['AV', 'P', 'The attacker must plug a device into the target’s USB port.'],
  ['AV', 'P', 'Exploiting the flaw requires opening the device’s case and attaching to a debug header.'],
  ['AC', 'H', 'The exploit only works if the attacker wins a race condition that succeeds a small fraction of the time.'],
  ['AC', 'H', 'The attacker must first get into a man-in-the-middle position on the victim’s traffic.'],
  ['AC', 'L', 'The exploit works the same way every time with no special preparation.'],
  ['PR', 'N', 'No account is needed: the flaw is reachable before login.'],
  ['PR', 'L', 'Any ordinary signed-in user of the application can trigger the flaw.'],
  ['PR', 'H', 'Only an administrator of the application can reach the vulnerable settings page.'],
  ['UI', 'R', 'The attack only works if a user clicks a crafted link.'],
  ['UI', 'R', 'A user must open a malicious attachment for the code to run.'],
  ['UI', 'N', 'The server is compromised without anyone doing anything: no clicks, no logins.'],
  ['S', 'C', 'A flaw in a hypervisor lets code in a guest VM affect the host and other VMs.'],
  ['S', 'C', 'A stored cross-site scripting bug in a web app runs script in visitors’ browsers.'],
  ['S', 'U', 'The flaw lets an attacker crash the vulnerable service, and nothing beyond it.'],
  ['C', 'H', 'The attacker can download the whole customer database, including password hashes.'],
  ['C', 'L', 'The attacker can read some error messages that reveal internal file paths, but not chosen data.'],
  ['I', 'H', 'The attacker can change any record in the database.'],
  ['A', 'H', 'A single crafted packet makes the service crash until it is restarted by hand.'],
  ['A', 'L', 'The attack slows the service noticeably but does not stop it.'],
];

/** All values of every metric, as [metric, value]. */
const ALL_VALUES = METRICS.flatMap((k) => Object.keys(META[k].values).map((v) => [k, v]));

// 1. What does AV:N mean? Wrong options: the same metric's other values first, then other metrics'.
function meaningQuestions(rand) {
  return ALL_VALUES.map(([k, v]) => {
    const line = (kk, vv) => META[kk].values[vv][1].replace(/^./, (c) => c.toUpperCase()) + '.';
    const same = Object.keys(META[k].values).filter((x) => x !== v).map((x) => line(k, x));
    const other = shuffle(rand, ALL_VALUES.filter(([kk]) => kk !== k)).map(([kk, vv]) => line(kk, vv));
    const wrong = [...new Set([...same, ...other])].filter((x) => x !== line(k, v)).slice(0, 3);
    return mc(rand, `In a CVSS 3.1 vector, what does ${k}:${v} mean?`, line(k, v), wrong,
      `${k}:${v} is ${META[k].name}: ${META[k].values[v][0]}, meaning ${META[k].values[v][1]}.`);
  });
}

// 2. A scenario in words → which value of the named metric. The wrong options are the
// metric's other values, padded with codes that metric doesn't have (UI:H), so no
// wrong option can also be true of the scenario.
const FAKE_CODES = ['N', 'L', 'H', 'R', 'A', 'P', 'U', 'C'];
function scenarioQuestions(rand) {
  return SCENARIOS.map(([k, v, text]) => {
    const legal = Object.keys(META[k].values);
    const wrong = [...legal.filter((x) => x !== v), ...shuffle(rand, FAKE_CODES.filter((x) => !legal.includes(x)))].map((x) => `${k}:${x}`);
    const others = legal.length < 4 ? ` ${META[k].name} only has ${legal.map((x) => `${k}:${x}`).join(', ')}.` : '';
    return mc(rand, `${text} Which ${META[k].name} value fits?`, `${k}:${v}`, wrong,
      `${k}:${v} (${META[k].values[v][0]}): ${META[k].values[v][1]}.${others}`);
  });
}

// The four severities shown in order, around the right one (None only when the answer is None).
function severityOptions(right) {
  const i = SEVERITIES.indexOf(right);
  return i === 0 ? SEVERITIES.slice(0, 4) : SEVERITIES.slice(1);
}

// 3. Vector → severity, scored in code. Every band from Low to Critical is asked several times.
function severityQuestions(rand, n) {
  const want = { Low: 0, Medium: 0, High: 0, Critical: 0 };
  const per = Math.ceil(n / 4);
  const seen = new Set();
  const out = [];
  for (let tries = 0; out.length < n && tries < 20000; tries += 1) {
    const m = randomVector(rand);
    const r = baseScore(m);
    const v = vectorString(m);
    if (!(r.severity in want) || want[r.severity] >= per || seen.has(v)) continue;
    want[r.severity] += 1;
    seen.add(v);
    const options = severityOptions(r.severity);
    out.push({ q: `A scanner reports ${v}. What is its CVSS 3.1 base severity?`, options, answer: options.indexOf(r.severity),
      why: `Base score ${one(r.score)} (${working(r)}), and ${one(r.score)} falls in the ${r.severity} band.` });
  }
  return out;
}

// 4. Four findings → which to fix first by base score. The top score leads the next by at least 0.5.
function highestQuestions(rand, n) {
  const out = [];
  for (let tries = 0; out.length < n && tries < 20000; tries += 1) {
    const vs = [];
    while (vs.length < 4) {
      const v = vectorString(randomVector(rand));
      if (!vs.includes(v) && baseScore(v).score > 0) vs.push(v);
    }
    const scored = vs.map((v) => ({ v, r: baseScore(v) })).sort((a, b) => b.r.score - a.r.score);
    if (scored[0].r.score - scored[1].r.score < 0.5) continue;
    const q = mc(rand, 'Four findings on the same network, with nothing else known about them. By CVSS 3.1 base score, which should be fixed first?',
      scored[0].v, scored.slice(1).map((s) => s.v), '');
    q.why = `Base scores: ${q.options.map((o, i) => `${'ABCD'[i]} ${one(baseScore(o).score)}`).join(', ')}. In real triage, CISA KEV and EPSS come before CVSS.`;
    out.push(q);
  }
  return out;
}

// 5. Score → severity band, at and around the band edges.
const BAND_SCORES = [0.1, 3.9, 4.0, 5.5, 6.9, 7.0, 8.9, 9.0, 10.0];
function bandQuestions() {
  return BAND_SCORES.map((s) => {
    const right = severity(s);
    const options = severityOptions(right);
    return { q: `A vulnerability has a CVSS 3.1 base score of ${one(s)}. Which severity rating is that?`, options, answer: options.indexOf(right),
      why: `The v3.x bands are Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9 and Critical 9.0–10.0, so ${one(s)} is ${right}.` };
  });
}

// 6. Fixed questions about CVSS itself, written to the v3.1 specification.
// Written with the right option first; buildQuestions() shuffles them.
export const CONCEPTS = [
  { q: 'Which of these is a CVSS 3.1 base metric?', options: ['Attack Complexity', 'Exploit Code Maturity', 'Remediation Level', 'Confidentiality Requirement'], answer: 0,
    why: 'Attack Complexity is a base metric. Exploit Code Maturity and Remediation Level are temporal metrics; Confidentiality Requirement is environmental.' },
  { q: 'Which CVSS 3.1 metric group lets an organization adjust a score for how important the affected system is to it?', options: ['Base', 'Temporal', 'Environmental', 'Exploitability'], answer: 2,
    why: 'Environmental metrics (such as the Confidentiality, Integrity and Availability Requirements) tailor the score to one organization’s systems.' },
  { q: 'Which CVSS 3.1 metric group changes over time as exploit code appears or a patch is released?', options: ['Base', 'Temporal', 'Environmental', 'Impact'], answer: 1,
    why: 'Temporal metrics (Exploit Code Maturity, Remediation Level, Report Confidence) change as the situation around the vulnerability changes.' },
  { q: 'Which three base metrics make up the impact part of a CVSS 3.1 score?', options: ['Confidentiality, Integrity and Availability', 'Attack Vector, Attack Complexity and Privileges Required', 'Scope, User Interaction and Attack Vector', 'Exploit Code Maturity, Remediation Level and Report Confidence'], answer: 0,
    why: 'Impact comes from C, I and A (adjusted by Scope); Attack Vector, Attack Complexity, Privileges Required and User Interaction make up exploitability.' },
  { q: 'What does a CVSS base score measure?', options: ['The severity of the vulnerability itself', 'The chance it will be exploited in the next 30 days', 'Whether it is being exploited in the wild today', 'The cost of fixing it'], answer: 0,
    why: 'CVSS rates severity. The chance of exploitation is EPSS, and known exploitation in the wild is the CISA KEV catalog.' },
  { q: 'Two vectors are identical except for Scope. Which statement is true?', options: ['S:C gives an equal or higher base score than S:U', 'S:U always gives the higher score', 'Scope only changes the temporal score', 'Scope has no effect when Privileges Required is None'], answer: 0,
    why: 'A changed Scope uses a larger impact formula and multiplies the total by 1.08, so the base score never goes down when S:U becomes S:C.' },
  { q: 'A vector has C:N/I:N/A:N. What is its CVSS 3.1 base score?', options: ['0.0', '1.0', '3.9', 'It depends on Attack Vector'], answer: 0,
    why: 'With no confidentiality, integrity or availability impact, the impact subscore is 0, and the spec sets the base score to 0.0 (None).' },
  { q: 'Which part of a CVSS 3.1 vector tells you an attacker needs no account?', options: ['PR:N', 'UI:N', 'AC:L', 'AV:N'], answer: 0,
    why: 'Privileges Required None (PR:N) means no login is needed. UI:N is about user action, AC:L about reliability, AV:N about network reach.' },
];

/** The whole bank, in a fixed order from a fixed seed. */
export function buildQuestions(seed = 20261124) {
  const rand = seeded(seed);
  return [
    ...CONCEPTS.map((c) => mc(rand, c.q, c.options[c.answer], c.options.filter((_, i) => i !== c.answer), c.why)),
    ...bandQuestions(),
    ...meaningQuestions(rand),
    ...scenarioQuestions(rand),
    ...severityQuestions(rand, 24),
    ...highestQuestions(rand, 12),
  ];
}
