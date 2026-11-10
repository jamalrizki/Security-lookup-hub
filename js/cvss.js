// CVSS: plain-English wording (shared by the Worker's CVE results and the
// Analyze CVSS reader, so the two never disagree) and the CVSS 3.x base-score
// calculator. The score is computed here with FIRST's published equations
// (https://www.first.org/cvss/v3.1/specification-document, section 7 and
// Appendix A); no model ever computes or states a score. DOM-free, so the
// Worker imports it and Node tests it.

// ---------- Plain-English wording (moved from worker/src/cve.js) ----------

export const ATTACK_VECTOR = {
  NETWORK: 'Can be attacked remotely over the network',
  ADJACENT_NETWORK: 'Attacker must be on the same local network segment',
  ADJACENT: 'Attacker must be on the same local network segment',
  LOCAL: 'Attacker needs local access to the machine',
  PHYSICAL: 'Attacker needs physical access to the device',
};
export const COMPLEXITY = {
  LOW: 'Easy to exploit; no special conditions needed',
  HIGH: "Harder to exploit; depends on conditions outside the attacker's control",
};
export const PRIVILEGES = {
  NONE: 'No login or privileges needed',
  LOW: 'Needs a basic user account',
  HIGH: 'Needs an administrator-level account',
};
export const INTERACTION = {
  NONE: 'No user has to do anything',
  REQUIRED: 'A user has to take an action (open a file, click a link)',
  PASSIVE: 'A user is involved only passively',
  ACTIVE: 'A user has to take a deliberate action',
};
export const IMPACT = { NONE: 'none', LOW: 'limited', HIGH: 'high' };
const SCOPE_CHANGED = 'Can affect resources beyond the vulnerable component';
const SCOPE_UNCHANGED = 'The damage stays within the vulnerable component';

/** Plain-English lines for an NVD cvssData object (v3.x or v4.0 field names). */
export function describeCvss(d) {
  const out = [];
  const add = (table, value) => table[value] && out.push(table[value]);
  add(ATTACK_VECTOR, d.attackVector);
  add(COMPLEXITY, d.attackComplexity);
  add(PRIVILEGES, d.privilegesRequired);
  add(INTERACTION, d.userInteraction);
  if (d.attackRequirements === 'PRESENT') out.push('Exploitation depends on specific deployment conditions');
  if (d.scope === 'CHANGED') out.push(SCOPE_CHANGED);
  // CVSS v3.x names these confidentialityImpact; v4.0 names them vulnConfidentialityImpact.
  const c = d.confidentialityImpact ?? d.vulnConfidentialityImpact;
  const i = d.integrityImpact ?? d.vulnIntegrityImpact;
  const a = d.availabilityImpact ?? d.vulnAvailabilityImpact;
  if (c || i || a) {
    out.push(`Impact: data exposure ${IMPACT[c] ?? 'unknown'}, data tampering ${IMPACT[i] ?? 'unknown'}, `
      + `service disruption ${IMPACT[a] ?? 'unknown'}`);
  }
  return out;
}

// ---------- CVSS 3.x base vectors ----------

export const MAX_VECTOR = 200;

/** The eight base metrics, in the order the specification writes them. */
export const BASE_METRICS = [
  { key: 'AV', name: 'Attack Vector', field: 'attackVector', values: { N: 'NETWORK', A: 'ADJACENT_NETWORK', L: 'LOCAL', P: 'PHYSICAL' } },
  { key: 'AC', name: 'Attack Complexity', field: 'attackComplexity', values: { L: 'LOW', H: 'HIGH' } },
  { key: 'PR', name: 'Privileges Required', field: 'privilegesRequired', values: { N: 'NONE', L: 'LOW', H: 'HIGH' } },
  { key: 'UI', name: 'User Interaction', field: 'userInteraction', values: { N: 'NONE', R: 'REQUIRED' } },
  { key: 'S', name: 'Scope', field: 'scope', values: { U: 'UNCHANGED', C: 'CHANGED' } },
  { key: 'C', name: 'Confidentiality', field: 'confidentialityImpact', values: { H: 'HIGH', L: 'LOW', N: 'NONE' } },
  { key: 'I', name: 'Integrity', field: 'integrityImpact', values: { H: 'HIGH', L: 'LOW', N: 'NONE' } },
  { key: 'A', name: 'Availability', field: 'availabilityImpact', values: { H: 'HIGH', L: 'LOW', N: 'NONE' } },
];

// Temporal and environmental metrics are legal in a 3.x vector but don't change
// the base score, so they are checked and then ignored.
const OTHER_METRICS = {
  E: 'XUPFH', RL: 'XOTWU', RC: 'XURC', CR: 'XLMH', IR: 'XLMH', AR: 'XLMH',
  MAV: 'XNALP', MAC: 'XLH', MPR: 'XNLH', MUI: 'XNR', MS: 'XUC', MC: 'XNLH', MI: 'XNLH', MA: 'XNLH',
};

const NOT_VALID = 'Not a valid CVSS 3.x base vector.';

/**
 * Parses and validates a CVSS 3.0/3.1 vector string. Returns
 * { version, metrics: { AV: 'N', … }, vector, ignored: ['E', …] } or { error }.
 */
export function parseVector(input) {
  const raw = String(input ?? '').trim();
  if (!raw) return { error: 'Paste a CVSS vector, like CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H.' };
  if (raw.length > MAX_VECTOR) return { error: `${NOT_VALID} That is too long (${MAX_VECTOR} characters at most).` };
  const v = raw.replace(/^\(|\)$/g, '');
  if (/^CVSS:4\.0\//i.test(v)) return { error: 'This is a CVSS 4.0 vector. Only CVSS 3.0 and 3.1 are supported here for now.', unsupported: '4.0' };
  if (/(^|\/)Au:/.test(v)) return { error: 'This looks like a CVSS v2 vector (it has Au:). Only CVSS 3.0 and 3.1 are supported here.', unsupported: '2.0' };
  const m = /^CVSS:(3\.[01])\/(.*)$/.exec(v);
  if (!m) {
    if (/^AV:/.test(v)) return { error: `${NOT_VALID} It must start with CVSS:3.1/ or CVSS:3.0/ (the version decides the rounding).` };
    return { error: `${NOT_VALID} It must start with CVSS:3.1/ or CVSS:3.0/.` };
  }
  const version = m[1];
  const metrics = {};
  const ignored = [];
  const seen = new Set();
  for (const part of m[2].split('/')) {
    const kv = /^([A-Z]{1,3}):([A-Z])$/.exec(part);
    if (!kv) return { error: `${NOT_VALID} "${part.slice(0, 20)}" is not a metric:value pair.` };
    const [, key, value] = kv;
    if (seen.has(key)) return { error: `${NOT_VALID} ${key} appears more than once.` };
    seen.add(key);
    const base = BASE_METRICS.find((b) => b.key === key);
    if (base) {
      if (!base.values[value]) return { error: `${NOT_VALID} ${key}:${value} is not allowed; ${key} takes ${Object.keys(base.values).join(', ')}.` };
      metrics[key] = value;
    } else if (OTHER_METRICS[key]) {
      if (!OTHER_METRICS[key].includes(value)) return { error: `${NOT_VALID} ${key}:${value} is not allowed.` };
      ignored.push(key);
    } else {
      return { error: `${NOT_VALID} ${key} is not a CVSS 3.x metric.` };
    }
  }
  const missing = BASE_METRICS.filter((b) => !metrics[b.key]).map((b) => b.key);
  if (missing.length) return { error: `${NOT_VALID} Missing ${missing.join(', ')}: all eight base metrics are needed.` };
  return { version, metrics, vector: toVector(version, metrics), ignored };
}

export const toVector = (version, metrics) => `CVSS:${version}/${BASE_METRICS.map((b) => `${b.key}:${metrics[b.key]}`).join('/')}`;

// ---------- Scoring (specification section 7.1 and 7.4) ----------

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};
// Privileges Required weighs more when Scope is Changed.
const prWeight = (pr, scope) => ({ N: 0.85, L: scope === 'C' ? 0.68 : 0.62, H: scope === 'C' ? 0.5 : 0.27 })[pr];

/** CVSS 3.1 Roundup (Appendix A): the smallest one-decimal number >= x, without float noise. */
export function roundup31(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}
/** CVSS 3.0 round up: plain ceiling to one decimal (3.1 replaced it because of float noise). */
export const roundup30 = (x) => Math.ceil(x * 10) / 10;

export function severityOf(score) {
  if (score === 0) return 'None';
  if (score < 4) return 'Low';
  if (score < 7) return 'Medium';
  if (score < 9) return 'High';
  return 'Critical';
}

/** Base score and the working, from validated metrics. */
export function baseScore(metrics, version = '3.1') {
  const { AV, AC, PR, UI, S, C, I, A } = metrics;
  const changed = S === 'C';
  const iss = 1 - (1 - W.CIA[C]) * (1 - W.CIA[I]) * (1 - W.CIA[A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exploitability = 8.22 * W.AV[AV] * W.AC[AC] * prWeight(PR, S) * W.UI[UI];
  const roundup = version === '3.0' ? roundup30 : roundup31;
  let score;
  let sum = null;
  if (impact <= 0) score = 0;
  else {
    sum = changed ? 1.08 * (impact + exploitability) : impact + exploitability;
    score = roundup(Math.min(sum, 10));
  }
  return {
    score,
    severity: severityOf(score),
    iss,
    impact,
    exploitability,
    sum,
    capped: sum !== null && sum > 10,
    weights: {
      AV: W.AV[AV], AC: W.AC[AC], PR: prWeight(PR, S), UI: W.UI[UI], C: W.CIA[C], I: W.CIA[I], A: W.CIA[A],
    },
  };
}

// ---------- Explanation ----------

const METRIC_LINE = {
  AV: (v) => ATTACK_VECTOR[v],
  AC: (v) => COMPLEXITY[v],
  PR: (v) => PRIVILEGES[v],
  UI: (v) => INTERACTION[v],
  S: (v) => (v === 'CHANGED' ? SCOPE_CHANGED : SCOPE_UNCHANGED),
  C: (v) => `Data exposure: ${IMPACT[v]}`,
  I: (v) => `Data tampering: ${IMPACT[v]}`,
  A: (v) => `Service disruption: ${IMPACT[v]}`,
};

/** Plain words for one metric value, e.g. ('AV', 'L') → 'Attacker needs local access to the machine'. */
export function metricText(key, letter) {
  const b = BASE_METRICS.find((m) => m.key === key);
  return METRIC_LINE[key](b.values[letter]);
}

/**
 * One line per base metric, plus the change to that metric alone that would
 * lower the score most (computed, not guessed). lower is null when no other
 * value of that metric gives a lower score.
 */
export function explainMetrics(metrics, version = '3.1') {
  const now = baseScore(metrics, version).score;
  return BASE_METRICS.map((b) => {
    const letter = metrics[b.key];
    let lower = null;
    for (const alt of Object.keys(b.values)) {
      if (alt === letter) continue;
      const s = baseScore({ ...metrics, [b.key]: alt }, version).score;
      if (s < now && (!lower || s < lower.score)) lower = { value: alt, text: metricText(b.key, alt), score: s, severity: severityOf(s) };
    }
    return { key: b.key, name: b.name, value: letter, text: metricText(b.key, letter), lower };
  });
}

/** Everything the reader shows, or { error }. */
export function readVector(input) {
  const p = parseVector(input);
  if (p.error) return p;
  return { ...p, ...baseScore(p.metrics, p.version), lines: explainMetrics(p.metrics, p.version) };
}

/** The working as short lines of text, two decimals (the score itself is exact). */
export function working(r) {
  const f = (x) => x.toFixed(2);
  const w = r.weights;
  const changed = r.metrics.S === 'C';
  const out = [
    `ISS = 1 − (1 − ${w.C}) × (1 − ${w.I}) × (1 − ${w.A}) = ${f(r.iss)}`,
    changed
      ? `Impact (Scope Changed) = 7.52 × (ISS − 0.029) − 3.25 × (ISS − 0.02)^15 = ${f(r.impact)}`
      : `Impact (Scope Unchanged) = 6.42 × ISS = ${f(r.impact)}`,
    `Exploitability = 8.22 × ${w.AV} × ${w.AC} × ${w.PR} × ${w.UI} = ${f(r.exploitability)}`,
  ];
  if (r.sum === null) out.push('Impact is 0 or less, so the base score is 0.0.');
  else {
    const rule = r.version === '3.0' ? 'CVSS 3.0 round-up' : 'CVSS 3.1 Roundup';
    out.push(changed
      ? `Score = ${rule}(min(1.08 × (Impact + Exploitability), 10)) = ${rule}(${r.capped ? '10' : f(r.sum)}) = ${r.score.toFixed(1)}`
      : `Score = ${rule}(min(Impact + Exploitability, 10)) = ${rule}(${r.capped ? '10' : f(r.sum)}) = ${r.score.toFixed(1)}`);
  }
  return out;
}
