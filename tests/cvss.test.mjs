// CVSS reader (js/cvss.js, js/analyze/cvss.js): base scores from FIRST's
// CVSS 3.x equations, pinned to known NVD scores; strict vector validation;
// per-metric lines and "what would lower it" computed by the same function.
// The full 3.0 and 3.1 base space (2 × 2,592 vectors) was also cross-checked
// once against an independent implementation (the `cvss` Python package by
// Red Hat): 0 differences. The pins below keep that true.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { installDom, settle } from './helpers/dom.mjs';
import {
  parseVector, baseScore, readVector, explainMetrics, working, roundup31, roundup30, severityOf,
  BASE_METRICS, MAX_VECTOR, describeCvss,
} from '../js/cvss.js';
import { describeCvss as workerDescribe } from '../worker/src/cve.js';

const root = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, root), 'utf8');

// Known scores: the CVE-tagged ones are NVD's published scores; the rest are
// the standard results for those vectors (same as NVD's calculator).
const KNOWN = [
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'Critical'], // CVE-2021-44228 (Log4Shell)
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'Critical'], // e.g. CVE-2024-4577
  ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8, 'High'],
  ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8, 'High'], // typical local privilege escalation
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5, 'High'], // typical remote DoS
  ['CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 6.8, 'Medium'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, 'Medium'], // typical reflected XSS
  ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9, 'Medium'],
  ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N', 6.4, 'Medium'], // typical stored XSS
  ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H', 5.5, 'Medium'],
  ['CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 2.0, 'Low'],
  ['CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.8, 'Low'],
  ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6, 'Low'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0, 'None'],
  ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'Critical'],
  ['CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 8.8, 'High'],
];

test('known vectors score as NVD publishes them', () => {
  for (const [v, score, severity] of KNOWN) {
    const r = readVector(v);
    assert.equal(r.error, undefined, v);
    assert.equal(r.score, score, v);
    assert.equal(r.severity, severity, v);
  }
});

test('Scope Changed uses the higher PR weights and the 1.08 multiplier; scores cap at 10', () => {
  const u = baseScore(parseVector('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H').metrics);
  const c = baseScore(parseVector('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H').metrics);
  assert.equal(u.weights.PR, 0.62);
  assert.equal(c.weights.PR, 0.68);
  assert.equal(baseScore(parseVector('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H').metrics).weights.PR, 0.5);
  assert.equal(c.score, 9.9);
  const log4j = readVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
  assert.equal(log4j.capped, true);
  assert.equal(log4j.impact.toFixed(2), '6.05');
  assert.equal(log4j.exploitability.toFixed(2), '3.89');
});

test('Roundup: 3.1 avoids float noise, 3.0 is a plain ceiling', () => {
  assert.equal(roundup31(4.02), 4.1);
  assert.equal(roundup31(4.0), 4.0);
  assert.equal(roundup31(0.1 + 0.2), 0.3); // 0.30000000000000004
  assert.equal(roundup30(0.1 + 0.2), 0.4); // the float-noise bug 3.1 fixed
  assert.equal(roundup31(9.9999999), 10);
});

test('severity bands follow the CVSS 3.x qualitative scale', () => {
  assert.deepEqual([0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10].map(severityOf),
    ['None', 'Low', 'Low', 'Medium', 'Medium', 'High', 'High', 'Critical', 'Critical']);
});

test('every legal value of every base metric parses', () => {
  const base = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' };
  for (const b of BASE_METRICS) {
    for (const letter of Object.keys(b.values)) {
      const m = { ...base, [b.key]: letter };
      const v = `CVSS:3.1/${BASE_METRICS.map((x) => `${x.key}:${m[x.key]}`).join('/')}`;
      const r = readVector(v);
      assert.equal(r.error, undefined, v);
      assert.equal(r.metrics[b.key], letter);
      assert.ok(r.score >= 0 && r.score <= 10);
      assert.ok(r.lines.find((l) => l.key === b.key).text.length > 5, `${b.key}:${letter} has words`);
    }
  }
});

test('invalid input gets a clear message, never a score', () => {
  const bad = {
    '': /Paste a CVSS vector/,
    'hello': /must start with CVSS:3\.1\//,
    'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H': /must start with CVSS:3\.1\//,
    'CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H': /must start/,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H': /Missing A/,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L': /AV appears more than once/,
    'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H': /AV:X is not allowed; AV takes N, A, L, P/,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:P/S:U/C:H/I:H/A:H': /UI:P is not allowed/,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:Q': /ZZ is not a CVSS 3\.x metric/,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:Z': /E:Z is not allowed/,
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/': /is not a metric:value pair/,
    'CVSS:3.1/av:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H': /is not a metric:value pair/,
    'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N': /CVSS 4\.0 vector.*3\.0 and 3\.1/,
    'AV:N/AC:L/Au:N/C:P/I:P/A:P': /CVSS v2 vector/,
    '(AV:N/AC:L/Au:N/C:P/I:P/A:P)': /CVSS v2 vector/,
    [`CVSS:3.1/${'AV:N/'.repeat(60)}`]: new RegExp(`${MAX_VECTOR} characters at most`),
  };
  for (const [input, msg] of Object.entries(bad)) {
    const r = readVector(input);
    assert.match(r.error ?? '', msg, JSON.stringify(input));
    assert.equal(r.score, undefined);
  }
  assert.equal(readVector('CVSS:4.0/AV:N').unsupported, '4.0');
  assert.equal(readVector(null).error.length > 0, true);
});

test('temporal and environmental metrics are checked, then ignored; the vector is normalised', () => {
  const r = readVector('  CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N/E:P/RL:O/RC:C/MAV:L  ');
  assert.equal(r.score, 9.8);
  assert.deepEqual(r.ignored, ['E', 'RL', 'RC', 'MAV']);
  assert.equal(r.vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
});

test('per-metric lines say what would lower the score, computed by the same function', () => {
  const r = readVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.equal(r.lines.length, 8);
  const av = r.lines.find((l) => l.key === 'AV');
  assert.equal(av.text, 'Can be attacked remotely over the network');
  assert.equal(av.lower.value, 'P');
  assert.equal(av.lower.score, readVector('CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').score);
  for (const l of r.lines) {
    if (!l.lower) continue;
    const m = { ...r.metrics, [l.key]: l.lower.value };
    assert.equal(l.lower.score, baseScore(m).score, l.key);
    assert.ok(l.lower.score < r.score);
  }
  // Already at the lowest value: no suggestion.
  const low = explainMetrics(parseVector('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N').metrics);
  assert.equal(low.find((l) => l.key === 'AV').lower, null);
  assert.equal(low.find((l) => l.key === 'I').lower, null);
  assert.equal(low.find((l) => l.key === 'C').lower.score, 0);
  assert.equal(r.lines.find((l) => l.key === 'S').text, 'The damage stays within the vulnerable component');
});

test('the working shows the formula for the scope and ends at the score', () => {
  const changed = working(readVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'));
  assert.match(changed[1], /Scope Changed.*= 6\.05/);
  assert.match(changed[2], /8\.22 × 0\.85 × 0\.77 × 0\.85 × 0\.85 = 3\.89/);
  assert.match(changed.at(-1), /1\.08 ×.*Roundup\(10\) = 10\.0$/);
  const unchanged = working(readVector('CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'));
  assert.match(unchanged[1], /6\.42 × ISS/);
  assert.match(unchanged.at(-1), /CVSS 3\.0 round-up.* = 1\.8$/);
  assert.match(working(readVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')).at(-1), /base score is 0\.0/);
});

test('the Worker and the reader share one plain-English wording', () => {
  assert.equal(workerDescribe, describeCvss);
  const lines = describeCvss({ attackVector: 'NETWORK', privilegesRequired: 'NONE', scope: 'CHANGED', confidentialityImpact: 'HIGH', integrityImpact: 'LOW', availabilityImpact: 'NONE' });
  assert.deepEqual(lines, [
    'Can be attacked remotely over the network',
    'No login or privileges needed',
    'Can affect resources beyond the vulnerable component',
    'Impact: data exposure high, data tampering limited, service disruption none',
  ]);
});

/* ---------- the page ---------- */

test('the Analyze page has the CVSS reader, it stays in the browser, and Ask can link to it', () => {
  const html = read('analyze.html');
  for (const id of ['cvss', 'cvss-form', 'cvss-input', 'cvss-example', 'cvss-result']) assert.ok(html.includes(`id="${id}"`), id);
  assert.ok(html.includes('<script type="module" src="js/analyze/cvss.js"></script>'));
  assert.ok(html.includes('href="#cvss"'));
  for (const f of ['js/analyze/cvss.js', 'js/cvss.js']) {
    assert.ok(!/innerHTML|localStorage|sessionStorage|fetch\(|XMLHttpRequest|sendBeacon/.test(read(f)), `${f}: textContent only, no storage, no requests`);
  }
  const features = JSON.parse(read('data/hub-features.json')).features;
  assert.equal(features.find((f) => f.id === 'cvss')?.href, './analyze.html#cvss');
});

test('in the page: Read shows the score, each metric and the working; bad input shows the message', async () => {
  const dom = installDom(read('analyze.html'), { url: 'https://jamalrizki.github.io/Security-lookup-hub/analyze.html' });
  try {
    await import('../js/analyze/cvss.js?page=1');
    await settle();
    const $ = (id) => dom.document.getElementById(id);
    $('cvss-example').click();
    let out = $('cvss-result').textContent;
    assert.match(out, /10\.0 Critical/);
    assert.match(out, /Scope \(S:C\)/);
    assert.match(out, /Can affect resources beyond the vulnerable component/);
    assert.match(out, /If it were AV:P/);
    assert.match(out, /would not lower the score \(it is capped at 10\)/);
    assert.match(out, /Exploitability = 8\.22/);
    assert.ok(!/null|undefined/.test(out), 'no stray null when nothing was ignored');
    $('cvss-input').value = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F';
    $('cvss-form').requestSubmit();
    out = $('cvss-result').textContent;
    assert.match(out, /9\.8 Critical/);
    assert.match(out, /Ignored E/);
    $('cvss-input').value = 'CVSS:2.0/AV:N';
    $('cvss-form').requestSubmit();
    assert.match($('cvss-result').textContent, /Not a valid CVSS 3\.x base vector/);
    $('cvss-input').value = ' ';
    $('cvss-form').requestSubmit();
    assert.equal($('cvss-result').textContent, '');
  } finally {
    dom.restore();
  }
});
