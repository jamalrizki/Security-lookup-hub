// CVSS reader (#cvss). Parses a CVSS 3.0/3.1 vector, computes the base score
// with FIRST's equations (js/cvss.js) and explains each metric. Runs in the
// browser only; nothing is sent.

import { readVector, working } from '../cvss.js';

export { readVector };

export const EXAMPLE = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('cvss-form')) {
  const { el, $, notice } = await import('./ui.js');
  const SEV = { None: 'muted', Low: 'ok', Medium: 'warn', High: 'bad', Critical: 'bad' };
  const show = () => {
    const out = $('cvss-result');
    const raw = $('cvss-input').value;
    if (!raw.trim()) { out.replaceChildren(); return; }
    const r = readVector(raw);
    if (r.error) { out.replaceChildren(notice('warn', r.error)); return; }
    out.replaceChildren(...[
      el('p', { class: `verdict ${SEV[r.severity]}` },
        el('strong', {}, `${r.score.toFixed(1)} ${r.severity}`), ` · CVSS ${r.version} base score, computed in your browser`),
      el('p', { class: 'hint mono' }, r.vector),
      r.ignored.length ? el('p', { class: 'hint' }, `Ignored ${r.ignored.join(', ')}: temporal and environmental metrics don't change the base score.`) : null,
      el('h3', {}, 'Each metric'),
      ...r.lines.map((l) => el('p', {},
        el('strong', {}, `${l.name} (${l.key}:${l.value})`), el('br'), l.text, el('br'),
        el('span', { class: 'hint' }, l.lower
          ? `If it were ${l.key}:${l.lower.value} (${l.lower.text.toLowerCase()}): ${l.lower.score.toFixed(1)} ${l.lower.severity}`
          : `Changing this one alone would not lower the score${r.capped ? ' (it is capped at 10)' : ''}.`))),
      el('h3', {}, 'Working'),
      el('pre', { class: 'json' }, working(r).join('\n')),
    ].filter(Boolean));
  };
  $('cvss-form').addEventListener('submit', (ev) => { ev.preventDefault(); show(); });
  $('cvss-input').addEventListener('input', show);
  $('cvss-example').addEventListener('click', () => { $('cvss-input').value = EXAMPLE; show(); });
}
