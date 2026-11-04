// Measures the Analyze message check's code rules on labelled messages nobody wrote
// for this project (the AI read isn't included: it needs the deployed Worker).
//   node scripts/eval-message-check.mjs <path to Dataset_5971.csv> [dev|holdout]
// The data is the SMS Phishing Dataset (Mishra & Soni, Mendeley Data, f45bkkt8pr). It
// isn't committed: the messages are other people's. Each message is put in dev or
// holdout by a hash of its text. Tune rules on dev only; holdout is for reporting.

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { checkMessage, compileSigns, compileTactics } from '../js/analyze/message-check.js';
import { parsePsl } from '../js/extract.js';

const [file, part = 'dev'] = process.argv.slice(2);
if (!file) throw new Error('Usage: node scripts/eval-message-check.mjs <csv> [dev|holdout]');
const read = (f) => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');

/** RFC 4180 rows: quoted fields may hold commas, quotes and newlines. */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') quoted = false; else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(cell); cell = ''; } else if (c === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; } else if (c !== '\r') cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows;
}

const inHoldout = (text) => createHash('sha256').update(text).digest()[0] % 5 === 0; // 20%

const data = JSON.parse(read('data/scam-signs.json'));
const options = { signs: compileSigns(data), tactics: compileTactics(data), psl: parsePsl(read('data/public_suffix_list.dat')), brands: JSON.parse(read('data/brands.json')).brands };

const seen = new Set();
const tally = { smishing: { scam: 0, warning: 0, none: 0 }, ham: { scam: 0, warning: 0, none: 0 } };
const missed = [];
const falseAlarms = [];
for (const [label, rawText] of parseCsv(readFileSync(file, 'latin1')).slice(1)) {
  const kind = label?.trim().toLowerCase();
  const text = rawText?.trim();
  if (!text || !tally[kind] || seen.has(text) || inHoldout(text) !== (part === 'holdout')) continue;
  seen.add(text);
  const r = checkMessage(text, options);
  tally[kind][r.verdict]++;
  if (kind === 'smishing' && r.verdict === 'none') missed.push(text);
  if (kind === 'ham' && r.verdict === 'scam') falseAlarms.push(text);
}

const line = (kind) => {
  const t = tally[kind];
  const n = t.scam + t.warning + t.none;
  const pct = (x) => `${x} (${((100 * x) / (n || 1)).toFixed(1)}%)`;
  return `${kind.padEnd(9)} ${String(n).padStart(5)}  scam ${pct(t.scam)}  warning ${pct(t.warning)}  nothing ${pct(t.none)}`;
};
console.log(`[${part}]`);
console.log(line('smishing'));
console.log(line('ham'));
if (part === 'dev') {
  console.log('--- normal messages called scam');
  for (const t of falseAlarms.slice(0, 15)) console.log(' ', t.slice(0, 140));
  console.log('--- scams with nothing found (sample)');
  for (let i = 0; i < 25 && i < missed.length; i++) console.log(' ', missed[Math.floor((i * missed.length) / 25)].slice(0, 140));
}
