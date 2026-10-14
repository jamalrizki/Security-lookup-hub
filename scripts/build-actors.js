// Builds data/actors.json from MITRE's Enterprise ATT&CK STIX bundle.
//
//   curl -sSo /tmp/enterprise-attack.json \
//     https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
//   node scripts/build-actors.js /tmp/enterprise-attack.json
//
// The bundle (~55 MB) is never committed; only the small extract is.

import { readFileSync, writeFileSync } from 'node:fs';
import { attribute } from './attribution.js';

const SOURCE_URL = 'https://github.com/mitre-attack/attack-stix-data';
const OUT = new URL('../data/actors.json', import.meta.url);
const overrides = JSON.parse(readFileSync(new URL('./attribution-overrides.json', import.meta.url), 'utf8'));

// Sectors named in a group's description. Matched loosely, so the page labels
// them "sectors mentioned" rather than a definitive targeting list.
const SECTORS = [
  ['Government', /\bgovernment(s|al)?\b(?![- ]sponsored|[- ]backed)|\bministr(y|ies)\b|\bdiplomat/i],
  ['Defense and military', /\bdefen[cs]e\b|\bmilitary\b(?! intelligence| unit)/i],
  ['Financial', /\bbank(s|ing)?\b|\bfinance\b|\bfinancial (institution|sector|services|industr|organi[sz]ation|entit)/i],
  ['Cryptocurrency', /\bcrypto(currency)?\b|\bblockchain\b/i],
  ['Healthcare', /\bhealth ?care\b|\bhospitals?\b|\bmedical\b|\bpharma/i],
  ['Energy', /\benergy\b|\boil\b|\bgas\b|\bpetro|\belectric|\bnuclear\b/i],
  ['Telecommunications', /\btelecom/i],
  ['Technology', /\btechnology\b|\bhigh[- ]tech\b|\bIT (service|compan|provider)|\bsoftware (compan|vendor|developer)|\bsemiconductor/i],
  ['Education and research', /\buniversit|\beducation|\bacadem|\bresearch (institut|organi[sz]ation|cent)|\bthink tank/i],
  ['Manufacturing', /\bmanufactur/i],
  ['Aerospace and aviation', /\baerospace\b|\baviation\b|\bairline|\bsatellite/i],
  ['Media and journalists', /\bmedia\b|\bjournalist|\bnews\b/i],
  ['NGOs and activists', /\bNGOs?\b|\bnon-?governmental|\bnon-?profit|\bactivist|\bdissident|\bhuman rights/i],
  ['Retail and hospitality', /\bretail|\bhospitality|\brestaurant|\bhotel|\bpoint[- ]of[- ]sale|\bpayment card/i],
  ['Transportation and logistics', /\btransportation|\blogistic|\bshipping|\bmaritime/i],
  ['Critical infrastructure', /\bcritical infrastructure|\bindustrial control|\bICS\b|\butilit(y|ies)\b|\bwater (utilit|treatment|sector|facilit|suppl)/i],
  ['Legal', /\blaw firm|\blegal\b/i],
  ['Elections and politics', /\belection|\bpolitical (part|campaign|organi[sz]ation)/i],
];

const clean = (s = '') => s
  .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // markdown links to plain text
  .replace(/\(Citation:[^)]*\)/g, '')
  .replace(/<\/?code>/g, '')
  .replace(/[ \t]+/g, ' ')
  .replace(/ ([.,;:])/g, '$1')
  .trim();

const attackId = (obj) => obj.external_references?.find((r) => r.source_name === 'mitre-attack')?.external_id;
const live = (obj) => obj && !obj.revoked && !obj.x_mitre_deprecated;

function main(path) {
  if (!path) {
    console.error('usage: node scripts/build-actors.js <enterprise-attack.json>');
    process.exit(2);
  }
  const objects = JSON.parse(readFileSync(path, 'utf8')).objects;
  const byId = new Map(objects.map((o) => [o.id, o]));
  const collection = objects.find((o) => o.type === 'x-mitre-collection');

  // Techniques: sub-techniques get their parent's name as a prefix.
  const patterns = objects.filter((o) => o.type === 'attack-pattern' && live(o));
  const patternName = new Map(patterns.map((p) => [attackId(p), p.name]));
  const techniqueLabel = (id) => (id.includes('.') ? `${patternName.get(id.split('.')[0])}: ${patternName.get(id)}` : patternName.get(id));

  const uses = new Map();
  for (const r of objects) {
    if (r.type !== 'relationship' || r.relationship_type !== 'uses' || !live(r)) continue;
    const src = byId.get(r.source_ref);
    const dst = byId.get(r.target_ref);
    if (src?.type !== 'intrusion-set' || !live(dst)) continue;
    if (!uses.has(src.id)) uses.set(src.id, { techniques: new Set(), software: new Set() });
    if (dst.type === 'attack-pattern') uses.get(src.id).techniques.add(attackId(dst));
    else if (dst.type === 'malware' || dst.type === 'tool') uses.get(src.id).software.add(dst.id);
  }

  const techniques = {};
  const software = {};
  const usedOverrides = new Set();
  const groups = objects
    .filter((o) => o.type === 'intrusion-set' && live(o))
    .map((g) => {
      const description = clean(g.description);
      let { countries, evidence } = attribute(description.replace(/\s+/g, ' '));
      const override = overrides[g.name];
      if (override) {
        usedOverrides.add(g.name);
        if (override.evidence && !description.replace(/\s+/g, ' ').includes(override.evidence)) {
          throw new Error(`Override evidence for ${g.name} is not in MITRE's description. Re-check the quote.`);
        }
        ({ countries, evidence } = override);
      }
      const u = uses.get(g.id) || { techniques: new Set(), software: new Set() };
      const techIds = [...u.techniques].filter(Boolean).sort();
      for (const id of techIds) techniques[id] = techniqueLabel(id);
      const sw = [...u.software].map((ref) => {
        const s = byId.get(ref);
        const id = attackId(s);
        software[id] = { name: s.name, type: s.type };
        return id;
      }).sort((a, b) => software[a].name.localeCompare(software[b].name));
      const id = attackId(g);
      return {
        id,
        name: g.name,
        url: `https://attack.mitre.org/groups/${id}/`,
        aliases: (g.aliases || []).filter((a) => a !== g.name),
        countries,
        evidence,
        sectors: SECTORS.filter(([, re]) => re.test(description.split(g.name).join(''))).map(([name]) => name),
        summary: description.split(/\n\s*\n/)[0],
        techniques: techIds,
        software: sw,
        modified: g.modified.slice(0, 10),
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }));

  const unused = Object.keys(overrides).filter((k) => !k.startsWith('_') && !usedOverrides.has(k));
  if (unused.length) console.warn(`Warning: overrides for groups not in this release: ${unused.join(', ')}`);

  const out = {
    source: {
      name: 'MITRE ATT&CK Enterprise',
      version: collection?.x_mitre_version ?? null,
      modified: collection?.modified?.slice(0, 10) ?? null,
      url: SOURCE_URL,
      license: 'ATT&CK® content © The MITRE Corporation, used under the ATT&CK Terms of Use.',
    },
    techniques,
    software,
    groups,
  };
  writeFileSync(OUT, `${JSON.stringify(out)}\n`);

  const counts = {};
  for (const g of groups) for (const c of g.countries.length ? g.countries : ['(not attributed)']) counts[c] = (counts[c] || 0) + 1;
  console.log(`ATT&CK v${out.source.version}: ${groups.length} groups, ${Object.keys(techniques).length} techniques, ${Object.keys(software).length} software`);
  console.log(Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(', '));
}

main(process.argv[2]);
