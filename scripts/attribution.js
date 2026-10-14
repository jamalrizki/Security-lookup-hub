// Infers the country a group is attributed to from MITRE's description text.
// ATT&CK has no country field, so this reads attribution phrasing only
// ("assessed as Chinese state-sponsored", "China-based", "on behalf of Iran's
// MOIS") and ignores victim mentions ("targeted ... in China").

export const COUNTRIES = [
  { name: 'China', terms: ["Chinese", "China", "PRC", "People['’]s Republic of China"] },
  { name: 'Russia', terms: ['Russian', 'Russia', 'GRU', 'FSB', 'SVR'] },
  { name: 'Iran', terms: ['Iranian', 'Iran', 'IRGC', 'MOIS'] },
  { name: 'North Korea', terms: ['North Korean', 'North Korea', 'DPRK', "Democratic People['’]s Republic of Korea"] },
  { name: 'Belarus', terms: ['Belarusian', 'Belorussian', 'Belarus'] },
  { name: 'Brazil', terms: ['Brazilian', 'Brazil'] },
  { name: 'India', terms: ['Indian', 'India'] },
  { name: 'Lebanon', terms: ['Lebanese', 'Lebanon'] },
  { name: 'Pakistan', terms: ['Pakistani', 'Pakistan'] },
  { name: 'Palestine (Gaza)', terms: ['Gaza', 'Palestinian'] },
  { name: 'South Korea', terms: ['South Korean', 'South Korea'] },
  { name: 'Turkey', terms: ['Turkish', 'Turkey', 'Türkiye'] },
  { name: 'United Arab Emirates', terms: ['Emirati', 'UAE', 'United Arab Emirates'] },
  { name: 'Vietnam', terms: ['Vietnamese', 'Vietnam'] },
  { name: 'Nigeria', terms: ['Nigerian', 'Nigeria'] },
];

const HEDGE = '(?:(?:suspected|likely|possibly|probable|possible|reportedly|presumed|alleged)\\s+)?';
const ACTOR = '(?:state[- ]sponsored|state[- ]backed|nation[- ]state|government[- ]sponsored|government[- ]backed|' +
  'threat|cyber|espionage|APT|actor|group|hacking|hacker|intelligence|military|ransomware|cybercriminal|criminal|' +
  'financially|politically|wiper|hacktivist|origins?)';
const LINK = '(?:-|\\s)(?:based|nexus|linked|related|sponsored|backed|affiliated|aligned|attributed|origin)';
const AGENCY = '(?:GRU|FSB|SVR|MSS|PLA|IRGC|MOIS|Ministry|General Staff|military|intelligence|government|' +
  'Reconnaissance General Bureau|Islamic Revolutionary Guard|security services|state|interests)';

function patternsFor(term) {
  const t = `(?:the\\s+)?(?:\\(\\s*)?${term}(?:\\s*\\))?`;
  return [
    // "is a suspected Chinese ...", "assessed as Chinese state-sponsored", "believed to be Iranian"
    new RegExp(`\\b(?:is|are|was|as|be|been)\\s+(?:an?\\s+)?${HEDGE}(?:\\w+[- ])?${t}\\b(?![- ](?:speaking))`, 'i'),
    // "Chinese state-sponsored", "North Korean threat group"
    new RegExp(`\\b${t}\\s+${ACTOR}`, 'i'),
    // "China-based", "(DPRK)-based", "Iran-nexus"
    new RegExp(`\\b${t}${LINK}`, 'i'),
    // "based in China", "operate out of China", "located in Iran"
    new RegExp(`\\b(?:based|operat\\w*|located|originat\\w*|work\\w*)\\s+(?:in|out of|from)\\s+${t}\\b`, 'i'),
    // "on behalf of Iran's MOIS", "attributed to Russia's GRU", "linked to Russian ... interests"
    new RegExp(`\\b(?:on behalf of|attributed to|linked to|associated with|tied to|part of|element within|unit of|` +
      `working for|sponsored by|in support of|supports?|serves?|aligned with|connected to|in association with|nexus to)\\s+${t}\\b`, 'i'),
    // "Russia's General Staff", "Iran’s Ministry of Intelligence"
    new RegExp(`\\b${t}['’]s\\s+${AGENCY}`, 'i'),
  ];
}

const COMPILED = COUNTRIES.map((c) => ({ name: c.name, patterns: c.terms.flatMap(patternsFor) }));

// Text right before a match that means the country is a target, not the actor.
const TARGET_CONTEXT = /(?:target\w*|against|victims?|attack\w*|compromis\w*|intrusions?|focus\w*|entities|organi[sz]ations|personnel|interest in|spying on)[^.]{0,60}$/i;

/**
 * Returns { countries: [...], evidence: "sentence" } using only the first
 * sentence or two, where MITRE states attribution.
 */
export function attribute(description) {
  const sentences = description.split(/(?<=[.!?])\s+/).slice(0, 3);
  for (const sentence of sentences) {
    const found = [];
    for (const c of COMPILED) {
      for (const re of c.patterns) {
        const m = re.exec(sentence);
        if (!m) continue;
        const before = sentence.slice(0, m.index);
        if (TARGET_CONTEXT.test(before)) continue;
        found.push(c.name);
        break;
      }
    }
    if (found.length) return { countries: [...new Set(found)], evidence: sentence.trim() };
  }
  return { countries: [], evidence: null };
}
