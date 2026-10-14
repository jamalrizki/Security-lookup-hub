// "View on <source>" links for a detected indicator. Phase 1 shows these on
// their own; from phase 3 each Worker result card uses the matching link.

const e = encodeURIComponent;

const HASH = [
  ['VirusTotal', 'AV detections and behaviour', (h) => `https://www.virustotal.com/gui/file/${h}`],
  ['MalwareBazaar', 'Known sample and family', (h, d) => `https://bazaar.abuse.ch/browse.php?search=${e(`${d.algorithm.replace('-', '').toLowerCase()}:${h}`)}`],
  ['ThreatFox', 'Linked IOCs', (h) => `https://threatfox.abuse.ch/browse.php?search=${e(`ioc:${h}`)}`],
  ['Hybrid Analysis', 'Sandbox reports', (h) => `https://www.hybrid-analysis.com/search?query=${e(h)}`],
  ['AlienVault OTX', 'Community pulses', (h) => `https://otx.alienvault.com/indicator/file/${h}`],
];

const DOMAIN = [
  ['VirusTotal', 'Reputation and relations', (d) => `https://www.virustotal.com/gui/domain/${d}`],
  ['ICANN Lookup', 'Registration date and registrar', (d) => `https://lookup.icann.org/en/lookup?name=${e(d)}`],
  ['crt.sh', 'Certificates and subdomains', (d) => `https://crt.sh/?q=${e(d)}`],
  ['MXToolbox', 'MX, SPF, DMARC, blocklists', (d) => `https://mxtoolbox.com/SuperTool.aspx?action=${e(`mx:${d}`)}&run=toolpage`],
  ['urlscan.io', 'Past scans of this domain', (d) => `https://urlscan.io/domain/${d}`],
  ['URLhaus', 'Malware URLs on this host', (d) => `https://urlhaus.abuse.ch/browse.php?search=${e(d)}`],
  ['Google Safe Browsing', 'Flagged as unsafe?', (d) => `https://transparencyreport.google.com/safe-browsing/search?url=${e(d)}`],
  ['SecurityTrails', 'Historical DNS', (d) => `https://securitytrails.com/domain/${d}/dns`],
  ['AlienVault OTX', 'Community pulses', (d) => `https://otx.alienvault.com/indicator/domain/${d}`],
];

const IP = [
  ['AbuseIPDB', 'Abuse reports and score', (ip) => `https://www.abuseipdb.com/check/${ip}`],
  ['VirusTotal', 'Reputation and relations', (ip) => `https://www.virustotal.com/gui/ip-address/${ip}`],
  ['Shodan', 'Open ports and CVEs', (ip) => `https://www.shodan.io/host/${ip}`],
  ['GreyNoise', 'Internet scanning noise?', (ip) => `https://viz.greynoise.io/ip/${ip}`],
  ['Censys', 'Services and certificates', (ip) => `https://search.censys.io/hosts/${ip}`],
  ['IPinfo', 'Owner, ASN and location', (ip) => `https://ipinfo.io/${ip}`],
];

const URL_LINKS = [
  ['VirusTotal', 'URL reputation', (u) => `https://www.virustotal.com/gui/search/${e(e(u))}`],
  ['URLhaus', 'Known malware URL?', (u) => `https://urlhaus.abuse.ch/browse.php?search=${e(u)}`],
  ['Google Safe Browsing', 'Flagged as unsafe?', (u) => `https://transparencyreport.google.com/safe-browsing/search?url=${e(u)}`],
];

const EMAIL = [
  ['Have I Been Pwned', 'Paste the address on their site (the email API is paid)', () => 'https://haveibeenpwned.com/'],
];

const TABLE = { hash: HASH, domain: DOMAIN, ipv4: IP, ipv6: IP, url: URL_LINKS, email: EMAIL };

/** Returns [{ name, what, href }] for a successful detect() result. */
export function linksFor(detected) {
  const rows = TABLE[detected.type] || [];
  return rows.map(([name, what, build]) => ({ name, what, href: build(detected.value, detected) }));
}
