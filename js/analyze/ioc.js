// IOC extractor (#ioc). Runs in the browser; only a "Look up" click on one
// value leaves the page. There is deliberately no "look up all": VirusTotal
// allows 4 lookups a minute for the whole site.

import { extractIocs, parseAccessLog, parseAuthLog, SSH_FLAGS, toCsv, MAX_TEXT } from '../extract.js';
import { ready } from './data.js';
import { el, $, notice, lookUpLink, copyButton, download, defang } from './ui.js';
import { providerRanges, rowLabel, RANGES_NOTE } from './provider-ranges.js';

const TYPES = [
  ['url', 'URLs', 'URL'], ['domain', 'Domains', 'domain'], ['ipv4', 'IPv4 addresses', 'IPv4 address'], ['ipv6', 'IPv6 addresses', 'IPv6 address'],
  ['email', 'Email addresses', 'email address'], ['hash', 'Hashes', 'hash'], ['cve', 'CVE IDs', 'CVE ID'],
];
const show = (type, v) => (['url', 'domain', 'email'].includes(type) ? defang(v) : v);

let last = null;

function groupTable(type, label, items) {
  return el('details', { class: 'ioc-group', open: true },
    el('summary', {}, `${label} (${items.length})`),
    el('table', { class: 'ioc-table' },
      el('thead', {}, el('tr', {}, el('th', {}, 'Value'), el('th', {}, 'Count'), el('th', {}, ''))),
      el('tbody', {}, ...items.map((i) => el('tr', {},
        el('td', { class: 'mono' }, show(type, i.value), i.note ? el('span', { class: 'flag warn' }, i.note) : null),
        el('td', {}, String(i.count)),
        el('td', { class: 'actions' }, lookUpLink(i.value), copyButton(() => i.value)))))));
}

function topList(label, items, type) {
  const top = [...items].sort((a, b) => b.count - a.count).slice(0, 10);
  return el('div', {}, el('h3', {}, label), top.length
    ? el('ol', { class: 'plain-list' }, ...top.map((i) => el('li', { class: 'mono' }, `${show(type, i.value)} × ${i.count}`)))
    : el('p', { class: 'hint' }, 'None'));
}

// Top IPs, with a button that labels each row from the provider lists (downloaded
// once, after the click; the IPs stay in the browser).
function topIps(items) {
  const top = [...items].sort((a, b) => b.count - a.count).slice(0, 10);
  if (!top.length) return el('div', {}, el('h3', {}, 'Top IPs'), el('p', { class: 'hint' }, 'None'));
  const labels = top.map(() => el('span', { class: 'net-label hint' }));
  const button = el('button', { type: 'button', class: 'secondary small' }, 'Label top IPs (cloud / Tor)');
  const status = el('p', { class: 'hint', 'aria-live': 'polite' }, RANGES_NOTE);
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      const lists = await providerRanges();
      top.forEach((i, n) => { labels[n].textContent = rowLabel(lists, i.value) ? ` \u2014 ${rowLabel(lists, i.value)}` : ''; });
      status.textContent = 'Labelled from the Tor and AWS / Google Cloud / Cloudflare lists. No label means none of them.';
    } catch (err) {
      status.textContent = err.message;
      button.disabled = false;
    }
  });
  return el('div', {}, el('h3', {}, 'Top IPs'),
    el('ol', { class: 'plain-list' }, ...top.map((i, n) => el('li', { class: 'mono' }, `${i.value} \u00d7 ${i.count}`, labels[n]))),
    el('div', { class: 'row' }, button), status);
}

/** Time range and top statuses, paths and user agents for a recognised access log. */
function accessLogSummary(a) {
  const list = (label, items) => el('div', {}, el('h3', {}, label), items.length
    ? el('ol', { class: 'plain-list' }, ...items.map((i) => el('li', { class: 'mono' }, `${i.value} \u00d7 ${i.count}`)))
    : el('p', { class: 'hint' }, 'None'));
  return el('section', { class: 'access-log' },
    el('h3', {}, 'Access log'),
    el('p', { class: 'hint' }, `${a.matched} of ${a.lines} lines in Apache/nginx format`, a.first ? `, from ${a.first} to ${a.last}.` : '.'),
    el('div', { class: 'tools pair' }, list('Top status codes', a.statuses), list('Top paths (query strings dropped)', a.paths)),
    a.agents.length ? list('Top user agents', a.agents) : null);
}

// A made-up sshd log for practice. Documentation addresses only (RFC 5737 / RFC 3849),
// so nothing here points at a real machine.
export const SSH_SAMPLE = [
  ...['root', 'admin', 'test', 'oracle', 'ubuntu', 'pi'].flatMap((u, i) => [
    `Nov 16 03:12:0${i} web1 sshd[2211]: Invalid user ${u} from 203.0.113.9 port 5012${i}`,
    `Nov 16 03:12:0${i} web1 sshd[2211]: Failed password for invalid user ${u} from 203.0.113.9 port 5012${i} ssh2`,
  ]),
  'Nov 16 03:12:09 web1 sshd[2211]: Connection closed by invalid user pi 203.0.113.9 port 50126 [preauth]',
  ...Array.from({ length: 11 }, (_, i) => `Nov 16 03:40:${String(10 + i * 3).padStart(2, '0')} web1 sshd[2290]: Failed password for deploy from 198.51.100.7 port 4410${i % 10} ssh2`),
  'Nov 16 03:41:02 web1 sshd[2290]: Accepted password for deploy from 198.51.100.7 port 44111 ssh2',
  'Nov 16 08:02:45 web1 sshd[3104]: Accepted publickey for jamie from 2001:db8::25 port 51515 ssh2: ED25519 SHA256:exampleKeyFingerprint',
  'Nov 16 08:15:30 web1 sshd[3120]: Failed password for jamie from 2001:db8::25 port 51600 ssh2',
].join('\n');

const SSH_NEXT = [
  ['Turn off password logins (keys only)', 'https://man.openbsd.org/sshd_config#PasswordAuthentication'],
  ['Stop direct root logins', 'https://man.openbsd.org/sshd_config#PermitRootLogin'],
  ['Block repeat offenders automatically (Fail2ban)', 'https://github.com/fail2ban/fail2ban'],
];
const FLAG_TITLES = { guessing: 'Password guessing from one source', spraying: 'Password spraying', 'accepted-after-failures': 'Worth checking' };

/** Totals, flags (decided in parseAuthLog) and accepted logins for a recognised sshd log. */
function authLogSummary(a) {
  const list = (label, items) => el('div', {}, el('h3', {}, label), items.length
    ? el('ol', { class: 'plain-list' }, ...items.map((i) => el('li', { class: 'mono' }, `${i.value} \u00d7 ${i.count}`)))
    : el('p', { class: 'hint' }, 'None'));
  const acceptedNote = a.acceptedCount > a.accepted.length ? ` (first ${a.accepted.length} shown)` : '';
  const worried = a.flags.some((f) => f.kind === 'accepted-after-failures');
  return el('section', { class: 'auth-log' },
    el('h3', {}, 'SSH logins'),
    el('p', { class: 'hint' }, `${a.matched} of ${a.lines} lines are sshd lines, from ${a.first} to ${a.last} (the log has no year or time zone).`),
    el('p', {}, `${a.failed} failed ${a.failed === 1 ? 'login' : 'logins'}, ${a.acceptedCount} accepted, ${a.invalidUsers} for usernames that don't exist on this server`,
      a.maxAuth ? `, ${a.maxAuth} cut off for too many tries.` : '.'),
    a.flags.length
      ? el('div', {}, ...a.flags.map((f) => notice(f.kind === 'accepted-after-failures' ? 'bad' : 'warn', el('strong', {}, `${FLAG_TITLES[f.kind]}: `), f.reason)))
      : el('p', { class: 'hint' }, `No pattern flagged (a flag needs ${SSH_FLAGS.guessingFailures}+ failures or ${SSH_FLAGS.sprayUsers}+ usernames from one IP, or a login after failures).`),
    el('div', { class: 'tools pair' }, list('Top IPs by failed logins', a.ips), list('Top usernames tried', a.users)),
    el('div', {}, el('h3', {}, `Accepted logins${acceptedNote}`), a.accepted.length
      ? el('ol', { class: 'plain-list' }, ...a.accepted.map((r) => el('li', { class: 'mono' }, `${r.time} \u2014 ${r.user} (${r.method}) from ${r.ip}`)))
      : el('p', { class: 'hint' }, 'None')),
    el('p', { class: 'hint' }, 'Next steps: ',
      ...SSH_NEXT.flatMap(([label, href], i) => [i ? ' \u00b7 ' : '', el('a', { href, target: '_blank', rel: 'noopener noreferrer' }, label)]),
      ...(worried ? [' \u00b7 ', el('a', { href: './reference.html#what-now' }, 'If a login wasn\u2019t you: what to do now')] : [])));
}

async function run() {
  const out = $('ioc-result');
  const text = $('ioc-input').value;
  if (!text.trim()) {
    out.replaceChildren();
    return;
  }
  let psl = null;
  try {
    ({ psl } = await ready);
  } catch {
    out.replaceChildren(notice('warn', 'The domain list could not load, so file names like report.txt may show up as domains.'));
  }
  const logMode = $('ioc-log').checked;
  const r = extractIocs(text, { psl, lineFilter: logMode ? $('ioc-filter').value : '' });
  last = r;
  const parts = [];
  if (text.length > MAX_TEXT) parts.push(notice('warn', `Only the first ${MAX_TEXT / 1024} KB were scanned.`));
  const counts = TYPES.filter(([t]) => r.groups[t]).map(([t, many, one]) => (r.groups[t].length === 1 ? `1 ${one}` : `${r.groups[t].length} ${many.replace(/^(?!URL|IPv|CVE)\w/, (c) => c.toLowerCase())}`));
  parts.push(el('p', {}, r.total ? `Found ${counts.join(', ')}.` : 'No indicators found.'));
  if (r.dropped.length) {
    const byReason = {};
    for (const d of r.dropped) byReason[d.kind] = (byReason[d.kind] || 0) + 1;
    parts.push(el('details', { class: 'more' },
      el('summary', {}, `Left out ${r.dropped.length}: ${Object.entries(byReason).map(([k, v]) => `${v} \u00d7 ${k}`).join('; ')}`),
      el('ul', { class: 'mono-list' }, ...r.dropped.slice(0, 200).map((d) => el('li', {}, `${d.value} — ${d.reason}`)))));
  }
  if (r.total) {
    parts.push(el('div', { class: 'row' },
      copyButton(() => TYPES.flatMap(([t]) => (r.groups[t] || []).map((i) => show(t, i.value))).join('\n'), 'Copy all (defanged)'),
      (() => {
        const b = el('button', { type: 'button', class: 'secondary small' }, 'Download CSV');
        b.addEventListener('click', () => download('iocs.csv', toCsv([['type', 'value', 'count', 'note'],
          ...TYPES.flatMap(([t]) => (r.groups[t] || []).map((i) => [t, i.value, i.count, i.note || '']))])));
        return b;
      })()));
  }
  const access = logMode ? parseAccessLog(text, { lineFilter: $('ioc-filter').value }) : null;
  if (access) parts.push(accessLogSummary(access));
  const auth = logMode && !access ? parseAuthLog(text, { lineFilter: $('ioc-filter').value }) : null;
  if (auth) parts.push(authLogSummary(auth));
  if (logMode && r.total) {
    parts.push(el('div', { class: 'tools pair' },
      topIps([...(r.groups.ipv4 || []), ...(r.groups.ipv6 || [])]),
      topList('Top domains', r.groups.domain || [], 'domain')));
  }
  for (const [t, l] of TYPES) if (r.groups[t]) parts.push(groupTable(t, l, r.groups[t]));
  out.replaceChildren(...parts);
}

$('ioc-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  run();
});
$('ioc-log').addEventListener('change', () => {
  $('ioc-filter-row').hidden = !$('ioc-log').checked;
});
$('ioc-sample').addEventListener('click', () => {
  $('ioc-input').value = SSH_SAMPLE;
  $('ioc-log').checked = true;
  $('ioc-filter-row').hidden = false;
  $('ioc-filter').value = '';
  run();
});
$('ioc-clear').addEventListener('click', () => {
  $('ioc-input').value = '';
  $('ioc-result').replaceChildren();
  last = null;
});

/** Lets other tools (the file analyzer's strings) hand text to the extractor. */
export function sendToExtractor(text) {
  $('ioc-input').value = text;
  location.hash = 'ioc';
  run();
}
export const lastResult = () => last;
