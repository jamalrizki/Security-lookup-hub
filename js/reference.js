// Reference page: renders data/reference.json with a text filter and toggles.

import { guidanceUrl, isHubHref } from './what-now.js';
import { searchPorts, portLabel, secureVersions } from './ports.js';
import { searchAcronyms } from './acronyms.js';

const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

let data;

function matches(site, group, query) {
  if ($('ref-noaccount').checked && site.account !== 'no') return false;
  if ($('ref-lookup').checked && !site.lookup) return false;
  if (!query) return true;
  return [site.name, site.desc, group.title].some((s) => s.toLowerCase().includes(query));
}

// Short labels for the key column; the full wording is in data.accountLegend.
const KEY = { no: 'No account', api: 'API key', yes: 'Account', paid: 'Paid API' };
let tab = 'all';

function row(site) {
  const name = site.url
    ? el('a', { href: site.url, target: '_blank', rel: 'noopener noreferrer' }, site.name)
    : site.name;
  return el('li', { class: 'ref-row' },
    el('span', { class: 'ref-key', title: data.accountLegend[site.account] || site.account }, `${site.lookup ? '\u2605 ' : ''}${KEY[site.account] || site.account}`),
    el('span', { class: 'ref-name' }, name, site.url ? null : el('span', { class: 'hint' }, ' (link not set yet)')),
    el('span', { class: 'ref-desc' }, site.desc));
}

function renderTabs() {
  const tabs = [['all', 'All'], ...data.groups.map((g) => [g.id, g.title])];
  $('ref-tabs').replaceChildren(...tabs.map(([id, label]) => {
    const b = el('button', { type: 'button', class: 'tab', 'aria-pressed': String(tab === id) }, label);
    b.addEventListener('click', () => {
      tab = id;
      renderTabs();
      render();
    });
    return b;
  }));
}

function render() {
  const query = $('ref-filter').value.trim().toLowerCase();
  const groups = data.groups
    .filter((g) => tab === 'all' || g.id === tab)
    .map((g) => ({ g, sites: g.sites.filter((s) => matches(s, g, query)) }))
    .filter(({ sites }) => sites.length);
  const items = groups.flatMap(({ g, sites }) => [
    tab === 'all' ? el('li', { class: 'ref-group-title' }, `${g.title} (${sites.length})`) : null,
    ...sites.map(row),
  ]).filter(Boolean);
  $('ref-list').replaceChildren(items.length ? el('ul', { class: 'rows' }, ...items) : el('p', { class: 'empty' }, 'No sites match.'));
}

// "Where to start": every outside link is looked up in the directory itself,
// so this section can only ever point at sites listed below.
export function siteByName(json, name) {
  for (const g of json.groups) for (const s of g.sites) if (s.name === name) return s;
  return null;
}

function renderWhereToStart() {
  $('wts-list').replaceChildren(...(data.whereToStart || []).map((row) => el('section', { class: 'panel wts-card' },
    el('span', { class: 'num', 'aria-hidden': 'true' }), // number comes from the CSS counter
    el('h3', {}, row.have),
    el('p', { class: 'wts-hub' }, el('span', { class: 'hint' }, 'Try it here first: '),
      ...row.hub.flatMap((h, i) => [i ? ' \u00b7 ' : null, el('a', { href: h.href }, h.label)])),
    el('ul', { class: 'plain-list' }, ...row.sites.map((ref) => {
      const site = siteByName(data, ref.name);
      const name = site?.url ? el('a', { href: site.url, target: '_blank', rel: 'noopener noreferrer' }, site.name) : ref.name;
      return el('li', {}, el('strong', {}, name), ` \u2014 ${ref.when}`);
    })))));
}

// "Already happened? What to do now": fixed first steps from data/what-now.json.
// Links are re-checked here too, so a bad edit never renders as a link.
function renderWhatNow(items) {
  $('wn-list').replaceChildren(...items.map((item) => {
    const links = item.guidance.map((g) => [g, guidanceUrl(g.url)]).filter(([, href]) => href);
    const hub = item.hub.filter((h) => isHubHref(h.href));
    return el('section', { class: 'panel wts-card', id: `what-now-${item.id}`, 'aria-labelledby': `wn-${item.id}-h` },
      el('span', { class: 'num', 'aria-hidden': 'true' }), // number comes from the CSS counter
      el('h3', { id: `wn-${item.id}-h` }, item.title),
      el('ol', { class: 'plain-list' }, ...item.steps.map((s) => el('li', {}, s))),
      hub.length ? el('p', { class: 'wts-hub' }, el('span', { class: 'hint' }, 'On this site: '),
        ...hub.flatMap((h, j) => [j ? ' \u00b7 ' : null, el('a', { href: h.href }, h.label)])) : null,
      links.length ? el('p', { class: 'small' }, el('span', { class: 'hint' }, 'Official guidance: '),
        ...links.flatMap(([g, href], j) => [j ? ' \u00b7 ' : null,
          el('a', { href, target: '_blank', rel: 'noopener noreferrer' }, g.title), ` (${g.by})`])) : null);
  }));
}

async function loadWhatNow() {
  try {
    const res = await fetch('data/what-now.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    renderWhatNow((await res.json()).items || []);
  } catch (err) {
    $('wn-list').replaceChildren(el('p', { class: 'notice warn' }, `Could not load the checklists: ${err.message}`));
  }
}

loadWhatNow();

// "Ports and protocols": data/ports.json, searched in code (js/ports.js).
// A port number from the address (#ports=3389) fills the box, so other pages can link here.
let ports = [];

function portRow(p) {
  const secure = secureVersions(ports, p);
  return el('li', { class: 'ref-row' },
    el('span', { class: 'ref-key' }, portLabel(p)),
    el('span', { class: 'ref-name' }, p.name, el('span', { class: 'hint' }, ` ${p.full}`)),
    el('span', { class: 'ref-desc' }, p.use,
      secure.length ? ` Encrypted version: ${secure.join(' or ')}.` : null,
      p.default ? ' (A common default, not its official assignment.)' : null,
      p.exposed ? el('span', {}, ' ', el('span', { class: 'badge' }, 'Keep off the internet')) : null));
}

function renderPorts() {
  const { results, error, kind } = searchPorts(ports, $('ports-filter').value);
  const shown = $('ports-exposed').checked ? results.filter((p) => p.exposed) : results;
  $('ports-count').textContent = error || (kind === 'all' && !$('ports-exposed').checked ? `${ports.length} common ports.` : `${shown.length} of ${ports.length} match.`);
  $('ports-list').replaceChildren(shown.length
    ? el('ul', { class: 'rows' }, ...shown.map(portRow))
    : el('p', { class: 'empty' }, kind === 'port' && !error
      ? 'Not in this list of common ports. Unlisted ports can be anything; check what is listening on the device itself.'
      : 'No ports match.'));
}

async function loadPorts() {
  try {
    const res = await fetch('data/ports.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    ports = (await res.json()).ports || [];
    const m = location.hash.match(/^#ports=(\d{1,5})$/);
    if (m) {
      $('ports-filter').value = m[1];
      $('ports').scrollIntoView();
    }
    for (const id of ['ports-filter', 'ports-exposed']) $(id).addEventListener('input', renderPorts);
    renderPorts();
  } catch (err) {
    $('ports-list').replaceChildren(el('p', { class: 'notice warn' }, `Could not load the port list: ${err.message}`));
  }
}

loadPorts();

// "Security acronyms": data/acronyms.json, searched in code (js/acronyms.js).
// An acronym from the address (#acronyms=XSS) fills the box, so other pages can link here.
let acronyms = [];

function acronymRow(a) {
  return el('li', { class: 'ref-row' },
    el('span', { class: 'ref-key' }, a.acronym),
    el('span', { class: 'ref-name' }, a.full),
    el('span', { class: 'ref-desc' }, a.plain));
}

function renderAcronyms() {
  const { results, kind } = searchAcronyms(acronyms, $('acronyms-filter').value);
  if (kind === 'empty') {
    $('acronyms-count').textContent = `${acronyms.length} acronyms. Type one to see what it means.`;
    $('acronyms-list').replaceChildren();
    return;
  }
  $('acronyms-count').textContent = `${results.length} of ${acronyms.length} match.`;
  $('acronyms-list').replaceChildren(results.length
    ? el('ul', { class: 'rows' }, ...results.map(acronymRow))
    : el('p', { class: 'empty' }, 'Not in this list. Try the NIST glossary at csrc.nist.gov/glossary, or ask on the Ask page.'));
}

async function loadAcronyms() {
  try {
    const res = await fetch('data/acronyms.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    acronyms = (await res.json()).acronyms || [];
    const m = location.hash.match(/^#acronyms=([A-Za-z0-9%&/ .+-]{1,60})$/);
    if (m) {
      let q = m[1];
      try { q = decodeURIComponent(q); } catch { /* keep as typed */ }
      $('acronyms-filter').value = q.slice(0, 60);
      $('acronyms').scrollIntoView();
    }
    $('acronyms-filter').addEventListener('input', renderAcronyms);
    renderAcronyms();
  } catch (err) {
    $('acronyms-list').replaceChildren(el('p', { class: 'notice warn' }, `Could not load the acronym list: ${err.message}`));
  }
}

loadAcronyms();

try {
  const res = await fetch('data/reference.json');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  data = await res.json();
  for (const id of ['ref-filter', 'ref-noaccount', 'ref-lookup']) $(id).addEventListener('input', render);
  renderWhereToStart();
  renderTabs();
  render();
} catch (err) {
  $('ref-list').replaceChildren(el('p', { class: 'notice warn' }, `Could not load the directory: ${err.message}`));
}
