// Reference page: renders data/reference.json with a text filter and toggles.

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
  $('wts-list').replaceChildren(...(data.whereToStart || []).map((row, i) => el('section', { class: 'panel wts-card' },
    el('span', { class: 'num', 'aria-hidden': 'true' }, String(i + 1).padStart(2, '0')),
    el('h3', {}, row.have),
    el('p', { class: 'wts-hub' }, el('span', { class: 'hint' }, 'Try it here first: '),
      ...row.hub.flatMap((h, i) => [i ? ' \u00b7 ' : null, el('a', { href: h.href }, h.label)])),
    el('ul', { class: 'plain-list' }, ...row.sites.map((ref) => {
      const site = siteByName(data, ref.name);
      const name = site?.url ? el('a', { href: site.url, target: '_blank', rel: 'noopener noreferrer' }, site.name) : ref.name;
      return el('li', {}, el('strong', {}, name), ` \u2014 ${ref.when}`);
    })))));
}

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
