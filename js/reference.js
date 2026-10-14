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

function card(site) {
  const title = site.url
    ? el('a', { href: site.url, target: '_blank', rel: 'noopener noreferrer' }, site.name)
    : site.name;
  return el('article', { class: 'ref-card' },
    el('h3', {}, title),
    el('p', {}, site.desc),
    el('div', { class: 'ref-meta' },
      el('span', { class: 'badge' }, data.accountLegend[site.account] || site.account),
      site.lookup ? el('span', { class: 'badge star' }, 'Lookup') : null,
      site.url ? null : el('span', { class: 'badge' }, 'Link not set yet')));
}

function render() {
  const query = $('ref-filter').value.trim().toLowerCase();
  const sections = data.groups
    .map((g) => ({ g, sites: g.sites.filter((s) => matches(s, g, query)) }))
    .filter(({ sites }) => sites.length)
    .map(({ g, sites }) => el('section', { class: 'ref-group', 'aria-labelledby': `g-${g.id}` },
      el('h2', { id: `g-${g.id}` }, `${g.title} (${sites.length})`),
      el('div', { class: 'ref-list' }, ...sites.map(card))));
  $('ref-list').replaceChildren(...(sections.length ? sections : [el('p', { class: 'empty' }, 'No sites match.')]));
}

try {
  const res = await fetch('data/reference.json');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  data = await res.json();
  for (const id of ['ref-filter', 'ref-noaccount', 'ref-lookup']) $(id).addEventListener('input', render);
  render();
} catch (err) {
  $('ref-list').replaceChildren(el('p', { class: 'notice warn' }, `Could not load the directory: ${err.message}`));
}
