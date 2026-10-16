// Threat actors page: renders data/actors.json (built by scripts/build-actors.js).
// Filters live in the URL fragment (#country=China&q=apt) so views can be shared.

const $ = (id) => document.getElementById(id);
const FEATURED = ['China', 'Russia', 'Iran', 'North Korea'];
const ATTACK = 'https://attack.mitre.org';

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

const extLink = (href, text) => el('a', { href, target: '_blank', rel: 'noopener noreferrer' }, text);
const techniqueUrl = (id) => `${ATTACK}/techniques/${id.replace('.', '/')}/`;

let data;
const state = { q: '', country: 'all', sector: '' };

function countryBucket(g) {
  if (!g.countries.length) return ['none'];
  return g.countries.map((c) => (FEATURED.includes(c) ? c : 'other'));
}

function matchesQuery(g, q) {
  if (!q) return true;
  if (/^t\d{4}/.test(q)) return g.techniques.some((t) => t.toLowerCase().startsWith(q));
  const haystack = [g.name, g.id, ...g.aliases, ...g.countries, ...g.software.map((s) => data.software[s].name)];
  return haystack.some((s) => s.toLowerCase().includes(q));
}

function visibleGroups(ignoreCountry = false) {
  return data.groups.filter((g) => matchesQuery(g, state.q)
    && (!state.sector || g.sectors.includes(state.sector))
    && (ignoreCountry || state.country === 'all' || countryBucket(g).includes(state.country)));
}

// ---------- Rendering ----------

function renderChips() {
  const pool = visibleGroups(true);
  const count = (key) => (key === 'all' ? pool.length : pool.filter((g) => countryBucket(g).includes(key)).length);
  const chips = [['all', 'All'], ...FEATURED.map((c) => [c, c]), ['other', 'Other countries'], ['none', 'Not attributed']];
  $('actor-countries').replaceChildren(...chips.map(([key, label]) => {
    const b = el('button', { type: 'button', class: 'chip', 'aria-pressed': String(state.country === key) },
      label, el('span', { class: 'chip-count' }, String(count(key))));
    b.addEventListener('click', () => update({ country: key }));
    return b;
  }));
}

function detailsBody(g) {
  const body = el('div', { class: 'actor-body' });
  body.append(g.evidence
    ? el('blockquote', { class: 'evidence' }, el('span', { class: 'hint' }, 'MITRE: '), `“${g.evidence}”`)
    : el('p', { class: 'hint' }, 'MITRE does not attribute this group to a country.'));

  // The evidence is usually the summary's first sentence; don't show it twice.
  const summary = g.evidence && g.summary.startsWith(g.evidence) ? g.summary.slice(g.evidence.length).trim() : g.summary;
  if (summary) body.append(el('p', {}, summary));

  if (g.sectors.length) {
    body.append(el('h3', {}, 'Sectors mentioned'),
      el('div', { class: 'ref-meta' }, ...g.sectors.map((s) => el('span', { class: 'badge' }, s))));
  }

  if (g.software.length) {
    body.append(el('h3', {}, `Software (${g.software.length})`),
      el('p', { class: 'inline-list' }, ...g.software.flatMap((id, i) => [
        i ? ', ' : null, extLink(`${ATTACK}/software/${id}/`, data.software[id].name)])));
  }

  if (g.techniques.length) {
    body.append(el('h3', {}, `Techniques (${g.techniques.length})`),
      el('ul', { class: 'techniques' }, ...g.techniques.map((id) =>
        el('li', {}, extLink(techniqueUrl(id), id), ` ${data.techniques[id]}`))));
  }

  body.append(el('p', {}, extLink(g.url, `Full profile on MITRE ATT&CK (${g.id}) →`)));
  return body;
}

function actorCard(g) {
  const summary = el('summary', {},
    el('span', { class: 'actor-meta' },
      el('span', { class: 'mono' }, g.id),
      el('span', { class: 'country' }, g.countries.length ? g.countries.join(' \u00b7 ') : 'Not attributed')),
    el('span', { class: 'actor-name' }, g.name),
    g.aliases.length ? el('span', { class: 'aliases' }, `aka ${g.aliases.join(' \u00b7 ')}`) : null,
    el('span', { class: 'actor-cta' }, 'View techniques \u2192'));
  const card = el('details', { class: 'actor' }, summary);
  // Technique lists are long; build the body only when first opened.
  card.addEventListener('toggle', () => {
    if (card.open && card.childElementCount === 1) card.append(detailsBody(g));
  });
  return card;
}

function render() {
  renderChips();
  const groups = visibleGroups();
  $('actor-count').textContent = `${groups.length} of ${data.groups.length} groups`;
  $('actor-list').replaceChildren(...(groups.length
    ? groups.map(actorCard)
    : [el('p', { class: 'empty' }, 'No groups match.')]));
}

// ---------- State and URL fragment ----------

function update(patch) {
  Object.assign(state, patch);
  const params = new URLSearchParams();
  if (state.q) params.set('q', state.q);
  if (state.country !== 'all') params.set('country', state.country);
  if (state.sector) params.set('sector', state.sector);
  const hash = params.toString();
  history.replaceState(null, '', hash ? `#${hash}` : location.pathname);
  render();
}

function readHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  state.q = (p.get('q') || '').toLowerCase();
  state.country = p.get('country') || 'all';
  state.sector = p.get('sector') || '';
  $('actor-filter').value = state.q;
  $('actor-sector').value = state.sector;
}

try {
  const res = await fetch('data/actors.json');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  data = await res.json();

  const sectors = [...new Set(data.groups.flatMap((g) => g.sectors))].sort();
  $('actor-sector').append(...sectors.map((s) => el('option', { value: s }, s)));
  $('actor-filter').addEventListener('input', (ev) => update({ q: ev.target.value.trim().toLowerCase() }));
  $('actor-sector').addEventListener('change', (ev) => update({ sector: ev.target.value }));
  window.addEventListener('hashchange', () => { readHash(); render(); });

  const s = data.source;
  $('actor-source').append(`Data: ${s.name} v${s.version} (${s.modified}). ${s.license} `,
    extLink(`${ATTACK}/resources/legal-and-branding/terms-of-use/`, 'Terms of use'), '.');

  readHash();
  render();
} catch (err) {
  $('actor-list').replaceChildren(el('p', { class: 'notice warn' }, `Could not load threat actor data: ${err.message}`));
}
