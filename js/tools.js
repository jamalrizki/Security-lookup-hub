// Tools glossary: renders data/tools.json, a list of { tool, whatItDoes }.
// The data is maintained separately from this page; everything is shown as text.

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

let tools = [];

function render() {
  const q = $('tools-filter').value.trim().toLowerCase();
  const shown = q ? tools.filter((t) => `${t.tool} ${t.whatItDoes}`.toLowerCase().includes(q)) : tools;
  $('tools-count').textContent = `${shown.length} tools`;
  if (!tools.length) {
    $('tools-list').replaceChildren(el('p', { class: 'empty' }, 'No tools listed yet.'));
    return;
  }
  $('tools-list').replaceChildren(shown.length
    ? el('ul', { class: 'tool-grid' }, ...shown.map((t) => el('li', { class: 'tool-card' },
      el('span', { class: 'tool-letter', 'aria-hidden': 'true' }, t.tool.trim()[0] || '?'),
      el('h3', { class: 'tool-name' }, t.tool),
      el('p', { class: 'tool-desc' }, t.whatItDoes))))
    : el('p', { class: 'empty' }, 'No tools match.'));
}

try {
  const res = await fetch('data/tools.json');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  tools = (Array.isArray(data.tools) ? data.tools : [])
    .filter((t) => t && typeof t.tool === 'string' && typeof t.whatItDoes === 'string')
    .sort((a, b) => a.tool.localeCompare(b.tool, 'en', { sensitivity: 'base', numeric: true }));
  $('tools-filter').addEventListener('input', render);
  render();
} catch (err) {
  $('tools-list').replaceChildren(el('p', { class: 'notice warn' }, `Could not load the glossary: ${err.message}`));
}
