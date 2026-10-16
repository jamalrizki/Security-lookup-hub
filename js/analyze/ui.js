// Small DOM helpers shared by the Analyze tools. All text goes in via
// textContent; nothing pasted is ever parsed as HTML.

import { defang } from '../detect.js';

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (v != null && v !== false) node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children) if (c != null && c !== false) node.append(c);
  return node;
}

export const $ = (id) => document.getElementById(id);
export const notice = (kind, ...children) => el('p', { class: `notice ${kind}` }, ...children);

/** "Look up" opens the hub's own lookup for one value: one click, one lookup. */
export const lookUpLink = (value) => el('a', { href: `./#q=${encodeURIComponent(value)}`, class: 'small-link' }, 'Look up');

export function copyButton(getText, label = 'Copy') {
  const b = el('button', { type: 'button', class: 'secondary small' }, label);
  b.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(getText());
      b.textContent = 'Copied';
    } catch {
      b.textContent = 'Blocked';
    }
    setTimeout(() => { b.textContent = label; }, 1200);
  });
  return b;
}

/** Offers text as a file download, built in the browser (no upload). */
export function download(filename, text, type = 'text/csv') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el('a', { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function rows(pairs) {
  return el('dl', { class: 'facts' }, ...pairs.filter(Boolean).flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v ?? '—')]));
}

export { defang };
