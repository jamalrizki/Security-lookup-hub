// Suspicious-link inspector and lookalike detector (#link). The URL is only
// parsed as text: this page never opens or fetches it.

import { inspectUrl } from '../extract.js';
import { ready } from './data.js';
import { el, $, notice, rows, lookUpLink, defang } from './ui.js';

function render(r) {
  if (r.error) return [notice('bad', r.error)];
  const parts = [
    el('div', { class: 'detected' }, el('span', { class: 'badge' }, 'URL'), el('span', { class: 'mono' }, defang(r.url))),
    r.reasons.length
      ? el('div', { class: 'verdict bad' }, el('strong', {}, 'Suspicious'), el('ul', { class: 'plain-list' }, ...r.reasons.map((x) => el('li', {}, x))))
      : el('p', { class: 'verdict ok' }, el('strong', {}, 'Looks normal'), ' — no warning signs in the link itself. That doesn’t make the site safe.'),
    ...r.notes.map((n) => el('p', { class: 'hint' }, n)),
    rows([
      ['Scheme', r.scheme],
      ['Real host', el('span', { class: 'mono' }, r.hostUnicode !== r.host ? `${r.hostUnicode} (${r.host})` : r.host)],
      ['Registrable domain', r.registrable ? el('span', { class: 'mono' }, r.registrable) : r.ipHost ? 'IP address' : 'Unknown'],
      r.userinfo ? ['Before "@"', el('span', { class: 'mono' }, r.userinfo)] : null,
      r.port ? ['Port', r.port] : null,
      ['Path', el('span', { class: 'mono' }, r.path.decoded || '/')],
      r.path.layers > 1 ? ['Path encoding', `${r.path.layers} layers`] : null,
      r.query.raw ? ['Query (decoded)', el('span', { class: 'mono' }, r.query.decoded)] : null,
      r.query.layers > 1 ? ['Query encoding', `${r.query.layers} layers`] : null,
    ]),
  ];
  if (r.params.length) {
    parts.push(el('details', { class: 'more', open: r.params.some((p) => p.base64 || p.redirect) },
      el('summary', {}, `Parameters (${r.params.length})`),
      el('table', { class: 'ioc-table' },
        el('thead', {}, el('tr', {}, el('th', {}, 'Name'), el('th', {}, 'Value'))),
        el('tbody', {}, ...r.params.map((p) => el('tr', {},
          el('td', { class: 'mono' }, p.name, p.redirect ? el('span', { class: 'flag warn' }, 'redirect') : null),
          el('td', { class: 'mono' }, p.value, p.base64 ? el('div', { class: 'hint' }, `Base64 decodes to: ${p.base64}`) : null)))))));
  }
  for (const n of r.nested) {
    const b = el('button', { type: 'button', class: 'secondary small' }, 'Inspect this nested URL');
    b.addEventListener('click', () => {
      $('link-input').value = n.url;
      inspect();
    });
    parts.push(el('p', {}, `Parameter "${n.param}" points to `, el('span', { class: 'mono' }, defang(n.url)), ' ', b));
  }
  if (r.shortener) {
    parts.push(el('p', { class: 'hint' }, 'To see where a short link goes without opening it yourself, ',
      el('a', { href: 'https://urlscan.io/', target: '_blank', rel: 'noopener noreferrer' }, 'scan it on urlscan.io'),
      ' (their sandbox browser opens it, not you).'));
  }
  if (r.registrable || r.ipHost) parts.push(el('p', { class: 'hint' }, 'Check the host’s reputation: ', lookUpLink(r.ipHost ? r.host : r.registrable)));
  return parts;
}

async function inspect() {
  const raw = $('link-input').value.trim();
  const out = $('link-result');
  if (!raw) {
    out.replaceChildren();
    return;
  }
  let data = {};
  try {
    data = await ready;
  } catch {
    out.replaceChildren(notice('warn', 'The domain lists could not load; lookalike checks are off.'));
  }
  out.replaceChildren(...render(inspectUrl(raw.slice(0, 8192), data)));
}

$('link-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  inspect();
});
