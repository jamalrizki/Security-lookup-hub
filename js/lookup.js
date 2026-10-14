// Lookup page wiring. All output goes through textContent / el(): nothing
// user-supplied or fetched is ever parsed as HTML.

import { detect, defang, identifyHash } from './detect.js';
import { linksFor } from './links.js';
import { md5, toHex } from './md5.js';
import { CODECS } from './encoding.js';
import { checkPassword } from './pwned.js';

const $ = (id) => document.getElementById(id);
const TYPE_LABELS = { ipv4: 'IPv4 address', ipv6: 'IPv6 address', domain: 'Domain', url: 'URL', email: 'Email address' };
const utf8 = new TextEncoder();

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

function notice(kind, ...children) {
  return el('p', { class: `notice ${kind}` }, ...children);
}

function externalLink(href, ...children) {
  return el('a', { href, target: '_blank', rel: 'noopener noreferrer' }, ...children);
}

async function sha(algo, bytes) {
  return toHex(new Uint8Array(await crypto.subtle.digest(algo, bytes)));
}

// ---------- Search ----------

function renderSearch(raw) {
  const out = $('search-result');
  const d = detect(raw);
  out.replaceChildren();
  if (d.type === 'empty') return;

  if (d.type === 'unknown') {
    out.append(notice('warn', d.error));
    return;
  }

  const shown = d.type === 'url' || d.type === 'domain' ? defang(d.value) : d.value;
  out.append(el('div', { class: 'detected' },
    el('span', { class: 'badge' }, d.label || TYPE_LABELS[d.type] || d.type),
    el('span', { class: 'mono' }, shown)));

  if (d.error) {
    out.append(notice('warn', d.error));
    return;
  }

  out.append(el('h3', {}, 'Open in'));
  out.append(el('ul', { class: 'links' }, ...linksFor(d).map((l) =>
    el('li', {}, externalLink(l.href, el('strong', {}, l.name), el('span', { class: 'what' }, l.what))))));

  if (d.type === 'url') {
    const btn = el('button', { type: 'button', class: 'secondary small' }, `Look up host ${defang(d.host)} instead`);
    btn.addEventListener('click', () => {
      $('search-input').value = d.host;
      renderSearch(d.host);
    });
    out.append(el('p', { class: 'hint' }, btn));
  }
  out.append(el('p', { class: 'hint' },
    'Automatic results from these sources are coming in a later phase. For now each link opens the source’s own report.'));
}

$('search-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  renderSearch($('search-input').value);
});

// Deep links use the fragment (#q=8.8.8.8) so the indicator is never sent to the web server.
function searchFromHash() {
  const q = new URLSearchParams(location.hash.slice(1)).get('q');
  if (q) {
    $('search-input').value = q;
    renderSearch(q);
  }
}
window.addEventListener('hashchange', searchFromHash);
searchFromHash();

// ---------- Password check ----------

$('pw-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const out = $('pw-result');
  const password = $('pw-input').value;
  if (!password) {
    out.replaceChildren();
    return;
  }
  const button = ev.submitter || ev.target.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const count = await checkPassword(password);
    out.replaceChildren(count > 0
      ? notice('bad', el('strong', {}, `Found ${count.toLocaleString()} times in known breaches.`),
        ' Do not use this password anywhere.')
      : notice('ok', el('strong', {}, 'Not found in known breaches.'),
        ' That does not make it strong, only not yet leaked.'));
  } catch (err) {
    out.replaceChildren(notice('warn', `Could not check: ${err.message}`));
  } finally {
    button.disabled = false;
  }
});

$('pw-toggle').addEventListener('click', (ev) => {
  const input = $('pw-input');
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  ev.target.textContent = showing ? 'Show' : 'Hide';
  ev.target.setAttribute('aria-pressed', String(!showing));
});

// ---------- Hash identifier ----------

$('hid-input').addEventListener('input', (ev) => {
  const out = $('hid-result');
  const value = ev.target.value.trim();
  if (!value) {
    out.replaceChildren();
    return;
  }
  const found = identifyHash(value);
  if (!found.length) {
    out.replaceChildren(notice('warn', 'No known hash format matches this length and character set.'));
    return;
  }
  out.replaceChildren(
    el('p', { class: 'hint' }, found.length > 1
      ? 'Possible types, most likely first. Format alone cannot tell these apart.'
      : 'Matches this format:'),
    el('ul', { class: 'candidates' }, ...found.map((h) =>
      el('li', {}, el('strong', {}, h.name), h.note ? el('span', { class: 'note' }, ` — ${h.note}`) : null))));
});

// ---------- Hash calculator ----------

const CALC = [
  ['MD5', async (b) => md5(b)],
  ['SHA-1', (b) => sha('SHA-1', b)],
  ['SHA-256', (b) => sha('SHA-256', b)],
  ['SHA-512', (b) => sha('SHA-512', b)],
];

let calcRun = 0;
async function renderCalc() {
  const run = ++calcRun;
  const bytes = utf8.encode($('calc-input').value);
  const digests = await Promise.all(CALC.map(([, fn]) => fn(bytes)));
  if (run !== calcRun) return; // a newer keystroke already started
  $('calc-result').replaceChildren(...CALC.flatMap(([name], i) => {
    const copy = el('button', { type: 'button', class: 'secondary small', 'aria-label': `Copy ${name}` }, 'Copy');
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(digests[i]);
        copy.textContent = 'Copied';
      } catch {
        copy.textContent = 'Blocked';
      }
      setTimeout(() => { copy.textContent = 'Copy'; }, 1200);
    });
    return [el('dt', {}, name), el('dd', {}, digests[i]), copy];
  }));
}
$('calc-input').addEventListener('input', renderCalc);
renderCalc();

// ---------- Decoder ----------

const codecSelect = $('dec-codec');
for (const [id, c] of Object.entries(CODECS)) codecSelect.append(el('option', { value: id }, c.label));

function runCodec(direction) {
  const codec = CODECS[codecSelect.value];
  const err = $('dec-error');
  try {
    $('dec-output').value = codec[direction]($('dec-input').value);
    err.replaceChildren();
  } catch (e) {
    $('dec-output').value = '';
    err.replaceChildren(notice('warn', e.message));
  }
}
$('dec-encode').addEventListener('click', () => runCodec('encode'));
$('dec-decode').addEventListener('click', () => runCodec('decode'));
$('dec-swap').addEventListener('click', () => {
  $('dec-input').value = $('dec-output').value;
  $('dec-output').value = '';
  $('dec-error').replaceChildren();
});
