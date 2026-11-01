// In-hub links (v4): Lookup moved from the home page to lookup.html. Every href in
// the pages, js/ and data/ must point at a page and anchor that exist, nothing may
// still link to ./#q=, and old ./#q= bookmarks are forwarded by js/forward.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, root), 'utf8');
const pages = readdirSync(root).filter((f) => f.endsWith('.html'));
const jsFiles = [
  ...readdirSync(new URL('js/', root)).filter((f) => f.endsWith('.js')).map((f) => `js/${f}`),
  ...readdirSync(new URL('js/analyze/', root)).filter((f) => f.endsWith('.js')).map((f) => `js/analyze/${f}`),
];
const dataFiles = readdirSync(new URL('data/', root)).filter((f) => f.endsWith('.json') && f !== 'actors.json').map((f) => `data/${f}`);

// Ids a page gets from its own script at runtime (rendered sections), keyed by page.
// js/reference.js renders one card per data/what-now.json item, id what-now-<id>.
const RUNTIME_IDS = { 'reference.html': JSON.parse(read('data/what-now.json')).items.map((i) => `what-now-${i.id}`) };

/** Checks one relative href from `from` (a page, or the site root for js/ and data/). */
function checkHref(href, where, fromPage = 'index.html') {
  if (/^(?:https?:|mailto:|data:|blob:|javascript:)/i.test(href) || href.startsWith('//')) return;
  if (/\$\{/.test(href)) return; // template with a dynamic part; checked by the #q= rule below
  const [path, anchor] = href.replace(/^\.\//, '').split('#');
  const page = path === '' ? (href.startsWith('#') ? fromPage : 'index.html') : path;
  if (/\.(?:css|js|svg|png|json|dat|woff2|xml)$/.test(page)) return;
  assert.ok(existsSync(new URL(page, root)), `${where}: ${href} -> ${page} does not exist`);
  if (!anchor || anchor.startsWith('q=') || anchor.startsWith('ask=') || anchor === 'main') return;
  const html = read(page);
  assert.ok(html.includes(`id="${anchor}"`) || (RUNTIME_IDS[page] || []).includes(anchor), `${where}: ${href} -> #${anchor} is not on ${page}`);
}

test('nothing links to the old ./#q= Lookup address', () => {
  for (const f of [...pages, ...jsFiles, ...dataFiles]) {
    if (f === 'js/forward.js') continue; // it forwards them
    const text = read(f);
    assert.ok(!/["'`(]\.\/#q=/.test(text), `${f} still links to ./#q=`);
    assert.ok(!/["'`]\.\/#(?:password|lookup)["'`]/.test(text), `${f} still links to ./#password or ./#lookup`);
  }
});

test('every built #q= link goes to lookup.html', () => {
  for (const f of jsFiles) {
    if (f === 'js/forward.js' || f === 'js/lookup.js') continue; // forward.js forwards; lookup.js reads its own fragment
    for (const m of read(f).matchAll(/['"`]([^\s"'`]*)#q=/g)) {
      assert.match(m[1], /\.\/lookup\.html$/, `${f}: ${m[0]}`);
    }
  }
});

test('every href in the pages, js/ and data/ points to a page and anchor that exist', () => {
  for (const page of pages) {
    for (const [, href] of read(page).matchAll(/\shref="([^"]+)"/g)) checkHref(href, page, page);
  }
  for (const f of jsFiles) {
    for (const [, href] of read(f).matchAll(/href:\s*['`]([^'`]+)['`]/g)) checkHref(href, f);
  }
  for (const f of dataFiles) {
    const walk = (v) => {
      if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) (k === 'href' && typeof x === 'string' ? checkHref(x, f) : walk(x));
    };
    walk(JSON.parse(read(f)));
  }
});

test('the Lookup page has Lookup and the panels; the Ask page has no Lookup code', () => {
  const lookup = read('lookup.html');
  for (const id of ['lookup', 'search-form', 'search-input', 'dkim-row', 'search-result', 'password', 'pw-form', 'hid-input', 'calc-input', 'dec-codec']) {
    assert.ok(lookup.includes(`id="${id}"`), `lookup.html: #${id}`);
  }
  assert.ok(lookup.includes('<script type="module" src="js/lookup.js"></script>'));
  assert.ok(!lookup.includes('js/ask.js"') && !lookup.includes('id="ask'), 'no Ask on the Lookup page');
  const ask = read('index.html');
  assert.ok(!ask.includes('js/lookup.js') && !ask.includes('id="search-form"'));
  const csp = (html) => /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  assert.ok(csp(lookup).includes('https://api.pwnedpasswords.com'), 'Lookup keeps the password check');
  assert.ok(!csp(ask).includes('pwnedpasswords'), 'Ask only talks to the Worker and Analytics');
  assert.ok(csp(ask).includes('https://security-lookup-hub.jamal-598.workers.dev'));
});

test('nav: Ask first (./), then Lookup, on every page', () => {
  for (const page of pages) {
    const nav = /<nav class="site-nav"[^>]*>([\s\S]*?)<\/nav>/.exec(read(page))[1];
    const links = [...nav.matchAll(/<a href="([^"]+)"[^>]*>([^<]+)<\/a>/g)].map((m) => `${m[2]}=${m[1]}`);
    assert.deepEqual(links, ['Ask=./', 'Lookup=lookup.html', 'Analyze=analyze.html', 'CVEs=cves.html', 'News=news.html', 'Threat actors=actors.html', 'Exposure=exposure.html', 'Reference=reference.html', 'Tools=tools.html'], page);
  }
});

/** Runs js/forward.js against a fake location; returns where it sent the page, or null. */
function forward(hash) {
  let to = null;
  const location = { hash, replace: (u) => { to = u; } };
  new Function('location', read('js/forward.js'))(location);
  return to;
}

test('forward.js: old Lookup fragments go to lookup.html; #ask= and no fragment stay', () => {
  assert.equal(forward('#q=8.8.8.8'), './lookup.html#q=8.8.8.8');
  assert.equal(forward('#q=hxxp%3A%2F%2Fbad%5B.%5Dexample'), './lookup.html#q=hxxp%3A%2F%2Fbad%5B.%5Dexample');
  assert.equal(forward('#password'), './lookup.html#password');
  assert.equal(forward('#lookup'), './lookup.html#lookup');
  assert.equal(forward('#ask=Explain%20CVE-2021-44228'), null);
  assert.equal(forward(''), null);
  assert.equal(forward('#main'), null);
  assert.equal(forward('#passwordx'), null);
});

test('forward.js is a classic script at the top of the Ask page, after the CSP', () => {
  const html = read('index.html');
  const at = html.indexOf('<script src="js/forward.js"></script>');
  assert.ok(at > 0, 'loaded as a classic script (CSP forbids inline scripts)');
  assert.ok(at > html.indexOf('Content-Security-Policy'), 'covered by the CSP');
  assert.ok(at < html.indexOf('<link rel="stylesheet"') && at < html.indexOf('<script type="module"'), 'runs before anything paints');
  assert.ok(!/fetch|XMLHttpRequest|sendBeacon|gtag/.test(read('js/forward.js')), 'never sends the fragment anywhere');
});
