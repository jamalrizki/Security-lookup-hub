// Every page must request css/style.css, js/nav.js and js/chrome.js with the content hash of
// the current files, so browsers never pair a new page with an old cached copy.
// If this fails, run: python3 scripts/nav.py
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';

const root = new URL('../', import.meta.url);
const hash = (p) => createHash('sha256').update(readFileSync(new URL(p, root))).digest('hex').slice(0, 10);

test('pages reference the current CSS and nav script versions', () => {
  const pages = readdirSync(root).filter((f) => f.endsWith('.html'));
  assert.ok(pages.length >= 7);
  for (const asset of ['css/style.css', 'js/nav.js', 'js/chrome.js', 'js/analytics.js']) {
    const want = `${asset}?v=${hash(asset)}`;
    for (const page of pages) {
      const html = readFileSync(new URL(page, root), 'utf8');
      assert.ok(html.includes(`"${want}"`), `${page} should reference ${want}; run python3 scripts/nav.py`);
    }
  }
});

test('every page has link-preview tags pointing at a real 1200x630 image, and icons', () => {
  const png = readFileSync(new URL('images/og-image.png', root));
  assert.equal(png.toString('ascii', 1, 4), 'PNG');
  assert.deepEqual([png.readUInt32BE(16), png.readUInt32BE(20)], [1200, 630], 'og-image size');
  for (const icon of ['favicon.svg', 'favicon-32.png', 'apple-touch-icon.png']) assert.ok(readFileSync(new URL(icon, root)).length > 0, icon);
  for (const page of readdirSync(root).filter((f) => f.endsWith('.html'))) {
    const html = readFileSync(new URL(page, root), 'utf8');
    const meta = (prop) => new RegExp(`<meta (?:property|name)="${prop}" content="([^"]+)"`).exec(html)?.[1];
    for (const prop of ['og:title', 'og:description', 'og:url', 'og:image', 'description', 'twitter:card']) assert.ok(meta(prop), `${page}: ${prop}`);
    // Facebook and LinkedIn need absolute https URLs.
    assert.match(meta('og:image'), /^https:\/\/jamalrizki\.github\.io\/Security-lookup-hub\/images\/og-image\.png$/, page);
    assert.match(meta('og:url'), /^https:\/\/jamalrizki\.github\.io\/Security-lookup-hub\//, page);
    assert.ok(meta('description').length <= 200, `${page}: description too long`);
    assert.equal((html.match(/rel="icon"/g) || []).length, 2, `${page}: one SVG and one PNG icon`);
  }
});

test('every page loads Google Analytics through a CSP that allows only its documented domains', () => {
  for (const page of readdirSync(root).filter((f) => f.endsWith('.html'))) {
    const html = readFileSync(new URL(page, root), 'utf8');
    assert.ok(html.includes('src="https://www.googletagmanager.com/gtag/js?id=G-26NLWZWCNN"'), `${page}: GA loader`);
    assert.ok(!/<script>(?!<\/script>)/.test(html), `${page}: no inline scripts`);
    const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
    assert.match(csp, /script-src 'self' https:\/\/www\.googletagmanager\.com;/, page);
    assert.ok(!csp.includes('unsafe-inline'), `${page}: no unsafe-inline`);
  }
  const snippet = readFileSync(new URL('js/analytics.js', root), 'utf8');
  assert.match(snippet, /page_location: location\.origin \+ location\.pathname \+ location\.search/, 'fragment (#q=...) is never sent');
});


test('Matrix palette: green accent and tokens; severity colours (neon orange, yellow and cyan; red as before); no red tints left; theme-color on every page', () => {
  const css = readFileSync(new URL('css/style.css', root), 'utf8');
  const token = (name) => new RegExp(`--${name}: ([^;]+);`).exec(css)[1];
  assert.equal(token('accent'), '#00ff41');
  assert.equal(token('bg'), '#000');
  assert.equal(token('on-accent'), '#000');
  for (const [name, value] of [['critical', '#ff3344'], ['high', '#ff8c1a'], ['medium', '#ffe600'], ['low', '#00e5ff'], ['ok', '#00e5ff'], ['warn', '#ffe600'], ['bad', '#ff3344']]) {
    assert.equal(token(name), value, `--${name}`);
  }
  assert.ok(!css.includes('rgba(255, 51, 68'), 'no hard-coded red tints');
  assert.ok(!/\.hero-fill \{[^}]*text-shadow/.test(css), 'no glow on the title fill (it clipped into a block)');
  assert.match(css, /@media \(prefers-reduced-motion: reduce\) \{[^}]*\.rain, \.radar-sweep, \.radar-ring \{ display: none; \}/);
  for (const page of readdirSync(root).filter((f) => f.endsWith('.html'))) {
    assert.ok(readFileSync(new URL(page, root), 'utf8').includes('<meta name="theme-color" content="#000000">'), page);
  }
});
