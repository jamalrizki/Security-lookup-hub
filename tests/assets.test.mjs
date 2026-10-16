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
  for (const asset of ['css/style.css', 'js/nav.js', 'js/chrome.js']) {
    const want = `${asset}?v=${hash(asset)}`;
    for (const page of pages) {
      const html = readFileSync(new URL(page, root), 'utf8');
      assert.ok(html.includes(`"${want}"`), `${page} should reference ${want}; run python3 scripts/nav.py`);
    }
  }
});
