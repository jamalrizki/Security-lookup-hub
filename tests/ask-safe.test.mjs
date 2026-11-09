// "Not sure something is safe?" links on the Ask home page (index.html, #ask-safe):
// plain routes for beginners to the hub's own checks. Each link must be a hub
// feature (data/hub-features.json), so it points where Ask's [[id]] links point,
// and its anchor must exist on the target page.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, root), 'utf8');
const html = read('index.html');
const features = JSON.parse(read('data/hub-features.json')).features;

const block = html.match(/<div id="ask-safe"[^>]*>([\s\S]*?)<\/div>/);
const links = block ? [...block[1].matchAll(/<a class="chip" href="([^"]+)">([^<]+)<\/a>/g)].map((m) => ({ href: m[1], text: m[2] })) : [];

test('the safe-check links sit in the Ask intro, labelled by their heading', () => {
  assert.ok(block, '#ask-safe is missing from index.html');
  const empty = html.slice(html.indexOf('id="ask-empty"'), html.indexOf('id="ask-top"'));
  assert.ok(empty.includes('id="ask-safe"'), '#ask-safe must be inside #ask-empty, so it hides once a chat starts');
  assert.match(block[0], /role="group" aria-labelledby="ask-safe-h"/);
  assert.match(html, /id="ask-safe-h"[^>]*><strong>Not sure something is safe\?<\/strong>/);
});

test('the safe-check links cover a link, a message, a file, a password and "already happened"', () => {
  assert.deepEqual(links.map((l) => l.href), [
    './analyze.html#link',
    './analyze.html#message',
    './analyze.html#file',
    './lookup.html#password',
    './reference.html#what-now',
  ]);
});

test('each safe-check link is a hub feature and its anchor exists on the target page', () => {
  const hrefs = new Set(features.map((f) => f.href));
  for (const { href, text } of links) {
    assert.ok(hrefs.has(href), `${href} is not an href in data/hub-features.json`);
    assert.ok(text.trim().length > 0 && text.length <= 50, `label too long for a chip: ${text}`);
    const [page, anchor] = href.replace('./', '').split('#');
    assert.ok(read(page).includes(`id="${anchor}"`), `${page} has no id="${anchor}"`);
  }
});

test('the safe-check labels are plain words, no jargon', () => {
  for (const { text } of links) {
    assert.doesNotMatch(text, /\b(IOC|URL|phish|malware|hash|SPF|DKIM|DMARC|breach)\b/i, text);
  }
});
