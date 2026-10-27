// "Already happened? What to do now" on the Reference page (data/what-now.json).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { guidanceUrl, isHubHref, GUIDANCE_HOSTS } from '../js/what-now.js';

const root = new URL('../', import.meta.url);
const { items } = JSON.parse(readFileSync(new URL('data/what-now.json', root), 'utf8'));

test('checklists cover the beginner situations, with short plain steps', () => {
  assert.deepEqual(items.map((i) => i.id),
    ['clicked-link', 'typed-password', 'opened-file', 'remote-access', 'paid-scammer', 'account-hacked', 'data-exposed']);
  const titles = new Set(items.map((i) => i.title));
  for (const item of items) {
    assert.match(item.id, /^[a-z]+(-[a-z]+)*$/);
    assert.ok(item.title.length > 10 && item.title.length <= 60, item.id);
    assert.ok(item.steps.length >= 3 && item.steps.length <= 7, `${item.id}: 3-7 steps`);
    for (const s of item.steps) {
      assert.equal(typeof s, 'string');
      assert.ok(s.length >= 20 && s.length <= 200, `${item.id}: step length: ${s}`);
      assert.ok(!/[<>]/.test(s), `${item.id}: no markup in steps`);
      // A step that points at another card must name a real card title.
      for (const [, ref] of s.matchAll(/follow "([^"]+)"/g)) assert.ok(titles.has(ref), `${item.id}: unknown card "${ref}"`);
    }
    assert.ok(item.guidance.length >= 1 && item.guidance.length <= 3, `${item.id}: 1-3 guidance links`);
  }
});

test('official guidance links are https on government hosts only', () => {
  for (const item of items) {
    for (const g of item.guidance) {
      assert.ok(g.title && g.by, `${item.id}: guidance needs title and publisher`);
      assert.equal(guidanceUrl(g.url), g.url, `${item.id}: ${g.url} is not an allowed guidance link`);
    }
  }
  for (const host of GUIDANCE_HOSTS) assert.match(host, /(\.gov|\.gov\.uk)$/);
  assert.equal(guidanceUrl('http://consumer.ftc.gov/x'), null);
  assert.equal(guidanceUrl('https://consumer.ftc.gov.evil.example/x'), null);
  assert.equal(guidanceUrl('https://user@www.ncsc.gov.uk/'), null);
  assert.equal(guidanceUrl('https://www.ncsc.gov.uk:8443/'), null);
  assert.equal(guidanceUrl('javascript:alert(1)'), null);
  assert.equal(guidanceUrl('not a url'), null);
});

test('hub links point at pages and anchors that exist', () => {
  assert.equal(isHubHref('javascript:alert(1)'), false);
  assert.equal(isHubHref('https://example.com/'), false);
  assert.equal(isHubHref('//example.com/'), false);
  for (const item of items) {
    for (const h of item.hub) {
      assert.ok(h.label, item.id);
      assert.ok(isHubHref(h.href), `${item.id}: ${h.href}`);
      const [path, anchor] = h.href.slice(2).split('#');
      const page = path || 'index.html';
      assert.ok(existsSync(new URL(page, root)), `${item.id}: ${page} missing`);
      if (anchor) assert.ok(readFileSync(new URL(page, root), 'utf8').includes(`id="${anchor}"`), `${item.id}: #${anchor} missing in ${page}`);
    }
  }
});

test('the Reference page has the section, and Ask can link to it and to the password check', () => {
  const html = readFileSync(new URL('reference.html', root), 'utf8');
  assert.ok(html.includes('id="what-now"') && html.includes('id="wn-list"'));
  const features = JSON.parse(readFileSync(new URL('data/hub-features.json', root), 'utf8')).features;
  const byId = Object.fromEntries(features.map((f) => [f.id, f.href]));
  assert.equal(byId['what-now'], './reference.html#what-now');
  assert.equal(byId.password, './lookup.html#password');
});
