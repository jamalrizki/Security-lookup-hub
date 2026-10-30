// My exposure page: data/exposure.json shape and links, and the page in the DOM stand-in.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { isHubHref } from '../js/what-now.js';
import { installDom, settle } from './helpers/dom.mjs';

const root = new URL('../', import.meta.url);
const read = (f) => readFileSync(new URL(f, root), 'utf8');
const DATA = JSON.parse(read('data/exposure.json'));
const LEGEND = Object.keys(JSON.parse(read('data/reference.json')).accountLegend);

test('every section has a title, why, steps and https site links with a known account type', () => {
  assert.ok(DATA.permission.includes('permission'));
  const ids = new Set();
  for (const s of DATA.sections) {
    assert.match(s.id, /^[a-z-]+$/);
    assert.ok(!ids.has(s.id), `${s.id} unique`);
    ids.add(s.id);
    for (const k of ['title', 'why']) assert.ok(typeof s[k] === 'string' && s[k].length > 20, `${s.id}.${k}`);
    assert.ok(s.steps.length >= 2 && s.steps.every((t) => typeof t === 'string' && t.length > 10), `${s.id} steps`);
    assert.ok(s.sites.length >= 1, `${s.id} sites`);
    for (const site of s.sites) {
      const u = new URL(site.url);
      assert.equal(u.protocol, 'https:', site.name);
      assert.ok(!u.username && !u.password, site.name);
      assert.ok(site.desc.length > 10, site.name);
      assert.ok(LEGEND.includes(site.account), `${site.name}: account "${site.account}"`);
    }
    for (const h of s.hub || []) {
      assert.ok(isHubHref(h.href), h.href);
      const file = h.href.replace(/^\.\//, '').split('#')[0] || 'index.html';
      assert.ok(existsSync(new URL(file, root)), h.href);
      const anchor = h.href.split('#')[1];
      if (anchor) assert.ok(read(file).includes(`id="${anchor}"`), h.href);
    }
  }
});

test('WiGLE is explained and linked, not searched: the note says why', () => {
  const wifi = DATA.sections.find((s) => s.id === 'wifi');
  assert.ok(wifi.sites.some((s) => s.url === 'https://wigle.net/'));
  assert.match(wifi.why, /SSID/);
  assert.match(wifi.note, /doesn't search WiGLE/);
  assert.ok(wifi.steps.some((t) => t.includes('_nomap')));
});

let dom;
afterEach(() => {
  dom?.restore();
  dom = null;
  delete globalThis.fetch;
});

test('the page renders every section with outside links opening safely, and sends nothing else', async () => {
  dom = installDom(read('exposure.html'), { url: 'https://jamalrizki.github.io/Security-lookup-hub/exposure.html' });
  const calls = [];
  globalThis.fetch = async (u) => {
    calls.push(String(u));
    return new Response(read(String(u)));
  };
  await import('../js/exposure.js?page=1');
  await settle();
  const $ = (id) => dom.document.getElementById(id);
  assert.deepEqual(calls, ['data/exposure.json'], 'only its own data file');
  assert.equal($('exposure-permission').textContent, DATA.permission);
  const blocks = dom.document.querySelectorAll('section.exposure-block');
  assert.deepEqual(blocks.map((b) => b.id), DATA.sections.map((s) => s.id));
  const outside = dom.document.querySelectorAll('#exposure-list a').filter((a) => a.getAttribute('target') === '_blank');
  assert.equal(outside.length, DATA.sections.reduce((n, s) => n + s.sites.length, 0));
  for (const a of outside) assert.equal(a.getAttribute('rel'), 'noopener noreferrer');
  assert.match($('wifi').textContent, /Crowd-sourced map of Wi-Fi/);
  assert.match($('breaches').textContent, /On this site: Check a password/);
});

test('exposure.html: in the nav as "Exposure", with "My exposure" as its title', () => {
  const html = read('exposure.html');
  assert.match(html, /<a href="exposure\.html" aria-current="page">Exposure<\/a>/);
  assert.match(html, /<span class="hero-outline">My exposure<\/span>/);
  const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
  assert.match(csp, /connect-src 'self' https:\/\/www\.googletagmanager\.com/, 'no Worker or other API');
});
