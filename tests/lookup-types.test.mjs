// Lookup's type buttons: data/lookup-types.json against the Worker's plan(), the
// display names, the buttons in lookup.html, and the page wiring (in the DOM stand-in).
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { plan, SOURCES } from '../worker/src/sources.js';
import { detect } from '../js/detect.js';
import { buttonFor, checksText, invalidMessage } from '../js/lookup-types.js';
import { installDom, settle } from './helpers/dom.mjs';

const root = new URL('../', import.meta.url);
const read = (f) => readFileSync(new URL(f, root), 'utf8');
const TYPES = JSON.parse(read('data/lookup-types.json'));
const NAMES = JSON.parse(read('data/source-names.json'));
const byId = Object.fromEntries(TYPES.map((t) => [t.id, t]));
const ids = (value) => plan(detect(value)).map((s) => s.id);

test('each type lists exactly the sources the Worker runs for it', () => {
  assert.deepEqual(byId.ip.sources, ids('8.8.8.8'));
  assert.deepEqual(byId.ip.sources, ids('2001:4860:4860::8888'));
  assert.deepEqual(byId.myip.sources, ids('8.8.8.8'), 'My IP runs the normal IP lookup');
  assert.deepEqual(byId.domain.sources, ids('example.com'));
  assert.deepEqual(byId.hash.sources, ids('44d88612fea8a8f36de82e1278abb02f'));
  assert.deepEqual(byId.email.sources, ids('someone@example.com'));
  assert.deepEqual(byId.cve.sources, ids('CVE-2021-44228'));
  // URL: the URL checks, then the host's, which depend on whether the host is a name or an IP.
  assert.deepEqual([...byId.url.sources, ...byId.url.hostSources.domain], ids('https://example.com/login'));
  assert.deepEqual([...byId.url.sources, ...byId.url.hostSources.ip], ids('http://8.8.8.8/x'));
});

test('every source id has a display name, and the Worker uses the same names', () => {
  for (const t of TYPES) {
    for (const id of [...t.sources, ...Object.values(t.hostSources || {}).flat()]) assert.ok(NAMES[id], `${t.id}: ${id} has a name`);
  }
  for (const [id, s] of Object.entries(SOURCES)) assert.equal(s.name, NAMES[id], id);
});

test('lookup.html has one button per type, same ids, labels and order', () => {
  const buttons = [...read('lookup.html').matchAll(/<button type="button" class="secondary" data-type="([a-z]+)" aria-pressed="(true|false)">([^<]+)<\/button>/g)];
  assert.deepEqual(buttons.map((m) => m[1]), TYPES.map((t) => t.id));
  assert.deepEqual(buttons.map((m) => m[3]), TYPES.map((t) => t.label));
  assert.deepEqual(buttons.filter((m) => m[2] === 'true').map((m) => m[1]), ['myip'], 'My IP is selected on load');
  for (const t of TYPES) assert.ok(t.about && typeof t.placeholder === 'string', t.id);
});

test('helpers: detected type → button, Checks line, invalid message', () => {
  assert.equal(buttonFor('ipv4'), 'ip');
  assert.equal(buttonFor('ipv6'), 'ip');
  assert.equal(buttonFor('hash'), 'hash');
  assert.equal(buttonFor('unknown'), null);
  assert.equal(checksText(byId.ip, NAMES), 'Checks: AbuseIPDB, VirusTotal, URLhaus, Shodan InternetDB, Network owner (RDAP), Network type.');
  assert.equal(checksText(byId.url, NAMES), 'Checks: VirusTotal, URLhaus, then the host: Domain registration (RDAP), DNS records, Certificates (or for an IP host: AbuseIPDB, Shodan InternetDB, Network owner (RDAP), Network type).');
  assert.equal(invalidMessage(byId.hash, detect('not a thing at all')), "That isn't a valid MD5, SHA-1 or SHA-256 hash.");
  // detect()'s specific messages are kept.
  assert.match(invalidMessage(byId.hash, detect('abc@not_valid')), /looks like an email address/);
});

// ---------- Page wiring ----------

let dom;
let loads = 0;

async function loadPage(url = 'https://jamalrizki.github.io/Security-lookup-hub/lookup.html') {
  dom = installDom(read('lookup.html'), { url });
  const calls = [];
  globalThis.fetch = async (input) => {
    const u = String(input);
    if (u.startsWith('data/')) return new Response(read(u));
    calls.push(u);
    return new Response(JSON.stringify({ sources: [], note: 'Nothing to show.' }));
  };
  await import(`../js/lookup.js?page=${++loads}`);
  await settle();
  const $ = (id) => dom.document.getElementById(id);
  const pressed = () => dom.document.querySelectorAll('#type-picker button').filter((b) => b.getAttribute('aria-pressed') === 'true').map((b) => b.getAttribute('data-type'));
  return { $, calls, pressed };
}

const pick = ($, id) => dom.document.querySelector(`#type-picker button[data-type="${id}"]`).click();

afterEach(() => {
  dom?.restore();
  dom = null;
  delete globalThis.fetch;
});

test('page: My IP is selected on load, with Show my IP instead of the box; nothing is looked up', async () => {
  const { $, calls, pressed } = await loadPage();
  assert.deepEqual(pressed(), ['myip']);
  assert.equal($('search-form').hidden, true);
  assert.equal($('myip-row').hidden, false);
  assert.equal($('type-checks').textContent, checksText(byId.myip, NAMES));
  assert.equal($('type-about').textContent, byId.myip.about);
  assert.equal($('dkim-row').hidden, true);
  assert.equal(calls.length, 0);
});

test('page: a #q= IP link switches from My IP to IP address and shows the box', async () => {
  const { $, calls, pressed } = await loadPage('https://jamalrizki.github.io/Security-lookup-hub/lookup.html#q=8.8.8.8');
  assert.deepEqual(pressed(), ['ip']);
  assert.equal($('search-form').hidden, false);
  assert.match(calls[0], /\/api\/lookup\?q=8\.8\.8\.8$/);
});

test('page: each button shows its placeholder, Checks line and extras, and sends nothing', async () => {
  const { $, calls, pressed } = await loadPage();
  for (const t of TYPES) {
    pick($, t.id);
    assert.deepEqual(pressed(), [t.id]);
    assert.equal($('type-checks').textContent, checksText(t, NAMES), t.id);
    assert.equal($('dkim-row').hidden, !['domain', 'email'].includes(t.id), `${t.id}: DKIM row`);
    assert.equal($('search-form').hidden, t.id === 'myip', `${t.id}: box`);
    assert.equal($('myip-row').hidden, t.id !== 'myip', `${t.id}: Show my IP`);
    if (t.id !== 'myip') assert.equal($('search-input').placeholder, t.placeholder);
  }
  assert.equal(calls.length, 0, 'type buttons alone make no request');
});

test('page: Hash selected, 8.8.8.8 pasted runs an IP lookup and switches to IP address', async () => {
  const { $, calls, pressed } = await loadPage();
  pick($, 'hash');
  $('search-input').value = '8.8.8.8';
  $('search-form').requestSubmit();
  await settle();
  assert.deepEqual(pressed(), ['ip']);
  assert.equal(calls.length, 1);
  assert.match(calls[0], /\/api\/lookup\?q=8\.8\.8\.8$/);
});

test('page: #q=CVE-2021-44228 selects CVE and runs it', async () => {
  const { calls, pressed } = await loadPage('https://jamalrizki.github.io/Security-lookup-hub/lookup.html#q=CVE-2021-44228');
  assert.deepEqual(pressed(), ['cve']);
  assert.match(calls[0], /\/api\/lookup\?q=CVE-2021-44228$/);
});

test('page: unrecognised input names the selected type; nothing is sent', async () => {
  const { $, calls } = await loadPage();
  pick($, 'hash');
  $('search-input').value = 'zzz not anything';
  $('search-form').requestSubmit();
  await settle();
  assert.equal($('search-result').textContent, "That isn't a valid MD5, SHA-1 or SHA-256 hash.");
  assert.equal(calls.length, 0);
});

test('page: switching to another type starts a fresh view; the selected type keeps it', async () => {
  const { $, pressed } = await loadPage('https://jamalrizki.github.io/Security-lookup-hub/lookup.html#q=8.8.8.8');
  assert.deepEqual(pressed(), ['ip']);
  assert.ok($('search-result').textContent, 'results showing');
  pick($, 'ip');
  assert.equal($('search-input').value, '8.8.8.8', 'same type: nothing cleared');
  assert.ok($('search-result').textContent);
  pick($, 'domain');
  assert.equal($('search-input').value, '');
  assert.equal($('search-result').textContent, '');
  assert.equal(location.hash, '', '#q= link removed');
});

test('page: a lookup or My IP answer that arrives after switching type is dropped', async () => {
  dom = installDom(read('lookup.html'), { url: 'https://jamalrizki.github.io/Security-lookup-hub/lookup.html' });
  const pending = [];
  globalThis.fetch = async (input) => {
    const u = String(input);
    if (u.startsWith('data/')) return new Response(read(u));
    const body = u.endsWith('/api/my-ip')
      ? { ip: '81.2.69.142', version: 4 }
      : { sources: [{ id: 'internetdb', name: 'Shodan InternetDB', status: 'empty', message: 'Late answer', link: 'https://www.shodan.io/host/8.8.8.8' }] };
    return new Promise((resolve) => { pending.push(() => resolve(new Response(JSON.stringify(body)))); });
  };
  await import(`../js/lookup.js?page=${++loads}`);
  await settle();
  const $ = (id) => dom.document.getElementById(id);
  $('search-input').value = '8.8.8.8';
  $('search-form').requestSubmit();
  await settle();
  pick($, 'hash');
  pending.shift()();
  await settle();
  assert.equal($('search-result').textContent, '', 'late lookup not shown');

  pick($, 'myip');
  $('myip-button').click();
  await settle();
  pick($, 'cve');
  pending.shift()();
  await settle();
  assert.equal($('search-result').textContent, '', 'late My IP not shown');
  assert.equal(location.hash, '');
});
