// Check my IP: GET /api/my-ip (worker/src/myip.js) with request.cf and headers stubbed.
import { test, afterEach } from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import worker from '../worker/src/index.js';
import { myIp } from '../worker/src/myip.js';
import { ORIGIN, installCaches, exec, memoryKv } from './helpers/ask-stubs.mjs';
import { installDom, settle } from './helpers/dom.mjs';

const CF = {
  country: 'GB', region: 'England', regionCode: 'ENG', city: 'London', timezone: 'Europe/London',
  asn: 2856, asOrganization: 'British Telecommunications PLC',
  latitude: '51.50853', longitude: '-0.12574', postalCode: 'EC1A', continent: 'EU', colo: 'LHR',
};

function req(headers = {}, cf = CF, origin = ORIGIN) {
  const r = new Request('https://w.example/api/my-ip', { headers: { ...(origin ? { origin } : {}), ...headers } });
  if (cf) Object.defineProperty(r, 'cf', { value: cf });
  return r;
}

test('a public IPv4 returns the address and the request.cf fields, never coordinates or postcode', () => {
  const r = myIp(req({ 'cf-connecting-ip': '81.2.69.142' }));
  assert.deepEqual(r, { ip: '81.2.69.142', version: 4, country: 'GB', region: 'England', city: 'London', timezone: 'Europe/London', asn: 2856, asOrganization: 'British Telecommunications PLC' });
  for (const k of ['latitude', 'longitude', 'postalCode', 'regionCode', 'colo']) assert.ok(!(k in r), k);
});

test('a public IPv6 returns version 6; missing request.cf fields are null', () => {
  const r = myIp(req({ 'cf-connecting-ip': '2a00:1450:4009:81f::200e' }, { country: 'GB' }));
  assert.equal(r.version, 6);
  assert.equal(r.ip, '2a00:1450:4009:81f::200e');
  assert.equal(r.country, 'GB');
  assert.equal(r.city, null);
});

test('private, loopback or missing addresses return { local: true }; X-Forwarded-For is ignored', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.4', '::1', 'fe80::1', '', 'not-an-ip']) {
    assert.deepEqual(myIp(req(ip ? { 'cf-connecting-ip': ip } : {})), { local: true }, ip || '(missing)');
  }
  assert.deepEqual(myIp(req({ 'x-forwarded-for': '8.8.8.8', 'x-real-ip': '8.8.8.8' })), { local: true });
  assert.equal(myIp(req({ 'cf-connecting-ip': '81.2.69.142', 'x-forwarded-for': '8.8.8.8' })).ip, '81.2.69.142');
});

test('the route: allowlisted origin only, no-store, and nothing written to the cache or KV', async () => {
  const store = installCaches();
  const NEWS = memoryKv();
  const env = { ALLOWED_ORIGINS: ORIGIN, NEWS };
  const res = await worker.fetch(req({ 'cf-connecting-ip': '81.2.69.142' }), env, exec());
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal((await res.json()).ip, '81.2.69.142');
  await new Promise((r) => setImmediate(r));
  assert.equal(store.size, 0, 'no edge-cache write');
  assert.equal(NEWS.puts.length, 0, 'no KV write');
  assert.equal((await worker.fetch(req({ 'cf-connecting-ip': '81.2.69.142' }, CF, null), env, exec())).status, 403);
});

// ---------- Page: the My IP button and the "Your connection" card ----------

const root = new URL('../', import.meta.url);
const read = (f) => readFileSync(new URL(f, root), 'utf8');
let dom;
let loads = 0;

async function loadPage(myIpReply) {
  dom = installDom(read('lookup.html'), { url: 'https://jamalrizki.github.io/Security-lookup-hub/lookup.html' });
  const calls = [];
  globalThis.fetch = async (input) => {
    const u = String(input);
    if (u.startsWith('data/')) return new Response(read(u));
    calls.push(u);
    if (u.endsWith('/api/my-ip')) return myIpReply();
    return new Response(JSON.stringify({ sources: [], note: 'Nothing to show.' }));
  };
  await import(`../js/lookup.js?myip=${++loads}`);
  await settle();
  const $ = (id) => dom.document.getElementById(id);
  return { $, calls };
}

afterEach(() => {
  dom?.restore();
  dom = null;
  delete globalThis.fetch;
});

const reply = (body, status = 200) => () => new Response(JSON.stringify(body), { status });
const PUBLIC = { ip: '81.2.69.142', version: 4, country: 'GB', region: 'England', city: 'London', timezone: 'Europe/London', asn: 2856, asOrganization: 'British Telecommunications PLC' };

test('page: the My IP button alone sends nothing and leaves the fragment alone', async () => {
  const { $, calls } = await loadPage(reply(PUBLIC));
  dom.document.querySelector('#type-picker button[data-type="myip"]').click();
  await settle();
  assert.equal(calls.length, 0);
  assert.equal($('myip-row').hidden, false);
  assert.equal($('search-form').hidden, true);
  assert.equal(location.hash, '');
});

test('page: Show my IP shows "Your connection" first, then runs the normal IP lookup', async () => {
  const { $, calls } = await loadPage(reply(PUBLIC));
  dom.document.querySelector('#type-picker button[data-type="myip"]').click();
  $('myip-button').click();
  await settle();
  assert.match(calls[0], /\/api\/my-ip$/);
  assert.match(calls[1], /\/api\/lookup\?q=81\.2\.69\.142$/);
  const out = $('search-result');
  const card = out.firstElementChild;
  assert.equal(card.querySelector('h3').textContent, 'Your connection');
  const text = card.textContent;
  for (const s of ['81.2.69.142', 'AS2856 British Telecommunications PLC', 'London, England, GB', 'Europe/London', 'It is not your home address.', "shows the VPN's address", 'both an IPv4 and an IPv6 address']) assert.ok(text.includes(s), s);
  assert.equal(location.hash, '#q=81.2.69.142', 'fragment set only after the click');
  assert.equal(dom.document.querySelector('#type-picker button[aria-pressed="true"]').getAttribute('data-type'), 'myip', 'stays on My IP');
});

test('page: local, rate-limited and unreachable answers are plain words, with no lookup', async () => {
  for (const [r, want] of [
    [reply({ local: true }), "Running locally: your public IP can't be seen from here."],
    [reply({ error: 'Too many requests. Try again in a minute.' }, 429), 'Too many requests. Try again in a minute.'],
    [() => { throw new TypeError('offline'); }, 'The lookup service could not be reached. Try again in a moment.'],
  ]) {
    const { $, calls } = await loadPage(r);
    dom.document.querySelector('#type-picker button[data-type="myip"]').click();
    $('myip-button').click();
    await settle();
    assert.equal($('search-result').textContent, want);
    assert.equal(calls.filter((u) => u.includes('/api/lookup')).length, 0);
    assert.equal(location.hash, '');
    dom.restore();
    dom = null;
  }
});
