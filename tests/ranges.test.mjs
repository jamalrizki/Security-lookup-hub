// Network type: list parsers, flattening, the cron rotation and refresh, the
// binary search at range edges, the "network" source, GET /api/ranges, and the card.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { parseTor, parseAws, parseGcp, parseCloudflare, prefixRange, flatten, rangesForRun, refreshRanges, rangesKey, RANGES_META_KEY, RANGE_LISTS } from '../worker/src/ranges.js';
import { ipKey, findRange, classify, providerText, shortLabel, NOT_LISTED } from '../js/ranges.js';
import { networkType, plan } from '../worker/src/sources.js';
import { detect } from '../js/detect.js';
import { facts } from '../worker/src/explain.js';
import worker from '../worker/src/index.js';
import { ORIGIN, installCaches, exec, memoryKv } from './helpers/ask-stubs.mjs';
import { installDom } from './helpers/dom.mjs';

const TOR_TXT = '171.25.193.25\n80.67.167.81\n\nnot an ip\n10.0.0.300\n2001:67c:289c::25\n';
const AWS_JSON = JSON.stringify({
  syncToken: '1', createDate: '2026-10-29-00-00-00',
  prefixes: [
    { ip_prefix: '3.5.0.0/16', region: 'us-east-1', service: 'AMAZON', network_border_group: 'us-east-1' },
    { ip_prefix: '3.5.16.0/20', region: 'us-east-1', service: 'AMAZON', network_border_group: 'us-east-1' },
    { ip_prefix: '3.5.16.0/20', region: 'us-east-1', service: 'EC2', network_border_group: 'us-east-1' },
    { ip_prefix: '52.95.0.0/24', region: 'eu-west-1', service: 'S3', network_border_group: 'eu-west-1' },
    { ip_prefix: 'garbage', region: 'x', service: 'EC2' },
  ],
  ipv6_prefixes: [{ ipv6_prefix: '2600:1f00::/40', region: 'GLOBAL', service: 'AMAZON', network_border_group: 'GLOBAL' }],
});
const GCP_JSON = JSON.stringify({ prefixes: [{ ipv4Prefix: '34.1.208.0/20', service: 'Google Cloud', scope: 'africa-south1' }, { ipv6Prefix: '2600:1900:4000::/44', service: 'Google Cloud', scope: 'us-central1' }] });
const CF_V4 = '173.245.48.0/20\n104.16.0.0/13\n';
const CF_V6 = '2400:cb00::/32\n';

test('prefixRange: IPv4 and IPv6 bounds; bad prefixes rejected', () => {
  assert.deepEqual(prefixRange('3.5.16.0/20'), { v: 4, start: ipKey('3.5.16.0').key, end: ipKey('3.5.31.255').key });
  assert.deepEqual(prefixRange('3.5.16.9/20'), prefixRange('3.5.16.0/20'), 'host bits cleared');
  assert.deepEqual(prefixRange('8.8.8.8'), { v: 4, start: ipKey('8.8.8.8').key, end: ipKey('8.8.8.8').key });
  const r6 = prefixRange('2600:1f00::/40');
  assert.equal(r6.v, 6);
  assert.equal(r6.start, BigInt(`0x${ipKey('2600:1f00::').key}`));
  assert.equal(r6.end, BigInt(`0x${ipKey('2600:1f00:ff:ffff:ffff:ffff:ffff:ffff').key}`));
  for (const bad of ['garbage', '1.2.3.4/33', '1.2.3.4/x', '1.2.3/24', '1.2.3.4/24/1', '<html>', '']) assert.equal(prefixRange(bad), null, bad);
});

test('Tor list: one address per line, non-IP lines skipped, IPv6 entries kept', () => {
  const e = parseTor(TOR_TXT);
  assert.equal(e.length, 3);
  assert.deepEqual(e.map((x) => x.v), [4, 4, 6]);
  assert.throws(() => parseTor('<!doctype html><html>Error</html>'), /HTML/);
  assert.deepEqual(parseTor(''), [], 'an empty file parses to nothing (refresh then refuses to store it)');
});

test('AWS: the service wins over the AMAZON catch-all; GLOBAL and AMAZON leave the label empty; bad entries skipped', () => {
  const f = flatten(parseAws(AWS_JSON));
  const at = (ip) => findRange(f.v4, ipKey(ip).key)?.[2];
  assert.equal(at('3.5.0.1'), 'us-east-1|', 'outer /16 is the catch-all');
  assert.equal(at('3.5.16.0'), 'us-east-1|EC2', 'first address of the nested /20');
  assert.equal(at('3.5.31.255'), 'us-east-1|EC2', 'last address of the nested /20');
  assert.equal(at('3.5.32.0'), 'us-east-1|', 'back in the /16 after it');
  assert.equal(at('3.5.255.255'), 'us-east-1|');
  assert.equal(at('3.6.0.0'), undefined, 'one past the end');
  assert.equal(at('52.95.0.200'), 'eu-west-1|S3');
  assert.equal(findRange(f.v6, ipKey('2600:1f00::1').key)?.[2], '|');
  assert.throws(() => parseAws('{"nope":1}'), /no prefixes/);
  assert.throws(() => parseAws('<html><body>503</body></html>'), /HTML/);
  assert.throws(() => parseAws('{"prefixes": ['), SyntaxError, 'malformed JSON');
});

test('Google Cloud and Cloudflare parsers', () => {
  const g = flatten(parseGcp(GCP_JSON));
  assert.equal(findRange(g.v4, ipKey('34.1.223.255').key)?.[2], 'africa-south1|');
  assert.equal(findRange(g.v6, ipKey('2600:1900:4000::5').key)?.[2], 'us-central1|');
  const c = flatten([...parseCloudflare(CF_V4), ...parseCloudflare(CF_V6)]);
  assert.equal(c.v4.length, 2);
  assert.equal(c.v6.length, 1);
  assert.throws(() => parseCloudflare('<html>Attention Required</html>'), /HTML/);
  assert.throws(() => parseGcp('not json'));
});

test('flatten: sorted, non-overlapping output; touching pieces with the same label join', () => {
  const f = flatten([...parseTor('1.2.3.4\n1.2.3.5\n1.2.3.7\n'), ...parseAws(AWS_JSON)]);
  for (let i = 1; i < f.v4.length; i++) assert.ok(f.v4[i][0] > f.v4[i - 1][1], 'no overlap');
  assert.ok(f.v4.some(([s, e]) => s === ipKey('1.2.3.4').key && e === ipKey('1.2.3.5').key), '1.2.3.4-1.2.3.5 joined');
});

test('binary search at the edges, IPv4 and IPv6', () => {
  const v4 = [[10, 20, 'a'], [30, 30, 'b'], [31, 40, 'c']];
  assert.equal(findRange(v4, 10)[2], 'a');
  assert.equal(findRange(v4, 20)[2], 'a');
  assert.equal(findRange(v4, 9), null);
  assert.equal(findRange(v4, 21), null);
  assert.equal(findRange(v4, 30)[2], 'b');
  assert.equal(findRange(v4, 41), null);
  assert.equal(findRange([], 5), null);
  const v6 = flatten(parseCloudflare(CF_V6)).v6;
  assert.ok(findRange(v6, ipKey('2400:cb00::').key));
  assert.ok(findRange(v6, ipKey('2400:cb00:ffff:ffff:ffff:ffff:ffff:ffff').key));
  assert.equal(findRange(v6, ipKey('2400:cb01::').key), null);
  assert.equal(findRange(v6, ipKey('2400:caff:ffff:ffff:ffff:ffff:ffff:ffff').key), null);
});

test('rotation: Tor every 2 hours, every list at least every 4 hours', () => {
  const day = Date.UTC(2026, 9, 29);
  const seen = {};
  for (let h = 0; h < 24; h++) for (const id of rangesForRun(day + h * 3_600_000 + 7 * 60_000)) (seen[id] ||= []).push(h);
  assert.deepEqual(Object.keys(seen).sort(), ['aws', 'cloudflare', 'gcp', 'tor']);
  for (const [id, hours] of Object.entries(seen)) {
    const gaps = hours.map((h, i) => (hours[(i + 1) % hours.length] - h + 24) % 24 || 24);
    assert.ok(Math.max(...gaps) <= (id === 'tor' ? 2 : 4), `${id}: ${hours}`);
  }
  for (const id of Object.keys(RANGE_LISTS)) assert.ok(RANGE_LISTS[id].maxBytes > 0);
});

// ---------- Refresh ----------

function stubFetch(map) {
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    const r = map[String(url)];
    if (r instanceof Error) throw r;
    return r ? new Response(r.body ?? r, { status: r.status || 200 }) : new Response('missing', { status: 404 });
  };
  return calls;
}
afterEach(() => { delete globalThis.fetch; });

test('refresh stores a good list and the meta key', async () => {
  const kv = memoryKv();
  stubFetch({ 'https://check.torproject.org/torbulkexitlist': TOR_TXT });
  const meta = await refreshRanges(kv, ['tor'], Date.UTC(2026, 9, 29, 2, 7));
  assert.equal(meta.tor.ok, true);
  const stored = JSON.parse(kv.map.get(rangesKey('tor')));
  assert.equal(stored.fetchedAt, '2026-10-29T02:07:00.000Z');
  assert.equal(stored.v4.length, 2);
  assert.equal(stored.v6.length, 1);
  assert.deepEqual(kv.puts.map((p) => p.key ?? p[0]).length, 2, 'one write for the list, one for meta');
  assert.ok(kv.map.has(RANGES_META_KEY));
});

test('a failed, empty or HTML refresh keeps the previous list and marks it stale', async () => {
  const old = { fetchedAt: '2026-10-29T00:07:00.000Z', ok: true, v4: [[1, 2, '']], v6: [] };
  for (const reply of [new Error('network down'), { body: '', status: 200 }, { body: '<html>Rate limited</html>', status: 200 }, { body: 'x', status: 503 }]) {
    const kv = memoryKv({ [rangesKey('tor')]: old, [RANGES_META_KEY]: { tor: { fetchedAt: old.fetchedAt, ok: true } } });
    stubFetch({ 'https://check.torproject.org/torbulkexitlist': reply });
    const meta = await refreshRanges(kv, ['tor'], Date.UTC(2026, 9, 29, 2, 7));
    assert.deepEqual(JSON.parse(kv.map.get(rangesKey('tor'))), old, 'old list kept');
    assert.equal(meta.tor.ok, false);
    assert.equal(meta.tor.fetchedAt, old.fetchedAt);
    assert.ok(meta.tor.error);
  }
});

test('the :07 cron run refreshes the rotation’s lists; other minutes still refresh news', async () => {
  const kv = memoryKv();
  const calls = stubFetch({ 'https://www.gstatic.com/ipranges/cloud.json': GCP_JSON, 'https://www.cloudflare.com/ips-v4': CF_V4, 'https://www.cloudflare.com/ips-v6': CF_V6 });
  const waits = [];
  await worker.scheduled({ scheduledTime: Date.UTC(2026, 9, 29, 3, 7) }, { NEWS: kv }, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
  assert.deepEqual(calls.sort(), ['https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6', 'https://www.gstatic.com/ipranges/cloud.json']);
  assert.ok(kv.map.has(rangesKey('gcp')) && kv.map.has(rangesKey('cloudflare')));
  calls.length = 0;
  await worker.scheduled({ scheduledTime: Date.UTC(2026, 9, 29, 3, 17) }, { NEWS: kv }, { waitUntil: (p) => waits.push(p.catch(() => {})) });
  await Promise.all(waits);
  assert.ok(calls.every((u) => !/torproject|amazonaws|gstatic|cloudflare\.com\/ips/.test(u)), 'news minute never fetches range lists');
});

// ---------- The network source and the card ----------

const NOW = Date.UTC(2026, 9, 29, 12, 0);
const fresh = (id, list) => ({ fetchedAt: new Date(NOW - 3_600_000).toISOString(), ok: true, ...list });
const LISTS = {
  tor: fresh('tor', flatten(parseTor(TOR_TXT))),
  aws: fresh('aws', flatten(parseAws(AWS_JSON))),
  gcp: fresh('gcp', flatten(parseGcp(GCP_JSON))),
  cloudflare: { ...fresh('cloudflare', flatten(parseCloudflare(CF_V4))), fetchedAt: new Date(NOW - 9 * 3_600_000).toISOString() },
};

test('networkType: Tor, provider, neither; stale lists named with their age', () => {
  assert.deepEqual(networkType(LISTS, '171.25.193.25', NOW).tor, true);
  const aws = networkType(LISTS, '3.5.20.1', NOW);
  assert.deepEqual(aws.provider, { id: 'aws', name: 'Amazon Web Services', region: 'us-east-1', service: 'EC2' });
  assert.equal(aws.tor, false);
  assert.deepEqual(aws.stale, [{ id: 'cloudflare', hours: 9 }]);
  assert.equal(networkType(LISTS, '8.8.8.8', NOW).provider, null);
  assert.deepEqual(networkType({ tor: null, aws: null, gcp: null, cloudflare: null }, '8.8.8.8', NOW).stale.map((s) => s.hours), [null, null, null, null]);
  assert.equal(providerText({ id: 'cloudflare', name: 'Cloudflare' }), 'Cloudflare (CDN and proxy network)');
  assert.equal(providerText({ id: 'gcp', name: 'Google Cloud', region: 'us-central1' }), 'Google Cloud (us-central1)');
});

test('plan: network runs for IPs and IP-host URLs only; it’s in facts() for Explain', () => {
  assert.ok(plan(detect('8.8.8.8')).some((s) => s.id === 'network'));
  assert.ok(plan(detect('http://8.8.8.8/x')).some((s) => s.id === 'network'));
  assert.ok(!plan(detect('example.com')).some((s) => s.id === 'network'));
  const f = facts({ type: 'ipv4', value: '3.5.20.1', sources: [{ id: 'network', name: 'Network type', status: 'ok', data: networkType(LISTS, '3.5.20.1', NOW) }] });
  assert.deepEqual(f.sources[0].data.torExitNode, false);
  assert.equal(f.sources[0].data.cloudProvider, 'Amazon Web Services (us-east-1, EC2)');
});

test('shortLabel for the browser tools', () => {
  assert.equal(shortLabel(classify(LISTS, '171.25.193.25')), 'Tor exit node');
  assert.equal(shortLabel(classify(LISTS, '52.95.0.9')), 'In Amazon Web Services (eu-west-1, S3)');
  assert.equal(shortLabel(classify(LISTS, '8.8.8.8')), NOT_LISTED);
  assert.equal(classify(LISTS, 'nope'), null);
});

test('card wording: Tor, AWS, neither, stale', async () => {
  const dom = installDom('<div></div>');
  try {
    const { sourceCard } = await import('../js/results.js');
    const card = (ip) => sourceCard({ id: 'network', name: 'Network type', status: 'ok', link: 'https://metrics.torproject.org/exonerator.html', data: networkType(LISTS, ip, NOW) }).textContent;
    assert.match(card('171.25.193.25'), /Tor exit node \(Tor Project list\)/);
    const aws = card('3.5.20.1');
    assert.match(aws, /Belongs to Amazon Web Services \(us-east-1, EC2\)/);
    assert.match(aws, /Traffic from cloud addresses usually comes from servers, scripts or VPN\/proxy services, not a person at home\./);
    assert.match(aws, /Cloudflare list last updated 9 h ago\./);
    assert.match(card('8.8.8.8'), /Not in the Tor or major cloud lists\. It could still be a VPN, proxy or smaller hosting company: this check can't tell\./);
  } finally {
    dom.restore();
  }
});

// ---------- Routes ----------

test('the network source reads KV only (no outbound fetch)', async () => {
  installCaches();
  const kv = memoryKv({ [rangesKey('aws')]: LISTS.aws });
  const calls = stubFetch({});
  const res = await worker.fetch(new Request('https://w.example/api/lookup?q=3.5.20.1', { headers: { origin: ORIGIN } }), { ALLOWED_ORIGINS: ORIGIN, NEWS: kv }, exec());
  const net = (await res.json()).sources.find((s) => s.id === 'network');
  assert.equal(net.status, 'ok');
  assert.equal(net.data.provider.name, 'Amazon Web Services');
  assert.ok(calls.every((u) => !/torproject|amazonaws|gstatic|cloudflare\.com\/ips/.test(u)));
});

test('GET /api/ranges: pending before the first run, then all lists without meta, edge-cached 1 hour', async () => {
  const store = installCaches();
  const kv = memoryKv();
  const get = () => worker.fetch(new Request('https://w.example/api/ranges', { headers: { origin: ORIGIN } }), { ALLOWED_ORIGINS: ORIGIN, NEWS: kv }, exec());
  assert.deepEqual(await (await get()).json(), { pending: true });
  assert.equal(store.size, 0, 'pending is not cached');
  kv.map.set(rangesKey('tor'), JSON.stringify(LISTS.tor));
  kv.map.set(RANGES_META_KEY, JSON.stringify({ tor: { ok: true } }));
  const body = await (await get()).json();
  assert.deepEqual(Object.keys(body), ['tor']);
  assert.deepEqual(Object.keys(body.tor), ['fetchedAt', 'v4', 'v6']);
  await new Promise((r) => setImmediate(r));
  assert.equal(store.size, 1);
});
