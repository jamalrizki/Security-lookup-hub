// Provider ranges in the browser tools: access-log recognition (IOC log mode),
// the once-per-visit download of GET /api/ranges, and the subnet calculator and
// Top IPs labels in the DOM stand-in, with a fetch spy.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseAccessLog, MAX_AGENT } from '../js/extract.js';
import { flatten, parseAws, parseTor } from '../worker/src/ranges.js';
import { installDom, settle } from './helpers/dom.mjs';

const root = new URL('../', import.meta.url);
const read = (f) => readFileSync(new URL(f, root), 'utf8');

// ---------- Access logs ----------

const AGENTS = ['Mozilla/5.0 (X11; Linux x86_64)', 'curl/8.4.0', 'python-requests/2.31'];
function nginxLog(n) {
  return Array.from({ length: n }, (_, i) => {
    const ip = ['3.5.20.1', '171.25.193.25', '8.8.8.8', '1.2.3.4'][i % 4];
    const minute = String(i % 60).padStart(2, '0');
    const status = [200, 200, 404, 301, 500][i % 5];
    return `${ip} - - [29/Oct/2026:1${Math.floor(i / 60) % 10}:${minute}:07 +0000] "GET /page/${i % 7}?session=${i} HTTP/1.1" ${status} ${100 + i} "https://ref.example/" "${AGENTS[i % 3]}"`;
  }).join('\n');
}

test('a 500-line nginx combined log: time range, top statuses, paths (no query) and agents', () => {
  const a = parseAccessLog(nginxLog(500));
  assert.equal(a.lines, 500);
  assert.equal(a.matched, 500);
  assert.equal(a.first, '29/Oct/2026:10:00:07 +0000');
  assert.equal(a.last, '29/Oct/2026:18:19:07 +0000');
  assert.deepEqual(a.statuses.map((s) => s.value), ['200', '301', '404', '500']);
  assert.equal(a.statuses[0].count, 200);
  assert.ok(a.paths.every((p) => !p.value.includes('?')), 'query strings dropped');
  assert.equal(a.paths.length, 7);
  assert.deepEqual(a.agents.map((x) => x.value).sort(), [...AGENTS].sort());
});

test('Apache common format (no referer or agent); time zones put first and last in order', () => {
  const a = parseAccessLog([
    '127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326',
    '127.0.0.1 - - [10/Oct/2026:20:00:00 +0000] "POST /login HTTP/1.1" 401 -',
    '127.0.0.1 - - [10/Oct/2026:21:00:00 +0200] "GET / HTTP/1.1" 200 512',
  ].join('\n'));
  assert.equal(a.matched, 3);
  assert.equal(a.first, '10/Oct/2026:21:00:00 +0200', '19:00 UTC');
  assert.equal(a.last, '10/Oct/2026:13:55:36 -0700', '20:55 UTC');
  assert.deepEqual(a.agents, []);
  assert.deepEqual(a.paths.map((p) => p.value).sort(), ['/', '/apache_pb.gif', '/login']);
});

test('mixed or unparseable text falls back (null) unless most lines match; the line filter applies', () => {
  assert.equal(parseAccessLog('Oct 29 12:00:01 host sshd[1]: Failed password for root from 1.2.3.4\njust text\n'), null);
  const half = `${nginxLog(2)}\nnot a log line\nnor this one`;
  assert.equal(parseAccessLog(half), null, 'exactly half is not most');
  assert.equal(parseAccessLog(''), null);
  assert.equal(parseAccessLog(nginxLog(20), { lineFilter: '171.25.193.25' }).lines, 5);
});

test('hostile agents and paths stay text, and are cut: agents to 120 characters, paths to 200', () => {
  const evil = `<script>alert(1)</script>${'A'.repeat(500)}`;
  const a = parseAccessLog(`1.2.3.4 - - [29/Oct/2026:10:00:00 +0000] "GET /<img/src=x/onerror=alert(1)>${'b'.repeat(400)}?x=<script> HTTP/1.1" 200 1 "-" "${evil}"`);
  assert.equal(a.agents[0].value.length, MAX_AGENT);
  assert.ok(a.agents[0].value.startsWith('<script>'), 'kept as text (rendered with textContent)');
  assert.equal(a.paths[0].value.length, 200);
  assert.ok(!a.paths[0].value.includes('?'));
});

// ---------- Download once, after the click ----------

const LISTS = {
  tor: { fetchedAt: '2026-10-29T10:07:00.000Z', ...flatten(parseTor('171.25.193.25\n')) },
  aws: {
    fetchedAt: '2026-10-29T09:07:00.000Z',
    ...flatten(parseAws(JSON.stringify({ prefixes: [{ ip_prefix: '3.5.16.0/20', region: 'us-east-1', service: 'EC2' }, { ip_prefix: '52.95.0.0/24', region: 'eu-west-1', service: 'S3' }], ipv6_prefixes: [] }))),
  },
};

let dom;
let loads = 0;

async function loadAnalyze(rangesReply = () => LISTS) {
  dom = installDom(read('analyze.html'), { url: 'https://jamalrizki.github.io/Security-lookup-hub/analyze.html' });
  const calls = [];
  globalThis.fetch = async (input) => {
    const u = String(input);
    if (u.startsWith('data/')) return new Response(read(u));
    calls.push(u);
    const r = rangesReply();
    return new Response(JSON.stringify(r), { status: r.httpStatus || 200 });
  };
  const { resetProviderRanges } = await import('../js/analyze/provider-ranges.js');
  resetProviderRanges();
  loads += 1;
  await import(`../js/analyze/subnet.js?page=${loads}`);
  await import(`../js/analyze/ioc.js?page=${loads}`);
  await settle();
  const $ = (id) => dom.document.getElementById(id);
  return { $, calls };
}

afterEach(() => {
  dom?.restore();
  dom = null;
  delete globalThis.fetch;
});

test('analyze.html allows the Worker in connect-src (for the ranges download only)', () => {
  const csp = /Content-Security-Policy" content="([^"]+)"/.exec(read('analyze.html'))[1];
  assert.match(csp, /connect-src 'self' http:\/\/127\.0\.0\.1:8787 https:\/\/security-lookup-hub\.jamal-598\.workers\.dev /);
});

test('subnet calculator: nothing is downloaded before the click; private IPs never download; one download per visit', async () => {
  const { $, calls } = await loadAnalyze();
  assert.equal(calls.length, 0, 'no request on load');
  $('subnet-check').value = '10.1.2.3';
  $('subnet-provider').click();
  await settle();
  assert.equal($('subnet-provider-result').textContent, 'Private address: not on the internet.');
  assert.equal(calls.length, 0, 'private: no download');

  $('subnet-check').value = '52.95.0.9';
  $('subnet-provider').click();
  await settle();
  assert.equal($('subnet-provider-result').textContent, '52.95.0.9: In Amazon Web Services (eu-west-1, S3).');
  assert.deepEqual(calls, ['https://security-lookup-hub.jamal-598.workers.dev/api/ranges'], 'no parameters: the IP is not sent');

  $('subnet-check').value = '';
  $('subnet-input').value = '171.25.193.25/32';
  $('subnet-provider').click();
  await settle();
  assert.equal($('subnet-provider-result').textContent, '171.25.193.25: Tor exit node.');
  $('subnet-input').value = '8.8.8.8';
  $('subnet-provider').click();
  await settle();
  assert.equal($('subnet-provider-result').textContent, '8.8.8.8: Not in the Tor or major cloud lists.');
  assert.equal(calls.length, 1, 'downloaded once for the page visit');
});

test('subnet calculator: pending and unreachable lists are plain words, and a later click retries', async () => {
  let reply = () => ({ pending: true });
  const { $, calls } = await loadAnalyze(() => reply());
  $('subnet-check').value = '52.95.0.9';
  $('subnet-provider').click();
  await settle();
  assert.match($('subnet-provider-result').textContent, /haven't been downloaded by the hub yet/);
  reply = () => LISTS;
  $('subnet-provider').click();
  await settle();
  assert.match($('subnet-provider-result').textContent, /Amazon Web Services/);
  assert.equal(calls.length, 2);
});

test('IOC log mode: access-log summary, and Top IPs labelled only after the click (one download)', async () => {
  const { $, calls } = await loadAnalyze();
  $('ioc-log').checked = true;
  $('ioc-input').value = nginxLog(40);
  $('ioc-form').requestSubmit();
  await settle(60);
  const out = $('ioc-result');
  assert.match(out.textContent, /Access log/);
  assert.match(out.textContent, /40 of 40 lines in Apache\/nginx format, from 29\/Oct\/2026:10:00:07 \+0000 to 29\/Oct\/2026:10:39:07 \+0000\./);
  assert.match(out.textContent, /Top user agents/);
  assert.equal(calls.length, 0, 'no download before the click');

  const label = out.querySelectorAll('button').find((b) => b.textContent === 'Label top IPs (cloud / Tor)');
  label.click();
  await settle();
  const rows = out.querySelectorAll('ol li').map((li) => li.textContent).filter((t) => /^\d+\.\d+/.test(t));
  assert.ok(rows.includes('3.5.20.1 × 10 — Amazon Web Services'), rows.join(' | '));
  assert.ok(rows.includes('171.25.193.25 × 10 — Tor'));
  assert.ok(rows.includes('1.2.3.4 × 10'), 'no label when in none of the lists');
  assert.equal(calls.length, 1);
  assert.equal(out.querySelectorAll('button').filter((b) => /look up all/i.test(b.textContent)).length, 0, 'still no "look up all"');
});

test('IOC log mode: a log that isn’t in access-log format works as before (no summary)', async () => {
  const { $ } = await loadAnalyze();
  $('ioc-log').checked = true;
  $('ioc-input').value = 'Oct 29 12:00:01 host sshd[1]: Failed password from 171.25.193.25\nOct 29 12:00:02 host sshd[1]: Failed password from 171.25.193.25\n';
  $('ioc-form').requestSubmit();
  await settle(60);
  const out = $('ioc-result');
  assert.ok(!out.textContent.includes('Access log'));
  assert.match(out.textContent, /Top IPs/);
});
