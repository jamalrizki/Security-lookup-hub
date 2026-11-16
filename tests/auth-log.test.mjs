// SSH auth logs in IOC log mode (#29): parseAuthLog() counts sshd lines and
// decides the flags in code; the page shows them as text, with a sample log.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseAuthLog, parseAccessLog, SSH_FLAGS, MAX_SSH_USER } from '../js/extract.js';
import { installDom, settle } from './helpers/dom.mjs';

const root = new URL('../', import.meta.url);
const read = (f) => readFileSync(new URL(f, root), 'utf8');
const line = (msg, t = '03:12:01') => `Nov 16 ${t} web1 sshd[2211]: ${msg}`;
const fails = (ip, n, user = 'root') => Array.from({ length: n }, (_, i) => line(`Failed password for ${user} from ${ip} port ${40000 + i} ssh2`));

test('thresholds are named constants', () => {
  assert.deepEqual({ ...SSH_FLAGS }, { guessingFailures: 10, sprayUsers: 5 });
  assert.ok(Object.isFrozen(SSH_FLAGS));
});

test('each sshd message type is counted', () => {
  const a = parseAuthLog([
    line('Invalid user admin from 203.0.113.9 port 50120'),
    line('Failed password for invalid user admin from 203.0.113.9 port 50120 ssh2'),
    line('Failed publickey for root from 203.0.113.9 port 50121 ssh2'),
    line('Accepted publickey for jamie from 198.51.100.7 port 44111 ssh2: ED25519 SHA256:abc', '08:02:45'),
    line('Accepted password for deploy from 198.51.100.8 port 44112 ssh2', '08:03:00'),
    line('error: maximum authentication attempts exceeded for invalid user admin from 203.0.113.9 port 50122 ssh2 [preauth]'),
    line('Connection closed by invalid user admin 203.0.113.9 port 50122 [preauth]'),
    line('Disconnected from authenticating user root 203.0.113.9 port 50123 [preauth]'),
    'Nov 16 08:04:00 web1 sshd-session[99]: Failed password for root from 203.0.113.10 port 1 ssh2',
  ].join('\n'));
  assert.equal(a.lines, 9);
  assert.equal(a.matched, 9, 'sshd-session (newer OpenSSH) counts too');
  assert.equal(a.failed, 3);
  assert.equal(a.invalidUsers, 1);
  assert.equal(a.maxAuth, 1);
  assert.equal(a.acceptedCount, 2);
  assert.deepEqual(a.accepted[0], { time: 'Nov 16 08:02:45', user: 'jamie', method: 'publickey', ip: '198.51.100.7', failedBefore: 0 });
  assert.equal(a.first, 'Nov 16 03:12:01');
  assert.equal(a.last, 'Nov 16 08:04:00');
  assert.deepEqual(a.ips, [{ value: '203.0.113.9', count: 2 }, { value: '203.0.113.10', count: 1 }]);
  assert.deepEqual(a.users.map((u) => u.value).sort(), ['admin', 'root']);
  assert.deepEqual(a.flags, []);
});

test('IPv6 sources are read and normalised; bad addresses are skipped', () => {
  const a = parseAuthLog([
    line('Failed password for root from 2001:DB8:0:0::25 port 51600 ssh2'),
    line('Failed password for root from 999.1.1.1 port 51600 ssh2'),
    line('Failed password for root from 2001:db8::zz port 51600 ssh2'),
  ].join('\n'));
  assert.equal(a.failed, 1);
  assert.deepEqual(a.ips, [{ value: '2001:db8::25', count: 1 }]);
});

test('"message repeated N times" counts N', () => {
  const a = parseAuthLog(line('message repeated 12 times: [ Failed password for root from 203.0.113.9 port 50120 ssh2]'));
  assert.equal(a.failed, 12);
  assert.equal(a.flags[0].kind, 'guessing');
});

test('password guessing: flagged at 10 failures from one IP, not at 9', () => {
  assert.deepEqual(parseAuthLog(fails('203.0.113.9', 9).join('\n')).flags, []);
  const f = parseAuthLog(fails('203.0.113.9', 10).join('\n')).flags;
  assert.equal(f.length, 1);
  assert.equal(f[0].kind, 'guessing');
  assert.equal(f[0].ip, '203.0.113.9');
  assert.equal(f[0].count, 10);
  assert.match(f[0].reason, /failed to log in 10 times \(10 or more/);
});

test('password spraying: flagged at 5 usernames from one IP, not at 4; invalid-user lines count', () => {
  const tries = (n) => Array.from({ length: n }, (_, i) => line(`Invalid user u${i} from 203.0.113.9 port ${50000 + i}`));
  assert.deepEqual(parseAuthLog(tries(4).join('\n')).flags, []);
  const f = parseAuthLog(tries(5).join('\n')).flags;
  assert.equal(f.length, 1);
  assert.equal(f[0].kind, 'spraying');
  assert.equal(f[0].count, 5);
  // The same user over and over is not spraying.
  assert.ok(!parseAuthLog(fails('203.0.113.9', 6, 'root').join('\n')).flags.some((x) => x.kind === 'spraying'));
});

test('worth checking: an accepted login after failures from the same IP, not before them, not from another IP', () => {
  const ok = line('Accepted password for deploy from 198.51.100.7 port 1 ssh2', '03:41:02');
  const after = parseAuthLog([...fails('198.51.100.7', 2, 'deploy'), ok].join('\n')).flags;
  assert.equal(after.length, 1);
  assert.equal(after[0].kind, 'accepted-after-failures');
  assert.equal(after[0].count, 2);
  assert.match(after[0].reason, /deploy logged in from 198\.51\.100\.7 at Nov 16 03:41:02 after 2 failed tries/);
  assert.match(after[0].reason, /Check whether this was you/);
  assert.doesNotMatch(after[0].reason, /hacked|compromised/i, 'cautious wording');
  assert.deepEqual(parseAuthLog([ok, ...fails('198.51.100.7', 2, 'deploy')].join('\n')).flags, [], 'failures after the login');
  assert.deepEqual(parseAuthLog([...fails('203.0.113.9', 2), ok].join('\n')).flags, [], 'failures from a different IP');
});

test('not an sshd log, or only half sshd lines: null; access logs are not sshd logs and vice versa', () => {
  assert.equal(parseAuthLog(''), null);
  assert.equal(parseAuthLog('just some text\nmore text'), null);
  assert.equal(parseAuthLog(`${fails('203.0.113.9', 1)[0]}\nnot a log line`), null, 'exactly half is not most');
  assert.equal(parseAuthLog('Nov 16 03:12:01 web1 cron[1]: Failed password for root from 203.0.113.9 port 1 ssh2'), null, 'not sshd');
  const nginx = '203.0.113.9 - - [29/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "curl/8"';
  assert.equal(parseAuthLog(nginx), null);
  assert.equal(parseAccessLog(fails('203.0.113.9', 3).join('\n')), null);
});

test('line filter applies before counting', () => {
  const a = parseAuthLog([...fails('203.0.113.9', 12), ...fails('198.51.100.7', 3)].join('\n'), { lineFilter: '198.51.100.7' });
  assert.equal(a.lines, 3);
  assert.equal(a.failed, 3);
  assert.deepEqual(a.flags, []);
});

test('hostile usernames stay text and are cut to 32 characters; empty usernames are labelled', () => {
  const evil = `<img/src=x/onerror=alert(1)>${'A'.repeat(100)}`;
  const a = parseAuthLog([
    line(`Failed password for invalid user ${evil} from 203.0.113.9 port 1 ssh2`),
    line('Invalid user  from 203.0.113.9 port 2'),
  ].join('\n'));
  assert.equal(a.users[0].value.length, MAX_SSH_USER);
  assert.ok(a.users[0].value.startsWith('<img'));
  assert.equal(a.invalidUsers, 1);
});

test('accepted rows are capped at 50, the total is not', () => {
  const many = Array.from({ length: 60 }, (_, i) => line(`Accepted publickey for u from 198.51.100.7 port ${i} ssh2`));
  const a = parseAuthLog(many.join('\n'));
  assert.equal(a.accepted.length, 50);
  assert.equal(a.acceptedCount, 60);
});

// ---------- On the page ----------

let loads = 0;
async function loadAnalyze() {
  const dom = installDom(read('analyze.html'), { url: 'https://jamalrizki.github.io/Security-lookup-hub/analyze.html' });
  const calls = [];
  globalThis.fetch = async (input) => {
    const u = String(input);
    if (u.startsWith('data/')) return new Response(read(u));
    calls.push(u);
    return new Response('{}', { status: 500 });
  };
  loads += 1;
  const mod = await import(`../js/analyze/ioc.js?auth=${loads}`);
  await settle();
  return { $: (id) => dom.document.getElementById(id), calls, mod };
}

test('the sample uses documentation addresses only and trips all three flags', async () => {
  const { mod } = await loadAnalyze();
  const ips = [...mod.SSH_SAMPLE.matchAll(/from (\S+) port/g)].map((m) => m[1]);
  assert.ok(ips.length > 10);
  for (const ip of ips) assert.match(ip, /^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:db8:)/, ip);
  const kinds = parseAuthLog(mod.SSH_SAMPLE).flags.map((f) => f.kind);
  assert.deepEqual([...new Set(kinds)].sort(), ['accepted-after-failures', 'guessing', 'spraying']);
});

test('"Try a sample SSH log" turns on log mode and shows the summary, flags and next steps; nothing is sent', async () => {
  const { $, calls } = await loadAnalyze();
  $('ioc-sample').click();
  await settle(60);
  assert.equal($('ioc-log').checked, true);
  assert.equal($('ioc-filter-row').hidden, false);
  const out = $('ioc-result');
  const text = out.textContent;
  assert.match(text, /SSH logins/);
  assert.match(text, /lines are sshd lines, from Nov 16 03:12:00 to Nov 16 08:15:30/);
  assert.match(text, /18 failed logins, 2 accepted, 6 for usernames that don't exist on this server\./);
  assert.match(text, /Password guessing from one source: 198\.51\.100\.7 failed to log in 11 times/);
  assert.match(text, /Password spraying: 203\.0\.113\.9 tried 6 different usernames/);
  assert.match(text, /Worth checking: deploy logged in from 198\.51\.100\.7/);
  assert.match(text, /Nov 16 08:02:45 — jamie \(publickey\) from 2001:db8::25/);
  const hrefs = out.querySelectorAll('a').map((a) => a.getAttribute('href'));
  assert.ok(hrefs.includes('./reference.html#what-now'), 'what-now link when a login followed failures');
  assert.ok(hrefs.includes('https://man.openbsd.org/sshd_config#PasswordAuthentication'));
  assert.ok(!text.includes('Access log'));
  assert.equal(calls.length, 0, 'the pasted log never leaves the browser');
});

test('an sshd log with no pattern says so, and has no what-now link', async () => {
  const { $ } = await loadAnalyze();
  $('ioc-log').checked = true;
  $('ioc-input').value = [line('Accepted publickey for jamie from 198.51.100.7 port 1 ssh2'), ...fails('203.0.113.9', 2)].join('\n');
  $('ioc-form').requestSubmit();
  await settle(60);
  const out = $('ioc-result');
  assert.match(out.textContent, /No pattern flagged \(a flag needs 10\+ failures or 5\+ usernames/);
  assert.ok(!out.querySelectorAll('a').some((a) => a.getAttribute('href') === './reference.html#what-now'));
});

test('without log mode, an sshd log gets no SSH summary', async () => {
  const { $ } = await loadAnalyze();
  $('ioc-input').value = fails('203.0.113.9', 12).join('\n');
  $('ioc-form').requestSubmit();
  await settle(60);
  assert.ok(!$('ioc-result').textContent.includes('SSH logins'));
});
