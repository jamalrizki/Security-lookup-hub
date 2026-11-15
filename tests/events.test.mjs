// "Windows event IDs" on the Reference page (data/events.json, js/events.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { searchEvents, eventProblems, eventDocUrl, eventPageId, normalizeStatus } from '../js/events.js';

const root = new URL('../', import.meta.url);
const data = JSON.parse(readFileSync(new URL('data/events.json', root), 'utf8'));
const ids = (r) => r.events.map((e) => e.id);

test('every event has a valid shape, sorted by ID, with unique (log, id) pairs', () => {
  assert.ok(data.events.length >= 35);
  const seen = new Set();
  let last = 0;
  for (const e of data.events) {
    assert.deepEqual(eventProblems(e), [], `${e.id}: ${eventProblems(e).join(', ')}`);
    assert.ok(e.id > last, `${e.id} is out of order or repeated`);
    last = e.id;
    const key = `${e.log}|${e.id}`;
    assert.ok(!seen.has(key), `duplicate ${key}`);
    seen.add(key);
    assert.ok(!/[<>]|https?:/.test(e.name + e.plain + e.why), `${e.id}: no markup or links`);
  }
});

test('every event links to its own Microsoft Learn page (https, learn.microsoft.com, path ends in event-<id>)', () => {
  for (const e of data.events) {
    const href = eventDocUrl(data.docBase, eventPageId(e));
    assert.ok(href, `${e.id}: no safe link`);
    const u = new URL(href);
    assert.equal(u.protocol, 'https:');
    assert.equal(u.hostname, 'learn.microsoft.com');
    assert.ok(u.pathname.endsWith(`/event-${eventPageId(e)}`), `${e.id}: ${u.pathname}`);
    if (e.page) assert.ok(data.events.some((x) => x.id === e.page), `${e.id}: page ${e.page} should be a listed event`);
  }
  const src = new URL(data.source.url);
  assert.equal(src.protocol, 'https:');
  assert.equal(src.hostname, 'learn.microsoft.com');
});

test('eventDocUrl refuses other hosts, http, odd IDs and paths that do not end in the ID', () => {
  assert.equal(eventDocUrl('http://learn.microsoft.com/x/event-', 4625), null);
  assert.equal(eventDocUrl('https://learn.microsoft.com.evil.example/event-', 4625), null);
  assert.equal(eventDocUrl('https://evil.example/learn.microsoft.com/event-', 4625), null);
  assert.equal(eventDocUrl('https://user@learn.microsoft.com/event-', 4625), null);
  assert.equal(eventDocUrl('https://learn.microsoft.com/page?id=', 4625), null);
  assert.equal(eventDocUrl('javascript:alert(1)//', 4625), null);
  assert.equal(eventDocUrl(data.docBase, 0), null);
  assert.equal(eventDocUrl(data.docBase, 1.5), null);
  assert.equal(eventDocUrl(data.docBase, '4625'), null);
  assert.ok(eventDocUrl(data.docBase, 4625).endsWith('/auditing/event-4625'));
});

test('exam and SOC staples are present with Microsoft\'s titles', () => {
  const want = {
    1102: 'The audit log was cleared.', 4624: 'An account was successfully logged on.', 4625: 'An account failed to log on.',
    4634: 'An account was logged off.', 4648: 'A logon was attempted using explicit credentials.',
    4672: 'Special privileges assigned to new logon.', 4688: 'A new process has been created.',
    4697: 'A service was installed in the system.', 4698: 'A scheduled task was created.',
    4719: 'System audit policy was changed.', 4720: 'A user account was created.', 4732: 'A member was added to a security-enabled local group.',
    4740: 'A user account was locked out.', 4768: 'A Kerberos authentication ticket (TGT) was requested.',
    4769: 'A Kerberos service ticket was requested.', 4771: 'Kerberos pre-authentication failed.',
    4776: 'The computer attempted to validate the credentials for an account.',
  };
  for (const [id, name] of Object.entries(want)) {
    const r = searchEvents(data, id);
    assert.equal(r.events.length, 1, id);
    assert.equal(r.events[0].name, name, id);
  }
});

test('the logon-type table is exactly Microsoft\'s nine types (no type 6)', () => {
  assert.deepEqual(data.logonTypes.map((l) => l.type), [2, 3, 4, 5, 7, 8, 9, 10, 11]);
  const names = Object.fromEntries(data.logonTypes.map((l) => [l.type, l.name]));
  assert.equal(names[3], 'Network');
  assert.equal(names[9], 'NewCredentials');
  assert.equal(names[10], 'RemoteInteractive');
  assert.equal(names[11], 'CachedInteractive');
  for (const l of data.logonTypes) assert.ok(l.plain.endsWith('.') && l.plain.length <= 160, `type ${l.type}`);
  assert.ok(eventDocUrl(data.docBase, data.logonTypesPage));
});

test('status codes are 0x + 8 upper-case hex digits, unique, and include the help-desk staples', () => {
  const codes = data.statusCodes.map((s) => s.code);
  assert.equal(new Set(codes).size, codes.length);
  for (const s of data.statusCodes) {
    assert.match(s.code, /^0xC[0-9A-F]{7}$/);
    assert.ok(s.plain.endsWith('.'), s.code);
    if (s.why) assert.ok(s.why.endsWith('.'), s.code);
  }
  for (const c of ['0xC0000064', '0xC000006A', '0xC000006D', '0xC0000072', '0xC0000193', '0xC0000234']) assert.ok(codes.includes(c), c);
  assert.ok(eventDocUrl(data.docBase, data.statusCodesPage));
});

test('normalizeStatus accepts 0x or bare hex in any case and refuses anything else', () => {
  assert.equal(normalizeStatus('0xC000006A'), '0xC000006A');
  assert.equal(normalizeStatus('0xc000006a'), '0xC000006A');
  assert.equal(normalizeStatus('C000006A'), '0xC000006A');
  assert.equal(normalizeStatus(' c000006a '), '0xC000006A');
  assert.equal(normalizeStatus('0x12345678'), '0x12345678');
  assert.equal(normalizeStatus('12345678'), null, 'an 8-digit decimal number is not a status code');
  assert.equal(normalizeStatus('0xC000006'), null);
  assert.equal(normalizeStatus('0xC000006AB'), null);
  assert.equal(normalizeStatus('0xG000006A'), null);
  assert.equal(normalizeStatus(''), null);
  assert.equal(normalizeStatus(undefined), null);
});

test('IDs: bare, "event", "event id" and "eventid" forms find the event; unlisted IDs say so', () => {
  for (const q of ['4625', 'event 4625', 'Event ID 4625', 'eventid 4625', 'event-4625', 'id: 4625', '  4625  ']) {
    const r = searchEvents(data, q);
    assert.equal(r.kind, 'id', q);
    assert.deepEqual(ids(r), [4625], q);
  }
  const missing = searchEvents(data, '4999');
  assert.equal(missing.kind, 'id');
  assert.deepEqual(missing.events, []);
  assert.equal(missing.error, undefined);
  assert.ok(searchEvents(data, '70000').error, 'above 65535 is refused');
  assert.ok(searchEvents(data, '0').kind === 'logon-type', 'one or two digits are logon types');
});

test('domain-group events point at the local-group page Microsoft documents them on', () => {
  for (const id of [4728, 4756]) {
    const e = searchEvents(data, String(id)).events[0];
    assert.equal(eventPageId(e), 4732);
  }
  assert.equal(eventPageId(searchEvents(data, '4625').events[0]), 4625);
});

test('logon types: "logon type 10", "type 10" and "10" find RemoteInteractive; 6 does not exist', () => {
  for (const q of ['logon type 10', 'Logon Type: 10', 'type 10', 'logontype 10', '10']) {
    const r = searchEvents(data, q);
    assert.equal(r.kind, 'logon-type', q);
    assert.deepEqual(r.logonTypes.map((l) => l.name), ['RemoteInteractive'], q);
  }
  const six = searchEvents(data, 'logon type 6');
  assert.equal(six.kind, 'logon-type');
  assert.deepEqual(six.logonTypes, []);
});

test('status codes: found in any form; an unlisted code says so', () => {
  const r = searchEvents(data, 'c000006a');
  assert.equal(r.kind, 'status');
  assert.equal(r.code, '0xC000006A');
  assert.match(r.statuses[0].plain, /password was wrong/);
  const unknown = searchEvents(data, '0xC0000999');
  assert.equal(unknown.kind, 'status');
  assert.deepEqual(unknown.statuses, []);
});

test('words: name matches first, then the plain sentence, then why it matters; tables match too', () => {
  const task = ids(searchEvents(data, 'scheduled task'));
  assert.deepEqual(task.slice(0, 5), [4698, 4699, 4700, 4701, 4702]);
  const locked = searchEvents(data, 'locked out');
  assert.equal(locked.events[0].id, 4740, 'name match first');
  assert.ok(locked.statuses.some((s) => s.code === '0xC0000234'));
  const rdp = searchEvents(data, 'remote desktop');
  assert.ok(ids(rdp).includes(4778));
  assert.ok(rdp.logonTypes.some((l) => l.type === 10));
  const spray = ids(searchEvents(data, 'password spraying'));
  for (const id of [4740, 4771]) assert.ok(spray.includes(id), `password spraying should find ${id}`);
  const kerb = ids(searchEvents(data, 'kerberos'));
  assert.deepEqual(kerb.slice(0, 3), [4768, 4769, 4771]);
});

test('empty, short, odd and long input never throws', () => {
  assert.equal(searchEvents(data, '').kind, 'empty');
  assert.equal(searchEvents(data, undefined).kind, 'empty');
  assert.equal(searchEvents(data, '   ').kind, 'empty');
  assert.deepEqual(searchEvents(data, 'ab').events, [], 'two letters match nothing');
  assert.deepEqual(searchEvents(data, '((([[[.*+?').events, []);
  assert.deepEqual(searchEvents(data, 'zzzz-not-an-event').events, []);
  assert.equal(searchEvents(data, 'x'.repeat(10000)).kind, 'text');
  assert.equal(searchEvents(null, '4625').kind, 'id');
});

test('eventProblems catches bad entries', () => {
  const ok = { log: 'Security', id: 4625, category: 'Logon/Logoff', name: 'An account failed to log on.', plain: 'A sign-in failed.', why: 'Watch bursts.' };
  assert.deepEqual(eventProblems(ok), []);
  assert.ok(eventProblems({ ...ok, log: 'System' }).length);
  assert.ok(eventProblems({ ...ok, id: '4625' }).length);
  assert.ok(eventProblems({ ...ok, id: 70000 }).length);
  assert.ok(eventProblems({ ...ok, name: 'No full stop' }).length);
  assert.ok(eventProblems({ ...ok, why: `${'x'.repeat(160)}.` }).length);
  assert.ok(eventProblems({ ...ok, page: 4625 }).length);
  assert.ok(eventProblems({ ...ok, extra: 1 }).length);
});

test('the Reference page has the events section, renders safely, and Ask can link to it', () => {
  const html = readFileSync(new URL('reference.html', root), 'utf8');
  for (const id of ['events', 'events-filter', 'events-count', 'events-list', 'events-logon-types', 'events-status-codes']) assert.ok(html.includes(`id="${id}"`), id);
  const js = readFileSync(new URL('js/reference.js', root), 'utf8');
  assert.ok(!/innerHTML/.test(js), 'render with textContent / DOM nodes only');
  assert.ok(/eventDocUrl\(/.test(js), 'Microsoft links are re-checked when rendering');
  const features = JSON.parse(readFileSync(new URL('data/hub-features.json', root), 'utf8')).features;
  const f = features.find((x) => x.id === 'events');
  assert.equal(f?.href, './reference.html#events');
  assert.ok(f.about.length <= 60);
});
