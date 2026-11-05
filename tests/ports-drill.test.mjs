// Ports practice (js/ports-drill.js): every answer comes from data/ports.json,
// the grader accepts fair wordings, and odd input never counts as wrong.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  KINDS, EXAM_PORTS, ALIASES, SUBJECT, MAX_ANSWER, seeded, makeQuestion, checkAnswer, explain,
  normName, acceptedNames, pool,
} from '../js/ports-drill.js';

const root = new URL('../', import.meta.url);
const { ports } = JSON.parse(readFileSync(new URL('data/ports.json', root), 'utf8'));
const byPort = (n) => ports.find((p) => p.port === n);
const many = (opts, n = 500, seed = 1) => {
  const rand = seeded(seed);
  return Array.from({ length: n }, () => makeQuestion(rand, ports, opts));
};

test('every port named in EXAM_PORTS, ALIASES and SUBJECT is in data/ports.json', () => {
  for (const n of EXAM_PORTS) assert.ok(byPort(n), `exam port ${n}`);
  for (const n of Object.keys(ALIASES)) assert.ok(byPort(Number(n)), `alias port ${n}`);
  for (const n of Object.keys(SUBJECT)) assert.ok(byPort(Number(n)), `subject port ${n}`);
  assert.equal(new Set(EXAM_PORTS).size, EXAM_PORTS.length);
  assert.equal(pool(ports, true).length, EXAM_PORTS.length);
});

test('questions are repeatable per seed, every kind comes up, and answers match the list', () => {
  assert.deepEqual(makeQuestion(seeded(9), ports), makeQuestion(seeded(9), ports));
  const seen = new Set();
  for (let seed = 1; seed <= 4; seed++) {
    for (const q of many({}, 400, seed)) {
      seen.add(q.kind);
      const e = q.entry;
      assert.equal(byPort(e.port), e, 'the entry is the list entry itself');
      if (q.kind === 'port') {
        assert.ok(q.ports.includes(e.port));
        for (const n of q.ports) assert.equal(checkAnswer(q, String(n)).status, 'correct');
        assert.ok(!q.prompt.includes(String(e.port)), `${q.prompt} gives the answer away`);
      }
      if (q.kind === 'secure') {
        assert.deepEqual(q.ports, e.secure);
        assert.equal(checkAnswer(q, String(e.secure[0])).status, 'correct');
        assert.equal(checkAnswer(q, String(e.port)).status, 'wrong');
      }
      if (q.kind === 'name') {
        assert.equal(checkAnswer(q, e.name).status, 'correct', `${e.port} ${e.name}`);
        assert.ok(!q.prompt.includes(e.name), `${q.prompt} gives the answer away`);
      }
      if (q.kind === 'transport') {
        const want = e.proto === 'TCP/UDP' ? 'both' : e.proto.toLowerCase();
        assert.equal(checkAnswer(q, want).status, 'correct');
        for (const other of ['tcp', 'udp', 'both'].filter((w) => w !== want)) assert.equal(checkAnswer(q, other).status, 'wrong');
      }
      assert.ok(q.prompt.length < 120);
    }
  }
  assert.deepEqual([...seen].sort(), [...KINDS].sort());
});

test('"Exam ports only" asks only about exam ports; all ports can come up otherwise', () => {
  for (const q of many({ examOnly: true }, 800)) assert.ok(EXAM_PORTS.includes(q.entry.port), `${q.entry.port}`);
  const asked = new Set(many({}, 4000).map((q) => q.entry.port));
  assert.ok([...asked].some((n) => !EXAM_PORTS.includes(n)));
});

test('port answers: numbers with an optional "port" or transport; words and big numbers are invalid', () => {
  const q = makeQuestion(seeded(1), ports, { kinds: ['port'] });
  const right = String(q.ports[0]);
  for (const a of [right, ` port ${right} `, `${right}/tcp`, `${right} / UDP`]) assert.equal(checkAnswer(q, a).status, 'correct', a);
  assert.equal(checkAnswer(q, '1').status, 'wrong');
  assert.match(checkAnswer(q, '1').message, new RegExp(`The answer is ${q.answer}\\.`));
  for (const a of ['', '   ', 'ssh', '70000', 'x'.repeat(MAX_ANSWER + 1)]) assert.equal(checkAnswer(q, a).status, 'invalid', a);
});

test('DHCP: the bare name accepts 67 or 68, "a DHCP server" only 67', () => {
  const dhcp = { kind: 'port', entry: { ...byPort(67) } };
  // Same shape makeQuestion builds when the name has no SUBJECT override.
  const both = { ...dhcp, ports: [67, 68], answer: '67 or 68' };
  assert.equal(checkAnswer(both, '68').status, 'correct');
  const rand = seeded(3);
  let server = null;
  for (let i = 0; i < 3000 && !server; i++) {
    const q = makeQuestion(rand, ports, { kinds: ['port'] });
    if (q.entry.port === 67) server = q;
  }
  assert.ok(server);
  assert.match(server.prompt, /DHCP server/);
  assert.deepEqual(server.ports, [67]);
  assert.equal(checkAnswer(server, '68').status, 'wrong');
});

test('name answers: case, punctuation, filler words, full names and listed aliases count', () => {
  const ask = (n) => ({ kind: 'name', entry: byPort(n), answer: byPort(n).name });
  const cases = {
    22: ['ssh', 'SSH', 'Secure Shell', 'SFTP', 'scp'],
    3389: ['rdp', 'RDP protocol', 'Remote Desktop Protocol', 'remote desktop'],
    1433: ['MS-SQL', 'ms sql', 'mssql', 'Microsoft SQL Server', 'SQL Server'],
    3306: ['MySQL', 'MariaDB'],
    49: ['TACACS+', 'tacacs plus'],
    445: ['SMB', 'the SMB service', 'Server Message Block'],
    20: ['FTP-DATA', 'ftp data', 'FTP'],
    587: ['Submission', 'SMTP'],
    6443: ['Kubernetes', 'k8s'],
  };
  for (const [port, answers] of Object.entries(cases)) {
    for (const a of answers) assert.equal(checkAnswer(ask(Number(port)), a).status, 'correct', `${port}: ${a}`);
  }
  for (const [port, a] of [[22, 'telnet'], [3389, 'vnc'], [445, 'nfs'], [20, 'data'], [5985, 'http'], [3268, 'ldap'], [500, 'ipsec']]) {
    assert.equal(checkAnswer(ask(port), a).status, 'wrong', `${port}: ${a}`);
  }
  assert.equal(checkAnswer(ask(22), '22').status, 'invalid');
});

test('no entry accepts another port\'s name unless ALIASES says so', () => {
  for (const p of ports) {
    const names = acceptedNames(p);
    assert.ok(names.has(normName(p.name)), `${p.port} accepts its own name`);
    for (const other of ports) {
      if (other.name === p.name) continue;
      const n = normName(other.name);
      if (!names.has(n)) continue;
      const allowed = (ALIASES[p.port] || []).map(normName);
      assert.ok(allowed.includes(n), `${p.port} ${p.name} accepts ${other.name} without an alias`);
    }
  }
});

test('transport answers accept TCP, UDP, both and "TCP/UDP"; anything else is invalid', () => {
  const dns = { kind: 'transport', entry: byPort(53), answer: 'both' };
  for (const a of ['both', 'TCP/UDP', 'udp and tcp', 'tcp & udp']) assert.equal(checkAnswer(dns, a).status, 'correct', a);
  assert.equal(checkAnswer(dns, 'udp').status, 'wrong');
  const snmp = { kind: 'transport', entry: byPort(161), answer: 'UDP' };
  assert.equal(checkAnswer(snmp, 'UDP').status, 'correct');
  assert.equal(checkAnswer(snmp, 'both').status, 'wrong');
  for (const a of ['icmp', 'tcp maybe', '161']) assert.equal(checkAnswer(snmp, a).status, 'invalid', a);
});

test('the explanation uses only the list\'s own text', () => {
  const q = { kind: 'name', entry: byPort(23) };
  const text = explain(ports, q);
  assert.match(text, /^23\/TCP Telnet\. /);
  assert.ok(text.includes(byPort(23).use));
  assert.match(text, /Encrypted version: 22 SSH\./);
  assert.match(text, /not be reachable from the internet/);
  assert.match(explain(ports, { entry: byPort(1521) }), /not its official IANA assignment/);
  assert.match(explain(ports, { entry: byPort(3389) }), /^3389\/TCP\/UDP RDP: Remote Desktop Protocol\. /);
});

test('the Reference page has the practice block and wires it after the list loads', () => {
  const html = readFileSync(new URL('reference.html', root), 'utf8');
  for (const id of ['ports-practice', 'pdrill-exam', 'pdrill-question', 'pdrill-form', 'pdrill-answer', 'pdrill-reveal', 'pdrill-next', 'pdrill-show', 'pdrill-result', 'pdrill-score']) {
    assert.ok(html.includes(`id="${id}"`), id);
  }
  assert.ok(html.indexOf('id="ports-practice"') > html.indexOf('id="ports-list"'));
  const js = readFileSync(new URL('js/reference.js', root), 'utf8');
  assert.match(js, /startPortsDrill\(ports,/);
  const drill = readFileSync(new URL('js/ports-drill.js', root), 'utf8');
  assert.ok(!/innerHTML|localStorage|sessionStorage|fetch\(/.test(drill), 'no innerHTML, storage or network in the drill');
});
