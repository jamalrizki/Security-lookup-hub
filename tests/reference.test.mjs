import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const data = JSON.parse(readFileSync(new URL('../data/reference.json', import.meta.url), 'utf8'));
const names = new Set(data.groups.flatMap((g) => g.sites.map((s) => s.name)));

test('"Where to start" links only to sites already in the directory, and to hub pages that exist', () => {
  const things = data.whereToStart.map((r) => r.have);
  assert.deepEqual(things, ['A file hash', 'A domain', 'An IP address', 'A URL', 'An email address', 'Email headers', 'A CVE ID', 'A suspicious file', 'A threat actor name']);
  for (const row of data.whereToStart) {
    assert.ok(row.sites.length >= 2 && row.sites.length <= 3, row.have);
    for (const s of row.sites) {
      assert.ok(names.has(s.name), `${row.have}: "${s.name}" is not in the directory`);
      assert.ok(s.when.length > 10);
      assert.ok(!('url' in s), 'URLs come from the directory entry, never from this section');
    }
    for (const h of row.hub) {
      const file = h.href.split('#')[0] || 'index.html';
      assert.ok(readFileSync(new URL(`../${file === './' ? 'index.html' : file}`, import.meta.url)), h.href);
    }
  }
});
