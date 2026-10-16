// data/tools.json is maintained separately; this only checks its shape.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('data/tools.json: { tools: [{ tool, whatItDoes }] } with unique, non-empty text', () => {
  const data = JSON.parse(readFileSync(new URL('../data/tools.json', import.meta.url), 'utf8'));
  assert.ok(Array.isArray(data.tools), 'top level needs a "tools" array');
  const seen = new Set();
  for (const [i, t] of data.tools.entries()) {
    assert.deepEqual(Object.keys(t).sort(), ['tool', 'whatItDoes'], `entry ${i} should have exactly "tool" and "whatItDoes"`);
    assert.ok(typeof t.tool === 'string' && t.tool.trim(), `entry ${i}: "tool" must be non-empty text`);
    assert.ok(typeof t.whatItDoes === 'string' && t.whatItDoes.trim(), `entry ${i}: "whatItDoes" must be non-empty text`);
    assert.ok(!seen.has(t.tool.toLowerCase()), `duplicate tool: ${t.tool}`);
    seen.add(t.tool.toLowerCase());
  }
});
