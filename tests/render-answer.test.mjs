import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseAnswer, parseInline, renderAnswer } from '../js/render-answer.js';

// A tiny DOM: enough to see which elements get created and what text they hold.
const fakeDoc = {
  created: [],
  createElement(tag) {
    const node = { tag, children: [], _text: '', append(...c) { this.children.push(...c); } };
    Object.defineProperty(node, 'textContent', { get() { return this._text + this.children.map((c) => c.textContent).join(''); }, set(v) { this._text = String(v); this.children = []; } });
    Object.defineProperty(node, 'innerHTML', { set() { throw new Error('innerHTML used'); } });
    this.created.push(tag);
    return node;
  },
  createTextNode(text) { return { tag: '#text', textContent: text }; },
};

test('Markdown subset: paragraphs, "- " lists, **bold**, `code`', () => {
  const blocks = parseAnswer('Intro line\nsecond line\n\n- one **bold**\n- two `code`\n\nEnd.');
  assert.deepEqual(blocks.map((b) => b.type), ['p', 'ul', 'p']);
  assert.equal(blocks[0].lines.length, 2);
  assert.deepEqual(blocks[1].items[0], [{ type: 'text', text: 'one ' }, { type: 'strong', text: 'bold' }]);
  assert.deepEqual(parseInline('a `b` c'), [{ type: 'text', text: 'a ' }, { type: 'code', text: 'b' }, { type: 'text', text: ' c' }]);
});

test('hostile answers render as text: no script, img or link elements are ever created', () => {
  fakeDoc.created = [];
  const hostile = '<script>alert(1)</script>\n\n- <img src=x onerror=alert(1)>\n- [click](javascript:alert(1)) **<b>x</b>**\n\n<a href="javascript:alert(1)">y</a>';
  const nodes = renderAnswer(hostile, fakeDoc);
  assert.ok(fakeDoc.created.every((t) => ['p', 'ul', 'li', 'strong', 'code', 'br'].includes(t)), fakeDoc.created.join());
  const text = nodes.map((n) => n.textContent).join('\n');
  assert.ok(text.includes('<script>alert(1)</script>'), 'shown literally');
  assert.ok(text.includes('<img src=x onerror=alert(1)>'));
  assert.ok(text.includes('javascript:alert(1)'));
});

test('no innerHTML (or other HTML parsing) in the Ask page code', () => {
  for (const f of ['js/ask.js', 'js/render-answer.js', 'js/analyze/handoff.js']) {
    const src = readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|DOMParser/.test(src), f);
  }
});
