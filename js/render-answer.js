// Renders an Ask answer: a small Markdown subset (paragraphs, "- " lists,
// **bold**, `code`) turned into DOM nodes. Every string goes in as a text node,
// so model output is never parsed as HTML: "<script>" shows as those characters.

/** Splits a line into [{ type: 'text' | 'strong' | 'code', text }]. */
export function parseInline(line) {
  const out = [];
  const re = /`([^`\n]+)`|\*\*([^*\n]+)\*\*/g;
  let last = 0;
  let m;
  while ((m = re.exec(line))) {
    if (m.index > last) out.push({ type: 'text', text: line.slice(last, m.index) });
    out.push(m[1] !== undefined ? { type: 'code', text: m[1] } : { type: 'strong', text: m[2] });
    last = re.lastIndex;
  }
  if (last < line.length) out.push({ type: 'text', text: line.slice(last) });
  return out;
}

const BULLET = /^\s*(?:[-*•]|\d{1,2}[.)])\s+/;

/**
 * Text -> blocks: [{ type: 'p', lines: [inline[]] }, { type: 'ul', items: [inline[]] }].
 * Headings ("## x") become bold paragraphs; tables and HTML are just text.
 */
export function parseAnswer(text) {
  const blocks = [];
  let para = null;
  let list = null;
  const close = () => { para = null; list = null; };
  for (const raw of String(text).replace(/\r\n?/g, '\n').split('\n')) {
    const line = raw.trimEnd();
    if (!line.trim()) { close(); continue; }
    if (BULLET.test(line)) {
      para = null;
      if (!list) { list = { type: 'ul', items: [] }; blocks.push(list); }
      list.items.push(parseInline(line.replace(BULLET, '')));
      continue;
    }
    const heading = /^\s*#{1,6}\s+(.*)$/.exec(line);
    if (heading) {
      close();
      blocks.push({ type: 'p', lines: [[{ type: 'strong', text: heading[1].replace(/\*\*/g, '') }]] });
      continue;
    }
    list = null;
    if (!para) { para = { type: 'p', lines: [] }; blocks.push(para); }
    para.lines.push(parseInline(line.trim()));
  }
  return blocks;
}

function inlineNodes(doc, parts) {
  return parts.map((p) => {
    if (p.type === 'text') return doc.createTextNode(p.text);
    const node = doc.createElement(p.type);
    node.textContent = p.text;
    return node;
  });
}

/** Returns an array of <p>/<ul> elements for the answer text. */
export function renderAnswer(text, doc = globalThis.document) {
  return parseAnswer(text).map((b) => {
    if (b.type === 'ul') {
      const ul = doc.createElement('ul');
      for (const item of b.items) {
        const li = doc.createElement('li');
        li.append(...inlineNodes(doc, item));
        ul.append(li);
      }
      return ul;
    }
    const p = doc.createElement('p');
    b.lines.forEach((line, i) => {
      if (i) p.append(doc.createElement('br'));
      p.append(...inlineNodes(doc, line));
    });
    return p;
  });
}
