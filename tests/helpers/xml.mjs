// A minimal DOMParser stand-in for XML in Node tests (Node has no DOMParser).
// Covers what js/analyze/dmarc.js reads: documentElement, children, localName,
// nodeName, namespaceURI, textContent and a <parsererror> on bad markup.
// Elements, text, comments, CDATA, the XML declaration and the five basic
// entities only; not a general XML parser. The page uses the browser's own.

const decode = (s) => s.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-f]+);/gi, (_, e) =>
  ({ lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" })[e.toLowerCase()]
  ?? String.fromCodePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : Number(e.slice(1))));

class El {
  constructor(name, attrs, parent) {
    this.nodeName = name;
    this.localName = name.includes(':') ? name.split(':')[1] : name;
    this.parent = parent;
    this.nodes = [];
    this.ns = { ...(parent?.ns || {}) };
    for (const [, k, v] of attrs.matchAll(/([\w:.-]+)\s*=\s*"([^"]*)"/g)) {
      if (k === 'xmlns') this.ns[''] = decode(v);
      else if (k.startsWith('xmlns:')) this.ns[k.slice(6)] = decode(v);
    }
    this.namespaceURI = this.ns[name.includes(':') ? name.split(':')[0] : ''] || null;
  }
  get children() { return this.nodes.filter((n) => n instanceof El); }
  get textContent() { return this.nodes.map((n) => (typeof n === 'string' ? n : n.textContent)).join(''); }
  getElementsByTagName(name) {
    const out = [];
    const walk = (e) => { for (const c of e.children) { if (c.nodeName === name) out.push(c); walk(c); } };
    walk(this);
    return out;
  }
}

export class XmlParser {
  parseFromString(src) {
    const top = new El('#document', '', null);
    let cur = top;
    let ok = true;
    const re = /<\?[\s\S]*?\?>|<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<!DOCTYPE[^>]*>|<\/([\w:.-]+)\s*>|<([\w:.-]+)((?:\s+[\w:.-]+\s*=\s*"[^"]*")*)\s*(\/?)>|([^<]+)|(<)/g;
    for (const m of src.matchAll(re)) {
      if (m[1] != null) cur.nodes.push(m[1]);
      else if (m[2]) { if (cur.nodeName !== m[2]) { ok = false; break; } cur = cur.parent; }
      else if (m[3]) { const e = new El(m[3], m[4] || '', cur === top ? null : cur); e.parent = cur; cur.nodes.push(e); if (!m[5]) cur = e; }
      else if (m[6] != null) { if (cur === top) { if (m[6].trim()) ok = false; } else cur.nodes.push(decode(m[6])); }
      else if (m[7]) { ok = false; break; }
    }
    if (cur !== top || top.children.length !== 1) ok = false;
    if (!ok) {
      const doc = new El('#document', '', null);
      doc.nodes.push(new El('parsererror', '', null));
      doc.documentElement = doc.children[0];
      return doc;
    }
    top.documentElement = top.children[0];
    return top;
  }
}
