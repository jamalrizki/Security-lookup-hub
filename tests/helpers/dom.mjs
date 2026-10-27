// A small DOM stand-in for the page-wiring tests (the repo has no browser test
// dependencies). It parses a page's well-formed markup and covers what js/ask.js,
// js/voice.js and js/ask-image.js touch: elements, text, attributes, classes,
// events, forms and a textarea's selection. Not a general DOM.

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);

class Node {
  constructor() { this.parentNode = null; this.childNodes = []; }
  get children() { return this.childNodes.filter((n) => n instanceof Element); }
  get childElementCount() { return this.children.length; }
  get firstElementChild() { return this.children[0] || null; }
  get firstChild() { return this.childNodes[0] || null; }
  get textContent() { return this.childNodes.map((n) => n.textContent).join(''); }
  set textContent(v) { this.replaceChildren(String(v)); }
  hasChildNodes() { return this.childNodes.length > 0; }
  _adopt(n) {
    const node = typeof n === 'string' ? new Text(n) : n;
    node.remove?.();
    node.parentNode = this;
    return node;
  }
  append(...nodes) { for (const n of nodes) if (n != null) this.childNodes.push(this._adopt(n)); }
  prepend(...nodes) { this.childNodes.unshift(...nodes.filter((n) => n != null).map((n) => this._adopt(n))); }
  appendChild(n) { this.append(n); return n; }
  insertBefore(n, ref) {
    const node = this._adopt(n);
    const i = ref ? this.childNodes.indexOf(ref) : -1;
    if (i < 0) this.childNodes.push(node); else this.childNodes.splice(i, 0, node);
    return n;
  }
  replaceChildren(...nodes) {
    for (const c of this.childNodes) c.parentNode = null;
    this.childNodes = [];
    this.append(...nodes);
  }
  remove() {
    if (!this.parentNode) return;
    const list = this.parentNode.childNodes;
    list.splice(list.indexOf(this), 1);
    this.parentNode = null;
  }
  contains(n) { for (let x = n; x; x = x.parentNode) if (x === this) return true; return false; }
}

class Text extends Node {
  constructor(text) { super(); this.data = String(text); }
  get textContent() { return this.data; }
  set textContent(v) { this.data = String(v); }
}

function matches(elm, selector) {
  // Compound selectors only: tag, #id, .class, [attr] / [attr="v"].
  const re = /([a-z0-9]+)|#([\w-]+)|\.([\w-]+)|\[([\w-]+)(?:="([^"]*)")?\]/gi;
  let m;
  let any = false;
  while ((m = re.exec(selector))) {
    any = true;
    if (m[1] && elm.tagName.toLowerCase() !== m[1].toLowerCase()) return false;
    if (m[2] && elm.id !== m[2]) return false;
    if (m[3] && !elm.classList.contains(m[3])) return false;
    if (m[4] && (!elm.hasAttribute(m[4]) || (m[5] !== undefined && elm.getAttribute(m[4]) !== m[5]))) return false;
  }
  return any;
}

function selectAll(root, selector) {
  const out = [];
  for (const group of selector.split(',')) {
    const parts = group.trim().split(/\s+/);
    const walk = (node) => {
      for (const c of node.children) {
        if (matches(c, parts.at(-1))) {
          // Ancestors must match the earlier parts, in order.
          let i = parts.length - 2;
          for (let a = c.parentNode; a && i >= 0; a = a.parentNode) if (a instanceof Element && matches(a, parts[i])) i--;
          if (i < 0 && !out.includes(c)) out.push(c);
        }
        walk(c);
      }
    };
    walk(root);
  }
  return out;
}

export class Event {
  constructor(type, init = {}) { Object.assign(this, init); this.type = type; this.defaultPrevented = false; }
  preventDefault() { this.defaultPrevented = true; }
  stopPropagation() { this.stopped = true; }
}

class EventTargetish extends Node {
  constructor() { super(); this._listeners = {}; }
  addEventListener(type, fn) { (this._listeners[type] ||= []).push(fn); }
  removeEventListener(type, fn) { this._listeners[type] = (this._listeners[type] || []).filter((f) => f !== fn); }
  dispatchEvent(ev) {
    if (!ev.target) ev.target = this;
    ev.currentTarget = this;
    for (const fn of [...(this._listeners[ev.type] || [])]) fn.call(this, ev);
    if (!ev.stopped && ev.bubbles !== false && this.parentNode?.dispatchEvent) this.parentNode.dispatchEvent(ev);
    return !ev.defaultPrevented;
  }
}

export class Element extends EventTargetish {
  constructor(tag, doc) {
    super();
    this.tagName = tag.toUpperCase();
    this.ownerDocument = doc;
    this.attributes = new Map();
    this.style = {};
    this._value = '';
    this.selectionStart = 0;
    this.selectionEnd = 0;
    this.scrollHeight = 40;
    const self = this;
    this.classList = {
      contains: (c) => self.className.split(/\s+/).includes(c),
      add: (...cs) => { for (const c of cs) if (!self.classList.contains(c)) self.className = `${self.className} ${c}`.trim(); },
      remove: (...cs) => { self.className = self.className.split(/\s+/).filter((x) => x && !cs.includes(x)).join(' '); },
      toggle: (c, on = !self.classList.contains(c)) => { if (on) self.classList.add(c); else self.classList.remove(c); return on; },
    };
  }
  get id() { return this.getAttribute('id') || ''; }
  set id(v) { this.setAttribute('id', v); }
  get className() { return this.getAttribute('class') || ''; }
  set className(v) { this.setAttribute('class', v); }
  get hidden() { return this.hasAttribute('hidden'); }
  set hidden(v) { if (v) this.setAttribute('hidden', ''); else this.removeAttribute('hidden'); }
  get disabled() { return this.hasAttribute('disabled'); }
  set disabled(v) { if (v) this.setAttribute('disabled', ''); else this.removeAttribute('disabled'); }
  get type() { return this.getAttribute('type') || (this.tagName === 'BUTTON' ? 'submit' : 'text'); }
  set type(v) { this.setAttribute('type', v); }
  get href() { return this.getAttribute('href'); }
  get value() { return this.tagName === 'TEXTAREA' || this.tagName === 'INPUT' ? this._value : this.getAttribute('value') || ''; }
  set value(v) { this._value = String(v); this.selectionStart = this.selectionEnd = this._value.length; }
  get files() { return this._files || []; }
  set files(v) { this._files = v; }
  setAttribute(k, v) { this.attributes.set(k, String(v)); }
  getAttribute(k) { return this.attributes.has(k) ? this.attributes.get(k) : null; }
  hasAttribute(k) { return this.attributes.has(k); }
  removeAttribute(k) { this.attributes.delete(k); }
  setSelectionRange(a, b) { this.selectionStart = a; this.selectionEnd = b; }
  focus() { this.ownerDocument.activeElement = this; }
  blur() { if (this.ownerDocument.activeElement === this) this.ownerDocument.activeElement = this.ownerDocument.body; }
  scrollIntoView(opts) { this.ownerDocument.scrolledTo.push({ el: this, opts }); }
  click() {
    if (this.disabled) return;
    const ev = new Event('click', { bubbles: true });
    this.dispatchEvent(ev);
    if (ev.defaultPrevented) return;
    if (this.tagName === 'BUTTON' && this.type === 'submit') this.closest('form')?.requestSubmit();
    if (this.tagName === 'A' && this.href) this.ownerDocument.navigations.push({ href: this.href, target: this.getAttribute('target') });
    if (this.tagName === 'INPUT' && this.type === 'file') this.ownerDocument.filePickers.push(this);
  }
  requestSubmit() { this.dispatchEvent(new Event('submit', { bubbles: true })); }
  closest(sel) { for (let x = this; x instanceof Element; x = x.parentNode) if (matches(x, sel)) return x; return null; }
  matches(sel) { return matches(this, sel); }
  querySelector(sel) { return selectAll(this, sel)[0] || null; }
  querySelectorAll(sel) { return selectAll(this, sel); }
  getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0, bottom: 0, right: 0 }; }
}

/** Parses well-formed markup (as the hub's pages are) into Elements. */
function parse(html, doc, parent) {
  const stack = [parent];
  const re = /<!--[\s\S]*?-->|<\/([a-z0-9]+)\s*>|<([a-z0-9]+)((?:\s+[\w:-]+(?:="[^"]*")?)*)\s*\/?>|([^<]+)/gi;
  let m;
  const decode = (t) => t.replace(/&rarr;/g, '→').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n))).replace(/&middot;/g, '·');
  while ((m = re.exec(html))) {
    const top = stack.at(-1);
    if (m[1]) {
      if (stack.length > 1) stack.pop();
    } else if (m[2]) {
      const elm = doc.createElement(m[2]);
      for (const [, k, v] of (m[3] || '').matchAll(/([\w:-]+)(?:="([^"]*)")?/g)) elm.setAttribute(k, decode(v ?? ''));
      top.append(elm);
      if (!VOID.has(m[2].toLowerCase())) stack.push(elm);
    } else if (m[4] && top.tagName !== 'SCRIPT') {
      if (top.tagName === 'TEXTAREA') top._value += decode(m[4]);
      else top.append(decode(m[4]));
    }
  }
}

/**
 * Installs document, window, location, history, navigator etc. on globalThis for
 * the page `html`, at `url`. Returns the document (with navigations, scrolledTo
 * and filePickers logs) and a restore() function.
 */
export function installDom(html, { url = 'https://jamalrizki.github.io/Security-lookup-hub/', touch = false, navigator: nav = {} } = {}) {
  const saved = {};
  const names = ['document', 'window', 'location', 'history', 'navigator', 'matchMedia', 'scrollY', 'sessionStorage', 'Event', 'KeyboardEvent', 'HTMLElement'];
  for (const n of names) saved[n] = Object.getOwnPropertyDescriptor(globalThis, n);

  const doc = new EventTargetish();
  Object.assign(doc, {
    navigations: [], scrolledTo: [], filePickers: [],
    createElement: (tag) => new Element(tag, doc),
    createTextNode: (t) => new Text(t),
    getElementById: (id) => selectAll(doc, `#${id}`)[0] || null,
    querySelector: (sel) => selectAll(doc, sel)[0] || null,
    querySelectorAll: (sel) => selectAll(doc, sel),
  });
  const body = doc.createElement('body');
  doc.append(body);
  doc.body = body;
  doc.activeElement = body;
  const bodyHtml = /<body[^>]*>([\s\S]*)<\/body>/i.exec(html);
  parse(bodyHtml ? bodyHtml[1] : html, doc, body);

  const u = new URL(url);
  const location = {
    get href() { return u.href; },
    set href(v) { doc.navigations.push({ href: v }); },
    get hash() { return u.hash; },
    set hash(v) { u.hash = v; },
    get pathname() { return u.pathname; },
    get search() { return u.search; },
    get origin() { return u.origin; },
    get hostname() { return u.hostname; },
    replace(v) { doc.navigations.push({ href: v, replace: true }); },
  };
  const historyLog = [];
  const history = {
    log: historyLog,
    replaceState(state, title, next) { historyLog.push(next); u.href = new URL(next, u).href; },
    pushState(state, title, next) { historyLog.push(next); u.href = new URL(next, u).href; },
    length: 1,
  };
  const media = { '(pointer: coarse)': touch };
  const define = (k, v) => Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true });
  define('document', doc);
  define('location', location);
  define('history', history);
  define('navigator', { userAgent: 'node', ...nav });
  define('matchMedia', (q) => ({ matches: Boolean(media[q]), addEventListener() {} }));
  define('scrollY', 0);
  define('Event', Event);
  define('KeyboardEvent', Event);
  define('HTMLElement', Element);
  define('window', globalThis);
  return {
    document: doc,
    history,
    restore() {
      for (const n of names) {
        if (saved[n]) Object.defineProperty(globalThis, n, saved[n]);
        else delete globalThis[n];
      }
    },
  };
}

/** Lets pending promise callbacks (fetch stubs, awaits) run. */
export const settle = async (n = 20) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };

/** Types into a textarea and fires input. */
export function type(elm, text) {
  elm.value = text;
  elm.dispatchEvent(new Event('input', { bubbles: true }));
}
