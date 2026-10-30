// My exposure: what an attacker can find out about you, and how to check it.
// Renders data/exposure.json as text and outside links; nothing is sent anywhere.

import { isHubHref } from './what-now.js';

const $ = (id) => document.getElementById(id);
// Short labels, as on the Reference page.
const KEY = { no: 'No account', api: 'API key', yes: 'Account', paid: 'Paid API' };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

/** An https link target with no userinfo, or null, so a bad edit never renders as a link. */
export function siteUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && !u.username && !u.password ? u.href : null;
  } catch {
    return null;
  }
}

function section(s) {
  const sites = s.sites.map((site) => [site, siteUrl(site.url)]).filter(([, href]) => href);
  const hub = (s.hub || []).filter((h) => isHubHref(h.href));
  return el('section', { class: 'block exposure-block', id: s.id, 'aria-labelledby': `${s.id}-h` },
    el('span', { class: 'num', 'aria-hidden': 'true' }),
    el('h2', { id: `${s.id}-h`, class: 'block-title' }, s.title),
    el('p', { class: 'exposure-why' }, s.why),
    el('h3', {}, 'Check and fix'),
    el('ol', { class: 'plain-list' }, ...s.steps.map((t) => el('li', {}, t))),
    s.note ? el('p', { class: 'hint' }, s.note) : null,
    hub.length ? el('p', { class: 'wts-hub' }, el('span', { class: 'hint' }, 'On this site: '),
      ...hub.flatMap((h, i) => [i ? ' · ' : null, el('a', { href: h.href }, h.label)])) : null,
    el('ul', { class: 'links' }, ...sites.map(([site, href]) => el('li', {},
      el('a', { href, target: '_blank', rel: 'noopener noreferrer' },
        el('strong', {}, site.name),
        el('span', { class: 'what' }, `${site.desc} (${KEY[site.account] || site.account})`))))));
}

if (globalThis.document?.getElementById('exposure-list')) {
  try {
    const res = await fetch('data/exposure.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    $('exposure-permission').textContent = data.permission;
    $('exposure-list').replaceChildren(...data.sections.map(section));
  } catch (err) {
    $('exposure-list').replaceChildren(el('p', { class: 'notice warn' }, `Could not load the page: ${err.message}`));
  }
}
