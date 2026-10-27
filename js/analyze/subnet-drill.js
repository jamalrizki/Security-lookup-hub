// Subnetting practice (#subnet-practice). Random IPv4 questions for
// Network+/Security+ students. Every answer comes from subnetInfo() and
// inRange() in subnet.js, so the drill and the calculator can never disagree;
// the "working" text is built from the same numbers. No AI, no network, no
// storage: the session score lives in a variable. Pure functions are exported
// for tests; the page wiring at the bottom only runs in a browser.

import { parseIPv4 } from '../detect.js';
import { subnetInfo, inRange } from './subnet.js';

export const KINDS = ['network', 'broadcast', 'first', 'last', 'usable', 'mask', 'inrange'];
export const MAX_ANSWER = 40;

// Questions only use private (RFC 1918) and documentation (RFC 5737) space,
// and the whole subnet stays inside its block, so no real public address shows.
// The weight makes RFC 1918 questions (the ones exams use) most common.
export const BLOCKS = [
  { base: [10, 0, 0, 0], prefix: 8, weight: 4 },
  { base: [172, 16, 0, 0], prefix: 12, weight: 3 },
  { base: [192, 168, 0, 0], prefix: 16, weight: 3 },
  { base: [192, 0, 2, 0], prefix: 24, weight: 1 },
  { base: [198, 51, 100, 0], prefix: 24, weight: 1 },
  { base: [203, 0, 113, 0], prefix: 24, weight: 1 },
];
export const MIN_PREFIX = 8;
export const MAX_PREFIX = 30;

/** Seeded generator for tests (mulberry32): returns floats in [0, 1). */
export function seeded(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Browser generator: crypto.getRandomValues, floats in [0, 1). */
export function cryptoRand() {
  const b = new Uint32Array(1);
  globalThis.crypto.getRandomValues(b);
  return b[0] / 4294967296;
}

const pick = (rand, list) => list[Math.floor(rand() * list.length)];
const between = (rand, lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));
const toInt = (o) => ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
const toIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
const maskOf = (bits) => (bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0);
const ORD = ['1st', '2nd', '3rd', '4th'];

/** The block (from BLOCKS) an address belongs to, or null. */
export function blockOf(ip) {
  const o = parseIPv4(ip);
  if (!o) return null;
  const n = toInt(o);
  return BLOCKS.find((b) => ((n & maskOf(b.prefix)) >>> 0) === toInt(b.base)) || null;
}

function pickBlock(rand) {
  const total = BLOCKS.reduce((s, b) => s + b.weight, 0);
  let r = rand() * total;
  for (const b of BLOCKS) { r -= b.weight; if (r < 0) return b; }
  return BLOCKS[0];
}

/** A random address inside block b (any host bits). */
const randomIn = (rand, b) => (toInt(b.base) | (Math.floor(rand() * 2 ** (32 - b.prefix)) >>> 0)) >>> 0;

/** Makes one question. kinds limits which kinds can come up. */
export function makeQuestion(rand, kinds = KINDS) {
  const allowed = kinds.filter((k) => KINDS.includes(k));
  const kind = pick(rand, allowed.length ? allowed : KINDS);
  const block = pickBlock(rand);
  const prefix = between(rand, Math.max(MIN_PREFIX, block.prefix), MAX_PREFIX);
  const ip = toIp(randomIn(rand, block));
  const cidr = `${ip}/${prefix}`;
  const info = subnetInfo(cidr);
  const q = { kind, cidr, ip, prefix, info };

  if (kind === 'network') q.prompt = `Host ${cidr}: what is the network address?`;
  else if (kind === 'broadcast') q.prompt = `Host ${cidr}: what is the broadcast address?`;
  else if (kind === 'first') q.prompt = `Host ${cidr}: what is the first usable host address?`;
  else if (kind === 'last') q.prompt = `Host ${cidr}: what is the last usable host address?`;
  else if (kind === 'usable') q.prompt = `Host ${cidr}: how many usable host addresses does its subnet have?`;
  else if (kind === 'mask') {
    q.toMask = rand() < 0.5;
    q.prompt = q.toMask ? `What is the subnet mask for a /${prefix}?` : `What prefix length is the mask ${info.netmask}?`;
  } else {
    // "Is X in this range?": about half inside, half just outside (same block).
    const net = toInt(parseIPv4(info.network.split('/')[0]));
    const size = 2 ** (32 - prefix);
    let target;
    if (rand() < 0.5 || prefix === block.prefix) {
      target = net + Math.floor(rand() * size);
    } else {
      // Flip one network bit between the block's prefix and this prefix: a
      // nearby subnet in the same private/documentation block.
      const bit = between(rand, block.prefix, prefix - 1);
      target = ((net ^ (1 << (31 - bit))) >>> 0) + Math.floor(rand() * size);
    }
    q.check = toIp(target >>> 0);
    q.inside = inRange(info.network, q.check);
    q.prompt = `Is ${q.check} in ${info.network}? (yes or no)`;
  }
  q.answer = canonicalAnswer(q);
  return q;
}

function canonicalAnswer(q) {
  const i = q.info;
  switch (q.kind) {
    case 'network': return i.network.split('/')[0];
    case 'broadcast': return i.broadcast;
    case 'first': return i.firstHost;
    case 'last': return i.lastHost;
    case 'usable': return Number(i.usable).toLocaleString('en-US');
    case 'mask': return q.toMask ? i.netmask : `/${q.prefix}`;
    default: return q.inside ? 'yes' : 'no';
  }
}

/** Step-by-step working, built from subnetInfo()'s numbers. */
export function working(q) {
  const i = q.info;
  const p = q.prefix;
  const net = i.network.split('/')[0];
  const lines = [`/${p} → mask ${i.netmask}.`];
  if (p % 8 === 0) {
    lines.push(`/${p} ends exactly on an octet boundary: keep the first ${p / 8} octet${p === 8 ? '' : 's'} and the rest are host bits, so the network is ${net} and the broadcast is ${i.broadcast}.`);
  } else {
    const idx = Math.floor(p / 8);
    const maskOctet = Number(i.netmask.split('.')[idx]);
    const blockSize = 256 - maskOctet;
    const value = Number(q.ip.split('.')[idx]);
    const lo = Number(net.split('.')[idx]);
    lines.push(`The ${ORD[idx]} octet is the interesting one: block size 256 − ${maskOctet} = ${blockSize}. ${value} falls in ${lo}–${lo + blockSize - 1}, so the network is ${net} and the broadcast is ${i.broadcast}.`);
  }
  const hostBits = 32 - p;
  if (q.kind === 'first') lines.push(`First usable = network + 1 = ${i.firstHost}.`);
  if (q.kind === 'last') lines.push(`Last usable = broadcast − 1 = ${i.lastHost}.`);
  if (q.kind === 'usable') lines.push(`32 − ${p} = ${hostBits} host bits: 2^${hostBits} − 2 = ${Number(i.usable).toLocaleString('en-US')} usable (the network and broadcast addresses are reserved).`);
  if (q.kind === 'mask') {
    const full = Math.floor(p / 8);
    const rest = p % 8;
    const parts = [...Array(full).fill('8'), ...(rest ? [String(rest)] : [])].join(' + ');
    lines.push(`/${p} = ${p} one-bits from the left (${parts})${rest ? `; ${rest} bits in an octet = 256 − 2^${8 - rest} = ${256 - 2 ** (8 - rest)}` : ''}. So /${p} and ${i.netmask} are the same mask.`);
  }
  if (q.kind === 'inrange') lines.push(`${q.check} is ${q.inside ? '' : 'not '}between ${net} and ${i.broadcast}, so the answer is ${q.inside ? 'yes' : 'no'}.`);
  return lines;
}

/** Parses a mask answer: "/21", "21" or "255.255.248.0". Returns a prefix or null. */
export function parseMaskAnswer(s) {
  const m = /^\/?(\d{1,2})$/.exec(s);
  if (m) { const n = Number(m[1]); return n <= 32 ? n : null; }
  const o = parseIPv4(s);
  if (!o) return null;
  const bits = (toInt(o) >>> 0).toString(2).padStart(32, '0');
  return /^1*0*$/.test(bits) ? bits.indexOf('0') === -1 ? 32 : bits.indexOf('0') : null;
}

/**
 * Grades an answer. Returns { status: 'correct' | 'wrong' | 'invalid', message }.
 * 'invalid' (not an IP / number / yes-no) never counts against the student.
 */
export function checkAnswer(q, input) {
  const raw = String(input ?? '').trim();
  if (!raw) return { status: 'invalid', message: 'Type an answer first.' };
  if (raw.length > MAX_ANSWER) return { status: 'invalid', message: `That answer is too long (${MAX_ANSWER} characters max).` };
  const ok = (good) => ({ status: good ? 'correct' : 'wrong', message: good ? 'Correct.' : `Not quite. The answer is ${q.answer}.` });

  if (['network', 'broadcast', 'first', 'last'].includes(q.kind)) {
    const [ip, pre, extra] = raw.split('/');
    if (extra !== undefined || !parseIPv4(ip.trim())) return { status: 'invalid', message: "That isn't an IPv4 address (like 10.1.2.3)." };
    if (pre !== undefined) {
      if (!/^\d{1,2}$/.test(pre.trim())) return { status: 'invalid', message: "That isn't an IPv4 address (like 10.1.2.3)." };
      if (Number(pre) !== q.prefix) return ok(false);
    }
    return ok(ip.trim() === q.answer);
  }
  if (q.kind === 'usable') {
    const m = /^(\d{1,3}(?:,\d{3})+|\d{1,10})(?:\s+(?:usable\s+)?(?:hosts?|addresses))?$/i.exec(raw);
    if (!m) return { status: 'invalid', message: "That isn't a number." };
    return ok(m[1].replace(/,/g, '') === q.info.usable);
  }
  if (q.kind === 'mask') {
    const n = parseMaskAnswer(raw.replace(/\s+/g, ''));
    if (n === null) return { status: 'invalid', message: "That isn't a mask: use /21 or 255.255.248.0." };
    return ok(n === q.prefix);
  }
  const yn = raw.toLowerCase();
  if (!['yes', 'no', 'y', 'n'].includes(yn)) return { status: 'invalid', message: 'Answer yes or no.' };
  return ok(yn.startsWith('y') === q.inside);
}

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('drill-form')) {
  const { el, $, notice } = await import('./ui.js');
  const score = { right: 0, answered: 0 };
  let q = null;
  let done = false;

  const showScore = () => {
    $('drill-score').textContent = score.answered ? `${score.right} / ${score.answered} this session` : '';
  };
  const workingBlock = (open) => {
    const d = el('details', { class: 'meaning' }, el('summary', {}, 'Working'),
      ...working(q).map((line) => el('p', {}, line)));
    if (open) d.open = true;
    return d;
  };
  const next = () => {
    q = makeQuestion(cryptoRand);
    done = false;
    $('drill-question').textContent = q.prompt;
    $('drill-answer').value = '';
    $('drill-result').replaceChildren();
  };

  $('drill-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const r = checkAnswer(q, $('drill-answer').value);
    if (r.status === 'invalid') { $('drill-result').replaceChildren(notice('warn', r.message)); return; }
    // Only the first real attempt at a question counts towards the score.
    if (!done) { score.answered++; if (r.status === 'correct') score.right++; done = true; }
    $('drill-result').replaceChildren(
      el('p', { class: `verdict ${r.status === 'correct' ? 'ok' : 'bad'}` }, r.status === 'correct' ? '✔ ' : '✘ ', r.message),
      workingBlock(r.status !== 'correct'),
    );
    showScore();
  });
  $('drill-reveal').addEventListener('click', () => {
    done = true; // revealed answers don't score
    $('drill-result').replaceChildren(el('p', { class: 'verdict muted' }, `The answer is ${q.answer}.`), workingBlock(true));
  });
  $('drill-next').addEventListener('click', () => { next(); $('drill-answer').focus(); });
  $('drill-open').addEventListener('click', () => {
    $('subnet-input').value = q.kind === 'inrange' ? q.info.network : q.cidr;
    $('subnet-check').value = q.kind === 'inrange' ? q.check : '';
    $('subnet-input').dispatchEvent(new Event('input'));
    $('subnet-form').scrollIntoView({ block: 'center' });
    $('subnet-input').focus();
  });
  next();
}
