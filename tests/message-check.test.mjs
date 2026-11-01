// "Is this message a scam?" (Analyze #message): signs from data/scam-signs.json
// matched in code, links read by the link inspector, verdict decided in code.
// The messages below were written for this test, following the FTC's and
// NCSC's descriptions of common text and email scams; the links are made up.
import { test } from 'node:test';
import { installDom, settle } from './helpers/dom.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parsePsl } from '../js/extract.js';
import { guidanceUrl } from '../js/what-now.js';
import { checkMessage, compileSigns, normalise, matchForms, messageLinks, MAX_MESSAGE, MAX_LINKS, VERDICT_TEXT } from '../js/analyze/message-check.js';

const root = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, root), 'utf8');
const DATA = JSON.parse(read('data/scam-signs.json'));
const signs = compileSigns(DATA);
const psl = parsePsl(read('data/public_suffix_list.dat'));
const brands = JSON.parse(read('data/brands.json')).brands;
const check = (text) => checkMessage(text, { signs, psl, brands });
const ids = (r) => r.signs.map((s) => s.id).sort();

/* ---------- the data file ---------- */

test('every sign compiles, has a known strength, a short plain sentence and an allowed guidance link', () => {
  assert.equal(signs.length, DATA.signs.length, 'no sign was dropped by compileSigns');
  const seen = new Set();
  for (const s of DATA.signs) {
    assert.match(s.id, /^[a-z]+(?:-[a-z]+)*$/, s.id);
    assert.ok(!seen.has(s.id), `duplicate id ${s.id}`);
    seen.add(s.id);
    assert.ok(['strong', 'warning'].includes(s.strength), s.id);
    assert.ok(s.says.length > 20 && s.says.length <= 160, `${s.id}: says is ${s.says.length} characters`);
    assert.ok(s.patterns.length >= 1, s.id);
    for (const p of [...s.patterns, ...(s.unless ?? [])]) assert.doesNotThrow(() => new RegExp(p, 'iu'), `${s.id}: ${p}`);
    assert.ok(guidanceUrl(s.guidance?.url), `${s.id}: guidance link must be https on an allowed host`);
    assert.ok(s.guidance.by && s.guidance.title, s.id);
  }
  assert.ok(DATA.signs.filter((s) => s.strength === 'strong').length >= 8);
});

test('compileSigns drops bad entries instead of throwing', () => {
  const out = compileSigns({ signs: [
    { id: 'ok', strength: 'strong', says: 'x', patterns: ['abc'], guidance: { by: 'X', title: 'X', url: 'https://evil.example/' } },
    { id: 'bad-re', strength: 'strong', says: 'x', patterns: ['(unclosed'] },
    { id: 'bad-strength', strength: 'maybe', says: 'x', patterns: ['abc'] },
    null,
  ] });
  assert.deepEqual(out.map((s) => s.id), ['ok']);
  assert.equal(out[0].guidance, null, 'a link off the allowlist is dropped');
  assert.deepEqual(compileSigns(null), []);
});

test('every pattern is fast on a worst-case 10 KB paste (no runaway backtracking)', () => {
  const nasty = [
    'a '.repeat(MAX_MESSAGE / 2),
    'account '.repeat(MAX_MESSAGE / 8),
    `${'did you make '.repeat(700)}`,
    `${'$1 '.repeat(3000)}`,
    `${'reply y '.repeat(1200)}`,
  ];
  for (const text of nasty) {
    const t0 = performance.now();
    check(text);
    assert.ok(performance.now() - t0 < 1500, `slow on ${text.slice(0, 20)}…`);
  }
});

/* ---------- scam messages ---------- */

const SCAMS = {
  toll: 'E-ZPass: You have an unpaid toll of $6.99. Pay by 11/02 to avoid a $50 late fee and suspension. Reply Y then reopen this message to activate the link: https://ezpass-tolls.help/pay',
  tollObfuscated: 'N0tice: Y0ur outstanding t0ll balance is $4.15. Settle t​oday: tolls-portal.top/pay',
  tollCyrillic: 'Final notice: unpаid tоll charges on your vehicle. Pay now to avoid penalties.',
  package: 'USPS: Your package is on hold due to an incomplete address. Please confirm your address within 24 hours for redelivery: hxxps://usps-redelivery[.]info/track',
  bank: 'Your Chase account has been suspended due to unusual activity. Verify your identity immediately at https://chase.com.secure-verify.co/login',
  giftCard: "This is Officer Daniels from the sheriff's office. There is a warrant for your arrest for missed jury duty. You can resolve it today by paying $500 in Google Play gift cards. Send photos of the card numbers.",
  code: 'Hi, I am selling my couch on Marketplace. To make sure you are real, I sent a 6-digit code to your phone. Please send me the code.',
  job: 'Hello! We are hiring for a remote position. Earn $300-$800 per day, only 1 hour a day, no experience needed. Reply on WhatsApp to start.',
  wrongNumber: 'Hi, is this Linda? We are still on for golf on Saturday?',
  prize: "Congratulations! You've won a $1,000 Walmart gift card. To claim your prize, pay a small shipping fee here: bit.ly/3xYz",
  crypto: 'Your Coinbase wallet is locked. To unlock and restore access, deposit $200 in Bitcoin to the address below.',
  irs: 'IRS NOTICE: You owe $2,340 in back taxes. Pay immediately or a warrant will be issued for your arrest.',
};

test('the example from the idea: toll scam, deadline plus penalty, reply-Y trick', () => {
  const r = check(SCAMS.toll);
  assert.equal(r.verdict, 'scam');
  for (const id of ['toll-fine', 'deadline-penalty', 'reply-to-activate']) assert.ok(ids(r).includes(id), id);
  assert.equal(r.signs[0].strength, 'strong', 'strong signs are listed first');
  assert.deepEqual(r.links.map((l) => l.value), ['https://ezpass-tolls.help/pay']);
});

for (const [name, text] of Object.entries(SCAMS)) {
  if (name === 'wrongNumber') continue;
  test(`scam fixture "${name}" gets "Scam signs found"`, () => {
    const r = check(text);
    assert.equal(r.verdict, 'scam', `${name}: ${JSON.stringify(ids(r))} links ${JSON.stringify(r.links.map((l) => l.verdict))}`);
  });
}

test('each fixture trips the sign it was written for', () => {
  const expect = {
    tollObfuscated: 'toll-fine', tollCyrillic: 'toll-fine', package: 'confirm-address-fee', bank: 'account-locked',
    giftCard: 'unusual-payment', code: 'share-code', job: 'job-offer', wrongNumber: 'wrong-number',
    prize: 'prize-to-claim', crypto: 'unusual-payment', irs: 'government-payment',
  };
  for (const [name, id] of Object.entries(expect)) assert.ok(ids(check(SCAMS[name])).includes(id), `${name} → ${id}: got ${ids(check(SCAMS[name]))}`);
  assert.ok(ids(check(SCAMS.package)).includes('delivery-problem'));
  assert.ok(ids(check(SCAMS.giftCard)).includes('government-payment'));
});

test('a "wrong number" opener alone is a warning, not a scam verdict', () => {
  const r = check(SCAMS.wrongNumber);
  assert.equal(r.verdict, 'warning');
  assert.deepEqual(ids(r), ['wrong-number']);
});

test('a "new number" family message asking for money is flagged, as warnings', () => {
  const r = check('Mom, I lost my phone, this is my new number. Can you send me $400 on Zelle for a bill? It is urgent');
  assert.deepEqual(ids(r), ['new-number', 'payment-app']);
  assert.equal(r.verdict, 'warning');
});

test('a link the inspector calls Suspicious makes it a scam even with no wording signs', () => {
  const r = check('Hey, check this out http://paypa1-login.com/account');
  assert.deepEqual(ids(r), []);
  assert.equal(r.links[0].verdict, 'Suspicious');
  assert.equal(r.verdict, 'scam');
  const bank = check(SCAMS.bank).links[0];
  assert.equal(bank.registrable, 'secure-verify.co');
  assert.equal(bank.verdict, 'Suspicious');
});

/* ---------- real messages ---------- */

const LEGIT = {
  twoFa: 'Your Google verification code is 482913. Don\'t share this code with anyone. Google will never ask you to share this code.',
  twoFa2: 'Use 739104 to sign in to your Microsoft account. Never give this code to anyone, even if they say they are from Microsoft.',
  appointment: 'Reminder: you have a dental appointment with Dr. Patel on Tue Nov 4 at 2:30pm. Reply C to confirm or call 555-0142 to reschedule.',
  shipped: 'Your order #112-4471 has shipped! It will arrive Thursday. Track it in the app.',
  orderEmail: 'Thanks for your order, Sam.\n\nOrder #A-88213\n1 x USB-C cable  $12.99\nShipping: Free shipping\nTotal: $12.99\n\nWe will email you when it ships. Returns are accepted within 30 days.',
  friend: 'Running 10 min late, save me a seat! Want to grab tacos after?',
};

for (const [name, text] of Object.entries(LEGIT)) {
  test(`real-style message "${name}" does not get "Scam signs found"`, () => {
    const r = check(text);
    assert.notEqual(r.verdict, 'scam', `${name}: ${JSON.stringify(ids(r))}`);
  });
}

test('real 2FA texts, the shipping notice and a friend\'s text get no signs at all', () => {
  for (const name of ['twoFa', 'twoFa2', 'shipped', 'friend', 'orderEmail']) assert.deepEqual(ids(check(LEGIT[name])), [], name);
  assert.equal(check(LEGIT.friend).verdict, 'none');
});

test('a real-style bank fraud alert is a warning, not a scam verdict', () => {
  const r = check('Chase Fraud Alert: Did you attempt a $1,249.00 purchase at BESTBUY on card ending 4421? Reply YES or NO. Msg&data rates may apply.');
  assert.equal(r.verdict, 'warning');
  assert.deepEqual(ids(r), ['fraud-alert']);
});

/* ---------- input handling ---------- */

test('normalise strips invisible characters and NFKC-folds; match forms fold look-alike letters and digits', () => {
  assert.equal(normalise('to​ll ＴＯＬＬ ‘x’'), "toll TOLL 'x'");
  const forms = matchForms('Unpa1d T0ll раy'); // Cyrillic р and а
  assert.ok(forms.includes('unpaid toll pay'));
  assert.ok(forms.includes('unpald toll pay'));
  assert.ok(forms[0] === 'unpa1d t0ll раy', 'the text as written is always matched too');
});

test('empty input is an error; long input is capped at 10 KB; links are capped', () => {
  assert.ok(check('   ').error);
  assert.ok(check(undefined).error);
  const long = check(`${'x '.repeat(MAX_MESSAGE)} unpaid toll`);
  assert.equal(long.truncated, true);
  assert.deepEqual(ids(long), [], 'text past the cap is not read');
  const many = Array.from({ length: MAX_LINKS + 5 }, (_, i) => `https://site${i}.example.com/`).join(' ');
  const r = check(many);
  assert.equal(r.links.length, MAX_LINKS);
  assert.equal(r.linksCapped, true);
  assert.equal(check('https://a.example.com/').linksCapped, false);
});

test('links: defanged links are read, bare domains count, a URL\'s own host is not listed twice, emails are not links', () => {
  const { links, total } = messageLinks(normalise('Go to hxxps://pay-toll[.]top/x or example.org, mail help@shop.example.net. Also https://pay-toll.top/y'), { psl, brands });
  assert.deepEqual(links.map((l) => l.value), ['https://pay-toll.top/x', 'https://pay-toll.top/y', 'example.org']);
  assert.equal(total, 3);
  assert.equal(links[2].registrable, 'example.org');
});

test('works without the domain lists (look-alike checks off) and with no signs loaded', () => {
  const r = checkMessage(SCAMS.toll, { signs });
  assert.equal(r.verdict, 'scam');
  assert.equal(checkMessage('unpaid toll', {}).verdict, 'none');
});

test('verdict wording is fixed in code', () => {
  assert.deepEqual(VERDICT_TEXT, { scam: 'Scam signs found', warning: 'Some warning signs', none: 'No known scam signs found' });
});

/* ---------- the page ---------- */

test('the Analyze page has the message check, loads the module, and Ask can link to it', () => {
  const html = read('analyze.html');
  for (const id of ['message', 'message-form', 'message-input', 'message-clear', 'message-result', 'message-next']) assert.ok(html.includes(`id="${id}"`), id);
  assert.ok(html.includes('<script type="module" src="js/analyze/message-check.js"></script>'));
  assert.ok(html.includes('href="#message"'));
  for (const id of ['clicked-link', 'typed-password', 'paid-scammer']) {
    assert.ok(html.includes(`href="./reference.html#what-now-${id}"`), id);
    assert.ok(JSON.parse(read('data/what-now.json')).items.some((i) => i.id === id), `${id} is a real what-now card`);
  }
  const src = read('js/analyze/message-check.js');
  assert.ok(!/innerHTML|localStorage|sessionStorage|XMLHttpRequest|sendBeacon/.test(src), 'textContent only, no storage');
  assert.deepEqual([...src.matchAll(/fetch\('([^']+)'/g)].map((m) => m[1]), ['data/scam-signs.json'], 'the only request is the bundled sign list');
  const features = JSON.parse(read('data/hub-features.json')).features;
  assert.equal(features.find((f) => f.id === 'message')?.href, './analyze.html#message');
  assert.ok(read('js/reference.js').includes('#what-now-'), 'Reference scrolls to a what-now card linked by id');
});

test('in the page: Check shows the verdict, signs, links and next steps; nothing but bundled data is fetched; Clear hides them', async () => {
  const dom = installDom(read('analyze.html'), { url: 'https://jamalrizki.github.io/Security-lookup-hub/analyze.html' });
  const requests = [];
  globalThis.fetch = async (input) => {
    const u = String(input);
    requests.push(u);
    return u.startsWith('data/') ? new Response(read(u)) : new Response('no', { status: 500 });
  };
  try {
    await import('../js/analyze/link.js');
    await import('../js/analyze/message-check.js?page=1'); // a fresh copy: the one imported above ran without a page
    await settle();
    const $ = (id) => dom.document.getElementById(id);
    assert.equal($('message-next').hidden, true);
    $('message-input').value = SCAMS.bank;
    $('message-form').requestSubmit();
    await settle();
    const out = $('message-result').textContent;
    assert.match(out, /Scam signs found/);
    assert.match(out, /locked or suspended/);
    assert.ok(out.includes('hxxps://chase[.]com[.]secure-verify[.]co/login'), 'links are shown defanged');
    assert.equal($('message-next').hidden, false);
    const inspect = $('message-result').querySelectorAll('button').find((b) => b.textContent === 'Inspect this link');
    inspect.click();
    await settle();
    assert.equal($('link-input').value, 'https://chase.com.secure-verify.co/login');
    assert.match($('link-result').textContent, /Suspicious/);
    assert.ok(requests.every((u) => u.startsWith('data/')), `only bundled data: ${requests}`);
    $('message-clear').click();
    assert.equal($('message-result').textContent, '');
    assert.equal($('message-next').hidden, true);
    $('message-input').value = '  ';
    $('message-form').requestSubmit();
    await settle();
    assert.match($('message-result').textContent, /Paste a message/);
    assert.equal($('message-next').hidden, true);
  } finally {
    dom.restore();
    delete globalThis.fetch;
  }
});
