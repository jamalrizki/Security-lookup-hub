// POST /api/transcribe (Ask's voice input) through the Worker's fetch handler, with
// Workers AI stubbed: checks before the model runs, what Whisper gets, limits.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/src/index.js';
import { audioMatches, cleanTranscript, vocabPrompt, MAX_PROMPT_CHARS, WHISPER_MODEL, DAILY_VOICE_MINUTES, VOICE_USED_UP } from '../worker/src/transcribe.js';
import { ORIGIN, installCaches, exec, memoryKv } from './helpers/ask-stubs.mjs';

const ascii = (s) => [...s].map((c) => c.charCodeAt(0));
const WEBM = Uint8Array.from([0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x86, 0x81, 0x01, 0x42, 0xf7, 0x81, ...new Array(500).fill(7)]);
const MP4 = Uint8Array.from([0, 0, 0, 0x20, ...ascii('ftypM4A '), ...new Array(500).fill(1)]);
const OGG = Uint8Array.from([...ascii('OggS'), ...new Array(508).fill(2)]);
const WAV = Uint8Array.from([...ascii('RIFF'), 1, 2, 3, 4, ...ascii('WAVEfmt '), ...new Array(500).fill(3)]);
const today = () => new Date().toISOString().slice(0, 10);

function ai(reply = { text: 'What is the EPSS score for CVE 2021 44228?' }) {
  const calls = [];
  return { calls, binding: { async run(model, input) { calls.push({ model, input }); return typeof reply === 'function' ? reply() : reply; } } };
}
const env = (extra = {}) => ({ ALLOWED_ORIGINS: ORIGIN, NEWS: memoryKv(), ...extra });
const post = (bytes, type = 'audio/webm;codecs=opus', origin = ORIGIN) => new Request('https://security-lookup-hub.example/api/transcribe', {
  method: 'POST', headers: { origin, 'content-type': type }, body: bytes,
});
async function send(bytes, e, type) {
  const res = await worker.fetch(post(bytes, type), e, exec());
  return { status: res.status, body: await res.json(), headers: res.headers };
}

beforeEach(() => { installCaches(); });

test('a valid WebM goes to Whisper as base64 with English, VAD and the vocabulary prompt; the text comes back cleaned', async () => {
  const model = ai();
  const { status, body, headers } = await send(WEBM, env({ AI: model.binding }));
  assert.equal(status, 200);
  assert.deepEqual(body, { text: 'What is the EPSS score for CVE-2021-44228?' });
  assert.equal(model.calls.length, 1);
  const { model: name, input } = model.calls[0];
  assert.equal(name, '@cf/openai/whisper-large-v3-turbo');
  assert.equal(WHISPER_MODEL, name);
  assert.equal(input.audio, Buffer.from(WEBM).toString('base64'));
  assert.equal(input.language, 'en');
  assert.equal(input.task, 'transcribe');
  assert.equal(input.vad_filter, true);
  assert.equal(input.initial_prompt, vocabPrompt());
  for (const term of ['KEV', 'EPSS', 'DMARC', 'Kerberoasting', 'Log4Shell']) assert.ok(input.initial_prompt.includes(term), term);
  assert.equal(headers.get('access-control-allow-methods'), 'POST, OPTIONS');
  assert.equal(headers.get('access-control-allow-origin'), ORIGIN);
});

test('MP4 (Safari), Ogg and WAV are accepted; a wrong magic number or content type is 415, before any model call', async () => {
  for (const [bytes, type] of [[MP4, 'audio/mp4'], [OGG, 'audio/ogg;codecs=opus'], [WAV, 'audio/wav']]) {
    const model = ai({ text: 'hello' });
    assert.equal((await send(bytes, env({ AI: model.binding }), type)).status, 200, type);
  }
  const model = ai();
  for (const [bytes, type] of [[MP4, 'audio/webm'], [WEBM, 'audio/mpeg'], [WEBM, 'video/webm'], [Uint8Array.from(ascii('<html><body>hi</body></html>')), 'audio/webm'], [OGG, ''], [Uint8Array.from([0x1a, 0x45]), 'audio/webm']]) {
    const r = await send(bytes, env({ AI: model.binding }), type);
    assert.equal(r.status, 415, `${type}`);
    assert.equal(r.body.error, "That audio format isn't supported.");
  }
  assert.equal(model.calls.length, 0);
});

test('a 2.1 MB body is 413 (by content-length or by reading); no model call', async () => {
  const model = ai();
  const big = new Uint8Array(2.1 * 1024 * 1024);
  big.set(WEBM.subarray(0, 12));
  const r = await send(big, env({ AI: model.binding }));
  assert.equal(r.status, 413);
  const declared = await worker.fetch(new Request('https://x.example/api/transcribe', { method: 'POST', headers: { origin: ORIGIN, 'content-type': 'audio/webm', 'content-length': String(big.length) }, body: WEBM }), env({ AI: model.binding }), exec());
  assert.equal(declared.status, 413);
  assert.equal(model.calls.length, 0);
});

test('limits: 20 a minute site-wide, then 429; the daily cap in KV, then 429 with the plain message', async () => {
  const model = ai({ text: 'hi' });
  const e = env({ AI: model.binding });
  for (let i = 0; i < 20; i++) assert.equal((await send(WEBM, e)).status, 200, `#${i + 1}`);
  const over = await send(WEBM, e);
  assert.equal(over.status, 429);
  assert.equal(over.body.error, VOICE_USED_UP);
  assert.equal(VOICE_USED_UP, 'Voice input is used up for now. Type your question instead.');
  assert.equal(model.calls.length, 20);

  installCaches();
  const kv = memoryKv({ [`voice:${today()}`]: String(DAILY_VOICE_MINUTES) });
  const daily = await send(WEBM, env({ AI: model.binding, NEWS: kv }));
  assert.equal(daily.status, 429);
  assert.equal(daily.body.error, VOICE_USED_UP);
  assert.equal(model.calls.length, 20, 'no model call over the cap');

  const fresh = memoryKv();
  await send(WEBM, env({ AI: model.binding, NEWS: fresh }));
  assert.deepEqual(fresh.puts.map((p) => [p.k, p.v, p.opts.expirationTtl]), [[`voice:${today()}`, '1', 172800]], 'counted per UTC day, expires after 2 days');
});

test('the daily budget counts audio minutes Whisper reports, so long low-bitrate audio can\'t slip past it', async () => {
  const kv = memoryKv();
  const long = ai({ text: 'a long one', transcription_info: { duration: 1500 } }); // 25 minutes in under 2 MB
  assert.equal((await send(WEBM, env({ AI: long.binding, NEWS: kv }))).status, 200);
  assert.equal(kv.map.get(`voice:${today()}`), '25');
  const short = ai({ text: 'hi', transcription_info: { duration: 7.5 } });
  await send(WEBM, env({ AI: short.binding, NEWS: kv }));
  assert.equal(kv.map.get(`voice:${today()}`), '26', 'a short clip counts one minute');
  kv.map.set(`voice:${today()}`, '50');
  assert.equal((await send(WEBM, env({ AI: short.binding, NEWS: kv }))).status, 429);
  assert.equal(short.calls.length, 1, 'no model call once the minutes are used up');
  const failing = { async run() { throw new Error('boom'); } };
  const kv2 = memoryKv();
  await send(WEBM, env({ AI: failing, NEWS: kv2 }));
  assert.equal(kv2.map.get(`voice:${today()}`), '1', 'a failed run still counts a minute');
});

test('the daily budget keeps voice at about 2,500 neurons (46.63 per audio minute)', () => {
  assert.ok(DAILY_VOICE_MINUTES * 46.63 <= 2500, `${DAILY_VOICE_MINUTES * 46.63}`);
  assert.equal(DAILY_VOICE_MINUTES, 50);
});

test('nothing heard: { text: "", empty: true }; a model failure is 502; no AI binding is 503', async () => {
  for (const reply of [{ text: '' }, { text: '   ' }, {}]) {
    const r = await send(WEBM, env({ AI: ai(reply).binding }));
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { text: '', empty: true });
  }
  const failing = { async run() { throw new Error('3040: capacity'); } };
  assert.equal((await send(WEBM, env({ AI: failing }))).status, 502);
  assert.equal((await send(WEBM, env())).status, 503);
});

test('Origin allowlist and methods: no origin is 403; GET is 405; preflight allows POST and content-type', async () => {
  const model = ai();
  const res = await worker.fetch(post(WEBM, 'audio/webm', 'https://evil.example'), env({ AI: model.binding }), exec());
  assert.equal(res.status, 403);
  const get = await worker.fetch(new Request('https://x.example/api/transcribe', { headers: { origin: ORIGIN } }), env({ AI: model.binding }), exec());
  assert.equal(get.status, 405);
  const pre = await worker.fetch(new Request('https://x.example/api/transcribe', { method: 'OPTIONS', headers: { origin: ORIGIN } }), env(), exec());
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-headers'), 'content-type');
  assert.equal(model.calls.length, 0);
});

test('transcript clean-up: whitespace, spoken CVE IDs, 1,000 characters', () => {
  assert.equal(cleanTranscript('  is   CVE 2021 44228\n in KEV? '), 'is CVE-2021-44228 in KEV?');
  assert.equal(cleanTranscript('cve 2021-44,228 and CVE-2024 3400'), 'CVE-2021-44228 and CVE-2024-3400');
  assert.equal(cleanTranscript('CVE 21 44228'), 'CVE 21 44228', 'not a CVE ID detect.js accepts: left alone');
  assert.equal(cleanTranscript('a'.repeat(1200)).length, 1000);
  assert.equal(cleanTranscript(undefined), '');
});

test('container checks', () => {
  assert.equal(audioMatches('audio/webm;codecs=opus', WEBM), true);
  assert.equal(audioMatches('AUDIO/MP4', MP4), true);
  assert.equal(audioMatches('audio/x-wav', WAV), false, 'only the four listed types');
});

test('the vocabulary prompt stays under Whisper\'s prompt limit, and the list is plain words', async () => {
  const { readFileSync } = await import('node:fs');
  const vocab = JSON.parse(readFileSync(new URL('../data/voice-vocab.json', import.meta.url), 'utf8'));
  assert.ok(Array.isArray(vocab.terms) && vocab.terms.length >= 20);
  assert.equal(new Set(vocab.terms).size, vocab.terms.length, 'no duplicates');
  for (const t of vocab.terms) assert.match(t, /^[A-Za-z0-9&.' -]{2,30}$/, t);
  assert.ok(vocabPrompt().length <= MAX_PROMPT_CHARS, `${vocabPrompt().length} characters`);
});
