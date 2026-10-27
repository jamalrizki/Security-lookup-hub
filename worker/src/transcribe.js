// POST /api/transcribe: Ask's voice input. The page records up to 60 s, posts the
// raw audio here, and gets text back to put in the box (it never sends itself).
// Whisper on Workers AI (the AI binding: no extra account or key).
//
// Checked in code before the model runs: size (2 MB), content type and the
// container's magic bytes, a site-wide per-minute limit and a daily cap that
// keeps voice to about a quarter of the free daily Workers AI neurons. No audio
// or transcript is logged or stored.

import { readCappedBytes } from './http.js';
import { CVE_ID_PATTERN } from '../../js/detect.js';
import VOICE_VOCAB from '../../data/voice-vocab.json' with { type: 'json' };

export const MAX_AUDIO_BYTES = 2 * 1024 * 1024;
export const WHISPER_MODEL = '@cf/openai/whisper-large-v3-turbo';
export const TRANSCRIBE_PER_MINUTE = 20; // site-wide
// The daily budget is counted in audio minutes, as Whisper reports them, not in
// requests: 2 MB of low-bitrate audio could be far longer than the page's 60 s.
// 46.63 neurons per audio minute (Workers AI pricing, Oct 2026), so 50 minutes a day
// is 50 x 46.63 = 2,331.5 neurons, under the 2,500 budget (a quarter of the 10,000
// free daily neurons Ask's reference search also uses). Each transcription counts
// at least one minute.
export const DAILY_VOICE_MINUTES = 50;
export const MAX_TRANSCRIPT = 1000;
// Whisper's prompt holds about 224 tokens; tests keep the vocabulary hint under this.
export const MAX_PROMPT_CHARS = 600;

export const VOICE_USED_UP = 'Voice input is used up for now. Type your question instead.';

const startsWith = (bytes, ascii, at = 0) => [...ascii].every((c, i) => bytes[at + i] === c.charCodeAt(0));

// The container each content type must really be (first bytes).
const CONTAINERS = {
  'audio/webm': (b) => b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3, // EBML
  'audio/mp4': (b) => startsWith(b, 'ftyp', 4),
  'audio/ogg': (b) => startsWith(b, 'OggS'),
  'audio/wav': (b) => startsWith(b, 'RIFF') && startsWith(b, 'WAVE', 8),
};

/** True if the bytes are the container the content type (parameters ignored) names. */
export function audioMatches(contentType, bytes) {
  const type = String(contentType || '').split(';')[0].trim().toLowerCase();
  const check = CONTAINERS[type];
  return Boolean(check && bytes.length >= 12 && check(bytes));
}

/** Whisper's initial prompt: the vocabulary list from data/voice-vocab.json. */
export function vocabPrompt(terms = VOICE_VOCAB.terms) {
  return `A security question mentioning terms such as ${terms.join(', ')}.`;
}

/**
 * Trims, collapses whitespace, writes spoken-style CVE IDs the way detect.js accepts
 * them ("CVE 2021 44228", "cve 2021-44,228" -> "CVE-2021-44228") and caps the length.
 */
export function cleanTranscript(text) {
  const out = String(text || '')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\bCVE[\s-]*(\d{4})[\s,.-]*(\d{1,3}(?:,\d{3})+|\d{4,19})\b/gi, (m, year, num) => {
      const id = `CVE-${year}-${num.replace(/,/g, '')}`;
      return CVE_ID_PATTERN.test(id) ? id : m;
    });
  return out.slice(0, MAX_TRANSCRIPT);
}

const utcDay = (now) => now.toISOString().slice(0, 10);

const voiceKey = (now) => `voice:${utcDay(now)}`;

/** True while today's voice minutes (KV) are under the cap. No KV, no cap. */
export async function voiceLeft(kv, now = new Date()) {
  if (!kv) return true;
  return (Number(await kv.get(voiceKey(now))) || 0) < DAILY_VOICE_MINUTES;
}

/** Adds a transcription's audio minutes (rounded up, at least 1) to today's count. */
export async function countVoice(kv, seconds, now = new Date()) {
  if (!kv) return;
  const minutes = Math.max(1, Math.ceil((Number(seconds) || 0) / 60));
  const used = Number(await kv.get(voiceKey(now))) || 0;
  await kv.put(voiceKey(now), String(used + minutes), { expirationTtl: 2 * 86400 });
}

function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

/** Handles POST /api/transcribe. deps: { quotaTools }. Returns { status, body, headers? }. */
export async function handleTranscribe(request, env, exec, deps) {
  if (!env.AI) return { status: 503, body: { error: 'Voice input is not configured.' } };
  const tooLarge = { status: 413, body: { error: 'Recordings are limited to 2 MB (about a minute).' } };
  if (Number(request.headers.get('content-length')) > MAX_AUDIO_BYTES) return tooLarge;
  const contentType = request.headers.get('content-type');
  const bytes = request.body ? await readCappedBytes(request, MAX_AUDIO_BYTES) : new Uint8Array();
  if (bytes === null) return tooLarge;
  if (!audioMatches(contentType, bytes)) return { status: 415, body: { error: "That audio format isn't supported." } };

  const busy = { status: 429, body: { error: VOICE_USED_UP }, headers: { 'retry-after': '60' } };
  if (!(await deps.quotaTools(env, exec).allow('transcribe', TRANSCRIBE_PER_MINUTE))) return busy;
  if (!(await voiceLeft(env.NEWS))) return busy;

  let out;
  try {
    out = await env.AI.run(WHISPER_MODEL, {
      audio: toBase64(bytes),
      task: 'transcribe',
      language: 'en',
      vad_filter: true,
      initial_prompt: vocabPrompt(),
    });
  } catch {
    await countVoice(env.NEWS, 60); // a failed run may still have used neurons
    return { status: 502, body: { error: 'Voice input failed. Try again, or type your question.' } };
  }
  await countVoice(env.NEWS, out?.transcription_info?.duration);
  const text = cleanTranscript(out?.text);
  return { status: 200, body: text ? { text } : { text: '', empty: true } };
}
