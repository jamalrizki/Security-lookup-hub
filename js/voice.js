// Ask's voice input. The browser records (up to 60 s), the Worker transcribes with
// Whisper (POST /api/transcribe), and the text goes into the box at the cursor. It
// never sends itself. The audio lives only in memory and is dropped after the
// request. Only on the Ask page: dictating hashes and IPs into Lookup is error-prone.

export const MAX_RECORDING_S = 60;
// Safari records audio/mp4; Chrome and Firefox webm or ogg with Opus.
export const RECORDING_TYPES = ['audio/webm;codecs=opus', 'audio/mp4', 'audio/ogg;codecs=opus'];

export const VOICE_MESSAGES = {
  blocked: "Microphone access is blocked. Allow it in your browser's site settings.",
  noMic: 'No microphone was found.',
  empty: "No speech was detected. Try again, a little closer to the microphone.",
  tooLong: 'That recording is too long. Keep it under a minute.',
  failed: 'Voice input failed. Try again, or type your question.',
  cut: 'The transcript was cut at the 1,000-character limit.',
};

/** True if this browser can record (getUserMedia and MediaRecorder; secure pages only). */
export function voiceSupported(nav = globalThis.navigator, Recorder = globalThis.MediaRecorder) {
  return Boolean(nav?.mediaDevices?.getUserMedia && typeof Recorder === 'function');
}

/** The first recording type this browser supports, or '' to let it choose. */
export function pickRecordingType(Recorder = globalThis.MediaRecorder) {
  return RECORDING_TYPES.find((t) => Recorder?.isTypeSupported?.(t)) || '';
}

/** "0:07" */
export const formatTimer = (secs) => `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}`;

/**
 * Puts text into value at the selection [start, end], with a space either side when
 * needed, cut so the result is at most max characters. Returns { value, caret, cut }.
 */
export function insertAtCursor(value, start, end, text, max) {
  const before = value.slice(0, start);
  const after = value.slice(end);
  let insert = `${before && !/\s$/.test(before) ? ' ' : ''}${text}${after && !/^\s/.test(after) ? ' ' : ''}`;
  const room = Math.max(0, max - before.length - after.length);
  const cut = insert.length > room;
  if (cut) insert = insert.slice(0, room);
  return { value: before + insert + after, caret: before.length + insert.length, cut };
}

/**
 * Wires the mic button. page: { button, input, status, apiBase, max, el, notice,
 * begin(kind) -> AbortController, end(controller), isBusy(), changed() }. begin/end
 * come from js/ask.js: while recording, Send turns into "Done" (stop and transcribe)
 * with a Cancel beside it, and the box says "Recording…"; Cancel or Esc throws the
 * recording away. While transcribing, Send is "Stop".
 */
export function setupVoice(page) {
  const { button, input, status, el, notice } = page;
  if (!voiceSupported()) {
    button.hidden = true;
    return;
  }
  button.hidden = false;
  const label = button.querySelector('.mic-time');
  let rec = null; // { recorder, stream, chunks, controller, timer, started, cancelled }

  const idle = () => {
    button.classList.remove('recording');
    button.setAttribute('aria-pressed', 'false');
    button.setAttribute('aria-label', 'Voice input');
    if (label) label.textContent = '';
  };
  const say = (kind, text) => status.replaceChildren(notice(kind, text));
  const release = (r) => {
    clearInterval(r.timer);
    for (const t of r.stream.getTracks?.() || []) t.stop();
  };

  async function transcribe(blob) {
    const controller = page.begin('transcribe', { message: 'Transcribing\u2026' });
    status.replaceChildren(el('p', { class: 'ask-thinking ask-transcribing', role: 'status' }, 'Transcribing', el('span', { class: 'ask-dots', 'aria-hidden': 'true' })));
    let res;
    let body;
    try {
      res = await fetch(`${page.apiBase}/api/transcribe`, {
        method: 'POST',
        headers: { 'content-type': blob.type || 'audio/webm' },
        body: blob,
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      });
      body = await res.json();
    } catch {
      body = null;
    }
    page.end(controller);
    status.replaceChildren();
    if (controller.signal.aborted) return;
    if (!res?.ok || !body) {
      if (res?.status === 413) return say('warn', VOICE_MESSAGES.tooLong);
      return say(res?.status === 429 ? 'bad' : 'warn', res?.status === 429 && body?.error ? String(body.error) : VOICE_MESSAGES.failed);
    }
    const text = typeof body.text === 'string' ? body.text.trim() : '';
    if (!text || body.empty) return say('warn', VOICE_MESSAGES.empty);
    const at = insertAtCursor(input.value, input.selectionStart ?? input.value.length, input.selectionEnd ?? input.value.length, text, page.max);
    input.value = at.value;
    input.setSelectionRange?.(at.caret, at.caret);
    page.changed();
    if (at.cut) say('warn', VOICE_MESSAGES.cut);
    input.focus();
  }

  function finish() {
    if (!rec || rec.recorder.state === 'inactive') return;
    rec.recorder.stop(); // onstop sends it
  }

  function start(stream) {
    const type = pickRecordingType();
    const recorder = new MediaRecorder(stream, type ? { mimeType: type } : undefined);
    const r = { recorder, stream, chunks: [], started: Date.now(), cancelled: false };
    r.controller = page.begin('record', { done: finish, message: "Recording\u2026 press Done when you've finished" });
    rec = r;
    // Cancel or Esc: the recording is thrown away.
    r.controller.signal.addEventListener('abort', () => {
      r.cancelled = true;
      if (recorder.state !== 'inactive') recorder.stop();
    });
    recorder.ondataavailable = (ev) => { if (ev.data?.size) r.chunks.push(ev.data); };
    recorder.onstop = () => {
      release(r);
      page.end(r.controller);
      rec = null;
      idle();
      const blob = r.cancelled ? null : new Blob(r.chunks, { type: recorder.mimeType || type || 'audio/webm' });
      r.chunks = [];
      if (blob?.size) transcribe(blob);
    };
    recorder.start();
    button.classList.add('recording');
    button.setAttribute('aria-pressed', 'true');
    button.setAttribute('aria-label', 'Recording. Press to finish and transcribe');
    const tick = () => {
      const secs = Math.min(MAX_RECORDING_S, Math.floor((Date.now() - r.started) / 1000));
      if (label) label.textContent = formatTimer(secs);
      if (secs >= MAX_RECORDING_S) finish(); // hard stop at 60 s
    };
    tick();
    r.timer = setInterval(tick, 250);
  }

  button.addEventListener('click', () => {
    if (rec) return finish();
    if (page.isBusy()) return;
    status.replaceChildren();
    // iPhone Safari only allows recording that starts from the tap itself, so
    // getUserMedia is called right here, with nothing awaited before it.
    let asked;
    try {
      asked = navigator.mediaDevices.getUserMedia({ audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true } });
    } catch (err) {
      asked = Promise.reject(err);
    }
    asked.then((stream) => {
      try {
        start(stream);
      } catch {
        for (const t of stream.getTracks?.() || []) t.stop();
        if (rec) page.end(rec.controller);
        rec = null;
        idle();
        say('warn', VOICE_MESSAGES.failed);
      }
    }, (err) => say('bad', err?.name === 'NotFoundError' ? VOICE_MESSAGES.noMic : err?.name === 'NotAllowedError' || err?.name === 'SecurityError' ? VOICE_MESSAGES.blocked : VOICE_MESSAGES.failed));
  });
  idle();
}
