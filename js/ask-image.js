// One image per Ask question: a screenshot of an email, text, pop-up or error
// message. Attached with the paperclip, by pasting into the box or by dropping it
// on the composer. It's checked by its first bytes, decoded, scaled so the longest
// side is at most 1,568 px and re-encoded as JPEG on a canvas that never touches
// the page; re-encoding also drops photo metadata such as location. Only the
// question it was attached to carries it.

export const MAX_SOURCE_BYTES = 10 * 1024 * 1024;
export const MAX_EDGE = 1568;
export const MAX_OUTPUT_BYTES = 1.5 * 1024 * 1024;
export const QUALITY = 0.85;
export const LOWER_QUALITY = 0.7;
export const IMAGE_ONLY_QUESTION = 'Is this safe? What should I do?';

export const IMAGE_MESSAGES = {
  sourceTooLarge: 'Images are limited to 10 MB.',
  wrongType: 'Only PNG, JPEG or WebP images can be attached.',
  unreadable: "That image couldn't be read.",
  tooLarge: 'That image is too large.',
};

/** The image type from its first bytes: 'image/png', 'image/jpeg', 'image/webp' or null. */
export function sniffImage(b) {
  if ([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((x, i) => b[i] === x)) return 'image/png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  const ascii = (from, to) => String.fromCharCode(...b.slice(from, to));
  if (ascii(0, 4) === 'RIFF' && ascii(8, 12) === 'WEBP') return 'image/webp';
  return null;
}

/** Width and height scaled so the longest side is at most max (never enlarged). */
export function scaledSize(width, height, max = MAX_EDGE) {
  const scale = Math.min(1, max / Math.max(width, height));
  return { width: Math.max(1, Math.round(width * scale)), height: Math.max(1, Math.round(height * scale)) };
}

async function toBase64(blob) {
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

function canvasFor(width, height) {
  if (typeof OffscreenCanvas === 'function') return new OffscreenCanvas(width, height);
  const c = document.createElement('canvas'); // never added to the page
  c.width = width;
  c.height = height;
  return c;
}

const encode = (canvas, quality) => (canvas.convertToBlob
  ? canvas.convertToBlob({ type: 'image/jpeg', quality })
  : new Promise((resolve) => { canvas.toBlob(resolve, 'image/jpeg', quality); }));

/**
 * File -> { blob, media_type: 'image/jpeg', data (base64), width, height }.
 * Throws an Error whose message is for the visitor. signal: Stop.
 */
export async function prepareImage(file, signal) {
  const stopped = () => { if (signal?.aborted) throw Object.assign(new Error('stopped'), { name: 'AbortError' }); };
  if (!file || file.size > MAX_SOURCE_BYTES) throw new Error(IMAGE_MESSAGES.sourceTooLarge);
  if (!sniffImage(new Uint8Array(await file.slice(0, 16).arrayBuffer()))) throw new Error(IMAGE_MESSAGES.wrongType);
  stopped();
  let bitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    throw new Error(IMAGE_MESSAGES.unreadable);
  }
  stopped();
  const { width, height } = scaledSize(bitmap.width, bitmap.height);
  const canvas = canvasFor(width, height);
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff'; // JPEG has no transparency
  ctx.fillRect(0, 0, width, height);
  ctx.drawImage(bitmap, 0, 0, width, height);
  bitmap.close?.();
  let blob = await encode(canvas, QUALITY);
  if (blob && blob.size > MAX_OUTPUT_BYTES) blob = await encode(canvas, LOWER_QUALITY); // once
  stopped();
  if (!blob) throw new Error(IMAGE_MESSAGES.unreadable);
  if (blob.size > MAX_OUTPUT_BYTES) throw new Error(IMAGE_MESSAGES.tooLarge);
  return { blob, media_type: 'image/jpeg', data: await toBase64(blob), width, height };
}

/**
 * Wires the paperclip, paste and drop. page: { button, fileInput, form, input,
 * preview, status, el, notice, begin, end, isBusy }. Returns { get(), take(), clear() }:
 * take() hands the attachment to the question being sent (its object URL then
 * belongs to the thread, which revokes it on New chat).
 */
export function setupImages(page) {
  const { button, fileInput, form, input, preview, status, el, notice } = page;
  let attached = null; // { blob, media_type, data, url }

  const render = () => {
    if (!attached) {
      preview.replaceChildren();
      preview.hidden = true;
      return;
    }
    const remove = el('button', { type: 'button', class: 'secondary small ask-attach-x', 'aria-label': 'Remove image' }, '×');
    remove.addEventListener('click', () => {
      clear();
      input.focus();
    });
    preview.replaceChildren(el('img', { src: attached.url, alt: 'Attached image', class: 'ask-thumb' }), remove);
    preview.hidden = false;
  };
  function clear() {
    if (attached) URL.revokeObjectURL(attached.url);
    attached = null;
    render();
  }

  async function attach(file) {
    if (!file || page.isBusy()) return;
    const controller = page.begin('image');
    status.replaceChildren(el('p', { class: 'hint ask-transcribing', role: 'status' }, 'Preparing image…'));
    let ready;
    let error;
    try {
      ready = await prepareImage(file, controller.signal);
    } catch (err) {
      error = err;
    }
    page.end(controller);
    status.replaceChildren();
    if (controller.signal.aborted) return;
    if (error) {
      status.replaceChildren(notice('warn', error.message || IMAGE_MESSAGES.unreadable));
      return;
    }
    clear(); // one image per question: a new one replaces the old
    attached = { ...ready, url: URL.createObjectURL(ready.blob) };
    render();
  }

  button.addEventListener('click', () => {
    if (!page.isBusy()) fileInput.click();
  });
  fileInput.addEventListener('change', () => {
    const file = fileInput.files?.[0];
    fileInput.value = ''; // choosing the same file again still fires change
    attach(file);
  });
  input.addEventListener('paste', (ev) => {
    const item = [...(ev.clipboardData?.items || [])].find((i) => i.kind === 'file' && /^image\//.test(i.type));
    if (!item) return; // ordinary text paste
    ev.preventDefault();
    attach(item.getAsFile());
  });
  form.addEventListener('dragover', (ev) => {
    if ([...(ev.dataTransfer?.types || [])].includes('Files')) {
      ev.preventDefault();
      form.classList.add('dropping');
    }
  });
  form.addEventListener('dragleave', () => form.classList.remove('dropping'));
  form.addEventListener('drop', (ev) => {
    const file = ev.dataTransfer?.files?.[0];
    form.classList.remove('dropping');
    if (!file) return;
    ev.preventDefault();
    attach(file);
  });

  return {
    get: () => attached,
    take() {
      const a = attached;
      attached = null;
      render();
      return a;
    },
    clear,
  };
}
