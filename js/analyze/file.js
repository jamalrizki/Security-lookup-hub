// File analyzer (#file). Reads the file locally (max 50 MB): hashes, type from
// magic bytes, extension mismatch, and printable strings. Nothing is uploaded.

export const MAX_FILE = 50 * 1024 * 1024;
const MAX_STRINGS = 5000;
const MIN_RUN = 6;

const startsWith = (b, sig, at = 0) => sig.every((x, i) => b[at + i] === x);
const ascii = (s) => [...s].map((c) => c.charCodeAt(0));

/** File type from the first bytes. Returns { type, label, exts } or null. */
export function sniffType(bytes, name = '') {
  const b = bytes;
  const zipHas = (s) => {
    const head = new TextDecoder('latin1').decode(b.subarray(0, Math.min(b.length, 64 * 1024)));
    return head.includes(s);
  };
  if (startsWith(b, [0x4d, 0x5a])) {
    const off = b.length > 0x40 ? b[0x3c] | (b[0x3d] << 8) | (b[0x3e] << 16) | (b[0x3f] << 24) : -1;
    const pe = off > 0 && off + 4 <= b.length && startsWith(b, ascii('PE\0\0'), off);
    return { type: 'pe', label: pe ? 'Windows executable (PE)' : 'DOS/MZ executable', exts: ['exe', 'dll', 'sys', 'scr', 'ocx', 'cpl', 'drv', 'efi', 'com', 'msstyles', 'mui'] };
  }
  if (startsWith(b, [0x7f, 0x45, 0x4c, 0x46])) return { type: 'elf', label: 'Linux/Unix executable (ELF)', exts: ['', 'so', 'elf', 'o', 'bin', 'ko', 'axf', 'prx', 'out'] };
  for (const sig of [[0xfe, 0xed, 0xfa, 0xce], [0xfe, 0xed, 0xfa, 0xcf], [0xce, 0xfa, 0xed, 0xfe], [0xcf, 0xfa, 0xed, 0xfe]]) {
    if (startsWith(b, sig)) return { type: 'macho', label: 'macOS executable (Mach-O)', exts: ['', 'dylib', 'bundle', 'o', 'so'] };
  }
  if (startsWith(b, [0xca, 0xfe, 0xba, 0xbe])) {
    // Fat Mach-O and Java class files share this magic; fat binaries list few architectures.
    const n = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7];
    return n > 0 && n < 20
      ? { type: 'macho', label: 'macOS universal executable (fat Mach-O)', exts: ['', 'dylib', 'bundle'] }
      : { type: 'class', label: 'Java class file', exts: ['class'] };
  }
  if (startsWith(b, ascii('%PDF-'))) return { type: 'pdf', label: 'PDF document', exts: ['pdf'] };
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06])) {
    if (zipHas('AndroidManifest.xml') || zipHas('classes.dex')) return { type: 'apk', label: 'Android app (APK, a ZIP)', exts: ['apk', 'aab', 'zip'] };
    if (zipHas('word/')) return { type: 'docx', label: 'Word document (Office Open XML, a ZIP)', exts: ['docx', 'docm', 'dotx', 'dotm'] };
    if (zipHas('xl/')) return { type: 'xlsx', label: 'Excel workbook (Office Open XML, a ZIP)', exts: ['xlsx', 'xlsm', 'xltx', 'xltm', 'xlsb'] };
    if (zipHas('ppt/')) return { type: 'pptx', label: 'PowerPoint (Office Open XML, a ZIP)', exts: ['pptx', 'pptm', 'potx', 'ppsx'] };
    if (zipHas('META-INF/')) return { type: 'jar', label: 'Java archive (JAR, a ZIP)', exts: ['jar', 'war', 'ear', 'zip'] };
    return { type: 'zip', label: 'ZIP archive', exts: ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk', 'epub', 'odt', 'ods', 'odp', 'kmz', 'vsix', 'nupkg', 'whl', 'xpi', 'ipa'] };
  }
  if (startsWith(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return { type: 'ole', label: 'Legacy Office / OLE file (doc, xls, ppt, msi)', exts: ['doc', 'xls', 'ppt', 'msi', 'msg', 'dot', 'xlt', 'pot', 'pub', 'vsd'] };
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return { type: 'png', label: 'PNG image', exts: ['png'] };
  if (startsWith(b, [0xff, 0xd8, 0xff])) return { type: 'jpeg', label: 'JPEG image', exts: ['jpg', 'jpeg', 'jpe', 'jfif'] };
  if (startsWith(b, ascii('GIF87a')) || startsWith(b, ascii('GIF89a'))) return { type: 'gif', label: 'GIF image', exts: ['gif'] };
  if (startsWith(b, [0x1f, 0x8b])) return { type: 'gzip', label: 'gzip archive', exts: ['gz', 'tgz', 'gzip'] };
  if (startsWith(b, ascii('Rar!'))) return { type: 'rar', label: 'RAR archive', exts: ['rar'] };
  if (startsWith(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return { type: '7z', label: '7-Zip archive', exts: ['7z'] };
  if (startsWith(b, ascii('#!'))) {
    const line = new TextDecoder('latin1').decode(b.subarray(0, Math.min(b.length, 200))).split('\n')[0];
    const interp = /^#!\s*(\S+)(?:\s+(\S+))?/.exec(line);
    const prog = interp ? (interp[1].endsWith('/env') ? interp[2] || 'env' : interp[1].split('/').pop()) : 'unknown';
    return { type: 'script', label: `Script (${prog})`, exts: ['', 'sh', 'bash', 'zsh', 'py', 'pl', 'rb', 'js', 'php', 'command', 'run', 'ksh'] };
  }
  void name;
  return null;
}

/** Extension checks: a mismatch with the detected type, and "invoice.pdf.exe" double extensions. */
export function extensionWarnings(name, sniffed) {
  const warnings = [];
  const parts = name.toLowerCase().split('.');
  const ext = parts.length > 1 ? parts.pop() : '';
  const DANGEROUS = ['exe', 'scr', 'com', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'hta', 'lnk', 'ps1', 'msi', 'jar', 'iso', 'img', 'dll'];
  if (parts.length > 1 && DANGEROUS.includes(ext) && /^(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip|rtf|csv)$/.test(parts[parts.length - 1])) {
    warnings.push(`Double extension: "${name}" looks like a .${parts[parts.length - 1]} but is a .${ext}.`);
  }
  if (sniffed && !sniffed.exts.includes(ext)) {
    warnings.push(`The content is a ${sniffed.label}, but the name ends in ${ext ? `.${ext}` : 'no extension'}.`);
  }
  return warnings;
}

/** ASCII and UTF-16LE runs of MIN_RUN+ printable characters, up to MAX_STRINGS in total. */
export function extractStrings(bytes, max = MAX_STRINGS) {
  const out = [];
  const printable = (c) => c >= 0x20 && c <= 0x7e;
  let run = '';
  for (let i = 0; i < bytes.length && out.length < max; i++) {
    if (printable(bytes[i]) || bytes[i] === 0x09) run += String.fromCharCode(bytes[i]);
    else {
      if (run.length >= MIN_RUN) out.push(run);
      run = '';
    }
  }
  if (run.length >= MIN_RUN && out.length < max) out.push(run);
  // UTF-16LE: printable byte followed by 0x00, at even and odd offsets.
  for (let start = 0; start < 2 && out.length < max; start++) {
    run = '';
    for (let i = start; i + 1 < bytes.length && out.length < max; i += 2) {
      if (printable(bytes[i]) && bytes[i + 1] === 0) run += String.fromCharCode(bytes[i]);
      else {
        if (run.length >= MIN_RUN) out.push(run);
        run = '';
      }
    }
    if (run.length >= MIN_RUN && out.length < max) out.push(run);
  }
  return out;
}

// ---------- Page wiring ----------

if (globalThis.document?.getElementById('file-input')) {
  const { el, $, notice, rows, lookUpLink, copyButton } = await import('./ui.js');
  const { md5, toHex } = await import('../md5.js');
  const { sendToExtractor } = await import('./ioc.js');
  let strings = [];

  const renderStrings = () => {
    const f = $('file-strings-filter').value.toLowerCase();
    const shown = f ? strings.filter((s) => s.toLowerCase().includes(f)) : strings;
    $('file-strings').textContent = shown.slice(0, MAX_STRINGS).join('\n');
    $('file-strings-count').textContent = `${shown.length.toLocaleString()} of ${strings.length.toLocaleString()} strings${strings.length >= MAX_STRINGS ? ' (first 5,000)' : ''}`;
  };

  const analyze = async (file) => {
    const out = $('file-result');
    if (!file) return;
    if (file.size > MAX_FILE) {
      out.replaceChildren(notice('warn', `That file is ${(file.size / 1048576).toFixed(1)} MB; the limit is 50 MB.`));
      return;
    }
    out.replaceChildren(el('p', { class: 'hint' }, 'Reading and hashing locally…'));
    const bytes = new Uint8Array(await file.arrayBuffer());
    const sha = async (algo) => toHex(new Uint8Array(await crypto.subtle.digest(algo, bytes)));
    const [h1, h256] = await Promise.all([sha('SHA-1'), sha('SHA-256')]);
    const hashes = [['MD5', md5(bytes)], ['SHA-1', h1], ['SHA-256', h256]];
    const type = sniffType(bytes, file.name);
    const warnings = extensionWarnings(file.name, type);
    strings = extractStrings(bytes);

    const sendBtn = el('button', { type: 'button', class: 'secondary small' }, 'Send strings to the IOC extractor');
    sendBtn.addEventListener('click', () => sendToExtractor(strings.join('\n')));
    out.replaceChildren(
      rows([
        ['Name', file.name],
        ['Size', `${file.size.toLocaleString()} bytes`],
        ['Type (from content)', type ? type.label : 'Unknown (no recognised signature)'],
      ]),
      ...warnings.map((w) => notice('bad', w)),
      el('dl', { class: 'facts hashes' }, ...hashes.flatMap(([k, v]) => [el('dt', {}, k), el('dd', { class: 'mono' }, v, ' ', lookUpLink(v), copyButton(() => v))])),
      el('p', { class: 'hint' }, 'Search by hash first. Uploading a file to VirusTotal shares it: anyone with a paid VirusTotal account can download it, so never upload anything private.'),
      el('h3', {}, 'Strings'),
      el('div', { class: 'row' },
        el('input', { id: 'file-strings-filter', type: 'text', placeholder: 'Filter strings (plain text)', 'aria-label': 'Filter strings', spellcheck: 'false' }),
        sendBtn),
      el('p', { id: 'file-strings-count', class: 'hint' }),
      el('pre', { id: 'file-strings', class: 'strings' }),
    );
    $('file-strings-filter').addEventListener('input', renderStrings);
    renderStrings();
  };

  $('file-input').addEventListener('change', (ev) => analyze(ev.target.files[0]));
  const drop = $('file-drop');
  drop.addEventListener('dragover', (ev) => { ev.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (ev) => {
    ev.preventDefault();
    drop.classList.remove('over');
    analyze(ev.dataTransfer.files[0]);
  });
}
