// Decorative page chrome: the typing terminal bar, the hex ticker and the
// binary rain. Purely visual (all aria-hidden) and runs nothing. With
// prefers-reduced-motion, the first command and its output are shown statically.

const COMMANDS = {
  lookup: [
    ['whois example.com', 'Registrar: IANA · created 1995-08-14'],
    ['dig +short bad[.]example', '198.51.100.23'],
    ['curl -s api.pwnedpasswords.com/range/5BAA6', '1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493'],
    ["hashid '$2b$12$KIXQ...'", '[+] bcrypt'],
  ],
  analyze: [
    ['ioc-extract --refang report.eml', '14 indicators · 3 private dropped'],
    ['jwt decode eyJhbGciOiJIUzI1NiJ9...', '{"alg":"HS256","typ":"JWT"}'],
    ['ipcalc 10.20.0.0/22', 'hosts: 1022 · bcast 10.20.3.255'],
    ['file --mime invoice.pdf', 'application/x-dosexec  (!) type mismatch'],
  ],
  cves: [
    ['nvd search --keyword openssl --sev critical', '10 results · newest first'],
    ['kev check CVE-2024-3400', '[!] in CISA KEV catalog'],
    ['epss CVE-2023-4966', 'score 0.97 · percentile 99.9'],
  ],
  news: [
    ['feeds pull --all', '3 sources · refreshed hourly'],
    ['tail -f /var/feeds/cisa-kev.rss', 'new: known exploited vulnerabilities'],
  ],
  actors: [
    ['attack groups --search "fancy bear"', 'G0007 APT28'],
    ['attack techniques G0032', 'T1566.001 · T1059.001 · T1105 ...'],
  ],
  reference: [
    ['grep -i sandbox reference.json', 'Hybrid Analysis · ANY.RUN'],
    ['cat where-to-start.txt | head -1', 'A file hash → Lookup first'],
  ],
  tools: [
    ['apropos "password cracker"', 'hashcat (1) · john (8)'],
    ['man nmap | head -1', 'nmap - Network exploration tool and security scanner'],
  ],
};

const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const page = document.body.dataset.page || 'lookup';
const rand = (n) => Math.floor(Math.random() * n);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function hexGroups(n) {
  return Array.from({ length: n }, () => rand(0x10000).toString(16).padStart(4, '0')).join('  ');
}

function ticker() {
  const track = document.querySelector('.ticker-track');
  if (!track) return;
  // Just enough 4-digit groups to overfill the screen (each "abcd  " is ~37px at
  // 12px, plus a margin), rather than a fixed 60: on phones a ~5,000px animated
  // layer flickers. Wider screens get more groups so the loop never shows a gap.
  const groups = Math.max(16, Math.ceil(window.innerWidth / 36) + 6);
  const s = hexGroups(groups);
  // Written twice so translateX(-50%) loops seamlessly; duration scales with
  // length so the speed matches the design's 60 groups in 22s.
  track.textContent = `${s}  ${s}  `;
  track.style.animationDuration = `${((22 * groups) / 60).toFixed(2)}s`;
}

function rain() {
  const layer = document.querySelector('.rain');
  if (!layer || reduced) return;
  for (let i = 0; i < 34; i++) {
    const col = document.createElement('span');
    col.textContent = Array.from({ length: 60 }, () => rand(2)).join('\n');
    // CSSOM writes are allowed by the CSP (only style attributes in markup are not).
    col.style.left = `${i * 3}%`;
    col.style.animationDuration = `${6 + ((i * 37) % 9)}s`;
    col.style.animationDelay = `-${(i * 53) % 11}s`;
    layer.append(col);
  }
}

async function terminal() {
  const cmd = document.querySelector('.term-cmd');
  const out = document.querySelector('.term-out');
  const pid = document.querySelector('.term-pid');
  if (!cmd || !out) return;
  if (pid) pid.textContent = `PID ${4000 + rand(900)} · tty/0`;
  const list = COMMANDS[page] || COMMANDS.lookup;
  if (reduced) {
    cmd.textContent = list[0][0];
    out.textContent = `→ ${list[0][1]}`;
    return;
  }
  for (let i = 0; ; i = (i + 1) % list.length) {
    const [command, output] = list[i];
    cmd.textContent = '';
    out.textContent = `→ ${output}`;
    out.classList.remove('shown');
    for (const ch of command) {
      cmd.textContent += ch;
      await sleep(45 + rand(71));
    }
    out.classList.add('shown');
    await sleep(2200);
    out.classList.remove('shown');
    await sleep(400);
  }
}

ticker();
rain();
terminal();
