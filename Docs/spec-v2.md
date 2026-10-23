Security Lookup Hub v2: CVEs, news, analysis tools

Oct 15, 2026 · @jamal · for Claude Code

This spec adds features to the live Security Lookup Hub. Read Docs/Requirements.md and README.md first: everything in them still applies (passive lookups only, $0, no keys in the browser, strict CSP, textContent rendering, private targets rejected). Where this spec and Requirements disagree, this spec wins.

How to work: run all phases (6 → 12) in one go, without stopping between them.

Work on a branch v2 (create it from main first). Build phases in order. At the end of each phase: npm test passes (from the repo root), the README Status table and Layout are updated, and you make one commit for that phase ("Phase 6: CVE lookups", …). Then go straight on to the next phase.
Don't stop to ask about choices this spec already settles. For small choices it doesn't cover, pick the simpler option, note it in the README or the commit message, and keep going.
Never run npx wrangler deploy, npx wrangler secret put, npx wrangler kv namespace create, or push to main. Those need Jamal. For the KV binding, use a placeholder id in wrangler.toml (local wrangler dev stores KV locally, so everything can be built and tested without the real namespace) and mark the line # TODO: replace with the id from kv namespace create.
Checks that only work on the deployed Worker (KEV parse CPU time, live NVD/CISA/BleepingComputer responses, the cron run in production) go on a list instead of blocking you.
Stop only if a test can't be made to pass or something in this spec turns out to be impossible as written; say which phase and why.
When everything is done, finish with one message for Jamal: what was built, anything dropped or changed and why, and a single ordered list of what he needs to do (create the KV namespace and paste its id, set any secrets, deploy from worker/, push/merge v2, then the post-deploy checks). Put every prerequisite or warning before the step it applies to.
Where things are

On Jamal's Mac (M1 MacBook Air). All three apps sit side by side:

~/Desktop/coding-projects/AI-Apps/
├── Security-lookup-hub/   ← this repo (work here). Confirm with `pwd`; if the folder name differs, use the real one
├── cve-explainer/         ← source for the Phase 6 port. READ ONLY: never edit, commit or deploy it
└── jazz-fact-chat/        ← unrelated. Don't touch

If ../cve-explainer isn't there, clone it read-only into a temp folder: git clone --depth 1 https://github.com/jamalrizki/cve-explainer.git /tmp/cve-explainer. The files to read are worker/src/tools.js and worker/test/tools.test.mjs.

	
Live site	https://jamalrizki.github.io/Security-lookup-hub/ (GitHub Pages, branch main, root)
Worker	https://security-lookup-hub.jamal-598.workers.dev
Repo	github.com/jamalrizki/Security-lookup-hub
CVE Explainer (link target only)	https://jamalrizki.github.io/cve-explainer/

Repo layout today, with what this spec adds (★ new, ✎ changed).

Security-lookup-hub/
├── index.html                 ✎ Lookup: CVE IDs, DKIM selector field, new nav
├── actors.html                ✎ nav only
├── reference.html             ✎ "Where to start" section, new nav
├── cves.html                  ★ Phase 6
├── news.html                  ★ Phase 7
├── analyze.html               ★ Phases 8, 10, 12
├── favicon.svg
├── css/style.css              ✎
├── js/
│   ├── detect.js              ✎ adds type 'cve' (shared with the Worker)
│   ├── results.js             ✎ CVE cards, email-security grade, Shodan CVEs link in-hub
│   ├── lookup.js              ✎ DKIM selector field
│   ├── links.js, md5.js, encoding.js, pwned.js, config.js
│   ├── reference.js           ✎   actors.js
│   ├── cves.js                ★   news.js ★
│   ├── extract.js             ★ shared extraction for the Analyze tools
│   └── analyze/               ★ one module per tool: ioc.js, link.js, headers.js, jwt.js, file.js, subnet.js, cert.js, nmap.js
├── data/
│   ├── reference.json         ✎   actors.json (generated, don't hand-edit)
│   ├── brands.json ★   public_suffix_list.dat ★
├── scripts/                   build-actors.js, attribution.js, attribution-overrides.json
├── tests/                     core, worker, explain, attribution  +  cve ★, news ★, extract ★, email-security ★, subnet ★
│   └── fixtures/              ★ RSS/Atom samples, headers, URLs, JWTs, Nmap XML, certs
├── worker/
│   ├── wrangler.toml          ✎ cron trigger, NEWS KV binding
│   └── src/
│       ├── index.js           ✎ routes /api/cve-search, /api/news; scheduled() handler
│       ├── sources.js         ✎ registers nvd/kev/epss; email-security parsing in dns
│       ├── cve.js             ★ ported from cve-explainer
│       ├── news.js            ★ feed fetch + RSS/Atom parser
│       ├── explain.js         ✎ CVE + email-security facts and verdicts
│       ├── keyed.js, http.js
├── Docs/
│   ├── Requirements.md        ✎
│   └── spec-v2.md             ★ this file
├── README.md                  ✎
└── package.json               (tests: `npm test` from the repo root)

Commands and folders.

Tests: from the repo root, npm test.
Site locally: from the repo root, python3 -m http.server 8000.
Worker locally: from worker/, npx wrangler dev --port 8787 --ip 127.0.0.1.
Deploy (Jamal only, after all phases): from worker/, npx wrangler deploy; then merge v2 and git push from the repo root.
wrangler is pinned to 4.86.0 (later 4.x needs Node 22). Ports 8000/8787 are shared with Jamal's other apps; check with lsof -nP -iTCP:8000 -iTCP:8787 -sTCP:LISTEN before starting servers.
Run git status before every git add.
Decisions (with the why)
CVE lookups become a native hub feature, not an embedded app. A CVE ID is detected in the main search box like a hash or IP, and the Worker calls NVD, CISA KEV and FIRST EPSS directly. No iframe, no chat. Why: the hub decides in code which sources to call, so the model never chooses arguments. The CVE Explainer's biggest bug (the model mistyping CVE digits) can't happen here.
CVE Explainer stays live as its own app. It is the tool-use / MCP exam project and keeps its own repo, Worker and chat. The hub only links to it. Code is copied from it (see "Porting map"), not shared.
Verdicts are decided in code, the model only explains (already true in explain.js). This extends to CVEs, email security and the link inspector.
The news page is built from a scheduled Worker job (Cron Trigger) into Workers KV. Visitors never cause feed fetches. Why: the edge cache is per data centre, so a cron job can't fill it for everyone; KV is global and free at this volume.
News shows headline, publisher, date and link only. No article excerpts from commercial outlets. CISA content (US government) may show a short summary.
Paste/drop tools run entirely in the browser. Nothing pasted (headers, tokens, files, logs, scan results) is sent anywhere. Only an explicit "Look up" click on one extracted indicator calls the Worker.
No "look up everything" button in any extractor. Each lookup is one click. Why: VirusTotal allows 4 requests a minute site-wide.
Rejected, don't build: website security-header checker (the Worker would fetch arbitrary user-supplied sites: active, SSRF surface), WiGLE lookup (locating people's Wi-Fi is a privacy/stalking risk), password generator and text diff (low value here), running or connecting offensive tools.
No chat and no MCP in the hub this round. Possible later as a separate phase.
New navigation

Lookup · CVEs · News · Analyze · Threat actors · Reference

Lookup (existing): now also accepts CVE IDs. Email-security details on domain/email results. Existing browser tools stay.
CVEs (cves.html, new): product/keyword search for CVEs.
News (news.html, new): advisories, exploited vulns, news.
Analyze (analyze.html, new): paste/drop tools: IOC extractor, link inspector, email-header analyzer, JWT decoder, file analyzer, subnet calculator; later certificate viewer and Nmap viewer. Each tool is a section with an anchor (analyze.html#ioc) and a short contents list at the top.
Reference (existing): gains a "Where to start" section.

Nav must wrap cleanly on a 390px phone (no horizontal scroll). Every new page copies the existing CSP meta tag; connect-src lists only what that page actually calls.

Porting map (from github.com/jamalrizki/cve-explainer, worker/src/tools.js)

Copy these into a new worker/src/cve.js and adapt them to the hub's source shape ({ name, run, link }) and http.js (getJson, QuotaError). Drop everything MCP- and chat-specific (TOOLS definitions, publicDefinition, runTool, serializeResult, mcp.js, mcp-client.js, the edit-distance ID correction in index.js).

From cve-explainer	Purpose
normalizeCveId, CVE_ID_PATTERN	ID validation (also feeds detect.js)
englishText, statusNotes	NVD description; Rejected / Reserved / Awaiting Analysis notes
CVSS_PREFERENCE, pickCvss, describeCvss, the ATTACK_VECTOR / COMPLEXITY / PRIVILEGES / INTERACTION / IMPACT tables	Primary CVSS score and plain-English vector
CWE_NAMES, weaknessList	Weakness names
affectedProducts, parseCpe, versionRange	Affected products and version ranges (cap 8)
topReferences	Vendor advisories first (cap 6)
KEV_URLS, loadKev, kevStatus	KEV with GitHub mirror fallback, parse once per isolate, 1 h TTL
epssScore, formatPercent	EPSS score, percentile, meaning sentence
searchCves (two-request newest-first workaround, SEARCH_WINDOW)	Keyword search
The "not in KEV never means safe" message	Keep word for word

Port the matching unit tests from worker/test/tools.test.mjs into tests/cve.test.mjs (fetch mocked, no network).

Phase 6: CVE lookups

Detection (js/detect.js). Add type cve, checked before the domain/hash rules. Accept any case and the Unicode dash variants the Explainer accepts (CVE[\s‐-―−_-]*(\d{4})[\s‐-―−_-]*(\d{4,19})), normalise to CVE-YYYY-NNNN… uppercase. Return { type: 'cve', value, label: 'CVE ID' }. Year must be 1999 to current year + 1, otherwise an error message.

Worker sources (worker/src/cve.js, registered in sources.js).

nvd: NVD API 2.0 by cveId. Link: https://nvd.nist.gov/vuln/detail/<id>.
kev: KEV status. Link: CISA KEV catalog search for the ID.
epss: FIRST EPSS. Link: https://www.first.org/epss/.
plan(): case 'cve': return run(['nvd', 'kev', 'epss'], value).

Limits and caching.

NVD without a key allows 5 requests per rolling 30 s. Use quotaTools.allow('nvd', 8) per minute without a key, 80 with one. On 429/403 from NVD, pause('nvd', 60).
Optional secret NVD_API_KEY (set per Worker, so the Explainer's doesn't carry over). Send it only if it matches a UUID pattern; otherwise ignore it and treat NVD as keyless. Why: the Explainer once nearly sent another service's key to NVD.
getJson caps responses at 1 MB by default. The KEV file is larger: pass maxBytes: 4_000_000 for KEV only.
Cache CVE lookups for 6 hours (not 24): KEV and EPSS change daily. Bump CACHE_VERSION if the result shape of existing types changes.
Measure the KEV parse on the deployed Worker. If requests fail with CPU-limit errors (1102), switch kev to read the compact KEV index that Phase 7's cron job writes to KV (see Phase 7). Don't build that fallback pre-emptively.

Result cards (js/results.js).

NVD card: description (truncate 600 chars, "more on NVD"), severity badge + score + version, plain-English vector line, CWE names, published/modified dates, status notes, affected products (8), references (6, vendor first). Links only after URL validation (https, no userinfo).
KEV card: in KEV yes/no; if yes: date added, due date, known ransomware use, required action. If no: the "not in KEV never means safe" line.
EPSS card: probability %, percentile, the meaning sentence, date of the score.
A small "Priority" strip on top from code (see verdict below).
Footer line: "Want to ask questions about it? Try CVE Explainer →" linking to https://jamalrizki.github.io/cve-explainer/.

Verdict for CVEs (verdict() in explain.js). Rules, in order, labelled in the UI as a rule of thumb, not a fact:

NVD status Rejected → "Rejected: not a valid vulnerability".
In KEV → "Exploited in the wild: patch urgently".
EPSS ≥ 0.10, or CVSS ≥ 9.0 with network vector, no privileges and no user interaction → "High priority".
Otherwise by CVSS severity (Critical/High → "Patch soon", Medium → "Patch on your normal cycle", Low → "Low priority"), or "No score yet" if NVD has none.

Explain button. Add CVE fields to PICK / facts(): ID, severity, score, vector sentence, CWE names, KEV yes/no and date added, EPSS %, first 300 chars of the description. Update SYSTEM to cover CVE IDs. Same injection rules as today (structured fields only, truncated, output defanged).

Shodan link-up. In the IP card, the "Known CVEs" list links to ./#q=<CVE> (the hub's own lookup) instead of NVD.

CVEs page (cves.html, js/cves.js). Keyword box (2–60 chars, letters, digits, spaces, .-_), optional severity filter (Low/Medium/High/Critical). Calls new route GET /api/cve-search?q=&severity=. Worker validates the same rules, makes at most the two NVD requests the Explainer makes, returns the 10 newest matches (ID, published date, severity, score, first 200 chars of description). Each row links to ./#q=<id>. Cache searches 6 hours. Show the total match count ("showing the 10 newest of 1,234").

Acceptance checks.

CVE-2021-44228, cve-2021-44228 and CVE‑2021‑44228 (non-breaking hyphen) all detect as the same CVE.
Log4Shell shows Critical 10.0, in KEV, EPSS above 90%, verdict "Exploited in the wild".
A Rejected CVE shows the rejected note and verdict.
A future-year or 3-digit ID is rejected before any request.
Keyword "fortinet" returns newest-first results.
With NVD paused, the card says "Skipped", the others still work.
Tests cover detection, CVSS decoding, KEV/EPSS parsing, verdict rules and search validation.
Phase 7: News page

Sources (start with three).

Source	Filter	Feed
CISA KEV	Exploited vulnerabilities	The KEV JSON (same URLs as Phase 6); the 25 most recently added entries
CISA cybersecurity advisories	Official advisories	CISA's advisories RSS. Find the current feed URL on cisa.gov and confirm it has items from the last few weeks before building on it
BleepingComputer	News	https://www.bleepingcomputer.com/feed/ (confirm)

Phase 7b, once the page has worked for a week: add The Hacker News (News) and UK NCSC (Official advisories). Confirm each feed URL from the publisher's own site.

Scheduled job.

Add a Cron Trigger to worker/wrangler.toml, hourly at an odd minute (e.g. 17 * * * *), and a scheduled() handler in worker/src/index.js.
Add a KV namespace binding NEWS. Jamal creates it once, from worker/: npx wrangler kv namespace create NEWS, then pastes the id into wrangler.toml. Write that step into the README before the deploy step.
Each run fetches every feed (8 s timeout, 2 MB cap each), parses, and writes one KV key news:v1 with all items plus per-source { ok, fetchedAt, error }. If a feed fails, keep that source's previous items and mark it stale; never wipe good data with an empty fetch.
Optional, only if Phase 6 needed it: also write kev:index:v1, a compact map of KEV entries (cveID → { added, due, ransomware, action }).
Writes: about 24 a day (Workers KV free tier allows 1,000 writes and 100,000 reads a day; confirm current limits on Cloudflare's pricing page and note them in the README).

Parsing (worker/src/news.js). Workers have no DOMParser. Write a small RSS 2.0 / Atom parser: <item>/<entry> blocks; title, link (or Atom link href), pubDate/updated/published; handle CDATA and entity decoding; strip all tags from titles; titles capped at 200 chars; max 30 items per feed. Links must be https: and their host must be the feed publisher's domain or a subdomain of it (per-source allowlist); drop items that fail. For CISA items only, a plain-text summary up to 240 chars (tags stripped).

Route. GET /api/news returns the KV value. Edge-cache the response for 5 minutes. If KV is empty (first deploy before the cron has run), return { items: [], pending: true } and the page says "First update runs within the hour."

Page (news.html, js/news.js).

Filters: All · News · Official advisories · Exploited vulnerabilities. Selected filter in the URL fragment (#filter=kev).
Each item: headline (link, opens in a new tab with noopener noreferrer), publisher, date ("3 hours ago" with the full date as a title attribute). KEV items: CVE ID linking to ./#q=<id>, vendor/product, date added, ransomware flag.
Footer: last updated per source; a stale source says so ("BleepingComputer: last updated 5 h ago").
Everything rendered with textContent.

Acceptance checks.

After one cron run (test locally with npx wrangler dev --test-scheduled, then curl "http://127.0.0.1:8787/__scheduled"), /api/news returns items from all three sources.
A feed returning HTML, 403, malformed XML or an item linking to another domain doesn't break the run or the page.
Loading the page makes exactly one request (to /api/news).
Parser tests with fixture files in tests/fixtures/ (RSS, Atom, CDATA, entities, hostile titles with <script>).
Phase 8: Analyze page: IOC extractor, link inspector, email headers

All three run in the browser. Shared code goes in js/extract.js and reuses detect.js (refang, defang, detect).

IOC extractor (#ioc).

Paste up to 500 KB of text (email, report, logs).
Refang first (hxxp, [.], (dot) etc.), then extract: IPv4, IPv6, domains, URLs, email addresses, MD5/SHA-1/SHA-256, CVE IDs.
Run every candidate through detect(); drop private/reserved IPs and internal names, show a count of what was dropped and why.
De-duplicate; count occurrences; group by type.
Flag likely false positives: domains whose TLD is also a common file extension (.zip, .mov, .py, .sh…) when they look like file names.
Log mode toggle: a line filter box (plain substring, no regex input), and "top IPs / top domains by count".
Per row: a "Look up" link (./#q=<value>), copy. Bulk actions: copy all (defanged), download CSV (built in the browser).
No "look up all".

Suspicious-link inspector + lookalike detector (#link).

Paste one URL. Never fetch it; say so on the page.
Show: scheme; the real host and the registrable domain (use the Public Suffix List, vendored as data/public_suffix_list.dat, refresh steps in README like actors.json); userinfo before @ (the paypal.com@evil.xyz trick); port; IP-literal hosts; punycode shown both as xn-- and Unicode; mixed scripts in one label (Latin + Cyrillic/Greek).
Lookalike check against a small brand list in data/brands.json (the usual phishing targets plus IBM): confusable-character skeleton (a curated confusables map, not all of Unicode) and edit distance ≤ 2 on the registrable domain's first label; brand name appearing only as a subdomain (paypal.com.login.xyz).
Decoding: percent-decode path and query up to 3 layers; detect Base64 values in parameters and show the decoded text (as text only); detect redirect parameters (url, redirect, next, u, dest, target, continue, or any value that is itself a URL) and offer "Inspect this nested URL".
Known shorteners (small list): say the destination can't be seen without opening it, and link to urlscan.io.
Verdict in code: "Looks normal" / "Suspicious: <reasons>" with each reason listed.

Email-header analyzer (#headers).

Paste raw headers (cap 200 KB). Unfold continuation lines.
Received chain, oldest at the bottom shown first: each hop's from/by host, IP, timestamp, delay since the previous hop.
Explain on the page that only the top Received lines (added by your own mail provider) are trustworthy; lower ones can be forged.
From vs Reply-To vs Return-Path domain mismatches; Message-ID domain; Authentication-Results parsed into SPF / DKIM / DMARC pass/fail with the domains each checked.
Extract public IPs and domains with "Look up" links.
Note that headers contain the user's own address and nothing leaves the page.

Acceptance checks. Test fixtures for each tool, including hostile input (HTML/JS in headers and URLs, 500 KB inputs, deeply nested encodings). Each tool works with the page offline (DevTools offline mode) except the "Look up" links.

Phase 9: Email-security assessment (domains and email addresses)

Extend the existing dns source and DNS card.

Null MX (RFC 7505): MX record 0 .. Report "This domain says it accepts no email."
SPF: all qualifier (-all strict, ~all soft, ?all neutral, +all dangerous), ptr (deprecated), and a count of DNS-lookup mechanisms in the top record (include, a, mx, ptr, exists, redirect). Say plainly that includes aren't expanded, so the real total is at least that number and the limit is 10.
DMARC: p, sp, pct, adkim/aspf, whether rua reporting is set.
DKIM: optional "DKIM selector" field shown only for domain/email lookups. Validate as a DNS label sequence (letters, digits, -, _, dots between labels, ≤ 63 per label, ≤ 100 total). Query <selector>._domainkey.<domain> TXT. Include the selector in the cache key. Explain why DKIM can't be checked without a selector.
Parked-domain advice: no MX at all → suggest null MX + v=spf1 -all + DMARC p=reject so it can't be spoofed.
Grade in code: "Protected" (SPF -all or ~all + DMARC quarantine/reject at 100%), "Partly protected", "Easy to spoof" (no DMARC or p=none, or SPF missing / +all). Show the reasons.
Add the grade and reasons to facts() for the Explain button.

Acceptance checks. Unit tests for each SPF/DMARC/null-MX case with recorded DoH answers; selector validation rejects injection attempts (a;b, ../, spaces, 200-char strings).

Phase 10: More Analyze tools (browser only)

JWT decoder (#jwt). Split, Base64url-decode header and payload, pretty-print JSON as text. Flag alg: none. Show exp/iat/nbf as dates with expired / not yet valid status. State clearly: "Decoded, not verified. The signature is not checked." Nothing is sent anywhere.

File analyzer (#file). Drag or pick a file, max 50 MB, read locally.

MD5 (existing md5.js), SHA-1, SHA-256 (WebCrypto), each with a "Look up" link.
File type from magic bytes (PE/MZ, ELF, Mach-O, PDF, ZIP/Office, OLE, PNG/JPEG/GIF, script shebangs) and a flag when the extension doesn't match.
Strings: ASCII and UTF-16LE runs of 6+ characters, first 5,000, with a filter box; a button sends the strings to the IOC extractor.
A note that uploading a file to VirusTotal makes it available to its paid users, so search by hash first.

Subnet calculator (#subnet). IPv4: network, broadcast, first/last usable host (handle /31 and /32 per RFC 3021), host count, netmask, wildcard. IPv6: network, first/last address, address count (BigInt). "Is this IP in this range?" check. Reuse parseIPv4/parseIPv6. Unit tests for edge prefixes (/0, /31, /32, /64, /127, /128).

Phase 11: Reference additions

"Where to start" (top of reference.html). One row per thing you might have: hash, domain, IP, URL, email address, email headers, CVE, suspicious file, threat actor name. For each: "Try it here first" (link to the hub feature) and the 2–3 best outside sites from the directory with one line on when to use each. Data in data/reference.json.

(The security tools guide originally planned for this phase was dropped on Oct 15, 2026; see README.)

Phase 12 (later): Certificate viewer and Nmap viewer

Certificate viewer (#cert). Paste PEM or drop .cer/.crt/.der. Minimal DER/X.509 parser written locally (no CDN; CSP forbids it): subject, issuer, SANs, validity with expired/not-yet-valid flags, key type and size, signature algorithm, SHA-256 fingerprint, self-signed flag, a crt.sh link by fingerprint. If the pasted text contains PRIVATE KEY, refuse to parse it and tell the user to treat that key as exposed and replace it.

Nmap viewer (#nmap). Drop Nmap XML (-oX), max 20 MB, parse with DOMParser('application/xml'). Table of host / port / state / service / version, filters by port and service, counts. CVE IDs found in script output link to ./#q=<id>. Private IPs are expected here: show them, but "Look up" links appear only for public addresses (detect() already enforces this).

Out of scope this round

Chat or tool-use in the hub; an MCP endpoint for the hub; active checks of user-supplied sites; WiGLE; password generator; text diff; storing anything about visitors.

Docs to update as you go
README.md: Status table (one row per phase), Layout, new secrets (NVD_API_KEY), the KV namespace step, cron schedule and limits, feed list and how to add a feed, PSL refresh steps.
Docs/Requirements.md: add CVE, News and Analyze to "Core features"; add the rejected items to "Non-goals".