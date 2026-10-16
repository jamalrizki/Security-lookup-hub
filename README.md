# Security Lookup Hub

One search box for a hash, domain, IP, URL or email, plus a password breach check, a threat-actor browser and a directory of free security sites. Passive lookups only, $0 to run. The full spec is in [Docs/Requirements.md](Docs/Requirements.md).

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Reference page; hash identifier, hash calculator, decoder, password check; type detection with "open in" links | Done |
| 2 | Threat actors page from MITRE ATT&CK data | Done |
| 3 | Cloudflare Worker with keyless lookups (RDAP, DNS, certificates, Shodan InternetDB), validation, cache | Done |
| 4 | Keyed lookups: VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus | Done |
| 5 | Result cards, polish, deploy | Done |
| Extra | "Explain these results" AI summary (Groq free tier) | Done |
| 6 | CVE lookups: CVE IDs in Lookup (NVD, CISA KEV, FIRST EPSS, priority rule), CVEs keyword search page | Built on `v2`, not deployed |
| 7 | News page: CISA KEV, CISA advisories, BleepingComputer via a Cron Trigger into Workers KV | Built on `v2`, not deployed |
| 8 | Analyze page: IOC extractor, suspicious-link inspector with lookalike detection, email-header analyzer (browser only) | Built on `v2`, not deployed |
| 9 | Email-security assessment on domain/email lookups: null MX, SPF, DMARC, optional DKIM selector, spoofing grade | Built on `v2`, not deployed |
| 10 | More Analyze tools: JWT decoder, file analyzer (hashes, magic bytes, strings), subnet calculator | Built on `v2`, not deployed |
| 11 | Reference: "Where to start" section (security tools guide dropped, see below) | Built on `v2`, not deployed |
| 12 | Analyze: certificate viewer and Nmap viewer | Built on `v2`, not deployed |

**Tools glossary:** the security tools guide originally planned for Phase 11 was dropped from the spec on Oct 15, 2026. In its place, `tools.html` (the Tools tab) renders `data/tools.json`, a list of `{ "tool": "…", "whatItDoes": "…" }` entries, as a filterable glossary. The data is written and maintained outside this build; the page ships with an empty list. `tests/tools.test.mjs` checks the file's shape: each entry has exactly those two non-empty text fields, and tool names are unique.

## Run locally

ES modules don't load from `file://`, so serve the folder over HTTP:

```sh
python3 -m http.server 8000
```

Then open http://localhost:8000. Lookups can be deep-linked as `/#q=8.8.8.8`. The indicator sits in the URL fragment, which browsers never send to the server.

## Lookup API (Cloudflare Worker)

The Worker in `worker/` is deployed at https://security-lookup-hub.jamalrizki.workers.dev. It only answers requests whose `Origin` is in `ALLOWED_ORIGINS` (`worker/wrangler.toml`).

| Indicator | Sources |
|---|---|
| Hash | VirusTotal, MalwareBazaar, URLhaus (MD5 and SHA-256 only) |
| Domain | VirusTotal, URLhaus, RDAP via rdap.org (registration date, registrar), Cloudflare DNS over HTTPS (A, AAAA, MX, NS, TXT, SPF, DMARC), certificates from crt.sh with Cert Spotter as fallback |
| IP | AbuseIPDB, VirusTotal, URLhaus, Shodan InternetDB (ports, CVEs, hostnames), RDAP (network owner) |
| URL | VirusTotal and URLhaus for the URL, plus the keyless domain or IP sources for its host |
| Email | DNS for the email's domain |

API keys are Worker secrets: `VT_API_KEY`, `ABUSEIPDB_API_KEY` and `ABUSECH_AUTH_KEY` (used by both MalwareBazaar and URLhaus). To set or rotate one, run this from `worker/`. It prompts for the value:

```sh
npx wrangler secret put VT_API_KEY
```

A source whose key is missing shows as "Skipped", and the rest still work.

- Results are cached at the edge for 24 hours (1 hour for "nothing found"), per data centre.
- VirusTotal's free tier allows 4 requests a minute and 500 a day. The Worker allows at most 4 VirusTotal calls a minute site-wide, and a URL search makes only one VirusTotal call. If any source answers 429, the Worker pauses that source for at least a minute. The card shows "Skipped" instead of failing.
- All keyed free tiers are for non-commercial use only.
- There is no per-visitor limit, by choice. Every account is on a free tier with no payment method, so running out of a quota only pauses that source until it resets. It costs nothing.
- crt.sh is frequently down. Cert Spotter allows only a few keyless queries per hour, so the certificates card is the one most likely to say "Unavailable".

Run it locally with `wrangler dev`. Pages served from `localhost:8000` call the local Worker automatically:

```sh
cd worker
npm install
npx wrangler dev --port 8787 --ip 127.0.0.1
```

Deploy:

```sh
cd worker
npx wrangler deploy
```

wrangler is pinned to 4.86.0 because later 4.x versions need Node 22.

## CVEs

A CVE ID in the Lookup box (any case, with copy-paste dash variants such as non-breaking hyphens) runs three sources, all keyless:

| Source | What it gives | Limit handling |
|---|---|---|
| NVD API 2.0 | Description, CVSS score and a plain-English vector, CWE names, affected products (8), references (6, vendor advisories first) | 8 calls a minute site-wide without a key (NVD allows 5 per rolling 30 s), 80 with `NVD_API_KEY`. A 403 or 429 pauses NVD for a minute |
| CISA KEV | In the catalog or not; date added, due date, ransomware use, required action | The ~1.8 MB file is downloaded once per Worker isolate per hour (GitHub mirror as fallback) and edge-cached |
| FIRST EPSS | Probability of exploitation in the next 30 days, percentile | None needed |

- CVE results are cached for 6 hours, not 24, because KEV and EPSS change daily.
- **Priority** is a rule of thumb decided in code, in this order: Rejected; in KEV ("Exploited in the wild: patch urgently"); EPSS of 10% or more, or CVSS 9+ that is remote with no login and no user action ("High priority"); otherwise by CVSS severity.
- Optional secret `NVD_API_KEY` (free from NVD). It is only sent if it looks like an NVD key (a UUID); anything else is ignored. CVE Explainer's key does not carry over, since secrets are per Worker. To set it, run this from `worker/`. It prompts for the value:

```sh
npx wrangler secret put NVD_API_KEY
```

- The CVEs page (`cves.html`) calls `GET /api/cve-search?q=&severity=`. Keywords are 2 to 60 letters, digits, spaces, dots, dashes or underscores. NVD lists matches oldest first and can't sort, so the Worker makes two requests (count, then the last page) and returns the 10 newest. Searches are cached for 6 hours.
- Lookup links CVE results to [CVE Explainer](https://jamalrizki.github.io/cve-explainer/) for follow-up questions. The parsing code in `worker/src/cve.js` is copied from it, not shared.

## News

`news.html` shows headlines from three feeds. Visitors never cause feed fetches: a Cron Trigger refreshes the feeds into Workers KV (one key, `news:v1`), and `GET /api/news` only reads it, edge-cached for 5 minutes.

| Source | Filter | Feed |
|---|---|---|
| CISA KEV | Exploited vulnerabilities | The KEV JSON (GitHub mirror as fallback); the 25 most recently added entries |
| CISA | Official advisories | `https://www.cisa.gov/cybersecurity-advisories/all.xml` (listed on cisa.gov's subscribe page; plain-text summaries up to 240 characters) |
| BleepingComputer | News | `https://www.bleepingcomputer.com/feed/` (headlines only, no excerpts) |

- **Schedule:** `17,37,57 * * * *` (UTC). That's one trigger out of the 5 the Free plan allows per account. Each run refreshes **one** source (:17 KEV, :37 CISA, :57 BleepingComputer), so every source still updates hourly. One run refreshing everything would parse about 3 MB (the CISA feed is 1.2 MB with full advisory text, KEV is 1.8 MB), which risks the Free plan's 10 ms CPU limit for cron runs. A manual trigger refreshes all three.
- **Limits:** that's about 72 KV writes and a few hundred reads a day. Workers KV Free allows 1,000 writes, 100,000 reads, 1,000 deletes and 1,000 lists a day, and 1 GB stored; limits reset at 00:00 UTC (Cloudflare pricing page, checked Oct 2026).
- **Safety:** each fetch has an 8-second timeout and a 2 MB cap. The parser keeps at most 30 items per feed, strips all tags from titles, caps them at 200 characters, and drops any item whose link isn't https on the publisher's own domain. A failed, HTML or empty fetch keeps that source's previous items and marks it stale.
- **Before the first deploy,** create the KV namespace. Run this from `worker/`:

```sh
npx wrangler kv namespace create NEWS
```

  Then paste the `id` it prints into `worker/wrangler.toml`, replacing the placeholder on the line marked `# TODO`.

- **Testing locally:** `wrangler dev` keeps KV in a local store, so the placeholder id works. Run this from `worker/`:

```sh
npx wrangler dev --test-scheduled --port 8787 --ip 127.0.0.1
```

  Then trigger a run with:

```sh
curl "http://127.0.0.1:8787/__scheduled"
```

- **Adding a feed:** add an entry to `FEEDS` in `worker/src/news.js` with its id, display name, filter (`news`, `advisories` or `kev`), URL, and the publisher domain(s) its links may point to (`hosts`). Set `summary: true` only for government sources. Give it a cron minute in `CRON_MINUTES` and add that minute to the cron in `wrangler.toml`. Add a fixture test in `tests/news.test.mjs`. Planned next (Phase 7b, after a week): The Hacker News and UK NCSC, confirming each feed URL on the publisher's own site.

## Email security

Domain and email lookups grade how easily someone could send mail pretending to be the domain. The grade is decided in code, in `emailGrade()` in `worker/src/sources.js`, and the Explain button gets the same grade and reasons.

| Grade | Rule |
|---|---|
| Protected | SPF ends in `-all` or `~all` (or delegates with `redirect=`), and DMARC is `quarantine` or `reject` at 100%, with at most 10 SPF lookups |
| Easy to spoof | No DMARC, `p=none`, no SPF, SPF `+all`, or more than one SPF record |
| Partly protected | Anything in between, e.g. SPF `?all`, DMARC `pct` below 100, or more than 10 SPF lookups |

- **Null MX** (RFC 7505, a single `0 .` record) is reported as "accepts no email". A domain with no MX at all gets advice to publish null MX, `v=spf1 -all` and DMARC `p=reject`, so a parked domain can't be spoofed.
- **SPF lookups** counts the DNS-lookup mechanisms in the top record (include, a, mx, ptr, exists, redirect). Includes aren't expanded, so the real total is at least that; the limit is 10. `ptr` is flagged as deprecated.
- **DMARC on subdomains:** if the exact name has no `_dmarc` record, the Worker walks up to two parent labels and applies the parent's `sp=` (falling back to `p=`), as receivers do with the organisational domain. The card says where the policy came from.
- **DKIM** needs a selector, because DNS can't list them. The optional "DKIM selector" field appears for domain and email lookups. Selectors are validated as DNS labels (letters, digits, `-`, `_`, dots between labels, 63 per label, 100 in all) on the page and in the Worker, and are part of the cache key. The card reports the key as present (with an approximate RSA size), revoked (empty `p=`) or not found.
- `CACHE_VERSION` went to `v2` in this phase, because the cached DNS result gained these fields.

## Reference: where to start

The top of `reference.html` has one card per thing you might have: a hash, domain, IP, URL, email address, email headers, CVE, suspicious file or threat actor name. Each card links first to the hub feature to try, then to 2–3 outside sites with one line on when to use each. The data is `whereToStart` in `data/reference.json`. Outside sites are named, not linked: the page takes each URL from the directory entry of the same name, so it can only point at sites the directory already lists. `tests/reference.test.mjs` fails if a name isn't in the directory.

## Analyze tools

`analyze.html` holds paste-and-check tools that run entirely in the browser; nothing pasted is sent anywhere. The page's CSP allows same-origin requests only, for the two data files. A "Look up" link on one extracted value opens the normal lookup (`./#q=…`). There is deliberately no "look up all", because VirusTotal allows 4 lookups a minute for the whole site. The tools keep working offline once the page has loaded.

- **IOC extractor** (`#ioc`): reads up to 500 KB and refangs it first. It extracts URLs, domains, IPv4/IPv6, emails, MD5/SHA-1/SHA-256 and CVE IDs, and checks each one with the same `detect()` the Worker uses. Private or reserved IPs, internal names and file names with no real top-level domain (`report.txt`) are dropped, with a count by reason. File-like domains on real TLDs (`invoice.zip`, `setup.py`) are kept but flagged. Log mode adds a plain-substring line filter and top IPs/domains. You can copy everything defanged, or download a CSV (cells starting with `=`, `+`, `-` or `@` are prefixed so spreadsheets don't run them).
- **Link inspector** (`#link`): never fetches the URL. It reports:
  - the real host and registrable domain;
  - text before `@` (`paypal.com@evil.example`), IP hosts and ports;
  - punycode alongside Unicode, and mixed scripts in one label;
  - brand lookalikes from `data/brands.json`: a curated confusables map ("skeleton"), edit distance on the first label, and brand names used only as a subdomain;
  - up to 3 layers of percent-encoding, Base64 parameters and redirect parameters (with "Inspect this nested URL"), and link shorteners.

  The verdict is decided in code: "Looks normal" or "Suspicious" with reasons. Edit distance is 2 for brand labels of 6+ characters, 1 for 4–5 and 0 for 3 or fewer (only look-alike characters count for `ups` or `ibm`). Any listed brand's own domain is never flagged.
- **Email-header analyzer** (`#headers`): reads up to 200 KB and unfolds continuation lines. It shows:
  - the Received chain oldest first, with delays and the IP each server actually saw;
  - From / Reply-To / Return-Path / Message-ID mismatches, compared by registrable domain;
  - SPF / DKIM / DMARC from the topmost Authentication-Results header;
  - public IPs and domains, with Look up links.

- **JWT decoder** (`#jwt`): splits the token and Base64url-decodes the header and payload, shown as text. It flags `alg: none`, empty signatures and `jku`/`x5u` key URLs, and shows `exp`/`iat`/`nbf` as dates with expired / not-yet-valid status. It says plainly that the signature is not checked. Encrypted (JWE) tokens are recognised and not decoded.
- **File analyzer** (`#file`): reads a dropped or chosen file locally (up to 50 MB). It computes MD5, SHA-1 and SHA-256 (with Look up links), and detects the real type from magic bytes: PE/MZ, ELF, Mach-O and fat Mach-O (told apart from Java class files), PDF, ZIP (Office, JAR and APK), OLE, PNG, JPEG, GIF, gzip, RAR, 7z and script shebangs. It flags extensions that don't match the content and double extensions such as `invoice.pdf.exe`. It also lists the first 5,000 ASCII and UTF-16LE strings of 6+ characters, with a filter and a button that sends them to the IOC extractor. The page warns that uploading to VirusTotal shares the file with its paid users, so search by hash first.
- **Subnet calculator** (`#subnet`): for IPv4 it gives the network, netmask, wildcard, broadcast, first/last host and host counts. `/31` follows RFC 3021 (two usable hosts, no broadcast) and `/32` is a single host; dotted netmasks are accepted. For IPv6 it gives the network and first/last address, with BigInt address counts and RFC 5952 formatting. It also answers "Is this IP in this range?".

- **Certificate viewer** (`#cert`): reads a pasted PEM (or a chain, up to 10) or a dropped `.cer`/`.crt`/`.der` file with a small DER/X.509 parser written here (the CSP allows no CDN libraries). It shows the subject, issuer, SANs (DNS, IP, email, URI), validity with expired / not-yet-valid flags, key type and size (RSA bits, EC curve, Ed25519/Ed448), signature algorithm (weak ones flagged), serial, the SHA-256 fingerprint with a crt.sh link, and self-signed and CA flags. Text containing `PRIVATE KEY` is refused without parsing and cleared, with advice to treat the key as exposed and replace it.
- **Nmap viewer** (`#nmap`): reads Nmap XML (`-oX`, up to 20 MB) with the browser's `DOMParser`. XML that declares entities or an internal DTD subset is refused first, since real Nmap output never has them. It shows a host / port / state / service / version table, filterable by port, by service or product text, and to open ports only, with counts by service. CVE IDs in script output link to the hub's lookup. Private addresses are shown, but only public ones get a Look up link. Parsing is checked in Chrome (Node has no DOMParser); `tests/nmap.test.mjs` covers the helpers, and the fixture validates against Nmap's own DTD.

**Refreshing the Public Suffix List.** The tools use a bundled copy, `data/public_suffix_list.dat`; the version is on its line 8. Download it only from publicsuffix.org (macOS/Linux):

```sh
curl -sS -o data/public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat
```

Then check the tests still pass:

```sh
npm test
```

**Adding a brand:** edit `data/brands.json`. `label` is compared against domains, and `domains` lists the registrable domains the brand really uses. If a real brand domain gets flagged, add it there.

## AI explanations

The "Explain these results" button calls `GET /api/explain?q=`. That route reuses the cached source results and asks `openai/gpt-oss-120b` on Groq's free tier (no payment method) for a short plain-English summary. The key is the Worker secret `GROQ_API_KEY`.

- **On demand only.** Nothing is sent to Groq unless a visitor clicks the button. Groq doesn't retain API data by default, and Zero Data Retention can be enabled under Data Controls.
- **The verdict is decided in code** (`verdict()` in `worker/src/explain.js`), and the model only explains it. Left to choose, the model called github.com "Likely malicious" because URLhaus lists malware hosted there.
- **Prompt injection.** Threat feeds contain attacker-written text, so the model only sees selected structured fields, truncated. It never sees TXT records, page titles, file names or URL lists. It's told the data is untrusted, it has no tools, and its output is shown as plain text with URLs defanged.
- **Caching and limits.** Explanations are cached for 24 hours per indicator, except when a source was skipped. The Worker allows at most 20 Groq calls a minute (Groq's free limit is 30 a minute and 1,000 a day).

## Tests

Node 20 or later, no dependencies:

```sh
npm test
```

## Refreshing the threat-actor data

`data/actors.json` is built from MITRE's Enterprise ATT&CK STIX bundle. The bundle is about 55 MB and is not committed. MITRE publishes new releases roughly twice a year.

Download the bundle (macOS/Linux):

```sh
curl -sSo /tmp/enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

Then rebuild:

```sh
node scripts/build-actors.js /tmp/enterprise-attack.json
```

The script prints the group count and the per-country totals. Check them against the previous run before committing.

**How countries are assigned.** ATT&CK has no country field, so `scripts/attribution.js` reads attribution phrasing in the first sentences of each description ("assessed as Chinese state-sponsored", "China-based", "on behalf of Iran's MOIS"). Mentions of victim countries ("targeted victims in Russia, China…") and language-only hints ("Russian-speaking") are ignored. Groups MITRE doesn't attribute show as "Not attributed". The page shows MITRE's sentence as evidence next to every attribution. Parser mistakes are fixed in `scripts/attribution-overrides.json`. Each override must quote MITRE's text exactly, and the build fails if the quote isn't found.

## Layout

```
index.html, cves.html, news.html, analyze.html, actors.html, reference.html, tools.html   the pages
scripts/nav.py   rewrites the shared nav in every page (run after adding a page)
favicon.svg
css/style.css
js/detect.js     input detection (incl. CVE IDs), validation, refang/defang, hash identification; shared with the Worker
js/links.js      "open in <source>" link builders
js/md5.js        MD5 (WebCrypto has none)
js/encoding.js   Base64 / URL / hex codecs
js/pwned.js      Pwned Passwords k-anonymity check
js/lookup.js     Lookup page wiring
js/reference.js  Reference page rendering
js/actors.js     Threat actors page rendering
js/config.js     Worker URL (local or deployed)
js/results.js    result cards for Worker lookups
js/cves.js       CVEs page (keyword search)
js/news.js       News page
js/tools.js      tools glossary page (renders data/tools.json)
js/extract.js    Analyze logic (IOCs, PSL, punycode, lookalikes, URL and header parsing); DOM-free, tested in Node
js/analyze/      one module per Analyze tool (ioc.js, link.js, headers.js, jwt.js, file.js, subnet.js, cert.js, nmap.js) plus ui.js and data.js; tool modules export their pure functions for tests and only wire up the page in a browser
data/reference.json   the site directory
data/actors.json      generated threat-actor extract (do not edit by hand)
data/public_suffix_list.dat   bundled Public Suffix List (refresh steps above)
data/brands.json      brands for the lookalike check
data/tools.json       tools glossary entries { tool, whatItDoes } (maintained separately)
scripts/build-actors.js, attribution.js, attribution-overrides.json   builds data/actors.json
worker/          Cloudflare Worker: src/index.js (routing, guardrails, cache, quotas), src/sources.js (keyless sources, plan), src/keyed.js (VirusTotal, AbuseIPDB, abuse.ch), src/explain.js (AI summary and verdicts), src/cve.js (NVD, KEV, EPSS, search), src/news.js (feeds, RSS/Atom parser, cron refresh), src/http.js
tests/           node:test unit tests; tests/fixtures/ holds feed samples
```

## Security notes

- Each page sets a strict Content-Security-Policy: no inline script or style, and the only network calls allowed are same-origin, `api.pwnedpasswords.com` and the lookup Worker.
- Everything is rendered with `textContent`; no fetched or pasted string is ever parsed as HTML.
- Private, loopback, link-local, CGNAT, documentation and multicast addresses, and internal names (`.local`, `.internal`, `localhost`…), are rejected before any link or lookup is built. `js/detect.js` is written to be imported by the Worker so it enforces the same rules.
- The password is hashed in the browser, and only a 5-character SHA-1 prefix is sent, with `Add-Padding` set so the response size doesn't leak the match.
