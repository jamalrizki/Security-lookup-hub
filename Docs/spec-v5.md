# Security Lookup Hub v5: clearer Lookup, Check my IP, network type, provider ranges, log labels

Oct 29, 2026 · @jamal · for Claude Code

This spec changes the live Security Lookup Hub. Read `Docs/Requirements.md`, `Docs/spec-v2.md`, `Docs/spec-v3.md`, `Docs/spec-v4.md` and `README.md` first: everything in them still applies (passive lookups only, $0 beyond Ask's prepaid credit, no keys in the browser, strict CSP, `textContent` rendering, nothing about visitors stored, Origin allowlist, private targets rejected, one lookup per click). Where this spec and the earlier docs disagree, this spec wins.

**How to work: run all phases (22 → 27) in one go, without stopping between them.**
- Work on a branch `v5` (create it from `main` first; `main` already has v4: `lookup.html`, Ask home page). Build phases in order. At the end of each phase: `npm test` passes (from the repo root), the README Status table and Layout are updated, and you make **one commit for that phase** ("Phase 22: section numbers without the white edge", …). Then go straight on to the next phase.
- Don't stop to ask about choices this spec already settles. For small choices it doesn't cover, pick the simpler option, note it in the README or the commit message, and keep going.
- Never run `npx wrangler deploy`, `npx wrangler secret put` or `npx wrangler kv namespace create`. Those need Jamal. Ask Jamal before pushing to `main`; once he says to push or merge, do it.
- Checks that only work on the deployed Worker (real `request.cf` data, the visitor's real IP, live provider range files, cron CPU time) go on a list instead of blocking you. Everything else is tested offline with `fetch`, KV and `request.cf` stubbed.
- `security-books/` stays gitignored. Never run `git add -A` or `git add .`; add files by name, and run `git status --short --ignored` before every commit.
- After adding a page or editing `css/style.css`, `js/nav.js` or `js/chrome.js`: re-run `scripts/nav.py`, then `npm test`.
- Stop only if a test can't be made to pass or something in this spec turns out to be impossible as written; say which phase and why.
- **When everything is done**, finish with one message for Jamal: what was built, anything dropped or changed and why, and a single ordered list of what he needs to do. Put every prerequisite or warning **before** the step it applies to, and say which folder each command runs from.

---

## Decisions (with the why)

1. **Lookup gets type buttons above its one smart box (Oct 29, Jamal).** Buttons: `My IP · IP address · Domain · URL · Hash · Email · CVE`. Picking one changes the placeholder, shows what that type checks, and shows type-specific extras. Detection still works on whatever is pasted and switches the button to match. *Why:* today nothing on the page says what Lookup can do or which sources it checks; Jamal himself wasn't sure. Separate stacked boxes were considered and rejected: one results area, and a phone page that stays short.
2. **Check my IP is a button, not a separate page (Oct 29, Jamal).** It uses the Worker's own view of the connection (`CF-Connecting-IP` and Cloudflare's `request.cf`), so no third-party service sees the visitor. Then it runs the normal IP lookup on that address.
3. **Network type comes from published lists, decided in code.** Tor exit nodes (Tor Project's bulk exit list) and cloud/CDN ranges (AWS, Google Cloud, Cloudflare) are refreshed by the existing cron into KV. A lookup reads KV; it never fetches a list itself. VPN detection is **not** offered: it needs paid data, so the page says "can't tell" rather than guess.
4. **Provider ranges reach the browser tools as a whole downloaded list.** The subnet calculator and the IOC extractor's log mode download the compact list once (on a button click) and check IPs locally. *Why:* Analyze's rule is that nothing pasted leaves the browser; sending each IP to the Worker would break it.
5. **Section numbers lose the white edge (Oct 29, Jamal).** Only titles keep the thin white edge; the red section numbers (01, 02…) don't.
6. **Not built (Oct 29, Jamal):** bulk IP → ASN/location tables (conflicts with one-lookup-per-click; skipped). Also rejected after looking at ipin.io: HTTP/SOCKS5 proxy checkers and a domain monitor (active connections to visitor-supplied hosts, stored watchlists), random IP generator, embeddable IP badge, a single 0–100 "fraud score" (the hub's verdicts list their reasons instead).

---

## Phase 22: Section numbers without the white edge

- `css/style.css` (the rule commented "Filled red titles … get a thin white edge"): today it reads `.hero-fill, .num, .tool-letter { -webkit-text-stroke: 2px rgba(255, 255, 255, 0.9); paint-order: stroke fill; }`. Remove `.num` from it. Titles (`.hero-fill`, the Tools page `.tool-letter`) keep the edge exactly as it is today (2px stroke painted behind the fill, so about 1px shows). Update the comment so it no longer mentions section numbers.
- `.num` stays red (`var(--accent)`), same font and size, no stroke, no shadow.
- Grep for any other place the numbers get a stroke or outline (media queries, `.num::before`, inline styles in `js/chrome.js`) and remove it there too.
- Re-run `scripts/nav.py` (CSS hash), then `npm test`.
- **Check:** every page's section numbers (Lookup, Analyze, CVEs, News, Reference, Ask if it has any) are plain red; the page titles and Tools letters still have the edge. Desktop and 390px.

---

## Phase 23: Lookup type buttons

### Layout (`lookup.html`, `js/lookup.js`, `css/style.css`)

- Directly above the search box in the `#lookup` block: a row of buttons `My IP · IP address · Domain · URL · Hash · Email · CVE`. They behave as one choice (`role="radiogroup"` with `role="radio"` and `aria-checked`, arrow keys move between them; or plain buttons with `aria-pressed`, whichever is simpler with the existing code). At 390px they wrap onto two or three rows; no sideways scroll, no hidden scrolling strip. Same Red Team Brutalist styling as the existing secondary buttons; the selected one is filled red.
- Under the box, one **"Checks:"** line for the selected type, listing the sources by their display names (e.g. IP address → "AbuseIPDB, VirusTotal, URLhaus, Shodan InternetDB, network owner (RDAP), network type"). Plus one short sentence on what you get (e.g. Hash → "Tells you if a file with this hash is known malware.").
- The placeholder changes with the type (e.g. Hash → "MD5, SHA-1 or SHA-256", CVE → "CVE-2021-44228", URL → "https://example.com/login (defanged works too)").
- **Extras per type:** the DKIM selector row shows for Domain and Email only (it already appears after detection; now it also appears as soon as Domain or Email is selected). My IP has no text box (see Phase 24).
- **Default** selection on first load: IP address. No selection is stored (no `localStorage`).
- **Detection still decides.** On submit, `detect()` runs as today. If it recognises a different type than the selected button, the lookup runs anyway and the button switches to the detected type. If detection fails, the error message names the selected type ("That isn't a valid SHA-256 hash" style where `detect()` gives enough to say so; otherwise today's message).
- **Fragments:** `#q=<value>` keeps working exactly as today and selects the matching button. No new fragment for the type.
- **Hero lede:** shorten it, since the buttons now explain the types: "Pick what you have, paste it, and the hub checks it against public sources. Defanged indicators like `hxxp://bad[.]example` work too. Have a question instead? Ask it." (keep the existing Ask link).

### One list, no drift (`data/lookup-types.json`)

- One entry per button: `{ id, label, placeholder, about, sources: [<source id>…] }`. `id` matches `detect()` types (`ipv4`/`ipv6` share the `ip` button), plus `myip`.
- The Checks line is built from `sources` and the display names already in the Worker's source table (move or export the names so the page can use them without importing Worker code, e.g. a small `data/source-names.json` that `sources.js` also reads).
- **Test:** for every type, `sources` equals the ids `plan()` returns for a sample value of that type (URL: the IP-host and domain-host variants both covered). A test also checks every id has a display name. So the page can't claim a check the Worker doesn't run.

### Acceptance checks

- Each button shows its placeholder, Checks line and extras; DKIM row only for Domain/Email.
- Selecting Hash and pasting `8.8.8.8` runs an IP lookup and switches to IP address.
- `lookup.html#q=CVE-2021-44228` selects CVE and runs it, as before.
- Old `./#q=` links still forward through `js/forward.js` and select the right button.
- 390px: buttons wrap, no horizontal scroll; fields stay 16px.

---

## Phase 24: Check my IP

### Worker (`worker/src/myip.js`, route in `index.js`)

- `GET /api/my-ip`. Origin allowlist as for the other routes.
- Reads the visitor's address from the `CF-Connecting-IP` header only (never `X-Forwarded-For` or anything the visitor can set). Validates it with the shared `detect()` (IPv4 or IPv6, public).
- Returns `{ ip, version: 4|6, country, region, city, timezone, asn, asOrganization }` from `request.cf` (check each field name against Cloudflare's current `request.cf` docs and note them in the README). **Leave out latitude, longitude and postal code**: they look exact and usually aren't.
- If the address is private, loopback or missing (local `wrangler dev`), return `{ local: true }` and the page says "Running locally: your public IP can't be seen from here."
- Response headers: `Cache-Control: no-store`, and **never** put it in the edge cache or KV. Not logged.

### Page (`js/lookup.js`, `js/results.js`)

- Selecting **My IP** replaces the box with a button "Show my IP" (clicking the type button alone does not call anything).
- On click: call `/api/my-ip`, then show a **"Your connection"** card first: IP address (with a Copy button), IPv4/IPv6, network (AS number + organisation), approximate place (city, region, country), time zone. Under it, in plain words:
  - "This is the address websites see. Its location is approximate, usually the city of your provider's equipment, and often wrong for mobile and VPN connections. It is not your home address."
  - "Using a VPN? This shows the VPN's address, not yours."
  - "Your device may have both an IPv4 and an IPv6 address; this shows the one this connection used."
- Then run the normal IP lookup on that address (same as typing it): results and verdict appear below the card. Set the box/fragment to `#q=<ip>` only after the visitor clicks, so a shared link never contains someone else's IP by surprise. (Note: Analytics already excludes fragments; keep it that way.)
- Errors in plain words (network, 429, local).

### Acceptance checks

Stubbed `request.cf` and headers: a public IPv4 and an IPv6 return the fields; latitude/longitude/postal code never appear; a private or missing address returns `local: true`; `X-Forwarded-For` is ignored; the response has `no-store` and no cache write. Page: the type button alone makes no request; the button shows the card then runs the lookup.

---

## Phase 25: Network type (Tor and cloud/CDN ranges)

### Lists refreshed by the cron (`worker/src/ranges.js`, `news.js` scheduler)

Sources (confirm each URL from the provider's own documentation before building on it, and note the URLs in the README):

| id | What | Published as |
|---|---|---|
| `tor` | Tor exit nodes | Tor Project bulk exit list (plain text, one IP per line) |
| `aws` | Amazon Web Services | `ip-ranges.json` (IPv4 and IPv6 prefixes with region and service) |
| `gcp` | Google Cloud customer ranges | Google's `cloud.json` (with scope/region) |
| `cloudflare` | Cloudflare | `ips-v4` and `ips-v6` text lists |

Azure is out of scope (its download URL changes weekly); say so in the README.

- **Schedule:** add minute `7` to the cron (`crons = ["7,17,37,57 * * * *"]`). The `:07` run refreshes **one list per run**, rotating by UTC hour (`tor` every other hour since it changes fastest, the three providers in turn in between; write the exact rotation in `sourcesForRun`). *Why:* the Free plan gives scheduled jobs about 10 ms of CPU, which is why the news feeds already rotate.
- **Size and CPU:** `getJson`/fetch caps: pass a `maxBytes` large enough for each file (AWS's file is the largest; measure it and set the cap with headroom). Keep only what's needed: prefix, and for AWS region + service, for Google scope. If parsing the AWS file risks the CPU limit (measure locally with `--test-scheduled`; put the real check on the post-deploy list), extract prefixes with a streaming or regex pass instead of `JSON.parse` of the whole file.
- **Stored as** one KV key per list, `ranges:<id>:v1`: `{ fetchedAt, ok, error?, v4: [[start, end, label]…] sorted, v6: [[startHex, endHex, label]…] sorted }`, plus a small index key `ranges:meta:v1` with each list's `fetchedAt` and ok/stale. Never overwrite a good list with an empty or failed fetch (same rule as news): keep the previous copy and mark it stale.
- KV writes: about 24 more a day. Note the total in the README against the free-tier limit.

### Lookup source (`network`, in `sources.js`)

- New keyless source `network`, display name "Network type", added to the IP plan (`forIp` and the URL-with-IP-host case). It reads the four KV keys (no outbound fetch) and binary-searches the IP.
- Result: `{ tor: true|false, provider: { name, region?, service? } | null, listsUpdated: {…}, stale: [...] }`.
- **Card wording (results.js):**
  - Tor: "Tor exit node (Tor Project list)" as a warning flag.
  - Provider: "Belongs to Amazon Web Services (us-east-1, EC2)" / "Google Cloud (…)" / "Cloudflare (CDN and proxy network)". Add one plain line: "Traffic from cloud addresses usually comes from servers, scripts or VPN/proxy services, not a person at home."
  - Neither: "Not in the Tor or major cloud lists. It could still be a VPN, proxy or smaller hosting company: this check can't tell."
  - A stale list adds "List last updated N h ago".
- Keep AbuseIPDB's existing Usage and Tor rows. If AbuseIPDB and the Tor list disagree, show both as they are; don't merge them.
- **Verdict:** unchanged (the code-decided verdict doesn't use network type). Add network type to `facts()` so Explain and In plain English can mention it.
- Cache: the `network` result follows the lookup's existing cache rules; if those cache longer than 6 hours, cap this source at 6 hours.

### Download route for the browser tools

- `GET /api/ranges` returns all four lists in one compact JSON (no `meta` duplication), edge-cached 1 hour. If KV is empty (before the first cron run), `{ pending: true }`.
- It takes no parameters; nothing about the visitor is sent.

### Acceptance checks

Fixtures for each list format (including a malformed file, an HTML error page, an empty file, an IPv6-only entry); the parser rejects non-IP lines; a failed refresh keeps the old list; the rotation covers every list at least every 4 hours; binary search tests at range edges (first and last address, one outside), IPv4 and IPv6; card wording for Tor, AWS, none, stale.

---

## Phase 26: Provider ranges in the subnet calculator and log mode (browser only)

### Subnet calculator (`js/analyze/subnet.js`)

- Next to the existing "Is this IP in this range?" check, add **"Check against known provider ranges"**. First click downloads `/api/ranges` once (then kept in a JS variable for the page visit); the check runs locally with the same `inRange`/parse helpers. Output: "In Amazon Web Services (eu-west-1, S3)", "Tor exit node", or "Not in the Tor or major cloud lists". Private IPs answer "Private address: not on the internet" without downloading.
- One line under the button: "Downloads the public provider lists once; the IP you typed stays in your browser."
- The page's CSP `connect-src` must allow the Worker on `analyze.html` (check it does; add it only if missing).

### IOC extractor log mode (`js/analyze/ioc.js`, `js/extract.js`)

- **Access-log recognition:** when log mode is on and most non-empty lines match the Apache/nginx combined or common log format, parse them and add: time range covered (first → last timestamp), top HTTP status codes, top requested paths (path only, query strings dropped from the display), top user agents (each truncated to 120 characters). Counts only; everything rendered with `textContent`. If the lines don't match, log mode works as today.
- **Network labels for top IPs:** a button "Label top IPs (cloud / Tor)" downloads `/api/ranges` once and adds a label to each row of the existing Top IPs list (provider name, "Tor", or nothing). Same one-line note that IPs stay in the browser.
- Still no "look up all": each row keeps its single Look up link.

### Acceptance checks

Fixtures: a 500-line nginx log, an Apache common-format log, a mixed/unparseable log (falls back to today's behaviour), hostile user agents and paths (`<script>`, very long lines); the ranges download happens once per page visit and only after the click; no request is made before the click (test with a fetch spy).

---

## Phase 27: Docs, Requirements, tests, wrap-up

- `README.md`: Status rows for Phases 22–27; Layout (`data/lookup-types.json`, `data/source-names.json`, `worker/src/myip.js`, `worker/src/ranges.js`); new routes `/api/my-ip` and `/api/ranges` and their caching; the new cron minute and rotation; the range list URLs, sizes and KV write count; what network type can and can't tell (no VPN detection); the `request.cf` fields used; total test count.
- `Docs/Requirements.md`: add Check my IP and network type to Core features; add to Non-goals: VPN detection from paid data, bulk IP tables, proxy checkers, domain monitoring, a numeric risk score.
- `data/hub-features.json`: add `myip` → `./lookup.html` (about: "Show your own public IP and what it reveals") so Ask can point to it; keep the existing link test passing.
- Ask's `SYSTEM` prompt: no change needed beyond the new hub feature id (generated from `hub-features.json`).

---

## Post-deploy checks (for the wrap-up list)

- Lookup: each type button on desktop and iPhone; no sideways scroll at phone width; section numbers plain red, titles still edged.
- Check my IP on home Wi-Fi, on mobile data (often IPv6 or carrier NAT), and with a VPN on if available: the card fields match, and no latitude/longitude appear.
- After the first `:07` runs (about four hours for all lists), `/api/ranges` returns all four lists; look up a known AWS IP (pick one from the AWS file), a Cloudflare IP such as `1.1.1.1`, and a current Tor exit from the Tor list.
- Cron CPU: check the Worker's scheduled-run logs (`npx wrangler tail` from `worker/` during a `:07` run) for CPU-limit errors on the AWS refresh.
- Subnet calculator and log mode: the ranges download appears once in DevTools Network, only after the button click.

## Out of scope this round

Bulk IP lookups; VPN detection; Azure ranges; maps or coordinates; storing the visitor's IP; proxy checkers; domain monitoring; an MCP endpoint for the hub.
