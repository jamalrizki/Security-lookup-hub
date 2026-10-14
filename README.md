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
index.html, actors.html, reference.html   the three pages
favicon.svg
css/style.css
js/detect.js     input detection, validation, refang/defang, hash identification (shared with the Worker later)
js/links.js      "open in <source>" link builders
js/md5.js        MD5 (WebCrypto has none)
js/encoding.js   Base64 / URL / hex codecs
js/pwned.js      Pwned Passwords k-anonymity check
js/lookup.js     Lookup page wiring
js/reference.js  Reference page rendering
js/actors.js     Threat actors page rendering
js/config.js     Worker URL (local or deployed)
js/results.js    result cards for Worker lookups
data/reference.json   the site directory
data/actors.json      generated threat-actor extract (do not edit by hand)
scripts/build-actors.js, attribution.js, attribution-overrides.json   builds data/actors.json
worker/          Cloudflare Worker: src/index.js (routing, guardrails, cache, quotas), src/sources.js (keyless sources, plan), src/keyed.js (VirusTotal, AbuseIPDB, abuse.ch), src/http.js
tests/           node:test unit tests
```

## Security notes

- Each page sets a strict Content-Security-Policy: no inline script or style, and the only network calls allowed are same-origin, `api.pwnedpasswords.com` and the lookup Worker.
- Everything is rendered with `textContent`; no fetched or pasted string is ever parsed as HTML.
- Private, loopback, link-local, CGNAT, documentation and multicast addresses, and internal names (`.local`, `.internal`, `localhost`…), are rejected before any link or lookup is built. `js/detect.js` is written to be imported by the Worker so it enforces the same rules.
- The password is hashed in the browser, and only a 5-character SHA-1 prefix is sent, with `Add-Padding` set so the response size doesn't leak the match.
