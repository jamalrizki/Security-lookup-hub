Security Lookup Hub: requirements
Oct 8, 2026 · @jamal
Overview
Security Lookup Hub is a free, standalone web app: one search box where you paste a file hash, a domain, an IP address or a password, and get a plain-English verdict pulled from several public threat-intelligence sources at once. It also has a threat-actor browser (for example, Chinese state-linked APT groups and their known techniques) and a reference page linking to the best free security sites for digging further.
It is for analysts, students and anyone who remembers that "there was a site for that" but not which one. The working name is a placeholder.
This is a separate app with its own repo. It is not part of the AI MCP build project and does not need to use AI or MCP, though it can add them later (see Architecture).
Goals and non-goals
The app must be a one-stop lookup page that costs $0 to run and never actively touches the systems it reports on.
Goals
• One search box that detects what was pasted (hash, domain, IP, URL, email or password) and runs the right lookups.
• Results from several sources side by side, each with a link to view the full report on that source's own site.
• A threat-actor browser covering APT groups, filterable by country (for example China, Russia, Iran, North Korea).
• A reference directory page listing the free security sites in this document, grouped by what they do.
• $0 running cost, using free tiers only, with no payment card on any account (Cloudflare stays on the Free plan), so going over a limit can only pause a source, never charge you.
• API keys never in the browser or the repo.
Non-goals
• No active scanning (port scans, vulnerability scans, crawling). Passive lookups of public data only.
• No user accounts, saved history or stored lookups.
• Not tied to the Claude exam or the MCP build. AI and MCP are optional extras, not requirements.
• Not a replacement for a SOC tool or a sandbox. It points to deeper tools; it does not detonate files.
• No website security-header checker: the Worker would fetch arbitrary user-supplied sites (active, and an SSRF surface). (Added in v2.)
• No WiGLE lookup: locating people's Wi-Fi networks is a privacy and stalking risk. (Added in v2.)
• No password generator or text diff (low value here), and no running or connecting offensive tools. (Added in v2.)
• No chat or MCP endpoint in the hub; CVE Explainer stays a separate app. (Added in v2.)
Core features
The app has three pages: Lookup (the search box), Threat actors, and Reference. Version 2 (Docs/spec-v2.md) adds CVEs, News and Analyze, and a security tools guide linked from Reference.
1. Lookup: one box, type detected automatically
The input type is detected in code (regex and length), then only the matching lookups run. Each result card shows the verdict, the key numbers, and a "view full report" link to the source.
You paste
Detected as
What you get back
32, 40 or 64 hex characters
MD5, SHA-1 or SHA-256 hash
Hash type; known-malware verdict and family name; antivirus detection count; first-seen date
example.com
Domain
Registration date and registrar (new domains are a phishing signal); DNS records; SPF and DMARC present or missing; certificates issued (reveals subdomains); reputation verdict
203.0.113.7
IPv4 or IPv6 address
Abuse reports and confidence score; owner and network (ASN); country; open ports and known CVEs from passive data; whether it is mass-scanning noise
https://…
URL
Known-malicious URL verdict; reputation
name@example.com
Email
Link out to Have I Been Pwned (the email search API is paid; see Data sources)
Any other text, via a separate "Check a password" field
Password
How many times it appears in known breaches, checked without the password leaving the browser
Extra tools on the same page, done entirely in the browser with no API:
• Hash identifier: guesses the hash type from length and format, including bcrypt ($2b$…) and NTLM.
• Hash calculator: type text and get its MD5, SHA-1 and SHA-256.
• Decoder: Base64, URL encoding and hex, both directions. A small slice of CyberChef.
2. Threat actors
A searchable list of APT groups from MITRE ATT&CK, filterable by country of attribution, with aliases (for example APT41 / Double Dragon / Wicked Panda), targeted sectors, and their known techniques linked to the ATT&CK site. Data is a static file refreshed from MITRE's published JSON, so it needs no API.
3. Reference
The directory in the next section, rendered as a page: every site grouped by job, with one line on what it does, whether it needs an account, and a link.
4. CVEs (v2)
A CVE ID pasted into Lookup is detected like a hash or IP, and the Worker calls NVD, CISA KEV and FIRST EPSS directly; a rule-of-thumb patching priority is decided in code. The CVEs page searches NVD by product or keyword and shows the 10 newest matches.
5. News (v2)
Headlines from CISA KEV, CISA advisories and BleepingComputer, refreshed hourly by a scheduled Worker job into Workers KV, so visitors never cause feed fetches. Headline, publisher, date and link only; CISA items may show a short summary.
6. Analyze (v2)
Paste/drop tools that run entirely in the browser: IOC extractor, suspicious-link inspector with lookalike detection, email-header analyzer, JWT decoder, file analyzer, subnet calculator, certificate viewer and Nmap viewer. Nothing pasted is sent anywhere; only an explicit "Look up" click on one extracted indicator calls the Worker.
Reference directory
These are the sites the Reference page lists, grouped by job. "Account" means a free sign-up is needed to use the site or its API. Sites marked with ★ also feed the Lookup page.
Files, hashes and malware
Site
What it does
Account
VirusTotal ★
Checks a hash, file, URL, domain or IP against ~70 antivirus engines and reputation feeds
For API
MalwareBazaar ★
Database of known malware samples, searchable by hash, family or tag
For API
URLhaus ★
Database of URLs known to distribute malware
For API
ThreatFox
Indicators of compromise (IPs, domains, hashes) tied to malware families
For API
Hybrid Analysis
Free sandbox: runs a file and reports what it did
Yes
ANY.RUN
Interactive sandbox you watch live
Yes
CyberChef
"Cyber Swiss Army knife": encode, decode, hash, decrypt and parse data in the browser
No
hashes.com hash identifier
Identifies a hash type from its format
No
Domains, DNS and certificates
Site
What it does
Account
ICANN Lookup ★
Official domain registration lookup (RDAP, the successor to WHOIS)
No
crt.sh ★
Certificate transparency search: every certificate issued for a domain, which reveals subdomains
No
MXToolbox
DNS, MX, SPF, DMARC and blocklist checks
No
DNSDumpster
Maps a domain's DNS records and hosts
No
SecurityTrails
Historical DNS and WHOIS records
Yes
urlscan.io
Loads a URL in a sandbox browser and shows screenshots, requests and verdict
For API
Google Safe Browsing site status
Whether Google flags a site as unsafe
No
SSL Labs
Grades a site's TLS configuration
No
securityheaders.com
Grades a site's HTTP security headers
No
IP addresses and exposure
Site
What it does
Account
AbuseIPDB ★
Community abuse reports for an IP, with a confidence score
For API
GreyNoise ★
Whether an IP is internet-wide scanning "noise" or something targeted
For API
Shodan ★
Search engine for internet-connected devices: open ports, banners, known CVEs
Yes
Censys
Shodan alternative focused on hosts and certificates
Yes
AlienVault OTX
Open threat exchange: community "pulses" of indicators
For API
IPinfo
IP owner, network (ASN) and location
For API
Breaches and passwords
Site
What it does
Account
Have I Been Pwned ★
Whether an email appeared in a data breach; Pwned Passwords checks a password safely
Email API is paid
Have I Been Pwned: Passwords ★
Checks a password against breached-password lists without sending it
No
Threat actors and attacker techniques
Site
What it does
Account
MITRE ATT&CK Groups ★
Profiles of APT groups (including Chinese, Russian, Iranian and North Korean groups) and the techniques they use
No
MITRE ATT&CK Navigator
Heat-map of techniques for a group or for your defenses
No
Malpedia
Encyclopedia of malware families and the actors behind them
No
CISA advisories
US government advisories, including joint ones on state-sponsored actors
No
ETDA Threat Group Cards
Cross-reference of APT group names across vendors
No
Vulnerabilities and exploits
Site
What it does
Account
NVD
US National Vulnerability Database: CVE details and CVSS scores
No
CISA KEV
CVEs confirmed exploited in the wild
No
FIRST EPSS
Probability a CVE will be exploited in the next 30 days
No
OSV.dev
Known vulnerabilities by open-source package and version
No
Exploit-DB
Archive of public exploits (the source of searchsploit)
No
CVE Explainer
Plain-English CVE summaries (your own app)
No
Learning and practice
Site
What it does
Account
TryHackMe
Guided hands-on security labs
Yes
Hack The Box
Practice machines and challenges
Yes
OverTheWire
Classic command-line wargames
No
GTFOBins
Unix binaries that can be abused to bypass restrictions (privilege escalation reference)
No
LOLBAS
The Windows equivalent of GTFOBins
No
Data sources and API notes
Every Lookup source below has a free option, but four of them need a free account key, and most free terms forbid commercial use. That suits a personal, non-commercial app; it rules out ever charging for it.
Source
Used for
Key
Free limit
Checked
VirusTotal
Hash, domain, IP, URL reputation
Free account
4 requests/minute, 500/day; no commercial use
Yes
AbuseIPDB
IP abuse reports and score
Free account
1,000 requests/day (shared with reports), resets 00:00 UTC
Yes
Shodan InternetDB
Open ports, hostnames, known CVEs for an IP
None
No limit stated; non-commercial only
Yes
HIBP Pwned Passwords
Password breach count
None
No rate limit
Yes
HIBP breached account (email)
Email in breaches
Paid subscription
Not free, so the app links out instead
Yes
HIBP list of breaches
Recent breaches feed for the Reference page
None (appears free)
Not stated
Partly
MalwareBazaar
Hash → known malware family
Free abuse.ch account (Auth-Key header)
Per key; non-commercial
Yes
URLhaus, ThreatFox
Known-bad URLs and indicators
Same abuse.ch key, assumed
Not yet checked
No
GreyNoise Community
Is an IP scanning noise
Optional
10 lookups/day without a key; a free key (50/week) needs a business email, not Gmail
Yes
RDAP via rdap.org
Domain registration date and registrar
None
Not yet checked
No
Cloudflare DNS over HTTPS
A, MX, TXT, NS records; SPF and DMARC
None
Not yet checked
No
crt.sh
Certificates and subdomains
None
Often slow or down; needs a timeout
No
MITRE ATT&CK STIX data (GitHub)
Threat-actor page
None
Static file, refreshed occasionally
No
Two consequences shape the build:
• GreyNoise is close to useless on the free tier (10 lookups a day for the whole site), so it should be a link on the result card, not an automatic lookup.
• VirusTotal's 4 requests a minute is the tightest limit. Results should be cached in the Worker (for example for 24 hours per hash, domain or IP) and the page should say when a source was skipped because of rate limits.
Architecture and stack
It uses the same $0 stack as your other two apps: a static site on GitHub Pages and one Cloudflare Worker. No language model is needed for the core app.
The page sends every lookup to the Worker, which checks and caches it before calling the outside sources. The password check is the exception: it goes straight from the browser to Have I Been Pwned, and only a 5-character hash prefix leaves the page.
• Frontend: plain HTML, CSS and JavaScript, three pages. The ATT&CK data and the reference list are static JSON files in the repo.
• Backend: one Worker with a /api/lookup route that fans out to the sources in parallel and returns one combined result. Keys are Worker secrets.
• Cache: Cloudflare's free cache or KV store, keyed by indicator.
• Optional later: an "explain this result" button on Groq's free tier, and an /mcp route exposing the same lookups as tools. The lookup functions should be written once so both can reuse them.
Safety and abuse guardrails
The Worker is a public proxy holding several API keys, so its main risks are someone draining those keys or using it to reach places it shouldn't.
• Passive lookups only. The Worker never connects to the domain or IP being looked up. It only asks third-party databases about it.
• Validate input in code before any request. Strict patterns for hashes, domains and IPs. Reject private, loopback and reserved addresses (10.x, 192.168.x, 127.x, 169.254.x, ::1) and names like localhost, so the Worker can't be pointed at internal targets.
• Passwords never leave the browser. The page hashes the password with SHA-1 and sends only the first 5 characters to Pwned Passwords (k-anonymity). The Worker never sees it.
• Rate limit the Worker itself. A per-visitor limit (for example 20 lookups an hour) and an Origin allowlist, so one person or script can't burn the free quotas for everyone.
• Cache results per indicator to save quota and speed up repeat lookups.
• Keys as Worker secrets only, never in the page or the repo.
• Store nothing about visitors. No lookup history, no logs of what was searched beyond what Cloudflare keeps by default.
• Render source data as text, not HTML. Threat feeds contain attacker-controlled strings (malware names, URLs), which could carry script injection.
• Defang dangerous links. Show malicious URLs as hxxp://bad[.]example so nobody clicks them by accident.
• Respect each source's terms: credit the source on every result card and link to its full report.
Build phases and open questions
Build it in five small phases, each usable on its own, starting with the parts that need no keys.
1. Reference page and browser-only tools. The directory, hash identifier, hash calculator, decoder and password check. Pure static site, no Worker, no keys.
2. Threat actors page. Convert MITRE's ATT&CK data to a small JSON file with a script, then build the searchable list. Still no Worker.
3. Worker plus keyless lookups. Domain (RDAP, DNS, crt.sh) and IP (Shodan InternetDB). Input validation, caching and the per-visitor limit go in here.
4. Keyed lookups. VirusTotal, AbuseIPDB and MalwareBazaar, after signing up for the three free accounts and setting their keys as Worker secrets.
5. Polish and deploy. Auto-detecting search box, result cards, defanging, mobile layout, README.
Later, optionally: an AI "explain this result" button, and the same lookups exposed as MCP tools so Claude or the CVE Explainer could call them.
Open questions
[ ] App name and repo name ("Security Lookup Hub" is a placeholder).
[ ] Is the Lookup page public? Decided: yes, with a per-visitor limit. When a free quota runs out, that source pauses until it resets; nothing is billed.
[ ] Confirm the limits marked "not yet checked" before phase 3.
[ ] Which threat-actor countries to feature by default (all, or China first)?