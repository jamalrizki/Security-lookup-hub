"""Keeps the shared page chrome identical across pages.

Run from the repo root after adding a page, or after changing css/style.css,
js/nav.js or js/chrome.js:  python3 scripts/nav.py

For every page it (re)writes:
  - the decorative layers: binary rain, terminal bar, hex ticker (aria-hidden;
    their contents are drawn by js/chrome.js)
  - the header: brand, phone menu button, main nav
  - the hero: giant outlined title (the nav label), the page's intro
    paragraph (kept as is), and the radar with "MODULE 0N/07"
  - script/stylesheet tags with a content hash (?v=...), so browsers never
    pair a new page with an old cached file (tests/assets.test.mjs checks it)
"""
import hashlib, pathlib, re

NAV = [
    ('./', 'index.html', 'Lookup', 'lookup'),
    ('analyze.html', 'analyze.html', 'Analyze', 'analyze'),
    ('cves.html', 'cves.html', 'CVEs', 'cves'),
    ('news.html', 'news.html', 'News', 'news'),
    ('actors.html', 'actors.html', 'Threat actors', 'actors'),
    ('reference.html', 'reference.html', 'Reference', 'reference'),
    ('tools.html', 'tools.html', 'Tools', 'tools'),
]
PAGES = [file for _, file, _, _ in NAV]

root = pathlib.Path(__file__).resolve().parent.parent
ASSETS = ['css/style.css', 'js/nav.js', 'js/chrome.js']
VERSIONS = {a: hashlib.sha256((root / a).read_bytes()).hexdigest()[:10] for a in ASSETS}

CHROME = '''  <div class="rain" aria-hidden="true"></div>
  <div class="term" aria-hidden="true">
    <span class="term-prompt">root@slh:~/{key}#</span>
    <span class="term-line"><span class="term-cmd"></span><span class="term-cursor"></span></span>
    <span class="term-out"></span>
    <span class="term-pid">PID 0000 &middot; tty/0</span>
  </div>
'''

HEADER = '''  <header class="site-header">
    <div class="inner">
      <a class="brand" href="./" aria-label="Security Lookup Hub, home"><span class="brand-dot" aria-hidden="true"></span>SECURITY_LOOKUP_HUB</a>
      <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="site-nav" hidden>
        <span class="when-closed">&#9776; MENU</span><span class="when-open">&#10005; CLOSE</span>
      </button>
      <nav class="site-nav" id="site-nav" aria-label="Main">
{links}
      </nav>
    </div>
  </header>
  <div class="ticker" aria-hidden="true"><span class="ticker-track"></span></div>
'''

HERO = '''    <section class="hero">
      <div class="hero-text">
        <h1 class="hero-title"><span class="hero-outline">{title}</span><span class="hero-fill" aria-hidden="true">{title}</span></h1>
        <p class="lede">{lede}</p>
      </div>
      <div class="radar-block" aria-hidden="true">
        <div class="radar"><span class="radar-sweep"></span><span class="radar-ring"></span><span class="radar-blip"></span><span class="radar-dot"></span></div>
        <p class="radar-caption">MODULE {num:02d}/{total:02d}<br>STATUS: ARMED</p>
      </div>
    </section>
'''

existing = [p for p in PAGES if (root / p).exists()]
for page in existing:
    path = root / page
    html = path.read_text()
    i = PAGES.index(page)
    _, _, title, key = NAV[i]

    # Body: page key for js/chrome.js.
    html = re.sub(r'<body[^>]*>', f'<body data-page="{key}">', html, count=1)

    # Decorative layers right after the skip link (replaced if already there).
    html = re.sub(r'  <div class="rain".*?</div>\n  <div class="term".*?\n  </div>\n', '', html, flags=re.S)
    html = re.sub(r'(<a class="skip"[^>]*>[^<]*</a>\n)', lambda m: m.group(1) + CHROME.format(key=key), html, count=1)

    # Header + ticker.
    links = []
    for href, file, label, _ in NAV:
        if file not in existing:
            continue
        attr = ' aria-current="page"' if file == page else ''
        links.append(f'        <a href="{href}"{attr}>{label}</a>')
    header = HEADER.format(links='\n'.join(links))
    html, n = re.subn(r'  <header class="site-header">.*?</header>\n(  <div class="ticker".*?</div>\n)?', lambda m: header, html, count=1, flags=re.S)
    assert n == 1, f'{page}: no header'

    # Hero: keep the existing intro paragraph, replace the title block.
    hero = re.search(r'    <section class="hero">.*?\n    </section>\n', html, re.S)
    if hero:
        lede = re.search(r'<p class="lede">(.*?)</p>', hero.group(0), re.S).group(1)
        span = hero.span()
    else:
        m = re.search(r'(    <p class="hint"><a href="reference.html">[^\n]*\n)?    <h1>.*?</h1>\n    <p class="lede">(.*?)</p>\n', html, re.S)
        assert m, f'{page}: no h1 + lede'
        lede, span = m.group(2), m.span()
    html = html[:span[0]] + HERO.format(title=title, lede=lede, num=i + 1, total=len(NAV)) + html[span[1]:]

    # Scripts and stylesheet, with cache-busting versions.
    if 'src="js/nav.js' not in html:
        html = html.replace('  <link rel="stylesheet" href="css/style.css', '  <script src="js/nav.js"></script>\n  <link rel="stylesheet" href="css/style.css', 1)
    if 'src="js/chrome.js' not in html:
        html = html.replace('  <link rel="stylesheet" href="css/style.css', '  <script type="module" src="js/chrome.js"></script>\n  <link rel="stylesheet" href="css/style.css', 1)
    for asset in ASSETS:
        html = re.sub(rf'(["\']){re.escape(asset)}(\?v=[0-9a-f]+)?(["\'])', rf'\g<1>{asset}?v={VERSIONS[asset]}\g<3>', html)

    path.write_text(html)
    print('layout updated:', page)
