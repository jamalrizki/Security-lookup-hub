"""Rewrites the main nav in every page so it stays identical across pages.

Run from the repo root after adding a page or changing css/style.css or
js/nav.js (it also stamps their content hash into every page):  python3 scripts/nav.py
"""
import hashlib, pathlib, re

NAV = [
    ('./', 'index.html', 'Lookup'),
    ('analyze.html', 'analyze.html', 'Analyze'),
    ('cves.html', 'cves.html', 'CVEs'),
    ('news.html', 'news.html', 'News'),
    ('actors.html', 'actors.html', 'Threat actors'),
    ('reference.html', 'reference.html', 'Reference'),
    ('tools.html', 'tools.html', 'Tools'),
]
PAGES = ['index.html', 'cves.html', 'news.html', 'analyze.html', 'actors.html', 'reference.html', 'tools.html']
CURRENT = {}  # page -> nav entry to highlight, for pages not in the nav

TOGGLE = (
    '      <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="site-nav" hidden>\n'
    '        <span class="nav-toggle-bars" aria-hidden="true"></span>\n'
    '        <span class="visually-hidden">Menu</span>\n'
    '      </button>\n'
)

root = pathlib.Path(__file__).resolve().parent.parent
ASSETS = ['css/style.css', 'js/nav.js']
VERSIONS = {a: hashlib.sha256((root / a).read_bytes()).hexdigest()[:10] for a in ASSETS}
existing = {p for p in PAGES if (root / p).exists()}
for page in sorted(existing):
    path = root / page
    html = path.read_text()
    current = CURRENT.get(page, page)
    links = []
    for href, file, label in NAV:
        if file not in existing:
            continue  # only link pages that exist yet
        attr = ' aria-current="page"' if file == current else ''
        links.append(f'        <a href="{href}"{attr}>{label}</a>')
    nav = '<nav class="site-nav" id="site-nav" aria-label="Main">\n' + '\n'.join(links) + '\n      </nav>'
    new, n = re.subn(r'<nav class="site-nav"[^>]*>.*?</nav>', nav, html, flags=re.S)
    assert n == 1, page
    # Phone menu button (shown by js/nav.js on narrow screens) and its script.
    if 'class="nav-toggle"' not in new:
        new = new.replace('      <nav class="site-nav"', TOGGLE + '      <nav class="site-nav"', 1)
    if 'src="js/nav.js' not in new:
        new = new.replace('  <link rel="stylesheet" href="css/style.css', '  <script src="js/nav.js"></script>\n  <link rel="stylesheet" href="css/style.css', 1)
    # Cache-busting: GitHub Pages lets browsers keep files for 10 minutes, so a
    # fresh page could pair with an old cached stylesheet. A content hash in the
    # URL changes whenever the file does.
    for asset in ASSETS:
        new = re.sub(rf'(["\']){re.escape(asset)}(\?v=[0-9a-f]+)?(["\'])', rf'\g<1>{asset}?v={VERSIONS[asset]}\g<3>', new)
    path.write_text(new)
    print('nav updated:', page)
