"""Rewrites the main nav in every page so it stays identical across pages.

Run from the repo root after adding a page:  python3 scripts/nav.py
"""
import pathlib, re

NAV = [
    ('./', 'index.html', 'Lookup'),
    ('cves.html', 'cves.html', 'CVEs'),
    ('news.html', 'news.html', 'News'),
    ('analyze.html', 'analyze.html', 'Analyze'),
    ('actors.html', 'actors.html', 'Threat actors'),
    ('reference.html', 'reference.html', 'Reference'),
]
PAGES = ['index.html', 'cves.html', 'news.html', 'analyze.html', 'actors.html', 'reference.html', 'tools.html']
# tools.html is reached from Reference, so it highlights Reference.
CURRENT = {'tools.html': 'reference.html'}

root = pathlib.Path(__file__).resolve().parent.parent
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
    nav = '<nav class="site-nav" aria-label="Main">\n' + '\n'.join(links) + '\n      </nav>'
    new, n = re.subn(r'<nav class="site-nav" aria-label="Main">.*?</nav>', nav, html, flags=re.S)
    assert n == 1, page
    path.write_text(new)
    print('nav updated:', page)
