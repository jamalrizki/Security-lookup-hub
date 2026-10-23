#!/usr/bin/env python3
"""
Scan the books folder and write a private manifest for the reference-library pipeline.

    python3 rag/build_manifest.py [--books DIR]

Run from the repo root. DIR defaults to security-books/ (gitignored: the repo is public,
so book files and everything generated from them stay out of git). Only files directly in
DIR are read (PDF, EPUB); subfolders and dot-files are ignored. Writes DIR/.rag/manifest.json
and nothing else.

For each book: an opaque id ("s" + the first 8 hex digits of the file's SHA-256, so it is
stable across runs and renames), the file name, the page count (EPUB: spine documents), and
whether it needs OCR. That is decided here, in code: a PDF whose text layer averages under
50 words a page is treated as scanned. Files that can't be read (encrypted, DRM, damaged)
are skipped and listed in the manifest's "skipped".

Needs poppler (pdfinfo, pdftotext). On a Mac: brew install poppler
"""
import argparse, hashlib, json, re, subprocess, sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OCR_WORDS_PER_PAGE = 50
# EPUB font obfuscation is not DRM; any other encryption.xml entry is.
FONT_OBFUSCATION = {"http://www.idpf.org/2008/embedding", "http://ns.adobe.com/pdf/enc#RC"}


def require_repo_root():
    if Path.cwd().resolve() != ROOT:
        sys.exit(f"Run this from the repo root ({ROOT}).")


def books_dir(arg):
    d = Path(arg).resolve() if arg else ROOT / "security-books"
    if not d.is_dir():
        sys.exit(f"No books folder at {d}. Create it and drop PDF or EPUB files in.")
    return d


def sha_id(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return "s" + h.hexdigest()[:8]


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace")


def pdf_info(path):
    """Returns (pages, needs_ocr) or raises ValueError with a reason."""
    try:
        info = run(["pdfinfo", str(path)])
    except FileNotFoundError:
        sys.exit("pdfinfo not found. Install poppler first (Mac: brew install poppler).")
    if info.returncode != 0:
        reason = (info.stderr.strip().splitlines() or ["unreadable"])[-1]
        raise ValueError("encrypted or DRM-protected" if re.search(r"password|encrypt", reason, re.I) else f"unreadable PDF ({reason[:80]})")
    m = re.search(r"^Pages:\s+(\d+)", info.stdout, re.M)
    pages = int(m.group(1)) if m else 0
    if pages <= 0:
        raise ValueError("no pages")
    text = run(["pdftotext", "-enc", "UTF-8", str(path), "-"])
    if text.returncode != 0:
        raise ValueError("encrypted or DRM-protected" if re.search(r"password|encrypt|copy", text.stderr, re.I) else "text could not be extracted")
    words = len(text.stdout.split())
    return pages, words / pages < OCR_WORDS_PER_PAGE


def epub_info(path):
    """Returns (spine documents, False) or raises ValueError."""
    try:
        z = zipfile.ZipFile(path)
        names = set(z.namelist())
        if "META-INF/encryption.xml" in names:
            algos = set(re.findall(r'Algorithm="([^"]+)"', z.read("META-INF/encryption.xml").decode("utf-8", "replace")))
            if algos - FONT_OBFUSCATION:
                raise ValueError("DRM-protected EPUB")
        opf_path = re.search(r'full-path="([^"]+)"', z.read("META-INF/container.xml").decode()).group(1)
        spine = re.findall(r'<itemref\b[^>]*\bidref="([^"]+)"', z.read(opf_path).decode("utf-8", "replace"))
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"unreadable EPUB ({type(e).__name__})")
    if not spine:
        raise ValueError("EPUB has no readable chapters")
    return len(spine), False


def main():
    require_repo_root()
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--books", help="books folder (default: security-books/)")
    args = ap.parse_args()
    books = books_dir(args.books)
    out_dir = books / ".rag"
    out_dir.mkdir(exist_ok=True)
    manifest_path = out_dir / "manifest.json"
    old = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"books": []}
    # Ids come from file contents, so they are stable; earlier entries also keep any
    # hand-set fields (e.g. "ocr_source": "raw" for a badly scanned book).
    previous = {b["id"]: b for b in old.get("books", [])}

    entries, skipped = [], []
    for path in sorted(p for p in books.iterdir() if p.is_file() and not p.name.startswith(".")):
        kind = path.suffix.lower()
        if kind not in (".pdf", ".epub"):
            continue
        try:
            pages, ocr = pdf_info(path) if kind == ".pdf" else epub_info(path)
        except ValueError as e:
            skipped.append({"file": path.name, "reason": str(e)})
            print(f"SKIPPED {path.name}: {e}")
            continue
        book_id = sha_id(path)
        entry = {**previous.get(book_id, {}), "id": book_id, "file": path.name, "format": kind[1:], "pages": pages, "ocr": ocr}
        entries.append(entry)
        print(f"{book_id}  {'OCR ' if ocr else 'text'}  {pages:>5} pages  {path.name}")

    manifest_path.write_text(json.dumps({"books": entries, "skipped": skipped}, indent=2, ensure_ascii=False) + "\n")
    print(f"{len(entries)} books, {sum(b['ocr'] for b in entries)} need OCR, {len(skipped)} skipped -> {manifest_path}")


if __name__ == "__main__":
    main()
