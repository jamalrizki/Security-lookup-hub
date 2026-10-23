#!/usr/bin/env bash
# OCR the scanned books in the manifest ("ocr": true), one text file per page:
#   <books>/.rag/ocr/<id>/page-0001.txt ...
# Run from the repo root:  bash rag/ocr_books.sh [book-id ...]
# Books folder: security-books/ (gitignored), or set BOOKS_DIR. Run rag/build_manifest.py first.
# Needs poppler (pdfinfo, pdftoppm) and tesseract. On a Mac: brew install poppler tesseract
# Resumable: pages that already have a .txt are skipped, so it can be stopped and restarted.
# FORCE=1 re-OCRs pages that already have text (e.g. after setting a book's "ocr_source": "raw").
# Ported from Jaizz Chat (jazz-fact-chat/rag/ocr_books.sh).
set -euo pipefail
JOBS="${JOBS:-4}"     # parallel pages
DPI="${DPI:-300}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$(pwd -P)" != "$(cd "$ROOT" && pwd -P)" ]; then
  echo "Run this from the repo root ($ROOT)." >&2; exit 1
fi
BOOKS="${BOOKS_DIR:-$ROOT/security-books}"
MANIFEST="$BOOKS/.rag/manifest.json"
[ -f "$MANIFEST" ] || { echo "No manifest at $MANIFEST. Run: python3 rag/build_manifest.py" >&2; exit 1; }
for tool in pdfinfo pdftoppm tesseract; do
  command -v "$tool" >/dev/null || { echo "$tool not found. Mac: brew install poppler tesseract" >&2; exit 1; }
done
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ocr.XXXXXX")"   # page images live outside the repo
trap 'rm -rf "$TMP"' EXIT
trap 'exit 143' TERM INT   # still runs the EXIT cleanup when stopped
# One tesseract thread per page: several multi-threaded runs at once fight over the CPU.
export OMP_THREAD_LIMIT=1

ocr_page() {  # pdf page outdir tmp dpi source
  local pdf="$1" n="$2" out="$3" tmp="$4" dpi="$5" source="${6:-render}" name img
  name=$(printf "page-%04d" "$n")
  # FORCE re-does a page unless its text is newer than the FORCE start marker (so a forced run can resume)
  if [ -s "$out/$name.txt" ]; then
    [ -z "${FORCE:-}" ] && return 0
    [ "$out/$name.txt" -nt "$out/.force-start" ] && return 0
  fi
  if [ "$source" = raw ]; then
    # Some scans are 8-bit JPEGs mislabelled as 1-bit; renderers then draw noise. Pull the
    # embedded image out as-is and upscale it 2.5x (low-res scans OCR better).
    pdfimages -f "$n" -l "$n" -j "$pdf" "$tmp/$name" >/dev/null 2>&1
    img=$(ls -S "$tmp/$name"* 2>/dev/null | head -1)
    if [ -n "$img" ] && python3 -c "import PIL" 2>/dev/null; then
      python3 -c "import sys; from PIL import Image; im=Image.open(sys.argv[1]).convert('L'); im.resize((im.width*5//2, im.height*5//2), Image.LANCZOS).save(sys.argv[2])" "$img" "$tmp/$name-up.png" && rm -f "$img" && img="$tmp/$name-up.png"
    fi
  else
    pdftoppm -f "$n" -l "$n" -r "$dpi" -gray -png "$pdf" "$tmp/$name" >/dev/null 2>&1
    img=$(ls "$tmp/$name"*.png 2>/dev/null | head -1)
  fi
  [ -n "$img" ] || { : > "$out/$name.txt"; return 0; }
  # Cap each page: figure-heavy pages can make tesseract grind for minutes. A capped page is
  # saved empty (and logged).
  if ! $TIMEOUT tesseract "$img" "$out/$name.part" -l eng --psm 3 >/dev/null 2>&1; then
    : > "$out/$name.part.txt"; echo "  $(basename "$out") page $n: OCR skipped (timeout or error)" >&2
  fi
  mv "$out/$name.part.txt" "$out/$name.txt"
  rm -f "$tmp/$name"*
}
# GNU timeout is "timeout" on Linux and "gtimeout" on a Mac with coreutils; without either, no cap.
if command -v timeout >/dev/null; then TIMEOUT="timeout ${PAGE_TIMEOUT:-60}"
elif command -v gtimeout >/dev/null; then TIMEOUT="gtimeout ${PAGE_TIMEOUT:-60}"
else TIMEOUT=""; fi
export TIMEOUT
export -f ocr_page

python3 - "$MANIFEST" "$@" > "$TMP/list" <<'PY'
import json, sys
want = set(sys.argv[2:])
for b in json.load(open(sys.argv[1]))["books"]:
    if b.get("ocr") and (not want or b["id"] in want): print(b["id"] + "\t" + b["file"] + "\t" + b.get("ocr_source", "render"))
PY

while IFS=$'\t' read -r id file source; do
  pdf="$BOOKS/$file"
  out="$BOOKS/.rag/ocr/$id"; mkdir -p "$out"
  [ -n "${FORCE:-}" ] && [ ! -e "$out/.force-start" ] && touch "$out/.force-start"
  pages=$(pdfinfo "$pdf" 2>/dev/null | awk '/^Pages:/{print $2}')
  echo "$(date +%H:%M:%S) $id: $pages pages"
  seq 1 "$pages" | xargs -P "$JOBS" -I{} bash -c 'ocr_page "$@"' _ "$pdf" {} "$out" "$TMP" "$DPI" "$source"
  echo "$(date +%H:%M:%S) $id: done ($(ls "$out" | grep -c '^page-.*\.txt$') page files)"
done < "$TMP/list"
