// The repo is public: nothing under security-books/ (or any PDF/EPUB) may ever be tracked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

function git(args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

let hasGit = true;
try { git(['rev-parse', '--git-dir']); } catch { hasGit = false; }

test('nothing under security-books/ is tracked', { skip: !hasGit && 'git not available' }, () => {
  assert.equal(git(['ls-files', 'security-books']).trim(), '');
});

test('no PDF or EPUB is tracked anywhere', { skip: !hasGit && 'git not available' }, () => {
  assert.equal(git(['ls-files', '*.pdf', '*.epub']).trim(), '');
});

test('security-books/ is gitignored', { skip: !hasGit && 'git not available' }, () => {
  // check-ignore exits 0 when the path is ignored and throws otherwise
  git(['check-ignore', '-q', 'security-books/x.pdf']);
  git(['check-ignore', '-q', 'security-books/.rag/chunks.jsonl']);
});
