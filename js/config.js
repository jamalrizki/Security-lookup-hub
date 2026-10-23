// Where the lookup Worker lives. Pages served from localhost use `wrangler dev`.
// If you change these, update connect-src in index.html's Content-Security-Policy too.

const LOCAL = ['localhost', '127.0.0.1'].includes(location.hostname);

export const API_BASE = LOCAL
  ? 'http://127.0.0.1:8787'
  : 'https://security-lookup-hub.jamal-598.workers.dev';
