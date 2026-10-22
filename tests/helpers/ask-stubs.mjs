// Offline stubs for the Ask tests: edge cache, KV, fetch routes, a scripted
// model, and Workers AI / Vectorize. No network.

export const ORIGIN = 'https://jamalrizki.github.io';

/** A Map-backed caches.default, installed globally (index.js uses it for quotas and results). */
export function installCaches() {
  const store = new Map();
  const key = (req) => (typeof req === 'string' ? req : req.url);
  globalThis.caches = {
    default: {
      async match(req) {
        return store.has(key(req)) ? new Response(store.get(key(req))) : undefined;
      },
      async put(req, res) {
        store.set(key(req), await res.text());
      },
    },
  };
  return store;
}

/** ExecutionContext whose waitUntil promises run immediately. */
export const exec = () => ({ waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } });

/** In-memory KV with the get(key, 'json') / put(key, value, opts) subset the Worker uses. */
export function memoryKv(initial = {}) {
  const map = new Map(Object.entries(initial).map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)]));
  const puts = [];
  return {
    map,
    puts,
    async get(k, type) {
      const v = map.get(k);
      if (v === undefined) return null;
      return type === 'json' ? JSON.parse(v) : v;
    },
    async put(k, v, opts) {
      puts.push({ k, v, opts });
      map.set(k, String(v));
    },
  };
}

const respond = (r) => {
  if (r instanceof Response) return r;
  if (r && r.httpStatus) return new Response(r.text ?? '', { status: r.httpStatus, headers: { 'content-type': 'application/json' } });
  return new Response(JSON.stringify(r), { status: 200, headers: { 'content-type': 'application/json' } });
};

/**
 * Replaces global fetch. routes: [[substring, handler(url, init, body)]]; the
 * first route whose substring is in the URL answers. Unmatched URLs throw.
 * Returns the call log [{ url, body }].
 */
export function installFetch(routes) {
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    let body = null;
    try { body = init.body ? JSON.parse(init.body) : null; } catch { body = init.body; }
    calls.push({ url, body });
    const route = routes.find(([sub]) => url.includes(sub));
    if (!route) throw new Error(`unexpected fetch ${url}`);
    return respond(await route[1](url, init, body));
  };
  return calls;
}

/**
 * A scripted model for the Groq route. Each step is a message object, a
 * function (body) -> message, or { httpStatus, text } for an HTTP error.
 */
export function modelScript(steps) {
  const queue = [...steps];
  const bodies = [];
  const handler = (url, init, body) => {
    bodies.push(body);
    if (!queue.length) throw new Error('model script ran out of steps');
    let step = queue.shift();
    if (typeof step === 'function') step = step(body);
    if (step.httpStatus) return step;
    return { model: body.model, choices: [{ message: step }] };
  };
  return { handler, bodies, remaining: () => queue.length };
}

let callN = 0;
export const toolCall = (...calls) => ({
  role: 'assistant',
  content: null,
  tool_calls: calls.map(([name, args]) => ({ id: `call_${++callN}`, type: 'function', function: { name, arguments: JSON.stringify(args) } })),
});
export const say = (content) => ({ role: 'assistant', content });

/** Workers AI + Vectorize stubs returning the given passages (ids like "s0a1b2c3d-12"). */
export function libraryBindings(passages) {
  return {
    AI: {
      async run(model, input) {
        if (model.includes('reranker')) return { response: input.contexts.map((c, id) => ({ id, score: 0.9 - id * 0.01 })) };
        return { data: [new Array(384).fill(0.01)] };
      },
    },
    BOOKS: {
      async query() {
        return { matches: passages.map((p, i) => ({ id: p.id, score: 0.8 - i * 0.01, metadata: { text: p.text, book_id: p.id.split('-')[0] } })) };
      },
    },
  };
}

export function askRequest(messages, { origin = ORIGIN, raw } = {}) {
  return new Request('https://security-lookup-hub.example/api/ask', {
    method: 'POST',
    headers: { origin, 'content-type': 'application/json' },
    body: raw ?? JSON.stringify({ messages }),
  });
}

// ---------- CVE fixtures (shapes follow the real APIs) ----------

export const PHP_CVE = 'CVE-2024-4577';

export const NVD_PHP = {
  totalResults: 1,
  vulnerabilities: [{
    cve: {
      id: PHP_CVE,
      published: '2024-06-09T20:15:49.300',
      lastModified: '2025-01-01T00:00:00.000',
      vulnStatus: 'Analyzed',
      descriptions: [{ lang: 'en', value: 'In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, argument injection is possible.' }],
      metrics: {
        cvssMetricV31: [{ source: 'nvd@nist.gov', type: 'Primary', cvssData: { version: '3.1', baseScore: 9.8, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', attackVector: 'NETWORK', attackComplexity: 'LOW', privilegesRequired: 'NONE', userInteraction: 'NONE', scope: 'UNCHANGED', confidentialityImpact: 'HIGH', integrityImpact: 'HIGH', availabilityImpact: 'HIGH' } }],
      },
      weaknesses: [{ source: 'nvd@nist.gov', type: 'Primary', description: [{ lang: 'en', value: 'CWE-78' }] }],
      configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', versionStartIncluding: '8.3.0', versionEndExcluding: '8.3.8' }] }] }],
      references: [
        { url: 'https://example.com/poc', tags: ['Exploit'] },
        { url: 'https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv', tags: ['Vendor Advisory'] },
      ],
    },
  }],
};

export const KEV_FILE = {
  title: 'CISA Catalog of Known Exploited Vulnerabilities',
  catalogVersion: '2026.10.20',
  dateReleased: '2026-10-20T15:00:00.0000Z',
  count: 1,
  vulnerabilities: [{
    cveID: PHP_CVE, vendorProject: 'PHP Group', product: 'PHP', vulnerabilityName: 'PHP-CGI OS Command Injection Vulnerability',
    dateAdded: '2024-06-12', shortDescription: 'x', requiredAction: 'Apply mitigations per vendor instructions.', dueDate: '2024-07-03', knownRansomwareCampaignUse: 'Known',
  }],
};

export const EPSS_PHP = { status: 'OK', total: 1, data: [{ cve: PHP_CVE, epss: '0.943580000', percentile: '0.999500000', date: '2026-10-21' }] };

/** fetch routes for NVD, KEV and EPSS answering the PHP fixtures. */
export const cveRoutes = () => [
  ['services.nvd.nist.gov', (url) => (url.includes(PHP_CVE) ? NVD_PHP : { totalResults: 0, vulnerabilities: [] })],
  ['known_exploited_vulnerabilities.json', () => KEV_FILE],
  ['api.first.org', (url) => (url.includes(PHP_CVE) ? EPSS_PHP : { status: 'OK', total: 0, data: [] })],
];

export const NEWS_SNAPSHOT = {
  updatedAt: '2026-10-22T10:00:00.000Z',
  sources: {
    thehackernews: {
      name: 'The Hacker News', filter: 'news', ok: true,
      items: [
        { source: 'thehackernews', filter: 'news', title: `Critical PHP-CGI flaw ${PHP_CVE} exploited to drop malware`, link: 'https://thehackernews.com/2026/10/php-cgi-flaw.html', date: '2026-10-22T08:00:00.000Z' },
        { source: 'thehackernews', filter: 'news', title: 'Older ransomware story', link: 'https://thehackernews.com/2026/10/old.html', date: '2026-10-01T08:00:00.000Z' },
      ],
    },
    kev: {
      name: 'CISA KEV', filter: 'kev', ok: true,
      items: [{ source: 'kev', filter: 'kev', title: 'PHP-CGI OS Command Injection Vulnerability', link: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${PHP_CVE}`, date: '2026-10-21T00:00:00.000Z', cve: PHP_CVE, vendor: 'PHP Group', product: 'PHP' }],
    },
  },
};
