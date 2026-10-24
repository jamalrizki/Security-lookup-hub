// "Already happened? What to do now" (Reference page): helpers with no DOM code,
// so tests can import them. The checklists themselves are data/what-now.json.

// Official guidance may only link to these hosts, over https.
export const GUIDANCE_HOSTS = ['consumer.ftc.gov', 'reportfraud.ftc.gov', 'www.identitytheft.gov', 'www.ncsc.gov.uk', 'www.cisa.gov'];

/** The URL as a safe link target, or null if it isn't https on an allowed host. */
export function guidanceUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && GUIDANCE_HOSTS.includes(u.hostname) && !u.username && !u.password && !u.port ? u.href : null;
  } catch {
    return null;
  }
}

/** Hub links must be relative links to this site's own pages (./, ./page.html, optional #anchor). */
export const isHubHref = (href) => typeof href === 'string' && /^\.\/(?:[a-z-]+\.html)?(?:#[a-z-]+)?$/.test(href);
