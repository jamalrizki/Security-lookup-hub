// Phone menu. Loaded as a classic script in <head> so the "js-nav" class is set
// before the page paints (no flash of the open menu). Without JavaScript the
// class is never set and the nav simply stays visible.
document.documentElement.classList.add('js-nav');

document.addEventListener('DOMContentLoaded', () => {
  const button = document.querySelector('.nav-toggle');
  const nav = document.getElementById('site-nav');
  if (!button || !nav) return;
  button.hidden = false;

  const set = (open) => {
    nav.classList.toggle('open', open);
    button.setAttribute('aria-expanded', String(open));
  };
  button.addEventListener('click', () => set(!nav.classList.contains('open')));
  // Close after choosing a link (some only change the URL fragment), or on Escape.
  nav.addEventListener('click', (ev) => { if (ev.target.closest('a')) set(false); });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape' && nav.classList.contains('open')) {
      set(false);
      button.focus();
    }
  });
});
