// Google Analytics 4. This is Google's inline gtag snippet moved into a file,
// because the site's CSP doesn't allow inline scripts. The loader itself is the
// <script async src="https://www.googletagmanager.com/gtag/js?id=..."> in each page.
window.dataLayer = window.dataLayer || [];
function gtag() { dataLayer.push(arguments); }
gtag('js', new Date());
// Report the page without its URL fragment: Lookup keeps the searched indicator
// (which can be an email address) in #q=, and that must not reach analytics.
gtag('config', 'G-26NLWZWCNN', { page_location: location.origin + location.pathname + location.search });
