// Old Lookup links. Lookup moved from the home page to lookup.html in v4, but
// bookmarks and shared links still say ./#q=8.8.8.8, ./#password or ./#lookup.
// Loaded as a classic script at the top of index.html's <head>, so the page
// moves on before anything paints. The fragment only ever goes to lookup.html.
(function () {
  var hash = location.hash;
  if (hash.indexOf('#q=') === 0 || hash === '#password' || hash === '#lookup') {
    location.replace('./lookup.html' + hash);
  }
})();
