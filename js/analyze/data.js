// Loads the Public Suffix List and brand list once, at page load, so the tools
// keep working if the connection drops afterwards.

import { parsePsl } from '../extract.js';

export const ready = (async () => {
  const [pslText, brandData] = await Promise.all([
    fetch('data/public_suffix_list.dat').then((r) => (r.ok ? r.text() : Promise.reject(new Error(`PSL HTTP ${r.status}`)))),
    fetch('data/brands.json').then((r) => (r.ok ? r.json() : Promise.reject(new Error(`brands HTTP ${r.status}`)))),
  ]);
  return { psl: parsePsl(pslText), brands: brandData.brands };
})();
