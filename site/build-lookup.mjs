// Builds site/lookup.html ("Look up a guard") from its one source, tools/lookup/demo.html, and copies
// the lookup library next to it so the live lookup works when site/ is served over http.
//   node site/build-lookup.mjs          (site/build.mjs also runs this at the end)
// The library, CLI and tests stay in tools/lookup/. Do not edit site/lookup.html or the copied
// site/arena-lookup.mjs and site/suites.mjs by hand: they are overwritten on every build.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { themeCss, topbar, footer, FAVICON } from "./chrome.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "..", "tools", "lookup");
const MODULES = ["arena-lookup.mjs", "suites.mjs"];

export function buildLookup() {
  let html = readFileSync(join(SRC, "demo.html"), "utf8");
  const swap = (marker, text) => {
    const n = html.split(marker).length - 1;
    if (n !== 1) throw new Error(`tools/lookup/demo.html: expected ${marker} once, found it ${n} times`);
    html = html.replace(marker, () => text);
  };
  swap('<link rel="stylesheet" href="../../site/theme.css" data-arena-theme>', `<style>\n${themeCss()}</style>`);
  // demo.html carries the tab icon as a literal (so it shows when opened from tools/lookup/ too);
  // it must be exactly chrome.mjs's FAVICON, or this stops.
  swap(FAVICON, FAVICON);
  swap("<!-- arena:topbar -->", topbar("lookup"));
  swap("<!-- arena:footer -->", footer("The live lookup reads public NEAR testnet state only. If it cannot load, the page shows a saved example and says so."));
  html = html.replace(/<!-- This file is the source of site\/lookup\.html[\s\S]*?-->\n/, "<!-- Built by site/build-lookup.mjs from tools/lookup/demo.html. Do not edit by hand. -->\n");
  writeFileSync(join(HERE, "lookup.html"), html);
  for (const m of MODULES) {
    const code = readFileSync(join(SRC, m), "utf8");
    writeFileSync(join(HERE, m), `// Copied from tools/lookup/${m} by site/build-lookup.mjs. Do not edit here.\n${code}`);
  }
  return { bytes: html.length, modules: MODULES };
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const r = buildLookup();
  console.log(`wrote site/lookup.html (${(r.bytes / 1024).toFixed(0)} KB) and copied ${r.modules.join(", ")}`);
}
