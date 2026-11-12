// The shared parts of every Arena page, for the Node builders (site/build.mjs, site/build-lookup.mjs).
// The look lives in site/theme.css, the links and the footer line in site/nav.json.
// tools/hunter/board.py reads the same two files and renders the same markup in Python.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export const NAV = JSON.parse(readFileSync(join(HERE, "nav.json"), "utf8"));

/** theme.css, checked so it is safe to put inside a <style> tag. */
export function themeCss() {
  const css = readFileSync(join(HERE, "theme.css"), "utf8");
  if (/<\/style/i.test(css) || /@import|url\(/i.test(css)) throw new Error("site/theme.css must not contain </style, @import or url(): it is inlined into every page");
  return css;
}

// The web fonts load without holding up the first paint: the stylesheet starts as media="print" and switches
// to all when it arrives, so text shows at once in the fallback fonts from theme.css. <noscript> keeps the plain link.
// tools/hunter/board.py and tools/lookup/demo.html carry the same two lines.
export const FONTS = `<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet" media="print" onload="this.media='all'"><noscript><link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet"></noscript>`;

/** The Arena logo, inline: ring in the text colour, dot in the theme's broke red (--bad). Data: nav.json "mark". */
export function markSvg() {
  const m = NAV.mark, d = m.dot;
  return `<svg class="brand-mark" viewBox="0 0 100 100" aria-hidden="true"><path d="${esc(m.ring)}" fill="none" stroke="currentColor" stroke-width="${esc(m.ring_width)}" stroke-linecap="round"/><circle cx="${esc(d.cx)}" cy="${esc(d.cy)}" r="${esc(d.r)}" style="fill:var(--bad)"/></svg>`;
}

/** The browser-tab icon: the logo with theme.css's ink (ring) and --bad (dot), light values, and the dark
 *  values inside the SVG when the browser is dark. tools/hunter/board.py and tools/check/report.py build the same string. */
export const FAVICON = (() => {
  const css = readFileSync(join(HERE, "theme.css"), "utf8");
  const ink = [...css.matchAll(/--ink:(#[0-9A-Fa-f]{3,8})/g)].map((x) => x[1]);
  const bad = [...css.matchAll(/--bad:(#[0-9A-Fa-f]{3,8})/g)].map((x) => x[1]);
  if (ink.length < 2 || bad.length < 2) throw new Error("site/theme.css: expected --ink and --bad in the light and the dark block");
  const m = NAV.mark, d = m.dot;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><style>.r{stroke:${ink[0]}}.d{fill:${bad[0]}}@media (prefers-color-scheme:dark){.r{stroke:${ink[1]}}.d{fill:${bad[1]}}}</style><path class="r" d="${m.ring}" fill="none" stroke-width="${m.ring_width}" stroke-linecap="round"/><circle class="d" cx="${d.cx}" cy="${d.cy}" r="${d.r}"/></svg>`;
  return `<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,${encodeURIComponent(svg)}">`;
})();

const links = (current) => NAV.links.map((l) => `<a href="${esc(l.href)}"${l.id === current ? ' aria-current="page"' : ""}>${esc(l.label)}</a>`).join("");

/** The top bar. `current` is the id of the link for this page (see nav.json). */
export function topbar(current) {
  return `<header class="topbar"><div class="topbar-in"><a class="brand" href="${esc(NAV.brand.href)}">${markSvg()}${esc(NAV.brand.label)}</a><nav aria-label="Arena pages">${links(current)}</nav></div></header>`;
}

/** The footer. `extraHtml` is already-escaped HTML for one page-specific line (may be empty). */
export function footer(extraHtml = "") {
  return `<footer class="site-foot"><div class="foot-in"><nav aria-label="Arena pages, again"><a href="${esc(NAV.brand.href)}">${esc(NAV.brand.label)}</a>${links(null)}</nav><p>${esc(NAV.footer_note)}</p>${extraHtml ? `<p>${extraHtml}</p>` : ""}</div></footer>`;
}
