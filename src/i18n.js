/* Translations live next to the markup as data-t="English|Español" so a string
   and its pair can never drift apart. nftables vocabulary is never translated —
   a Spanish sysadmin writes `accept`, not `aceptar`. */

import { onRender, rerender } from "./core/bus.js";

/* The core imports t() too, and the test runner has no DOM. Everything here
   degrades to a no-op outside the browser rather than guarding at each site. */
const web = typeof document !== "undefined";
const store = web && typeof localStorage !== "undefined" ? localStorage : null;

let LANG = store?.getItem("efeflow.lang") || "es";

export const lang = () => LANG;
export const t = (en, es) => (LANG === "es" ? es : en);

/* One registry, on the bus. There used to be a second array here, and every
   view that registered against the other one silently never ran — including
   the analyser, which meant no findings and no badges in the desktop build. */
export const onLangChange = onRender;

export function setLang(next) {
  if (next === LANG) return;
  LANG = next;
  store?.setItem("efeflow.lang", LANG);
  applyLang();
}

const pick = (v) => {
  const i = v.indexOf("|");
  if (i < 0) return v;    /* no separator: `slice(0,-1)` would eat the English label's last character */
  return LANG === "es" ? v.slice(i + 1) : v.slice(0, i);
};

export function applyLang(root) {
  if (!web) return;
  root = root || document;
  root.querySelectorAll("[data-t]").forEach((n) => {
    const v = pick(n.dataset.t);
    if (n.hasAttribute("data-html")) n.innerHTML = v;
    else n.textContent = v;
  });
  root.querySelectorAll("[data-tp]").forEach((n) => (n.placeholder = pick(n.dataset.tp)));
  root.querySelectorAll("[data-tt]").forEach((n) => (n.title = pick(n.dataset.tt)));
  document.querySelectorAll("#lang button").forEach((b) =>
    b.classList.toggle("on", b.dataset.lang === LANG),
  );
  document.documentElement.lang = LANG;
  rerender();
}
