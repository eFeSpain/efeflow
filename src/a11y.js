/* Making the non-semantic controls operable.
 *
 * The interface builds its switches as `<span class="sw-toggle">` and its
 * segmented pickers as `<button>`/`<div class="choice">` across a dozen
 * templates. They look and click like controls, but a span is not focusable and
 * announces nothing to a screen reader, and there was not one tab stop of this
 * kind in the whole document. Rather than annotate every template, this gives
 * each one a role, a tab stop and a state as it enters the DOM, keeps the state
 * in step with the `.on` class that already drives it (see the global click
 * handler in app.js, which flips that class and now sets aria-checked beside
 * it), and gives them the keyboard a real control has.
 */

const asSwitch = el => {
  if (el.getAttribute("role") !== "switch") { el.setAttribute("role", "switch"); el.tabIndex = 0; }
  el.setAttribute("aria-checked", el.classList.contains("on") ? "true" : "false");
};
const asRadio = el => {
  if (el.getAttribute("role") !== "radio") { el.setAttribute("role", "radio"); el.tabIndex = 0; }
  el.setAttribute("aria-checked", el.classList.contains("on") ? "true" : "false");
};

const SWITCHES = ".sw-toggle";
const RADIOS = ".seg button, .choice, [data-lang]";

/** Annotate every control under `root` (default the whole document). */
export function wireA11y(root = document) {
  root.querySelectorAll?.(SWITCHES).forEach(asSwitch);
  root.querySelectorAll?.(RADIOS).forEach(asRadio);
}

/* Space and Enter operate a switch or a radio; a click already does, and these
   dispatch one so both the global painter and the control's own handler run. */
document.addEventListener("keydown", e => {
  const el = e.target?.closest?.("[role=switch],[role=radio]");
  if (el && (e.key === " " || e.key === "Enter")) { e.preventDefault(); el.click(); }
});

/* Controls are rebuilt on almost every render, so wire whatever the DOM grows.
   childList only: class changes are frequent and are handled at the click
   choke point instead, so there is nothing to gain from watching attributes. */
const MO = globalThis.MutationObserver || globalThis.window?.MutationObserver;
if (MO) new MO(muts => {
  for (const m of muts) for (const n of m.addedNodes) {
    if (n.nodeType !== 1) continue;
    if (n.matches?.(SWITCHES)) asSwitch(n); else n.querySelectorAll?.(SWITCHES).forEach(asSwitch);
    if (n.matches?.(RADIOS)) asRadio(n); else n.querySelectorAll?.(RADIOS).forEach(asRadio);
  }
}).observe(document.documentElement, { subtree: true, childList: true });

wireA11y();
