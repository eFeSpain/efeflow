/* Entry point. Boots the shell, wires the window chrome, and starts the
   ambient flow on the canvas. */

import "./app.js";
import { applyLang, t } from "./i18n.js";
import * as native from "./native.js";
import { probe } from "./target.js";
import { MODEL, UID } from "./core/model.js";
import { onModelChange } from "./core/bus.js";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/* ── window chrome ──────────────────────────────────────────────────────
   No top-level await here. A module that awaits before it finishes evaluating
   can miss the window `load` event entirely, and the boot splash would then
   never lift — which is exactly what happened the first time. */
native.ready.then(() => {
  native.applyPlatformClass();
  detectTarget();
});

$$(".tb-win button").forEach((b) =>
  b.addEventListener("click", () => native.windowAction(b.dataset.win)),
);
$$("[data-drag]").forEach((n) =>
  n.addEventListener("pointerdown", (e) => {
    if (e.button !== 0 || e.target.closest("button")) return;
    // Windows treats a double-click inside a drag region as maximise. Letting
    // that through as well as the handler below toggles twice and looks like
    // the first press did nothing.
    if (e.detail >= 2) return;
    native.windowAction("startDrag");
  }),
);
$("#titlebar").addEventListener("dblclick", (e) => {
  if (!e.target.closest("button")) native.windowAction("maximize");
});

/* Where nft will run, said without asking anybody.
 *
 * This used to probe on the way up. It is a designer, not a firewall manager,
 * and the README's first promise is that nothing reaches a live host unless
 * you ask — so opening the editor and having it ssh into a production firewall
 * was the application contradicting its own argument. It was also two
 * connections at eight seconds of timeout each before the window settled.
 *
 * So the chip says what it is pointed at, and finds out whether that answers
 * the first time something needs the answer. */
function detectTarget() {
  const chip = $("#tb-target");
  const label = $("#tb-target-t");
  if (!native.isDesktop()) {
    label.textContent = t("browser preview", "vista de navegador");
    chip.title = t(
      "Running in a browser — nft integration needs the desktop app.",
      "Ejecutándose en navegador — la integración con nft necesita la app de escritorio.",
    );
    return;
  }
  /* app.js owns the chip from here: it knows which target is configured, and
     it is the one that will ask when somebody wants to know. */
}

/* ── ambient flow ──────────────────────────────────────────────────────
   Packets drift along the connectors the whole time the editor is open. It is
   decoration, but it is decoration that says something true: this is the path
   a packet takes, and these are the directions it can go. */
function ambientFlow() {
  const svg = $("#wires");
  if (!svg) return;
  const layer = document.createElementNS("http://www.w3.org/2000/svg", "g");
  layer.setAttribute("id", "flow-layer");
  svg.appendChild(layer);

  let motes = [];
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  function seed() {
    layer.innerHTML = "";
    motes = [];
    if (reduced) return;
    $$("#wires path").forEach((p, i) => {
      if (p.parentNode === layer) return;
      const len = p.getTotalLength();
      if (!len) return;
      const n = Math.max(1, Math.round(len / 240));
      for (let k = 0; k < n; k++) {
        const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        c.setAttribute("r", "2.2");
        c.setAttribute("fill", "var(--aqua)");
        c.setAttribute("opacity", "0.55");
        layer.appendChild(c);
        motes.push({ el: c, path: p, len, at: (k / n + i * 0.13) % 1, speed: 0.055 + Math.random() * 0.04 });
      }
    });
  }

  let last = performance.now();
  function tick(now) {
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    const visible = $("#s-editor")?.classList.contains("on");
    if (visible) {
      for (const m of motes) {
        m.at = (m.at + m.speed * dt) % 1;
        const pt = m.path.getPointAtLength(m.at * m.len);
        m.el.setAttribute("cx", pt.x);
        m.el.setAttribute("cy", pt.y);
        // fade in at the start of a run and out at the end, so nothing pops
        const edge = Math.min(m.at, 1 - m.at) * 6;
        m.el.setAttribute("opacity", (Math.min(1, edge) * 0.5).toFixed(3));
      }
    }
    requestAnimationFrame(tick);
  }

  seed();
  onModelChange(() => requestAnimationFrame(seed));
  window.addEventListener("resize", () => requestAnimationFrame(seed));
  requestAnimationFrame(tick);
}

/* ── boot ──────────────────────────────────────────────────────────── */
applyLang();
ambientFlow();

/* Hold the splash for the length of the draw, then hand over. Driven from a
   timer rather than an event, so nothing can strand it. */
const MIN_SPLASH = matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : 2150;
setTimeout(() => window.__efeflowBooted(), MIN_SPLASH);

/* Keep the titlebar honest about what is being edited. */
onModelChange(() => {
  const rules = MODEL.chains.reduce((a, c) => a + c.rules.filter((r) => r.on).length, 0);
  $("#tb-origin").textContent = `${MODEL.chains.length} chains · ${rules} rules`;
});
