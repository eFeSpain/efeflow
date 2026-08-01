/* Boots the real interface in jsdom.
 *
 * Not a rendering test — jsdom has no layout — but it evaluates every module,
 * builds every screen and dispatches real events. All three bugs that reached
 * the running app this cycle (a temporal-dead-zone read, a CSS class collision
 * and a parameter shadowing the translation helper) were module-evaluation or
 * handler-time throws, and every one of them dies here. */

import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";

let booted = null;

/* Kept before the globals are swapped: the harness's own waiting must outlive
   the window it is tearing down. */
const nodeSetTimeout = setTimeout;

/* jsdom implements the DOM, not the browser. These are the browser bits the
   interface touches; each is a genuine no-op for a headless run. */
function stubMissingPlatform(win) {
  const { Element, SVGElement, HTMLCanvasElement } = win;

  win.matchMedia ||= () => ({
    matches: false,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
  });

  Element.prototype.scrollIntoView ||= function () {};
  Element.prototype.setPointerCapture ||= function () {};
  Element.prototype.releasePointerCapture ||= function () {};
  Element.prototype.animate ||= function () {
    return { finished: Promise.resolve(), cancel() {} };
  };

  // SVG geometry: the ambient flow walks the connector paths
  SVGElement.prototype.getTotalLength ||= function () {
    return 100;
  };
  SVGElement.prototype.getPointAtLength ||= function () {
    return { x: 0, y: 0 };
  };

  if (HTMLCanvasElement) HTMLCanvasElement.prototype.getContext ||= () => null;

  win.URL.createObjectURL ||= () => "blob:stub";
  win.URL.revokeObjectURL ||= () => {};
}

export async function boot() {
  if (booted) return booted;

  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const dom = new JSDOM(html, {
    url: "http://localhost:5183/",
    pretendToBeVisual: true, // gives requestAnimationFrame
    runScripts: "dangerously", // the inline boot guard must run
  });
  const win = dom.window;
  stubMissingPlatform(win);

  // The modules read these off the global scope, exactly as in a browser.
  globalThis.window = win;
  globalThis.document = win.document;
  globalThis.localStorage = win.localStorage;
  globalThis.HTMLElement = win.HTMLElement;
  globalThis.Element = win.Element;
  globalThis.Node = win.Node;
  globalThis.CSS = win.CSS;
  globalThis.getComputedStyle = win.getComputedStyle.bind(win);
  globalThis.matchMedia = win.matchMedia;
  globalThis.innerWidth = win.innerWidth;
  globalThis.innerHeight = win.innerHeight;
  /* Timers stay on Node's. jsdom's own setTimeout delegates to the global one,
     so aliasing makes it call itself — the same trap as performance.now.
     The consequence is that the app's pending timers outlive close(); the
     collector below ignores anything thrown once teardown has begun. */
  globalThis.requestAnimationFrame = win.requestAnimationFrame.bind(win);
  globalThis.cancelAnimationFrame = win.cancelAnimationFrame.bind(win);
  /* Deliberately not globalThis.performance: jsdom's Performance.now() reads
     the global performance internally, so aliasing it makes it call itself. */

  /* The modules run in Node's realm, not jsdom's, so a throw inside a timer
     surfaces as an uncaughtException rather than a window error event. Both
     are collected: an exception in a callback is still a bug, and it is
     precisely the kind that never reaches a user-visible console. */
  const errors = [];
  const collect = (e) => { if (!tearing) errors.push(e); };
  win.addEventListener("error", (e) => collect(e.error || e.message));
  win.addEventListener("unhandledrejection", (e) => collect(e.reason));
  process.on("uncaughtException", collect);
  process.on("unhandledRejection", collect);

  const app = await import("../src/app.js");

  booted = { dom, win, doc: win.document, errors, app };
  return booted;
}

/* jsdom's visual loop and the app's own timers keep the event loop alive, so
   the runner would hang after the last assertion. Every file tears down. */
let tearing = false;

/* Quiesce before dismantling. The simulator drives a chain of timers; closing
   the window underneath them makes them fire against a detached document, and
   node:test reports that as a failure of whichever test happened to be last.
   Navigating away is what stops it — the same thing a user does. */
export async function shutdown() {
  if (!booted) return;
  const dash = booted.doc.querySelector('.rb[data-go="dash"]');
  if (dash) dash.dispatchEvent(new booted.win.MouseEvent("click", { bubbles: true }));
  await new Promise((r) => nodeSetTimeout(r, 60));
  tearing = true;
  booted.win.close();
  booted = null;
}

/* Helpers that read the way the assertions do. */
export const $ = (sel) => globalThis.document.querySelector(sel);
export const $$ = (sel) => [...globalThis.document.querySelectorAll(sel)];

export function click(target) {
  const node = typeof target === "string" ? $(target) : target;
  if (!node) throw new Error(`click: no element for ${target}`);
  node.dispatchEvent(new globalThis.window.MouseEvent("click", { bubbles: true }));
  return node;
}

export function setValue(sel, value, event = "change") {
  const node = $(sel);
  if (!node) throw new Error(`setValue: no element for ${sel}`);
  node.value = value;
  node.dispatchEvent(new globalThis.window.Event(event, { bubbles: true }));
  return node;
}

export const text = (sel) => $(sel)?.textContent.trim() ?? null;

/* Real time, on Node's clock, so it works during and after teardown. */
export const settle = (ms = 250) => new Promise((r) => nodeSetTimeout(r, ms));

/* The app opens on a blank ruleset, so anything that needs rules to look at
   brings its own. Loading it through the import dialog rather than poking
   MODEL means the fixture arrives the way a user's ruleset would. */
/* New asks before discarding edits, so a test that just clicks it and moves on
   is left waiting on a dialog nobody answered. */
export async function newRuleset() {
  click("#btn-new");
  await settle(25);
  if ($("#scrim-confirm")?.classList.contains("on")) {
    click("#cf-yes");
    await settle(25);
  }
}

export async function importFixture(name = "flawed.nft") {
  /* Blank first. edit() is a no-op when the snapshot is unchanged, so
     re-importing the same fixture in a later test would skip the re-render
     and leave the previous test's DOM standing. */
  await newRuleset();

  const text = readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");
  const area = $("#imp-text");
  area.value = text;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(80);
}

/* The interface animates on timers; poll rather than guess a duration. */
export async function until(fn, { timeout = 6000, step = 25 } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error("timed out waiting for condition");
    await new Promise((r) => nodeSetTimeout(r, step));
  }
}
