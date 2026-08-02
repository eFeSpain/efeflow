/* How much of the window the canvas gets.
 *
 * The library and the properties panel took 564px between them and neither
 * could be put away, so on a 1440px laptop the canvas had 828 — under half the
 * ruleset visible at any zoom where a rule was still readable. Fit to view
 * apologised for it in a toast rather than being able to do anything about it. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { boot, shutdown, importFixture, $, click, settle } from "./harness.js";

after(shutdown);

const editor = () => $("#s-editor");
const off = (which) => editor().classList.contains(which + "-off");
const floating = () => $(".props").classList.contains("floating");

/* One jsdom per file, so every test but the first inherits what the last one
   left behind. Each starts from both panels docked and open. */
async function reset() {
  if (floating()) { click("#props-float"); await settle(40); }
  if (off("lib")) { click("#cv-lib"); await settle(40); }
  if (off("props")) { click("#cv-props"); await settle(40); }
}

test("both panels are open, and the dock offers to close either", async () => {
  await boot();
  await importFixture();
  assert.ok($("#cv-lib"), "no way to put the library away");
  assert.ok($("#cv-props"), "no way to put the properties panel away");
  assert.ok($("#cv-lib").classList.contains("on"));
  assert.ok($("#cv-props").classList.contains("on"));
  assert.ok(!off("lib") && !off("props"), "nothing starts collapsed");
});

test("closing one closes its column, not just its contents", async () => {
  await boot();
  await importFixture();
  await reset();

  click("#cv-lib");
  await settle(60);
  assert.ok(off("lib"));
  assert.ok(!$("#cv-lib").classList.contains("on"), "the button has to show the state");

  click("#cv-props");
  await settle(60);
  assert.ok(off("props"));

  click("#cv-lib"); click("#cv-props");
  await settle(60);
  assert.ok(!off("lib") && !off("props"));
});

test("the brackets do it from the keyboard", async () => {
  await boot();
  await importFixture();
  await reset();
  const key = (k) => globalThis.document.dispatchEvent(
    new globalThis.window.KeyboardEvent("keydown", { key: k, bubbles: true }));

  key("[");
  await settle(60);
  assert.ok(off("lib"));
  key("]");
  await settle(60);
  assert.ok(off("props"));
  key("["); key("]");
  await settle(60);
  assert.ok(!off("lib") && !off("props"));
});

/* Typing `[` into a set element is not a request to rearrange the window. */
test("not while you are typing", async () => {
  await boot();
  await importFixture();
  await reset();
  $("#lib-filter").dispatchEvent(
    new globalThis.window.KeyboardEvent("keydown", { key: "[", bubbles: true }));
  await settle(60);
  assert.ok(!off("lib"));
});

/* Floating left the 320px column standing, empty, and dropped the panel on top
   of the canvas — so it cost you the space twice. */
test("floating the properties panel closes the column behind it", async () => {
  await boot();
  await importFixture();
  await reset();

  click("#props-float");
  await settle(80);
  assert.ok(floating());
  assert.ok(off("props"), "the column it left has to close");
  assert.ok(!$("#cv-props").classList.contains("on"), "it is not docked, so the dock says so");
  assert.ok($(".float-bar"), "a floating panel needs its own title bar to drag");
});

test("the dock brings a floating panel home", async () => {
  await boot();
  await importFixture();
  await reset();

  click("#props-float");
  await settle(80);
  click("#cv-props");
  await settle(80);

  assert.ok(!floating());
  assert.ok(!off("props"), "coming home means being here");
  assert.ok($("#cv-props").classList.contains("on"));
  assert.equal($(".float-bar"), null);
});

test("the choice is remembered", async () => {
  await boot();
  await importFixture();
  await reset();

  click("#cv-lib");
  await settle(60);
  assert.deepEqual(JSON.parse(globalThis.localStorage.getItem("efeflow.panels")),
                   { lib: false, props: true });
  click("#cv-lib");
  await settle(60);
  assert.deepEqual(JSON.parse(globalThis.localStorage.getItem("efeflow.panels")),
                   { lib: true, props: true });
});

/* Two things the stylesheet has to say that jsdom cannot be asked about, and
   both were bugs in a browser:
   — hiding the library takes it out of the grid, and auto-placement then slides
     the canvas into the 0px track it left behind. The canvas went to nothing.
   — the float bar names the panel, and the docked header named it again. */
test("the layout says in CSS what jsdom cannot be asked", () => {
  const css = readFileSync(new URL("../src/styles/app.css", import.meta.url), "utf8");
  for (const [sel, col] of [[".lib", 1], [".mid", 2], [".props", 3]])
    assert.match(css, new RegExp(`#s-editor > \\${sel}\\{grid-column:${col}\\}`),
      `${sel} must name its column, or hiding a sibling moves it`);
  assert.match(css, /\.props\.floating > \.panel-hd\{display:none\}/,
    "a floating panel carries its own title bar and must not keep the docked one");
});
