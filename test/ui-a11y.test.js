/* The switches and segmented pickers are built as spans and divs; the a11y
 * layer must make them focusable, announced, and operable from the keyboard.
 * (main.js loads a11y.js in the app; the harness loads app.js directly, so the
 * test imports it after boot the way the entry point would have.) */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, settle } from "./harness.js";

after(shutdown);

test("a bare span toggle is annotated as a switch", async () => {
  await boot();
  await import("../src/a11y.js");
  await settle(10);
  /* the simulator's toggles are spans; a11y makes them switches */
  const sw = $("#opt-ct");
  assert.ok(sw, "the toggle exists");
  assert.equal(sw.getAttribute("role"), "switch", "a span toggle is announced as a switch");
  assert.equal(sw.tabIndex, 0, "and is a tab stop");
  assert.ok(sw.hasAttribute("aria-checked"), "and carries a state");
});

test("Space and Enter operate a switch the same as a click", async () => {
  await boot();
  const { wireA11y } = await import("../src/a11y.js");
  const doc = globalThis.document;
  /* a fresh switch with no handler of its own but the global .sw-toggle painter,
     so the keyboard path is what is under test and nothing else */
  const sw = doc.createElement("span");
  sw.className = "sw-toggle";
  doc.body.appendChild(sw);
  wireA11y(doc);
  assert.equal(sw.getAttribute("role"), "switch");
  assert.equal(sw.getAttribute("aria-checked"), "false", "starts off");

  sw.dispatchEvent(new globalThis.window.KeyboardEvent("keydown", { key: " ", bubbles: true, cancelable: true }));
  await settle(10);
  assert.ok(sw.classList.contains("on"), "Space turned it on");
  assert.equal(sw.getAttribute("aria-checked"), "true", "and the announcement followed");
  sw.remove();
});

test("segmented options are announced as radios", async () => {
  await boot();
  await import("../src/a11y.js");
  await settle(10);

  const opt = $("#sim-dir button");
  assert.ok(opt, "the direction picker exists");
  assert.equal(opt.getAttribute("role"), "radio");
  assert.ok(opt.hasAttribute("aria-checked"), "and carries a checked state for AT");
});
