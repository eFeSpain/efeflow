/* The canvas controls, and whether they do what they are labelled.
 *
 * "Fit to view" ran setZoom(.72): a fixed number wearing the name of a
 * measurement. On a wide ruleset it left two chains off the right-hand edge and
 * on a narrow one it shrank three cards for nothing. Its tooltip has also
 * promised a Shift+1 shortcut for as long as the button has existed, and there
 * was no handler for it anywhere. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, importFixture, $, $$, click, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

const zoom = () => $("#zl").textContent;

const shift1 = async () => {
  globalThis.document.dispatchEvent(new globalThis.window.KeyboardEvent("keydown", {
    key: "1", shiftKey: true, bubbles: true, cancelable: true,
  }));
  await settle(60);
};

test("the shortcut the tooltip promises is wired to the same thing as the button", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  await settle(120);

  click("#zi");
  await settle(60);
  const zoomedIn = zoom();

  await shift1();
  assert.notEqual(zoom(), zoomedIn, "Shift+1 did nothing");
  assert.equal(zoom(), $("#zl").textContent);
});

/* jsdom has no layout, so nothing measures: the fit has to notice that and
   fall back rather than divide by zero and set the zoom to NaN. */
test("with nothing measurable it falls back instead of computing nonsense", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  await settle(120);

  click("#zf");
  await settle(80);
  assert.match(zoom(), /^\d+%$/, `zoom read ${zoom()}`);
  assert.ok(Number(zoom().replace("%", "")) > 0);
});

/* Typing a 1 into a field is not a request to re-frame the canvas. */
test("the shortcut keeps out of text fields", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  await settle(120);
  click($$("#chains .rule")[0]);
  await settle(80);

  click("#zi");
  await settle(60);
  const before = zoom();

  const field = $("#f-dport");
  field.focus();
  field.dispatchEvent(new globalThis.window.KeyboardEvent("keydown", {
    key: "1", shiftKey: true, bubbles: true, cancelable: true,
  }));
  await settle(60);
  assert.equal(zoom(), before, "re-framed the canvas while someone was typing");
});

/* The canvas is as wide as the hooks in use now, so the minimap and the wires
   may not assume the 1680 it used to be. */
test("the overview is drawn against the canvas there is", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  await settle(150);

  const width = $("#canvas").style.width;
  assert.match(width, /^\d+px$/, "the canvas has no width to measure against");
  assert.equal($("#wires").getAttribute("width"), String(parseInt(width)),
    "the wire layer is a different size from the canvas it draws on");
});
