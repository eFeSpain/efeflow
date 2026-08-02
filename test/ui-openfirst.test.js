/* Opening a project as the very first thing you do.
 *
 * Every other test of Open calls newRuleset() first, which is why this went
 * unnoticed: from a launched-and-untouched window, a .json loaded into the
 * model and then sat behind the empty state, which never came down. Nothing
 * failed, nothing was reported — the window simply did not change.
 *
 * The empty state hangs off `project.open`, which is not part of MODEL and has
 * no hook of its own. Open ran edit() first and set the project open second, so
 * the repaint inside edit() still saw a closed project, and nothing repainted
 * after. New worked because it sets the project open before it edits.
 *
 * This file boots and opens, in that order, with nothing in between. The launch
 * state only exists in the first test of a file, so that is where it lives. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, $$, settle, until } from "./harness.js";
import { project } from "../src/core/project.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

const PAYLOAD = JSON.stringify({
  app: "eFeFlow", v: 1, name: "edge-fw",
  scratch: { ifaces: ["wan0"], networks: [] },
  chains: [{
    id: "input", table: "inet filter", hook: "input", prio: 0,
    type: "filter", policy: "drop",
    rules: [{ expr: "tcp dport 22", verdict: "accept", on: true }],
  }],
  sets: [],
});

async function openPayload(payload, filename = "edge-fw.efeflow.json") {
  const win = globalThis.window;
  const input = $('input[type="file"]');
  const file = new win.File([payload], filename, { type: "application/json" });
  Object.defineProperty(input, "files", { value: [file], configurable: true });
  input.dispatchEvent(new win.Event("change", { bubbles: true }));
  await until(() => MODEL.chains.length > 0, { timeout: 2000 }).catch(() => {});
  await settle(60);
}

test("a project opened as the first action actually appears", async () => {
  await boot();

  /* the launch state: nothing open, and the empty state saying so */
  assert.equal(project.open, false);
  assert.ok($("#empty-state").classList.contains("on"), "this test is only meaningful from launch");

  await openPayload(PAYLOAD);

  assert.equal(MODEL.chains.length, 1, "the file did load");
  assert.equal(project.name, "edge-fw");
  assert.equal(project.open, true);
  assert.ok(!$("#empty-state").classList.contains("on"),
    "the ruleset loaded behind the empty state, so nothing looked like it happened");
  assert.ok($("#s-editor").classList.contains("on"), "and it should land on the editor");
  assert.equal($$(".scrim.on").length, 0);
});

test("and the canvas is drawn, not just the model filled", async () => {
  await boot();
  assert.equal($$("#chains .chain").length, 1);
  assert.equal($$("#chains .rule").length, 1);
  assert.match($("#proj-name-t").textContent, /edge-fw/);
});

/* The same repaint gap, reached from the other side: a file that is not a
   project must leave the empty state up, because nothing was opened. */
test("a file that is not a project leaves the empty state where it was", async () => {
  await boot();
  const { startEmpty } = await import("../src/app.js");
  void startEmpty;
  /* get back to nothing open the way the product does */
  project.open = false;
  const { rerender } = await import("../src/core/bus.js");
  rerender();
  await settle(60);
  assert.ok($("#empty-state").classList.contains("on"));

  await openPayload(JSON.stringify({ hello: "world" }), "notes.json");

  assert.ok($("#empty-state").classList.contains("on"),
    "nothing opened, so the way in has to stay on screen");
});
