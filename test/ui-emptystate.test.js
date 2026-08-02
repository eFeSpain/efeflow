import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, $$, click, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";
import { project } from "../src/core/project.js";

after(shutdown);

/* The application used to boot holding a ruleset called "untitled" that nobody
   had asked for, under a dialog offering to replace it. Every screen describes
   a ruleset, so inventing one is a lie about which state you are in — and it
   left people looking for the project they had supposedly opened. */

const empty = () => $("#empty-state").classList.contains("on");

test("nothing is open at boot", async () => {
  await boot();
  assert.equal(project.open, false);
  assert.equal(MODEL.chains.length, 0, "no chains, not even a skeleton");
  assert.equal(MODEL.sets.length, 0);
  assert.equal(project.name, "", "and no invented name");

  const shown = $("#proj-name-t").textContent.trim();
  assert.ok(shown, "an empty name left a folder icon over nothing");
  assert.doesNotMatch(shown, /untitled/i, "and the toolbar must not invent one either");
});

test("and it says so, rather than showing an empty canvas", async () => {
  await boot();
  assert.ok(empty(), "the editor has to explain itself when there is nothing in it");
  assert.ok($("#empty-state h2").textContent.trim());
  assert.ok($("#es-new"), "a way to start from nothing");
  assert.ok($("#es-import"), "and a way to bring something in");

  /* still the pristine boot: nothing above has opened anything */
  assert.equal($("#proj-tables").textContent.trim(), "", "no table list to show");
  assert.doesNotMatch($("#st-counts").textContent, /[1-9]\d* (chains|cadenas)/,
    "and nothing to count");
});

test("the old first-run dialog is gone, not merely hidden", async () => {
  await boot();
  assert.equal($("#scrim-welcome"), null,
    "it offered the same choices over a project you had not asked for");
});

test("New opens a project and clears the empty state", async () => {
  await boot();
  click("#es-new");
  await settle(60);

  assert.equal(project.open, true);
  assert.ok(!empty(), "the canvas has something on it now");
  assert.ok(MODEL.chains.length >= 3, "the blank skeleton is what New produces");
  assert.equal(project.name, "untitled");
});

test("importing opens a project too", async () => {
  await boot();
  /* back to nothing, the way a fresh launch arrives */
  MODEL.chains.length = 0; MODEL.sets.length = 0;
  project.open = false;

  click("#es-import");
  await settle(50);
  assert.ok($("#scrim-import").classList.contains("on"), "it should offer the import dialog");
});

test("with nothing open there is nothing to rename", async () => {
  await boot();
  /* back to a fresh launch */
  MODEL.chains.length = 0; MODEL.sets.length = 0;
  project.open = false; project.name = "";

  click("#proj-name");
  assert.equal($("#proj-input").classList.contains("on"), false,
    "renaming a project that does not exist would name the placeholder");
});
