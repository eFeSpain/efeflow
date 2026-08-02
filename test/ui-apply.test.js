/* The apply dialog, in a browser — which is to say with no host to reach.
 *
 * src/apply.js proves the ordering. This proves the dialog says true things
 * before anything happens: which machine, which tables, what the net does, and
 * that there is nothing to apply to from here. The README documented applying
 * as a feature for a long time while no button called it. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, importFixture, $, $$, click, settle, until } from "./harness.js";
import { MODEL } from "../src/core/model.js";
import { generate } from "../src/core/generate.js";

after(shutdown);

const open = async () => {
  click('.rb[data-go="validate"]');
  await settle(60);
  click("#val-apply");
  await settle(60);
};

/* Its label was only written by the dialog, so the button on the screen behind
   read as an em dash until you had opened it once. */
test("the button says what it does before it has ever been pressed", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="validate"]');
  await settle(80);
  assert.match($("#val-apply-t").textContent, /Apply|Aplicar/);
});

test("the validation screen offers to apply, and the dialog opens", async () => {
  await boot();
  await importFixture();
  await open();
  assert.ok($("#scrim-apply").classList.contains("on"), "the apply dialog never opened");
  assert.ok($("#ap-after").style.display === "none", "the countdown belongs after, not before");
});

/* `flush ruleset` on a host that also runs Docker deletes Docker's tables and
   nothing tells anybody. The dialog has to say which of the two it is doing. */
test("the dialog names the tables it will replace", async () => {
  await boot();
  await importFixture();
  await open();

  const note = $("#ap-scope-note").textContent;
  for (const tb of new Set(MODEL.chains.map((c) => c.table)))
    assert.ok(note.includes(tb), `${tb} is replaced and the dialog does not say so`);

  click('#ap-scope [data-scope="ruleset"]');
  await settle(30);
  assert.match($("#ap-scope-note").textContent, /flush ruleset/);
  assert.match($("#ap-scope-note").textContent, /Docker|deleted|borra/i);
});

/* A scope of "the whole ruleset", remembered from an apply ten minutes ago and
   applied to a different host, is how somebody's Docker tables disappear. */
test("both dangerous choices go back to the safe one every time it opens", async () => {
  await boot();
  await importFixture();
  await open();
  click('#ap-scope [data-scope="ruleset"]');
  click('#ap-window [data-secs="0"]');
  await settle(30);
  click("#scrim-apply [data-close]");
  await settle(30);

  await open();
  assert.equal($('#ap-scope [data-scope="tables"]').classList.contains("on"), true,
    "the destructive scope was remembered");
  assert.equal($('#ap-window [data-secs="60"]').classList.contains("on"), true,
    "the net was left off");
});

/* What the scope button picks has to be what gets sent. */
test("the scope chosen is the ruleset that would be sent", async () => {
  await boot();
  await importFixture();
  await open();

  click('#ap-scope [data-scope="tables"]');
  await settle(20);
  assert.ok(!generate(MODEL, { scope: "tables" }).includes("flush ruleset"));

  click('#ap-scope [data-scope="ruleset"]');
  await settle(20);
  assert.ok(generate(MODEL, { scope: "ruleset" }).includes("flush ruleset"));
});

test("turning the net off says what that costs", async () => {
  await boot();
  await importFixture();
  await open();

  click('#ap-window [data-secs="0"]');
  await settle(30);
  assert.match($("#ap-window-note").textContent, /console|consola/i,
    "the one thing to say about no net is what you need if it goes wrong");

  click('#ap-window [data-secs="120"]');
  await settle(30);
  assert.match($("#ap-window-note").textContent, /120/);
});

/* A browser has no nft and no ssh. The button that cannot work says why,
   rather than failing at the far end of an apply that never started. */
test("with nowhere to apply to, the dialog says so and the button is dead", async () => {
  await boot();
  await importFixture();
  await open();
  await until(() => $("#ap-warn").style.display !== "none", { timeout: 3000 }).catch(() => {});

  assert.equal($("#ap-go").disabled, true, "a button that cannot work must not look like it can");
  assert.match($("#ap-warn").textContent, /desktop|escritorio/i);
});
