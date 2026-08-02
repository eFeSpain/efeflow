import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, click, settle } from "./harness.js";

after(shutdown);

/* A green core suite is not evidence that the button works. This drives the
   real dialog: the ruleset the product offers has to arrive through the same
   review the user's own paste goes through. */

test("the sample loads into the import dialog and reviews clean", async () => {
  await boot();
  click('.rb[data-go="dash"]');
  $("#imp-text").value = "";
  click("#imp-sample");
  await settle(40);

  assert.match($("#imp-text").value, /^table inet filter \{/, "the textarea should hold the sample");
  const side = $("#imp-side").textContent;
  assert.match(side, /100%/, "the round-trip review must be perfect: " + side.slice(0, 200));
  assert.doesNotMatch(side, /Unparsed lines|Líneas no analizadas/, "no line may fail to parse");
  assert.equal($("#imp-go").disabled, false, "it must be importable");
});

test("clearing the dialog puts the review back to its empty state", async () => {
  await boot();
  click("#imp-sample");
  await settle(20);
  click("#imp-clear");
  await settle(20);

  assert.equal($("#imp-text").value, "");
  assert.equal($("#imp-go").disabled, true, "there is nothing to import");
  assert.match($("#imp-side").textContent, /Nothing to read yet|Nada que leer todavía/);
});
