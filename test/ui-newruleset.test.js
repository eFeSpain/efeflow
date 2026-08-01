import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

/* Starting from an empty ruleset is the path a real user takes on day one.
   It was never exercised: every other test edits the bundled sample. */

const chains = () => $$("#chains .chain");
const rules = () => $$("#chains .rule");

test("New produces an editable ruleset", async () => {
  const { errors } = await boot();
  click("#btn-new");
  await settle(60);

  assert.deepEqual(
    errors.map((e) => (e && e.stack) || String(e)),
    [],
    "starting empty threw",
  );
  assert.ok(MODEL.chains.length >= 3, "the new ruleset should have base chains");
  assert.ok(chains().length >= 3, `expected chain cards, got ${chains().length}`);
  assert.equal($("#sample-tag").style.display, "none", "the sample badge should clear");
});

test("a rule in the new ruleset can be selected and edited", async () => {
  await boot();
  click("#btn-new");
  await settle(60);

  const row = rules()[0];
  assert.ok(row, "the new ruleset should start with at least one rule");
  click(row);

  assert.ok($("#props-body .rule-hero"), "properties did not open");
  const dport = $("#f-dport");
  assert.ok(dport, "no editable match fields");

  setValue("#f-dport", "22", "input");
  const code = $$("#codeout .ln .tx").map((n) => n.textContent).join("\n");
  assert.match(code, /dport 22/, "the edit never reached the generated code");
});

test("rules can be added to an empty chain", async () => {
  await boot();
  click("#btn-new");
  await settle(60);

  const output = $$("#chains .chain").find((c) => c.dataset.chain.endsWith("/output"));
  assert.ok(output, "the new ruleset should have an output chain");
  const before = rules().length;

  click(output.querySelector(".addrule"));
  await settle(30);

  assert.equal(rules().length, before + 1, "add rule did nothing");
  assert.ok($("#props-body .rule-hero"), "the new rule should be selected for editing");
});

test("the generated code reflects the new ruleset, not the sample", async () => {
  await boot();
  click("#btn-new");
  await settle(60);

  const code = $$("#codeout .ln .tx").map((n) => n.textContent).join("\n");
  assert.match(code, /table inet filter/);
  assert.ok(!/raw_pre|@admin_nets/.test(code), "traces of the sample survived");
});
