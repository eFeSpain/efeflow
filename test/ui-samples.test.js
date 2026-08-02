import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { SAMPLES } from "../src/core/samples.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

/* The scenarios are only worth shipping if they can be reached, read and
   imported. The core suite proves each one round-trips; this proves the
   dialog offers them and that picking one lands a working ruleset. */

const openImport = async () => { click('[data-go="import"]'); await settle(50); };

test("the dialog offers every scenario, named", async () => {
  await boot();
  await openImport();

  const opts = $$("#imp-sample option");
  assert.equal(opts.length, SAMPLES.length + 1, "one placeholder plus one per scenario");
  assert.equal(opts[0].value, "", "the first is the placeholder, not a scenario");
  for (const o of opts)
    assert.ok(o.textContent.trim(), "a scenario nobody can name is one nobody will pick");
});

test("picking one fills the textarea and reviews it", async () => {
  await boot();
  await openImport();

  setValue("#imp-sample", "dnat");
  await settle(60);

  const text = $("#imp-text").value;
  assert.match(text, /^#/, "the description leads, as a comment the parser ignores");
  assert.match(text, /dnat to 192\.168\.10\.20:443/, "and the ruleset follows");
  assert.ok(!$("#imp-go").disabled, "the review ran, so Import is live");
});

test("an imported scenario becomes the project", async () => {
  await boot();
  await newRuleset();
  await openImport();

  setValue("#imp-sample", "wireguard");
  await settle(60);
  click("#imp-go");
  await settle(80);

  assert.equal($$(".scrim.on").length, 0, "the dialog closes behind it");
  const rules = MODEL.chains.reduce((a, c) => a + c.rules.length, 0);
  assert.ok(rules > 5, "the rules arrived");
  assert.ok(MODEL.chains.some((c) => c.rules.some((r) => /51820/.test(r.expr))),
    "and they are the WireGuard ones, not another scenario's");
});

test("the scenario names follow the language", async () => {
  await boot();
  await openImport();

  const named = (l) => {
    click(`#lang [data-lang="${l}"]`);
    return $$("#imp-sample option").map((o) => o.textContent.trim());
  };
  const en = named("en");
  const es = named("es");
  assert.notDeepEqual(en, es, "the picker was left in one language");
  assert.equal(en.length, es.length);
});

test("switching language keeps the scenario you chose", async () => {
  await boot();
  await openImport();

  setValue("#imp-sample", "balancer");
  await settle(40);
  click('#lang [data-lang="es"]');
  await settle(40);
  assert.equal($("#imp-sample").value, "balancer",
    "re-labelling the options must not silently deselect one");
});
