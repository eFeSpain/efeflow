/* The three host actions, seen from a browser — which is to say with no host.
 *
 * src/host.js proves the ordering and the refusals. This proves the buttons
 * exist, say what they do, and decline rather than fail somewhere far away. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, importFixture, $, $$, click, settle, until } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

test("the canvas offers to read the counters and to watch the host", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  await settle(120);
  for (const id of ["cv-counters", "cv-watch"]) assert.ok($("#" + id), `${id} is missing`);
});

/* With nowhere to read from, the button says so instead of failing at the far
   end of a call that was never going to connect. */
test("with no host they decline and name the reason", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  await settle(120);

  click("#cv-counters");
  const said = await until(() => $("#toast")?.textContent, { timeout: 3000 });
  assert.match(said, /host|máquina/i);
  assert.match(said, /desktop|escritorio/i);
});

/* The counters on the canvas came from the text of the import and stay there
   until something reads the host, which is the whole point of the button. */
test("nothing is changed by a read that could not happen", async () => {
  await boot();
  await importFixture();
  const before = MODEL.chains.flatMap((c) => c.rules.map((r) => r.pkts));
  click('.rb[data-go="editor"]');
  await settle(120);
  click("#cv-counters");
  await settle(300);
  assert.deepEqual(MODEL.chains.flatMap((c) => c.rules.map((r) => r.pkts)), before);
});

/* A handle is the only way to name one rule of a running kernel, so the chip
   that shows it is the place to offer it. */
test("a rule read from a host offers to be pushed by its handle", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  await settle(120);
  click($$("#chains .rule")[0]);
  await settle(80);

  /* the fixture carries no handles, so there is nothing to offer */
  assert.equal($("#rule-push"), null);

  MODEL.chains[0].rules[0].handle = 7;
  click($$("#chains .rule")[0]);
  await settle(80);
  const chip = $("#rule-push");
  assert.ok(chip, "a rule with a handle should offer it");
  assert.match(chip.textContent, /handle 7/);
  assert.match(chip.title, /whole table|tabla entera/i);
});

test("pushing one with no host to push to says so and sends nothing", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  await settle(120);
  MODEL.chains[0].rules[0].handle = 7;
  click($$("#chains .rule")[0]);
  await settle(80);

  const before = $("#toast")?.textContent;
  click("#rule-push");
  const said = await until(() => $("#toast")?.textContent !== before && $("#toast")?.textContent,
                           { timeout: 3000 });
  assert.match(said, /host|máquina/i);
});
