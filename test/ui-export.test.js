/* One question about what a ruleset replaces, asked the same way everywhere.
 *
 * There were three. The apply dialog and the code pane offered a scope — the
 * whole ruleset, or only the tables this project owns. The export dialog
 * instead had a toggle that deleted the `flush ruleset` line, which is a third
 * meaning again: a file that neither empties the kernel nor replaces its own
 * tables merges into whatever is already there, and the rules pile up on every
 * re-apply. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, importFixture, $, $$, click, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

const open = async () => { click('[data-go="export"]'); await settle(80); };
const scope = () => $("#ex-scope .on")?.dataset.scope;

test("the export dialog asks the same question as the apply one", async () => {
  await boot();
  await importFixture();
  await open();

  assert.ok($("#ex-scope"), "no scope choice in the export dialog");
  assert.equal(scope(), "tables", "the destructive scope must not be the default");
  assert.equal($$("#scrim-export .sw-toggle").length, 2,
    "the flush toggle is a third meaning and should be gone");
});

test("the note says which tables, or says what flush ruleset costs", async () => {
  await boot();
  await importFixture();
  await open();

  for (const tb of new Set(MODEL.chains.map((c) => c.table)))
    assert.ok($("#ex-scope-note").textContent.includes(tb), `${tb} is replaced and unsaid`);

  click('#ex-scope [data-scope="ruleset"]');
  await settle(60);
  assert.equal(scope(), "ruleset");
  assert.match($("#ex-scope-note").textContent, /flush ruleset/);
});

/* The count under the dialog is of the file it would actually write. */
test("the scope chosen is the file that comes out", async () => {
  await boot();
  await importFixture();
  await open();

  const lines = () => Number($$("#scrim-export .card .num")[0].textContent);
  click('#ex-scope [data-scope="tables"]');
  await settle(60);
  const scoped = lines();

  click('#ex-scope [data-scope="ruleset"]');
  await settle(60);
  assert.notEqual(lines(), scoped, "switching the scope changed nothing about the file");
});

/* The toggles were read by position, so the flush one leaving shifted the two
   after it — the dry-run check would have become the comment one. */
test("the remaining options are read by name, not by where they sit", async () => {
  await boot();
  await importFixture();
  await open();
  for (const id of ["ex-comments", "ex-check"])
    assert.ok($("#" + id), `${id} has no id to be read by`);
});
