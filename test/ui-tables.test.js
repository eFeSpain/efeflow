/* The table editor: the one level of nftables the interface could not touch.
 *
 * Tables were derived from the chains filed under them and had no properties of
 * their own, so `flags dormant` and a table comment both survived an import and
 * could not be written — and dormant is not decoration, it is how a firewall is
 * parked. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, importFixture, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";
import { readTable, tableNames, writeTable } from "../src/core/tables.js";

after(shutdown);

const chip = (name) => $$(".tbl-chip[data-table]").find((b) => b.dataset.table === name);

test("the tables in the header are the way into their properties", async () => {
  await boot();
  await importFixture();
  const names = tableNames(MODEL);
  assert.ok(names.length, "the fixture has tables");
  assert.ok(chip(names[0]), "the first table is not clickable");
  assert.ok($("[data-table-new]"), "and there is no way to add one");

  click(chip(names[0]));
  await settle(60);
  assert.ok($("#scrim-table").classList.contains("on"));
  assert.equal($("#tbl-name").value, names[0].split(" ").slice(1).join(" "));
  assert.equal($("#tbl-family").value, names[0].split(" ")[0]);
});

test("parking a table writes the flag and nothing else", async () => {
  await boot();
  await importFixture();
  const name = tableNames(MODEL)[0];
  click(chip(name));
  await settle(60);

  $("#tbl-comment").value = "parked while we migrate";
  click("#tbl-dormant");
  await settle(20);
  click("#tbl-save");
  await settle(120);

  const info = readTable(MODEL, name);
  assert.equal(info.dormant, true);
  assert.equal(info.comment, "parked while we migrate");
  assert.equal(info.full, name, "the name was not meant to change");
});

/* The toggle that flips .sw-toggle lives on the document, so it runs after any
   handler bound to the switch itself: the preview read the state it had just
   left and showed the opposite of what would be saved. */
test("the preview shows the flag the moment it is switched on", async () => {
  await boot();
  await importFixture();
  click(chip(tableNames(MODEL)[0]));
  await settle(60);
  assert.doesNotMatch($("#tbl-preview").textContent, /dormant/);

  click("#tbl-dormant");
  await settle(60);
  assert.match($("#tbl-preview").textContent, /flags dormant/,
    "the preview must show what saving would write, not what it replaced");
  assert.match($("#tbl-dormant-note").textContent, /registr|packet|paquete/i);
});

/* The flag decides whether any of it runs. A canvas that draws a parked table
   the same as a live one is the one lie the editor could tell. */
test("a parked table is drawn as parked", async () => {
  await boot();
  await importFixture();
  const name = tableNames(MODEL)[0];
  const cards = () => $$(`.chain.parked`).length;
  assert.equal(cards(), 0);

  click(chip(name));
  await settle(60);
  click("#tbl-dormant");
  click("#tbl-save");
  await settle(150);

  const parked = MODEL.chains.filter((c) => c.table === name).length;
  assert.equal(cards(), parked, "every chain in it is loaded and filtering nothing");
  assert.ok(chip(name).classList.contains("off"), "and the header says so too");
  assert.match(chip(name).textContent, /dormant/);
});

test("renaming a table takes its chains and sets with it", async () => {
  await boot();
  await importFixture();
  const name = tableNames(MODEL)[0];
  const chains = MODEL.chains.filter((c) => c.table === name).length;
  assert.ok(chains > 0);

  click(chip(name));
  await settle(60);
  setValue("#tbl-name", "edge", "input");
  await settle(20);
  click("#tbl-save");
  await settle(150);

  const to = name.split(" ")[0] + " edge";
  assert.equal(MODEL.chains.filter((c) => c.table === to).length, chains);
  assert.ok(!tableNames(MODEL).includes(name));
});

test("a name that is already taken is refused before it is saved", async () => {
  await boot();
  await importFixture();
  const names = tableNames(MODEL);
  assert.ok(names.length >= 2, "the fixture has more than one table");

  click(chip(names[0]));
  await settle(60);
  const [family, ...rest] = names[1].split(" ");
  setValue("#tbl-family", family, "change");
  setValue("#tbl-name", rest.join(" "), "input");
  await settle(30);

  assert.equal($("#tbl-warn").style.display, "");
  assert.ok($("#tbl-save").disabled, "saving would have merged two tables into one");
});

test("a new table can be made, and it is empty", async () => {
  await boot();
  await importFixture();
  const before = tableNames(MODEL).length;

  click("[data-table-new]");
  await settle(60);
  assert.equal($("#tbl-name").value, "", "a new table starts blank");
  setValue("#tbl-family", "netdev", "change");
  setValue("#tbl-name", "on_wire", "input");
  await settle(20);
  click("#tbl-save");
  await settle(150);

  assert.equal(tableNames(MODEL).length, before + 1);
  const info = readTable(MODEL, "netdev on_wire");
  assert.equal(info.chains, 0);
  assert.equal(info.dormant, false);
  assert.ok(chip("netdev on_wire") || tableNames(MODEL).includes("netdev on_wire"));
});

/* The header shows two names and a count; the palette shows all of them, and
   the state that matters beside each. */
test("the palette lists every table and marks the parked ones", async () => {
  await boot();
  await importFixture();
  const name = tableNames(MODEL)[0];
  writeTable(MODEL, name, { dormant: true });
  const { rerender } = await import("../src/core/bus.js");
  rerender();
  await settle(80);

  const rows = $$('.cat[data-kind="TB"] .obj').map((o) => [
    o.querySelector(".nm").textContent.trim(),
    o.querySelector(".rf").textContent.trim(),
  ]);
  assert.deepEqual(rows.map((r) => r[0]), tableNames(MODEL));
  assert.equal(rows.find((r) => r[0] === name)[1], "dormant");
});

test("deleting a table asks first, and says what goes with it", async () => {
  await boot();
  await importFixture();
  const name = tableNames(MODEL)[0];
  const info = readTable(MODEL, name);

  click(chip(name));
  await settle(60);
  click("#tbl-delete");
  await settle(80);

  const asked = $("#cf-body")?.textContent || "";
  assert.match(asked, new RegExp(`\\b${info.chains}\\b`));
  assert.match(asked, new RegExp(`\\b${info.rules}\\b`));

  click("#cf-yes");
  await settle(150);
  assert.ok(!tableNames(MODEL).includes(name));
  assert.equal(MODEL.chains.filter((c) => c.table === name).length, 0);
});
