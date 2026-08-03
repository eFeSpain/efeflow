/* Renaming a chain to `log` and watching the export die.
 *
 * The core test for this lives in `names.test.js`; this one is here because
 * the finding arrives too late to be the whole answer. By the time the
 * analyser reports it the chain exists, the canvas has drawn it, and the file
 * that will not load looks finished — and a name is the one property a user
 * changes without expecting consequences.
 *
 * So the panel refuses it, and the refusal has to leave the model exactly as
 * it was. A half-applied save is worse than the name.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL, UID } from "../src/core/model.js";

after(shutdown);

const SRC = `table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		tcp dport 22 accept
	}
}`;

async function load() {
  await boot();
  await newRuleset();
  const area = $("#imp-text");
  area.value = SRC;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(90);
  click('.rb[data-go="editor"]');
  await settle(60);
}

const chainOf = (id) => MODEL.chains.find((c) => c.id === id);

async function openChain(id) {
  const card = $$(".chain").find((el) => el.dataset.chain === UID(chainOf(id)));
  assert.ok(card, `no card for ${id}`);
  card.dispatchEvent(new globalThis.window.MouseEvent("contextmenu",
    { bubbles: true, cancelable: true }));
  await settle(40);
  const item = $$("[data-act]").find((a) => a.dataset.act === "props");
  click(item);
  await settle(60);
}

test("a chain cannot be renamed to a word nftables keeps", async () => {
  await load();
  await openChain("input");
  setValue("#ch-name", "log", "input");
  click("#ch-save");
  await settle(90);

  assert.ok(chainOf("input"), "the chain is still called what it was called");
  assert.equal(MODEL.chains.some((c) => c.id === "log"), false, "and nothing is called log");
  assert.equal(MODEL.chains.length, 1, "nor was a second chain made");
});

test("the panel stays open on the name, so the next attempt is one word away", async () => {
  await load();
  await openChain("input");
  setValue("#ch-name", "ct", "input");
  click("#ch-save");
  await settle(90);

  assert.ok($("#scrim-chain").classList.contains("on"), "the dialog closed on a refusal");
  assert.equal($("#ch-name").value, "ct", "and it threw away what was typed");
});

test("a name it has no quarrel with saves as it always did", async () => {
  await load();
  await openChain("input");
  setValue("#ch-name", "wan_in", "input");
  click("#ch-save");
  await settle(90);

  assert.ok(chainOf("wan_in"), "the rename went through");
  assert.equal(chainOf("wan_in").rules.length, 1, "with its rule");
  assert.equal($("#scrim-chain").classList.contains("on"), false, "and the dialog closed");
});
