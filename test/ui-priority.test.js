/* The priority field, which is where the screen and the export could disagree.
 *
 * nft prints a priority by name — `priority filter`, `priority dstnat` — so
 * every imported base chain carries one, and a chain ordered against a
 * well-known one carries a name with an offset. The parser keeps the text as
 * written, because that is what has to go back out, and generate.js writes it
 * back in preference to the number.
 *
 * The panel read only the number, and on save wrote only the number. So the
 * text it was written with survived the edit untouched: change `priority
 * filter` to 50 and the canvas moves the chain to 50, the panel says 50, and
 * the exported ruleset still says `priority filter`, which is 0. The screen
 * and the file disagree, and nothing anywhere says so.
 *
 * It is not an edge case. It is every chain of every imported ruleset. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL, UID } from "../src/core/model.js";
import { generate } from "../src/core/generate.js";

after(shutdown);

const SRC = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept
	}

	chain late {
		type filter hook input priority filter + 10; policy drop;
		tcp dport 80 accept
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
const emitted = () => generate(MODEL).join("\n");

/** Open a chain's properties the way a user does: the card's context menu. */
async function openChain(id) {
  const card = $$(".chain").find((el) => el.dataset.chain === UID(chainOf(id)));
  assert.ok(card, `no card for ${id}`);
  const ev = new globalThis.window.MouseEvent("contextmenu", { bubbles: true, cancelable: true });
  card.dispatchEvent(ev);
  await settle(40);
  const item = $$("[data-act]").find((a) => a.dataset.act === "props");
  assert.ok(item, "the chain menu offers no properties entry");
  click(item);
  await settle(60);
}

/* ── what the field shows ────────────────────────────────────────────────── */

test("the field shows the priority as it was written, not as a number", async () => {
  await load();
  await openChain("input");
  assert.equal($("#ch-prio").value, "filter",
    "nft prints it by name, and that is the text the file has to keep");

  await openChain("late");
  assert.equal($("#ch-prio").value, "filter + 10");
});

/* ── and what saving it does ─────────────────────────────────────────────── */

test("saving a number takes the name off, so the export follows the screen", async () => {
  await load();
  await openChain("input");
  setValue("#ch-prio", "50", "input");
  click("#ch-save");
  await settle(90);

  assert.equal(chainOf("input").prio, 50);
  assert.ok(emitted().includes("priority 50;"),
    `the export still disagrees with the panel:\n${emitted()}`);
  assert.ok(!emitted().includes("priority filter;"), "the old text outlived the edit");
});

test("saving a name keeps it, and computes what it is worth", async () => {
  await load();
  await openChain("late");
  setValue("#ch-prio", "dstnat", "input");
  click("#ch-save");
  await settle(90);

  assert.equal(chainOf("late").prio, -100);
  assert.ok(emitted().includes("priority dstnat;"), emitted());
});

test("an offset can be typed, and is worth what it adds up to", async () => {
  await load();
  await openChain("input");
  setValue("#ch-prio", "srcnat + 5", "input");
  click("#ch-save");
  await settle(90);

  assert.equal(chainOf("input").prio, 105);
  assert.ok(emitted().includes("priority srcnat + 5;"), emitted());
});

/* An edit that does not touch the priority must not rewrite it either — the
   panel is opened for every other field on the chain too. */
test("editing something else leaves the priority text alone", async () => {
  await load();
  await openChain("late");
  setValue("#ch-policy", "accept", "change");
  click("#ch-save");
  await settle(90);

  assert.equal(chainOf("late").prio, 10);
  assert.ok(emitted().includes("priority filter + 10;"), emitted());
});
