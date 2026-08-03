/* Opening a panel and saving it unchanged must change nothing.
 *
 * That is the whole invariant, and it is stronger than it looks. Every field
 * on the chain panel is a round trip of its own: the model holds the text nft
 * wrote, the panel unwraps it into a control, and saving wraps it back. Any
 * asymmetry between the unwrapping and the wrapping is a silent edit — the
 * user opened a dialog to read it and the file changed underneath.
 *
 * `edit()` records a snapshot either way, so it is not even visible as an
 * unexpected undo step: it looks exactly like a change that was asked for.
 *
 * The priority field was the first of these found, and it was the worst
 * because it changed what the ruleset does. These are the rest of the fields
 * on the same panel, held to the same rule. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, settle } from "./harness.js";
import { MODEL, UID } from "../src/core/model.js";
import { generate } from "../src/core/generate.js";

after(shutdown);

const SRC = `table netdev wire {
	chain ing {
		type filter hook ingress device "wan0" priority -500; policy accept;
		comment "watches the uplink"
		ip saddr 203.0.113.0/24 drop
	}

	chain pair {
		type filter hook ingress devices = { eth0, br0 } priority -400; policy accept;
		ip saddr 198.51.100.0/24 drop
	}
}

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		comment "the front door"
		flags offload
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
  await settle(120);
}

const chainOf = (id) => MODEL.chains.find((c) => c.id === id);
const emitted = () => generate(MODEL).join("\n");

async function openChain(id) {
  const card = $$(".chain").find((el) => el.dataset.chain === UID(chainOf(id)));
  assert.ok(card, `no card for ${id}`);
  card.dispatchEvent(new globalThis.window.MouseEvent("contextmenu",
    { bubbles: true, cancelable: true }));
  await settle(40);
  const item = $$("[data-act]").find((a) => a.dataset.act === "props");
  assert.ok(item, "the chain menu offers no properties entry");
  click(item);
  await settle(60);
}

/** open, save, and say what moved */
async function openAndSave(id) {
  const before = emitted();
  await openChain(id);
  click("#ch-save");
  await settle(90);
  return { before, after: emitted() };
}

/* ── the invariant, one chain at a time ──────────────────────────────────── */

for (const id of ["ing", "pair", "input"])
  test(`opening ${id} and saving it unchanged changes nothing`, async () => {
    await load();
    const { before, after } = await openAndSave(id);
    assert.equal(after, before,
      `the panel rewrote the chain:\n--- before\n${before}\n--- after\n${after}`);
  });

/* ── and what each field was doing ───────────────────────────────────────── */

/* `/^comments+"?/` is `comment` followed by one or more `s`, which is a lost
   `\s`. So the prefix was never stripped, the field showed `comment "the
   front door` — quote and all — and saving wrote that back inside another
   comment. Twice through the dialog and the comment has grown two prefixes. */
test("the comment field holds the comment, not the line it came from", async () => {
  await load();
  await openChain("input");
  assert.equal($("#ch-comment").value, "the front door");
});

test("and it survives being saved twice", async () => {
  await load();
  await openAndSave("input");
  const once = emitted();
  await openAndSave("input");
  assert.equal(emitted(), once, "the comment grew on the second pass");
  assert.ok(emitted().includes('comment "the front door"'), emitted());
});

/* A device list is held verbatim because that is what has to go back out. The
   panel unwraps it to a plain list for the field and wraps it again on save,
   and the two have to agree about quoting and about which form to use. */
test("a single device keeps its form", async () => {
  await load();
  await openChain("ing");
  assert.equal($("#ch-dev").value, "wan0");
  click("#ch-save");
  await settle(90);
  assert.ok(emitted().includes('device "wan0"'), emitted());
});

test("a device list keeps its form too", async () => {
  await load();
  await openChain("pair");
  assert.equal($("#ch-dev").value, "eth0, br0");
  click("#ch-save");
  await settle(90);
  assert.ok(emitted().includes("devices = { eth0, br0 }"), emitted());
});

/* `flags offload` and `comment` are the two statements the panel owns; every
   other chain-level line is held verbatim in `extra` and must come back in the
   place it was written, not appended after whatever the panel rebuilt. */
test("a chain statement the panel does not own keeps its place", async () => {
  await load();
  const input = chainOf("input");
  input.extra.push("flags dormant-ish");           /* not one the panel knows */
  await openAndSave("input");
  assert.ok(chainOf("input").extra.includes("flags dormant-ish"),
    `it was dropped: ${JSON.stringify(chainOf("input").extra)}`);
});

/* ── the flag the panel owns ─────────────────────────────────────────────── */

/* The pattern behind this toggle had `\b` saved as the byte it escapes, so it
   matched nothing: the switch read as off on every imported chain that carried
   the flag, and saving then took the flag out. Hardware offload turned off by
   opening a dialog and pressing Save. */
test("the offload switch reads the flag the chain has", async () => {
  await load();
  await openChain("input");
  assert.ok($("#ch-offload").classList.contains("on"),
    "the chain has `flags offload` and the switch says it does not");
});

test("and turning it off takes out the flag, not the line's companions", async () => {
  await load();
  chainOf("input").extra = ["flags offload,foo"];
  await openChain("input");
  assert.ok($("#ch-offload").classList.contains("on"));
  click("#ch-offload");                       /* the global handler flips it */
  click("#ch-save");
  await settle(90);
  assert.deepEqual(chainOf("input").extra, ["flags foo"]);
});
