/* The canvas, once netdev became something the model has.
 *
 * The whole claim of this screen is that position is meaning: a chain sits at
 * the hook it is attached to, left to right in the order a packet meets them,
 * and you read evaluation order off the screen instead of reconstructing it.
 *
 * `ingress` and `egress` had columns of their own — that much was thought
 * through before the simulator could walk them at all. What they did not have
 * was a wire to anything, so a netdev chain sat on the canvas beside the path
 * rather than on it, and the order the screen showed was not the order the
 * kernel takes. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, settle } from "./harness.js";
import { MODEL, UID } from "../src/core/model.js";

after(shutdown);

const SRC = `table netdev on_wire {
	chain ingress {
		type filter hook ingress device "wan0" priority -500; policy accept;
		ip saddr 203.0.113.0/24 drop
	}
}

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related accept
	}

	chain postrouting {
		type filter hook postrouting priority srcnat; policy accept;
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

test("the ruleset arrives with its netdev chain attached", async () => {
  await load();
  const ing = MODEL.chains.find((c) => c.id === "ingress");
  assert.ok(ing, "the chain is not in the model");
  assert.equal(ing.hook, "ingress");
  assert.equal(ing.prio, -500);
  assert.ok(/wan0/.test(ing.dev || ""), `the device was lost: ${ing.dev}`);
});

test("the hook rail grows a column for it, before prerouting", async () => {
  await load();
  const hooks = $$(".hookrail .hk").map((h) => h.dataset.hook);
  assert.ok(hooks.includes("ingress"), `no ingress column: ${hooks.join(" ")}`);
  assert.ok(hooks.indexOf("ingress") < hooks.indexOf("prerouting"),
    `ingress is not first: ${hooks.join(" ")}`);
});

test("and the chain card is drawn in it", async () => {
  await load();
  const card = $$(".chain").find((el) => el.dataset.chain === UID(MODEL.chains.find((c) => c.id === "ingress")));
  assert.ok(card, "the chain has no card on the canvas");
});

/* The wires are the path. A column with no wire into it is a chain the screen
   shows and does not place in the order the packet takes. */
test("a wire joins ingress to the rest of the path", async () => {
  await load();
  const wires = $$("#wires path").length;
  /* ingress → input, ingress → forward, forward → postrouting. Nothing sits
     at prerouting in this ruleset, and the line has to carry on past it: a
     pair that only drew when both its hooks had chains left most filter-only
     rulesets with no wires between hooks at all. */
  assert.ok(wires >= 3, `only ${wires} wires drawn for four hooks in use`);
});

test("an empty hook in the middle does not break the line", async () => {
  await load();
  const before = $$("#wires path").length;
  assert.ok(!MODEL.chains.some((c) => c.hook === "prerouting"),
    "this ruleset is supposed to have nothing at prerouting");
  assert.ok(before > 0, "the path stopped at the gap");
});

/* The simulator walks ingress before prerouting; the canvas has to agree, or
   one of the two is lying about the order. */
test("the screen and the simulator order the hooks the same way", async () => {
  await load();
  const { PATHS } = await import("../src/core/simulate.js");
  const hooks = $$(".hookrail .hk").map((h) => h.dataset.hook);
  const walked = PATHS.in.flat();
  const onScreen = hooks.filter((h) => walked.includes(h));
  assert.deepEqual(onScreen, walked.filter((h) => hooks.includes(h)),
    "the columns are not in the order the packet meets them");
});
