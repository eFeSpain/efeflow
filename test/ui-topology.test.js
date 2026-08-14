/* The topology, through the real interface: the graph logic is proven in
 * topology.test.js; this proves the canvas wears it — an unreachable chain is
 * marked, the wires carry direction, a simulated packet lights its path, and an
 * empty ruleset says so rather than showing a blank. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, importFixture, $, $$, click, settle, until } from "./harness.js";
import { MODEL, UID } from "../src/core/model.js";

after(shutdown);

const RULESET = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 jump ssh
	}

	chain ssh {
		tcp dport 22 accept
	}

	chain orphan {
		tcp dport 80 accept
	}
}`;

async function load() {
  await boot();
  await newRuleset();
  const area = $("#imp-text");
  area.value = RULESET;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(90);
  click('.rb[data-go="editor"]');
  await settle(120);
}

const cardOf = (id) =>
  $$(".chain").find((el) => el.dataset.chain === UID(MODEL.chains.find((c) => c.id === id)));

test("a regular chain nobody jumps to is marked unreachable", async () => {
  await load();
  const orphan = cardOf("orphan");
  assert.ok(orphan, "the orphan chain has a card");
  assert.ok(orphan.classList.contains("unreachable"), "and it is flagged unreachable");
  assert.ok($(".chip.dead", orphan), "with an unreachable chip");
  /* a chain reached by a jump is not flagged */
  assert.ok(!cardOf("ssh").classList.contains("unreachable"),
    "a chain reached by a jump is not called unreachable");
});

test("the wires carry arrowheads", async () => {
  await load();
  assert.ok($("#wires marker"), "arrowhead markers are defined in the wire layer");
});

test("an empty ruleset says so instead of showing a blank canvas", async () => {
  await boot();
  /* imported after boot so the canvas module's setup runs against a live DOM */
  const { renderChains } = await import("../src/ui/canvas.js");
  MODEL.chains.length = 0;
  renderChains();
  assert.ok($(".empty-canvas"), "an empty canvas carries a message");
});

test("a simulated packet lights the chains on its path", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="sim"]');
  await until(() => $$("#lane .hop").length > 0);
  await settle(40);
  assert.ok($$(".chain.hot").length > 0, "the topology lights the chains the packet entered");
});
