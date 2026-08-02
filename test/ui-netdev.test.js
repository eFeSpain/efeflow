/* netdev chains, sets you can configure, and maps you can make.
 *
 * All three could be imported and carried through untouched, and none of them
 * could be written. A designer you cannot design in is a viewer. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";
import { generate } from "../src/core/generate.js";

after(shutdown);

const code = () => generate(MODEL).join("\n");

async function newChain(fields) {
  click("#chain-new");
  await settle(40);
  for (const [id, value] of Object.entries(fields)) setValue("#" + id, value, "input");
  await settle(40);
  return $("#ch-warn");
}

test("an ingress chain can be written, and it names its device", async () => {
  await boot();
  await newRuleset();

  await newChain({ "ch-name": "ddos", "ch-table": "netdev guard", "ch-hook": "ingress" });
  assert.notEqual($("#ch-dev-fld").style.display, "none", "the device field has to appear");
  assert.equal($("#ch-save").disabled, true, "and nft will not take the chain without one");

  setValue("#ch-dev", "eth0", "input");
  await settle(40);
  assert.equal($("#ch-save").disabled, false);
  click("#ch-save");
  await settle(60);

  assert.match(code(), /type filter hook ingress device "eth0" priority \d+;/);
});

test("more than one device is a devices list", async () => {
  await boot();
  await newRuleset();
  await newChain({ "ch-name": "ddos2", "ch-table": "netdev guard", "ch-hook": "ingress",
                   "ch-dev": "eth0, eth1" });
  click("#ch-save");
  await settle(60);
  assert.match(code(), /hook ingress devices = \{ eth0, eth1 \}/);
});

/* The ingress hook does not exist outside a netdev table, and saying so before
   the ruleset reaches nft is the whole point of having the dialog. */
test("an ingress chain in the wrong family is refused with the reason", async () => {
  await boot();
  await newRuleset();
  const warn = await newChain({ "ch-name": "x", "ch-table": "inet filter", "ch-hook": "ingress",
                                "ch-dev": "eth0" });
  assert.equal($("#ch-save").disabled, true);
  assert.match(warn.textContent, /netdev/);
});

/* Before this the canvas had five fixed columns and an ingress chain was drawn
   on top of prerouting. */
test("the netdev hooks take a column only when something is attached to one", async () => {
  await boot();
  await newRuleset();
  assert.deepEqual($$(".hookrail .hk").map((n) => n.dataset.hook),
    ["prerouting", "input", "forward", "output", "postrouting"]);

  await newChain({ "ch-name": "ddos3", "ch-table": "netdev guard", "ch-hook": "ingress",
                   "ch-dev": "eth0" });
  click("#ch-save");
  await settle(80);
  assert.deepEqual($$(".hookrail .hk").map((n) => n.dataset.hook),
    ["ingress", "prerouting", "input", "forward", "output", "postrouting"]);
});

test("a map can be made, not only imported", async () => {
  await boot();
  await newRuleset();
  click('.rb[data-go="sets"]');
  await settle(60);
  click("#map-new");
  await settle(60);

  const m = MODEL.sets.at(-1);
  assert.equal(m.kind, "map");
  assert.match(m.t, /:/, "a map's type is a key and a value");
  assert.ok($("#set-vtype"), "and both halves are editable");

  setValue("#set-vtype", "verdict", "change");
  await settle(40);
  assert.match(MODEL.sets.at(-1).t, /: verdict$/, "which is what makes a verdict map");
  assert.match(code(), /map new_map_1 \{/);
});

/* size, timeout, gc-interval, policy and auto-merge were carried through an
   import untouched and could not be changed, nor given to a new set. */
test("the set attributes nftables has are fields", async () => {
  await boot();
  await newRuleset();
  click('.rb[data-go="sets"]');
  await settle(60);
  click("#set-new");
  await settle(60);

  setValue("#set-a-timeout", "1h", "change");
  setValue("#set-a-size", "65536", "change");
  await settle(40);
  click("#set-a-automerge");
  await settle(40);

  const out = code();
  assert.match(out, /^\s*timeout 1h$/m);
  assert.match(out, /^\s*size 65536$/m);
  assert.match(out, /^\s*auto-merge$/m);
  assert.ok(out.indexOf("timeout 1h") < out.indexOf("elements") || !out.includes("elements"),
    "nft wants the attributes before the elements");
});
