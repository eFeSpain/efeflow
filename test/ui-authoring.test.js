import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, importFixture, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

const code = () => $$("#codeout .ln .tx").map((n) => n.textContent).join("\n");
const chainNamed = (id) => MODEL.chains.find((c) => c.id === id);

/* You could edit rules but never create the chain to hold them, and a set you
   had just made could not be corrected. Both made a ruleset impossible to
   build from scratch — which is the only way the app now opens. */

test("a base chain can be created on any hook", async () => {
  await boot();
  click("#chain-new");
  assert.ok($("#scrim-chain").classList.contains("on"));

  setValue("#ch-name", "nat_pre", "input");
  setValue("#ch-table", "ip nat", "input");
  setValue("#ch-type", "nat");
  setValue("#ch-hook", "prerouting");
  setValue("#ch-prio", "-100", "input");
  click("#ch-save");
  await settle(40);

  const ch = chainNamed("nat_pre");
  assert.ok(ch, "the chain was not created");
  assert.equal(ch.table, "ip nat");
  assert.equal(ch.hook, "prerouting");
  assert.equal(ch.prio, -100);
  assert.match(code(), /table ip nat/);
  assert.match(code(), /hook prerouting priority -100/);
});

test("priorities can be given by name", async () => {
  await boot();
  click("#chain-new");
  setValue("#ch-name", "mangle_pre", "input");
  setValue("#ch-table", "inet filter", "input");
  setValue("#ch-prio", "mangle", "input");
  click("#ch-save");
  await settle(40);
  assert.equal(chainNamed("mangle_pre").prio, -150, "the named priority was not resolved");
});

test("a duplicate chain name in the same table is refused", async () => {
  await boot();
  await newRuleset();          /* nothing is open at boot, so there is nothing to clash with */
  click("#chain-new");
  setValue("#ch-name", "input", "input");
  setValue("#ch-table", "inet filter", "input");
  assert.ok($("#ch-save").disabled, "nftables allows one chain of that name per table");
  assert.notEqual($("#ch-warn").style.display, "none", "and it should say why");
});

test("a nat chain cannot be attached to the forward hook", async () => {
  await boot();
  click("#chain-new");
  setValue("#ch-name", "bad", "input");
  setValue("#ch-table", "ip nat", "input");
  setValue("#ch-type", "nat");
  setValue("#ch-hook", "forward");
  assert.ok($("#ch-save").disabled);
});

test("a regular chain drops the hook fields", async () => {
  await boot();
  click("#chain-new");
  click('#ch-kind [data-kind="regular"]');
  assert.equal($("#ch-base").style.display, "none");

  setValue("#ch-name", "fwd_mgmt", "input");
  setValue("#ch-table", "inet filter", "input");
  click("#ch-save");
  await settle(40);

  const ch = chainNamed("fwd_mgmt");
  assert.equal(ch.hook, null, "a regular chain has no hook");
  assert.ok(!/chain fwd_mgmt \{\s*type/.test(code()), "and emits no type line");
});

test("a set can be renamed, and the rules that use it follow", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="sets"]');
  click($$(".set-item")[0]); // @admin_nets

  const usedBefore = code().match(/@admin_nets/g)?.length ?? 0;
  assert.ok(usedBefore > 1, "the fixture should reference it from several rules");

  setValue("#set-name", "trusted_nets");
  await settle(40);

  assert.ok(MODEL.sets.some((s) => s.n === "trusted_nets"));
  assert.equal(code().match(/@admin_nets/g), null, "a stale reference points at nothing");
  assert.equal(code().match(/@trusted_nets/g).length, usedBefore, "every reference should follow");
});

test("a set element can be edited in place", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="sets"]');
  click($$(".set-item")[0]);

  const first = $("[data-edit='0']");
  assert.ok(first, "elements should be editable, not just removable");
  setValue("[data-edit='0']", "10.99.0.0/16");
  await settle(40);
  assert.equal(MODEL.sets[0].el[0], "10.99.0.0/16");
});

test("type and flags are editable, and reach the generated code", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="sets"]');
  click($$(".set-item")[1]); // @mgmt_ports

  setValue("#set-type", "inet_service");
  click("#set-flags [data-flag='timeout']");
  await settle(40);
  assert.match(MODEL.sets[1].f, /timeout/);
  assert.match(code(), /flags[^\n]*timeout/);
});

test("a set nobody uses can be deleted; one in use cannot", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="sets"]');

  const items = $$(".set-item");
  const unused = items.findIndex((n) => /cdn_edges/.test(n.textContent));
  assert.ok(unused >= 0, "the fixture carries an unused set");

  click(items[unused]);
  assert.ok(!$("#set-del").disabled, "an unreferenced set should be deletable");
  const n = MODEL.sets.length;
  click("#set-del");
  await settle(40);
  assert.equal(MODEL.sets.length, n - 1);

  click($$(".set-item")[0]); // @admin_nets, heavily referenced
  assert.ok($("#set-del").disabled, "a referenced set must not be silently removable");
});
