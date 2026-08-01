import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

/* The blank ruleset has input, forward and output. Getting a prerouting chain
   onto the canvas is the first thing anyone building a NAT ruleset needs, and
   dragging one out of the library used to show the no-entry cursor. */

const has = (id) => MODEL.chains.some((c) => c.id === id);

function dragFromLibrary(name, dropOn = "#cscroll") {
  const obj = $$("#lib-body .obj").find((o) => o.querySelector(".nm").textContent.trim() === name);
  if (!obj) throw new Error(`library has no "${name}"`);
  const dt = { effectAllowed: "", dropEffect: "", setData() {}, getData: () => name };
  const ev = (type, target) => {
    const e = new globalThis.window.Event(type, { bubbles: true, cancelable: true });
    e.dataTransfer = dt;
    e.clientX = 500;
    e.clientY = 300;
    target.dispatchEvent(e);
    return e;
  };
  ev("dragstart", obj);
  const over = ev("dragover", $(dropOn));
  ev("drop", $(dropOn));
  ev("dragend", obj);
  return over;
}

test("the library offers the hooks as draggable objects", async () => {
  await boot();
  await newRuleset();            // each test starts from the blank ruleset
  click('.rb[data-go="editor"]');
  const names = $$("#lib-body .obj .nm").map((n) => n.textContent.trim());
  for (const hook of ["prerouting", "postrouting"])
    assert.ok(names.includes(hook), `the library should offer ${hook}`);
});

test("dragging prerouting onto the canvas is accepted, not refused", async () => {
  await boot();
  await newRuleset();            // each test starts from the blank ruleset
  click('.rb[data-go="editor"]');
  assert.ok(!has("prerouting"), "the blank ruleset has no prerouting");

  const over = dragFromLibrary("prerouting");
  assert.ok(over.defaultPrevented, "the canvas must accept a chain — this was the no-entry cursor");
  await settle(60);

  assert.ok(has("prerouting"), "the chain was not created");
  const ch = MODEL.chains.find((c) => c.id === "prerouting");
  assert.equal(ch.hook, "prerouting");
  assert.equal(ch.table, "inet filter", "it joins the table already in play");
  assert.ok($('.chain[data-chain="inet filter/prerouting"]'), "and appears on the canvas");
});

test("postrouting too, with a policy that suits the hook", async () => {
  await boot();
  await newRuleset();            // each test starts from the blank ruleset
  click('.rb[data-go="editor"]');
  dragFromLibrary("postrouting");
  await settle(60);

  const ch = MODEL.chains.find((c) => c.id === "postrouting");
  assert.ok(ch);
  assert.equal(ch.policy, "accept", "only the hooks facing the network default to drop");
});

test("clicking a hook in the rail adds a chain there", async () => {
  await boot();
  await newRuleset();            // each test starts from the blank ruleset
  click('.rb[data-go="editor"]');
  assert.ok(!has("prerouting"));

  click('.hookrail .hk[data-hook="prerouting"]');
  await settle(60);
  assert.ok(has("prerouting"), "the rail names every hook; it should be where you add one");
});

test("dropping a hook that already exists asks instead of colliding", async () => {
  await boot();
  await newRuleset();            // each test starts from the blank ruleset
  click('.rb[data-go="editor"]');
  const before = MODEL.chains.length;

  dragFromLibrary("input"); // the blank ruleset already has one
  await settle(60);

  assert.equal(MODEL.chains.length, before, "nftables allows one chain of that name per table");
  assert.ok($("#scrim-chain").classList.contains("on"), "so it should ask what to do");
});
