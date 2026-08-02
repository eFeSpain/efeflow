import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { project, serialise, deserialise } from "../src/core/project.js";

after(shutdown);

/* Showing five ranges nobody can change, in a category advertised as "your
   ruleset", was a contradiction. Either the list is yours or it is not. */

const libNames = (kind) =>
  $$(`.cat[data-kind="${kind}"] .obj .nm`).map((n) => n.textContent.trim());

async function addVia(kind, value) {
  click(`[data-add="${kind}"]`);
  await settle(30);
  $("#cf-body input").value = value;
  click("#cf-yes");
  await settle(40);
}

test("an empty ruleset shows no invented networks", async () => {
  await boot();
  await newRuleset();
  assert.deepEqual(libNames("NW"), [], "a placeholder you cannot change is worse than an empty shelf");
});

test("a network can be kept before any rule uses it", async () => {
  await boot();
  await newRuleset();
  await addVia("NW", "10.10.0.0/24");

  assert.ok(libNames("NW").includes("10.10.0.0/24"));
  assert.ok(project.scratch.networks.includes("10.10.0.0/24"));
  const row = $$('.cat[data-kind="NW"] .obj').find((o) =>
    o.querySelector(".nm").textContent.trim() === "10.10.0.0/24");
  assert.match(row.querySelector(".rf").textContent, /unused|sin usar/,
    "and it should be honest that no rule uses it yet");
});

test("interfaces work the same way", async () => {
  await boot();
  await newRuleset();
  await addVia("IF", "eth1");
  assert.ok(libNames("IF").includes("eth1"));
  assert.ok(project.scratch.ifaces.includes("eth1"));
});

test("a kept name that a rule adopts stops being a note", async () => {
  await boot();
  await newRuleset();
  await addVia("IF", "eth1");

  click('.rb[data-go="editor"]');
  click($$("#chains .rule")[0]);
  setValue("#f-iif", "eth1", "input");
  await settle(60);

  const row = $$('.cat[data-kind="IF"] .obj').find((o) =>
    o.querySelector(".nm").textContent.trim() === "eth1");
  assert.match(row.querySelector(".rf").textContent, /rule|regla/,
    "once a rule names it, the count replaces the note");
  assert.equal(libNames("IF").filter((n) => n === "eth1").length, 1, "and it is listed once");
});

test("a kept name is saved with the project", async () => {
  await boot();
  await newRuleset();
  await addVia("NW", "192.168.7.0/24");

  const round = deserialise(serialise());
  assert.ok(round.scratch.networks.includes("192.168.7.0/24"),
    "notes belong to the project, not to the session");
});

test("an unused entry can be edited and removed", async () => {
  await boot();
  await newRuleset();
  await addVia("NW", "172.20.0.0/16");
  assert.ok(project.scratch.networks.includes("172.20.0.0/16"));

  /* the same right-click that renames a used one offers plain edit here,
     because there are no rules to keep in step */
  assert.ok(libNames("NW").includes("172.20.0.0/16"));
});

/* A name you keep is only worth keeping if the rest of the app offers it.
   ifaceNames() read the rules alone, so an interface added by hand showed up
   in the palette and nowhere else — not in the simulator, not on a rule. */
const optionValues = (sel) => $$(`${sel} option`).map((o) => o.value || o.textContent.trim());

test("an interface you keep is offered where interfaces are chosen", async () => {
  await boot();
  await newRuleset();
  await addVia("IF", "vlan99");

  assert.ok(optionValues("#dl-ifaces").includes("vlan99"),
    "the rule editor suggests interfaces from this list");
  assert.ok(optionValues("#sim-iif").includes("vlan99"),
    "and the simulator has to let you send a packet in on it");
  assert.ok(optionValues("#sim-oif").includes("vlan99"));
});

test("renaming or dropping a kept interface reaches those lists too", async () => {
  await boot();
  await newRuleset();
  await addVia("IF", "vlan99");
  assert.ok(optionValues("#sim-iif").includes("vlan99"));

  /* the lists are not part of MODEL, so nothing re-renders them on its own */
  project.scratch.ifaces.length = 0;
  const { ifaceNames } = await import("../src/app.js");
  assert.ok(!ifaceNames().includes("vlan99"), "the source of the list follows the project");
});
