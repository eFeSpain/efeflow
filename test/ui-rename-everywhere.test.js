import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, importFixture, $, $$, click, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

/* An interface or an address is a string repeated across rules, not an object
   you can open. So the operation people want is "change it everywhere", and
   without it the only route was editing every rule by hand. */

const code = () => $$("#codeout .ln .tx").map((n) => n.textContent).join("\n");

function libItem(name) {
  return $$("#lib-body .obj").find((o) => o.querySelector(".nm").textContent.trim() === name);
}

function rightClick(node) {
  const e = new globalThis.window.MouseEvent("contextmenu", {
    bubbles: true, cancelable: true, clientX: 200, clientY: 200,
  });
  node.dispatchEvent(e);
  return e;
}

test("the library separates what is yours from what is a palette", async () => {
  await boot();
  await importFixture();
  const derived = $$(".cat[data-kind='IF'] .derived, .cat[data-kind='NW'] .derived");
  assert.ok(derived.length >= 2, "interfaces and networks come from the ruleset");
  assert.equal($$(".cat[data-kind='SV'] .derived").length, 0, "services are constants");
});

test("networks are the ones the rules carry", async () => {
  await boot();
  await importFixture();
  const names = $$(".cat[data-kind='NW'] .obj .nm").map((n) => n.textContent.trim());
  assert.ok(names.includes("10.10.0.0/24"), `expected the fixture's networks, got ${names}`);
  assert.ok(!names.includes("172.16.0.0/12"), "and not invented ones");
});

test("an interface renames across every rule that names it", async () => {
  await boot();
  await importFixture();
  const before = (code().match(/"wan0"/g) || []).length;
  assert.ok(before > 2, "the fixture uses wan0 in several rules");

  rightClick(libItem("wan0"));
  assert.ok($(".ctx"), "right-clicking should offer something");
  click($('.ctx [data-act="ren"]'));
  await settle(30);

  $("#cf-body input").value = "eth0";
  click("#cf-yes");
  await settle(40);

  assert.equal(code().match(/"wan0"/g), null, "a rule was left naming the old interface");
  assert.equal((code().match(/"eth0"/g) || []).length, before, "every mention should move");
});

test("renaming is one undo away", async () => {
  await boot();
  await importFixture();
  rightClick(libItem("wan0"));
  click($('.ctx [data-act="ren"]'));
  await settle(30);
  $("#cf-body input").value = "eth0";
  click("#cf-yes");
  await settle(40);

  click("#undo");
  await settle(40);
  assert.match(code(), /"wan0"/, "undo should bring the old name back");
});

test("an address can be changed everywhere too", async () => {
  await boot();
  await importFixture();
  const item = libItem("10.10.0.0/24");
  assert.ok(item, "the fixture carries that network");

  rightClick(item);
  click($('.ctx [data-act="ren"]'));
  await settle(30);
  $("#cf-body input").value = "10.99.0.0/24";
  click("#cf-yes");
  await settle(40);

  assert.match(code(), /ip saddr 10\.99\.0\.0\/24/, "the rule should carry the new address");
  assert.equal(
    code().match(/saddr 10\.10\.0\.0\/24/),
    null,
    "and no rule should be left on the old one",
  );

  /* Deliberately bounded: an element inside a set is the set's data, edited in
     the Set Manager. The Networks category counts rule literals, so renaming
     one must not reach in and rewrite a set behind the user's back. */
  assert.match(
    code(),
    /elements = \{[^}]*10\.10\.0\.0\/24/,
    "set contents belong to the set",
  );
});

test("constants are not offered a rename they cannot honour", async () => {
  await boot();
  await importFixture();
  const ssh = libItem("ssh");
  assert.ok(ssh, "services are still a palette");
  const e = rightClick(ssh);
  assert.ok(!e.defaultPrevented, "a constant has nothing to rename");
});
