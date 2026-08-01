import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

/* An interface in nftables is a name written inside a rule, not a declared
   object. Offering a closed list of six invented names meant a ruleset using
   vlan40 could not be edited without losing it. */

const code = () => $$("#codeout .ln .tx").map((n) => n.textContent).join("\n");
const firstRule = () => $$("#chains .rule")[0];

test("the interface field is free text, not a fixed list", async () => {
  await boot();
  await newRuleset();
  click('.rb[data-go="editor"]');
  click(firstRule());

  const field = $("#f-iif");
  assert.ok(field, "there should be an input interface field");
  assert.equal(field.tagName, "INPUT", "a select cannot hold a name it was not built with");
  assert.equal(field.getAttribute("list"), "dl-ifaces", "it should still suggest known names");
});

test("an interface nobody predicted can be typed in", async () => {
  await boot();
  await newRuleset();
  click('.rb[data-go="editor"]');
  click(firstRule());

  setValue("#f-iif", "vlan40", "input");
  await settle(30);
  assert.match(code(), /iifname "vlan40"/, "the name never reached the ruleset");
});

test("editing a rule does not silently drop an unfamiliar interface", async () => {
  await boot();
  await newRuleset();
  click('.rb[data-go="editor"]');
  click(firstRule());
  setValue("#f-iif", "vlan40", "input");
  await settle(30);

  // reselect, then change something unrelated
  click($$("#chains .rule")[0]);
  assert.equal($("#f-iif").value, "vlan40", "the panel must show what the rule says");
  setValue("#f-dport", "53", "input");
  await settle(30);

  assert.match(code(), /iifname "vlan40"/, "the interface was lost by editing a different field");
  assert.match(code(), /dport 53/);
});

test("the library lists the interfaces the ruleset uses", async () => {
  await boot();
  await newRuleset();
  click('.rb[data-go="editor"]');
  click(firstRule());
  setValue("#f-iif", "vlan40", "input");
  await settle(60);

  const names = $$("#lib-body .obj .nm").map((n) => n.textContent.trim());
  assert.ok(names.includes("vlan40"), `the library should follow the ruleset, got ${names.slice(0, 12)}`);
});

test("suggestions are offered without being imposed", async () => {
  await boot();
  await newRuleset();
  click('.rb[data-go="editor"]');
  click(firstRule());
  setValue("#f-iif", "vlan40", "input");
  await settle(60);

  const suggested = $$("#dl-ifaces option").map((o) => o.value);
  assert.ok(suggested.includes("vlan40"), "a name in use should become a suggestion");
  assert.ok(suggested.includes("lo"), "loopback is always worth offering");
});
