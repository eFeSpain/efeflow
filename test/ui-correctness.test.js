/* Two fixes that only show through the real interface: the Problems drawer tab
 * (which threw a ReferenceError and blanked itself), and a set reference that
 * must not match a longer name it is a prefix of. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, importFixture, $, $$, click, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

test("the Problems drawer tab renders instead of throwing", async () => {
  const { errors } = await boot();
  await importFixture();               /* the demo ruleset carries defects */
  click('[data-dw="problems"]');
  await settle(30);
  assert.ok($("#dw-problems").textContent.trim().length > 0,
    "the Problems tab rendered nothing — it used to throw on an undefined name");
  assert.deepEqual(errors, [], "no exception escaped opening the tab");
});

const REFS = `table inet filter {
	set blocklist { type ipv4_addr ; elements = { 10.0.0.1 } }
	set blocklist_v6 { type ipv6_addr ; elements = { 2001:db8::1 } }
	chain input {
		type filter hook input priority filter; policy drop;
		ip saddr @blocklist drop
		ip6 saddr @blocklist_v6 drop
	}
}`;

async function loadRefs() {
  await newRuleset();
  const area = $("#imp-text");
  area.value = REFS;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(90);
}

test("a set reference does not match a longer name it prefixes", async () => {
  await boot();
  await loadRefs();
  const { refsTo } = await import("../src/ui/sets.js");
  const hits = refsTo("blocklist", "inet filter");
  assert.equal(hits.length, 1, "@blocklist matched @blocklist_v6 as well");
  assert.match(hits[0].r.expr, /@blocklist\b/);
  assert.doesNotMatch(hits[0].r.expr, /_v6/);
  /* and the longer name resolves only to its own rule */
  assert.equal(refsTo("blocklist_v6", "inet filter").length, 1);
});
