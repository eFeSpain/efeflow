/* A set the type control cannot represent is a set it must not damage.
 *
 * The control was a list of seven scalar types. On a set declared `typeof ip
 * saddr . tcp dport` it showed the whole expression as an extra option, and
 * picking anything from the list left the `typeof` keyword in front of a type
 * name — `typeof ipv4_addr`, which nft rejects. The editor could break a set
 * it had no way of expressing. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";
import { generate } from "../src/core/generate.js";

after(shutdown);

const code = () => generate(MODEL).join("\n");

const RULESET = `table inet filter {
	set plain {
		type ipv4_addr
		elements = { 10.0.0.1 }
	}

	set conns {
		typeof ip saddr . tcp dport
		elements = { 10.0.0.1 . 22 }
	}

	set pairs {
		type ipv4_addr . inet_service
		elements = { 10.0.0.1 . 22 }
	}
}`;

async function load() {
  await newRuleset();
  const area = $("#imp-text");
  area.value = RULESET;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(100);
  click('.rb[data-go="sets"]');
  await settle(80);
}
const pick = (n) => { click($$(".set-item")[MODEL.sets.findIndex((s) => s.n === n)]); return settle(60); };

test("a plain scalar type is still a list to pick from", async () => {
  await boot();
  await load();
  await pick("plain");
  assert.equal($("#set-type").tagName, "SELECT");
});

/* Both are expressions, not names out of a list. */
test("a typeof and a concatenation are edited as what they are", async () => {
  await boot();
  await load();

  await pick("conns");
  assert.equal($("#set-type").tagName, "INPUT", "a typeof expression is not a name from a list");
  assert.equal($("#set-type").value, "ip saddr . tcp dport");

  await pick("pairs");
  assert.equal($("#set-type").tagName, "INPUT", "nor is a concatenation");
  assert.equal($("#set-type").value, "ipv4_addr . inet_service");
});

test("editing one keeps the keyword it was declared with", async () => {
  await boot();
  await load();
  await pick("conns");

  setValue("#set-type", "ip saddr . udp dport", "change");
  await settle(60);
  assert.match(code(), /typeof ip saddr \. udp dport/);
  assert.doesNotMatch(code(), /type ipv4_addr\b.*\n.*typeof/, "the keyword did not change");
});

/* The keyword is the thing that decides whether the value is a name or an
   expression, so it has to be something you can set. */
test("type and typeof can be switched between", async () => {
  await boot();
  await load();
  await pick("plain");
  assert.ok($("#set-decl"), "no way to say which of the two this is");

  click('#set-decl [data-decl="typeof"]');
  await settle(80);
  assert.equal($("#set-type").tagName, "INPUT", "typeof takes an expression");
  assert.match(code(), /typeof ipv4_addr/, "and keeps what was there until you change it");

  click('#set-decl [data-decl="type"]');
  await settle(80);
  assert.equal($("#set-type").tagName, "SELECT");
  assert.match(code(), /^\s*type ipv4_addr$/m);
});

test("a map with a concatenated key still has both halves", async () => {
  await boot();
  await newRuleset();
  const area = $("#imp-text");
  area.value = `table inet filter {
	map fwd {
		typeof ip saddr . tcp dport : verdict
		elements = { 10.0.0.1 . 22 : accept }
	}
}`;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(100);
  click('.rb[data-go="sets"]');
  await settle(80);
  click($$(".set-item")[0]);
  await settle(60);

  assert.equal($("#set-type").value, "ip saddr . tcp dport");
  assert.equal($("#set-vtype").value, "verdict");
  setValue("#set-type", "ip saddr . udp dport", "change");
  await settle(60);
  assert.match(code(), /typeof ip saddr \. udp dport : verdict/);
});
