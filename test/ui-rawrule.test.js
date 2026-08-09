/* Writing nftables the panel does not model.
 *
 * The nine fields cover the nine things they cover. Everything else — a mark,
 * a verdict map, an fib lookup, a tproxy — could be imported and preserved but
 * never written, which made the editor a place to keep rules rather than a
 * place to author them. The rule line is the rule, and it is editable. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, settle } from "./harness.js";
import { MODEL, ruleLine } from "../src/core/model.js";

after(shutdown);

const RULESET = `table inet filter {
	set admins {
		type ipv4_addr
		elements = { 10.0.0.1 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept
	}

	chain ssh {
		accept
	}
}`;

async function load() {
  await newRuleset();
  const area = $("#imp-text");
  area.value = RULESET;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(90);
  click('.rb[data-go="editor"]');
  click($$("#chains .rule")[0]);
  await settle(40);
}

const theRule = () => MODEL.chains.find((c) => c.id === "input").rules[0];
const raw = () => $("#f-raw");

/* focus swaps the highlighted markup for plain text, the way the panel does */
async function type(text) {
  raw().dispatchEvent(new globalThis.window.Event("focus", { bubbles: false }));
  await settle(20);
  raw().textContent = text;
  raw().dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  await settle(20);
}
async function commit() {
  raw().dispatchEvent(new globalThis.window.Event("blur", { bubbles: false }));
  await settle(60);
}

test("the rule line is editable, and it is the rule", async () => {
  await boot();
  await load();
  assert.ok(raw(), "the hero expression should be a field");
  assert.equal(raw().getAttribute("contenteditable"), "plaintext-only");
});

/* None of this is expressible through the fields, and all of it is nftables. */
test("statements the panel cannot show can still be written", async () => {
  await boot();
  await load();
  await type('meta mark set 0x1 ip saddr @admins tcp flags syn / syn,ack counter accept');
  await commit();

  assert.equal(
    ruleLine(theRule()),
    'meta mark set 0x1 ip saddr @admins tcp flags syn / syn,ack counter accept',
  );
  assert.equal(theRule().verdict, "accept");
  assert.equal(theRule().ctr, true);
});

test("a verdict map survives being typed", async () => {
  await boot();
  await load();
  await type("tcp dport vmap { 22 : accept, 80 : drop }");
  await commit();
  assert.equal(ruleLine(theRule()), "tcp dport vmap { 22 : accept, 80 : drop }");
});

test("editing the source is one undo step", async () => {
  await boot();
  await load();
  const before = ruleLine(theRule());
  await type("udp dport 53 accept");
  await commit();
  assert.equal(ruleLine(theRule()), "udp dport 53 accept");

  click("#undo");
  await settle(60);
  assert.equal(ruleLine(MODEL.chains.find((c) => c.id === "input").rules[0]), before);
});

/* Clearing the box is not how you delete a rule, and a rule that vanished
   because a field was emptied is a very expensive thing to miss. */
test("emptying the box leaves the rule alone", async () => {
  await boot();
  await load();
  const before = ruleLine(theRule());
  await type("   ");
  await commit();
  assert.equal(ruleLine(theRule()), before);
});

test("a comment survives an edit to the source, because the source cannot carry it", async () => {
  await boot();
  await load();
  MODEL.chains.find((c) => c.id === "input").rules[0].cmt = "management plane";
  click($$("#chains .rule")[0]);
  await settle(40);

  await type("tcp dport 2222 accept");
  await commit();
  assert.equal(theRule().cmt, "management plane");
});

/* The handle used to go with the edit, on the grounds that `nft replace` did
 * not keep it either. Measured on nft 1.1.3: it does — a rule replaced at
 * handle 4 is still handle 4 afterwards; only its counters restart. Dropping
 * it cost three things, and all three showed up in one screen when the apply
 * dialog was driven against a real firewall: the rule stopped pairing with its
 * own copy on the host, so an edit was drawn as a deletion and an unrelated
 * addition; the drift warning read that deletion as somebody else having added
 * a rule since you looked, which nobody had; and the surgical apply had to
 * spend a delete and an insert on what nftables does in one replace. */
test("the handle survives an edit, because nft replace keeps it", async () => {
  await boot();
  await load();
  const r = theRule();
  r.handle = 7;
  r.pkts = 4200;
  r.bytes = 260000;
  click($$("#chains .rule")[0]);
  await settle(40);

  await type("tcp dport 8443 accept");
  await commit();

  assert.equal(theRule().handle, 7, "an edited rule can no longer be replaced where it lives");
  /* the counters described the rule as it was, and those really do restart */
  assert.ok(!theRule().pkts, "the old rule's traffic was carried onto a different rule");
});

test("a rule typed from nothing still has no handle to keep", async () => {
  await boot();
  await load();
  const r = theRule();
  delete r.handle;
  click($$("#chains .rule")[0]);
  await settle(40);
  await type("tcp dport 9090 accept");
  await commit();
  assert.equal(theRule().handle, undefined, "a handle was invented for a rule no host has");
});

test("a rule nft would refuse says so while you type it", async () => {
  await boot();
  await load();
  await type('tcp dport 22 prefix "ssh " jump nowhere');

  const said = $$("#f-raw-lint .raw-lint").map((n) => n.textContent.trim());
  assert.equal(said.length, 2, said.join(" | "));
  assert.ok(said.some((s) => /log/i.test(s)), said.join(" | "));
  assert.ok(said.some((s) => /nowhere/.test(s)), said.join(" | "));
  assert.ok(raw().classList.contains("bad"));
});

test("a rule that loads says nothing", async () => {
  await boot();
  await load();
  await type("tcp dport 22 jump ssh");
  assert.deepEqual($$("#f-raw-lint .raw-lint"), []);
  assert.ok(!raw().classList.contains("bad"));
});
