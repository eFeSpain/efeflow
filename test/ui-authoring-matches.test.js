/* The match and log fields the panel learned to show.
 *
 * core/expr.js proves the string surgery for icmp type, tcp flags, the
 * firewall mark and the log prefix/level in isolation; ui-props proves the
 * older fields are wired to it. This proves the new ones are controls too, and
 * that each edits its own fragment through the real interface. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

/* Five rules, each carrying one of the things the fields learned to read. */
const RULESET = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ip protocol icmp icmp type echo-request accept
		tcp dport 22 tcp flags syn / syn,ack accept
		meta mark 0x1 accept
		udp dport 53 log prefix "dns " level info accept
		tcp dport 80 log group 2 accept
	}
}`;

async function load(i) {
  await newRuleset();
  const area = $("#imp-text");
  area.value = RULESET;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(90);
  click('.rb[data-go="editor"]');
  click($$("#chains .rule")[i]);
  await settle(40);
}
const rule = (i) => MODEL.chains[0].rules[i];

test("the ICMP type is read from the rule and written back to it", async () => {
  await boot();
  await load(0);
  assert.equal($("#f-icmptype").value, "echo-request");

  setValue("#f-icmptype", "echo-reply", "input");
  await settle(40);
  assert.match(rule(0).expr, /icmp type echo-reply/);
});

test("editing the port leaves a tcp-flags match standing", async () => {
  await boot();
  await load(1);
  assert.equal($("#f-tcpflags").value, "syn / syn,ack");

  setValue("#f-dport", "2222", "input");
  await settle(40);
  assert.match(rule(1).expr, /tcp dport 2222/, "the edit itself");
  assert.match(rule(1).expr, /tcp flags syn \/ syn,ack/, "the flag match the panel now shows survives");
});

test("the firewall mark is a control", async () => {
  await boot();
  await load(2);
  assert.equal($("#f-metamark").value, "0x1");

  setValue("#f-metamark", "0x10", "input");
  await settle(40);
  assert.match(rule(2).expr, /meta mark 0x10/);
});

test("the log prefix and level edit one without disturbing the other", async () => {
  await boot();
  await load(3);
  assert.equal($("#f-logprefix").value, "dns ");
  assert.equal($("#f-loglevel").value, "info");

  setValue("#f-logprefix", "resolver ", "input");
  await settle(40);
  assert.match(rule(3).expr, /log prefix "resolver "/, "the prefix changed");
  assert.match(rule(3).expr, /level info/, "and the level stayed");

  setValue("#f-loglevel", "warn", "change");
  await settle(40);
  assert.match(rule(3).expr, /level warn/, "the level changed");
  assert.match(rule(3).expr, /prefix "resolver "/, "and the prefix stayed");
});

/* nftables refuses a log that is both nflog (group) and syslog (level), so the
   panel does not offer a level to add to one. */
test("a log to an nflog group offers no level field", async () => {
  await boot();
  await load(4);
  assert.ok($("#f-logprefix"), "the prefix is still editable alongside a group");
  assert.equal($("#f-loglevel"), null, "but there is no level to conflict with the group");
});
