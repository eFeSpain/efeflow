/* The properties panel, through the real interface.
 *
 * core/expr.js proves the string surgery in isolation. This proves the panel
 * is wired to it — and that the controls it draws are controls. Several of
 * them were painted from the rule and connected to nothing at all, which is a
 * worse lie than a missing feature: the switch moves and the rule does not. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL, ruleLine } from "../src/core/model.js";

after(shutdown);

/* One rule, holding four statements the panel cannot show and two it can. */
const RICH = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ip6 saddr @admins tcp dport 22 tcp flags syn / syn,ack log prefix "ssh " limit rate 3/minute burst 3 packets accept
	}
}`;

async function loadRich() {
  await newRuleset();
  const area = $("#imp-text");
  area.value = RICH;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(90);
  click('.rb[data-go="editor"]');
  click($$("#chains .rule")[0]);
  await settle(40);
}

const theRule = () => MODEL.chains[0].rules[0];

test("typing a comment does not cost you the rest of the rule", async () => {
  await boot();
  await loadRich();
  const before = theRule().expr;

  setValue("#f-cmt", "why this rule exists", "input");
  await settle(40);

  assert.equal(theRule().expr, before,
    "the comment box rewrote the match expression");
  assert.equal(theRule().cmt, "why this rule exists");
});

test("editing one match field leaves the statements around it standing", async () => {
  await boot();
  await loadRich();

  setValue("#f-dport", "2222", "input");
  await settle(40);

  const e = theRule().expr;
  assert.match(e, /ip6 saddr @admins/, "the IPv6 family and the set reference");
  assert.match(e, /tcp dport 2222/, "the edit itself");
  assert.match(e, /tcp flags syn \/ syn,ack/, "the flag match");
  assert.match(e, /log prefix "ssh "/, "the log prefix");
  assert.match(e, /burst 3 packets/, "the burst");
});

test("the conntrack chips are controls", async () => {
  await boot();
  await loadRich();
  assert.equal($$('#f-state [data-ct]').length, 5, "five conntrack states to pick from");

  click('#f-state [data-ct="new"]');
  await settle(40);
  assert.match(theRule().expr, /ct state new/);

  click('#f-state [data-ct="new"]');
  await settle(40);
  assert.doesNotMatch(theRule().expr, /ct state/, "clicking it again takes it back off");
});

test("the counter toggle counts, and reads from whether it counts", async () => {
  await boot();
  await loadRich();
  assert.equal(theRule().ctr, false);

  click("#f-ctr");
  await settle(40);
  assert.equal(theRule().ctr, true);
  assert.match(ruleLine(theRule()), /counter/);
});

test("the log toggle removes the prefix along with the log", async () => {
  await boot();
  await loadRich();
  click("#f-log");
  await settle(40);
  assert.doesNotMatch(theRule().expr, /\blog\b/);
  assert.doesNotMatch(theRule().expr, /prefix/,
    "a dangling prefix is a rule nft will not load");
});

/* A jump with nowhere to jump to emits `jump undefined`. The field used to
   appear only when the rule already carried a target. */
test("changing the verdict to one that needs a target offers the field", async () => {
  await boot();
  await loadRich();
  assert.equal($("#f-to"), null, "an accept has no target");

  setValue("#f-verdict", "jump", "change");
  await settle(60);
  assert.ok($("#f-to"), "a jump must be able to say where");

  setValue("#f-to", "ssh_hardening", "change");
  await settle(40);
  assert.match(ruleLine(theRule()), /jump ssh_hardening$/);
});
