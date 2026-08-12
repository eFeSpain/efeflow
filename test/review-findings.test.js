/* Seven things a review found, each reproduced before it was believed and
 * pinned here afterwards. Three of them made the application say something
 * false about a live firewall.
 *
 * They share a shape. Every one is a piece of code answering a slightly
 * different question from the one being asked of it: how do these two
 * documents differ, rather than what will this apply do; does this text come
 * back byte for byte, rather than did we understand it; is a rollback armed,
 * rather than is it ours to disarm. */
import test from "node:test";
import assert from "node:assert/strict";
import { parseNft, verify } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";
import { applyPlan, addressable, syncReport } from "../src/core/sync.js";
import { ruleLine } from "../src/core/model.js";
import { applyWithNet } from "../src/apply.js";

const LIVE = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" counter packets 12 bytes 800 accept # handle 2
		tcp dport 22 counter packets 3 bytes 180 accept # handle 3
	}
}`;
const OURS = ["inet filter"];

/* ── 1. the diff said nothing differs while the apply deleted a rule ────────
   generate.js emits only the rules that are switched on. pairChain paired the
   ones that are off with the host's copy anyway, so unticking a rule read as
   `identical: true, keep: 2, destroy: 0` — on the screen built to say what an
   apply does, about the rule it was about to remove from the firewall. */
test("a rule switched off here is a rule this apply deletes there", () => {
  const model = parseNft(LIVE);
  model.chains[0].rules[1].on = false;

  const p = applyPlan(model, parseNft(LIVE), { tables: OURS });
  const input = p.chains[0];

  assert.equal(p.identical, false, "the screen said nothing differs");
  assert.equal(input.destroy.length, 1, "the rule it is about to delete is not shown");
  assert.match(JSON.stringify(input.destroy[0]), /dport 22/);
  assert.equal(input.keep, 1);

  /* and the same thing said as a number, for the drift line */
  assert.equal(syncReport(model, parseNft(LIVE), { tables: OURS }).inSync, false);
});

test("a rule switched off before it was ever applied is not created either", () => {
  const model = parseNft(LIVE);
  model.chains[0].rules.push({ expr: "tcp dport 25", verdict: "accept", on: false });
  const p = applyPlan(model, parseNft(LIVE), { tables: OURS });
  assert.equal(p.chains[0].create.length, 0,
    "it offered to create a rule that generate() never writes");
  assert.equal(p.identical, true);
});

/* ── 2. a trailing comment swallowed the verdict ────────────────────────────
   Only `# handle N` was taken off the end of a line. Anything else a person
   had typed stayed on it and became part of the rule — and because the rule
   then re-emitted byte for byte, the round-trip check called it a perfect
   reproduction of a rule it had misread. */
test("a comment on the end of a rule is a comment, not part of the rule", () => {
  const m = parseNft(`table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept  # ssh from the office
	}
}`);
  const r = m.chains[0].rules[0];
  assert.equal(r.verdict, "accept", "the verdict was swallowed into the expression");
  assert.equal(r.expr, "tcp dport 22");
  assert.doesNotMatch(ruleLine(r), /#/, "the comment is re-emitted into the ruleset");
});

test("but a # inside a string belongs to the string", () => {
  const m = parseNft(`table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 80 log prefix "web #1 " accept
	}
}`);
  const r = m.chains[0].rules[0];
  assert.match(r.expr, /web #1 /, "cutting at the # lost half the log statement");
  assert.equal(r.verdict, "accept");
});

test("and the handle is still read, which is what the comment used to be for", () => {
  const m = parseNft(LIVE);
  assert.deepEqual(m.chains[0].rules.map((r) => r.handle), [2, 3]);
});

/* ── 3. a failed apply cancelled somebody else's rollback ───────────────────
   Covered by its own ordering tests in apply.test.js; this is the end of it
   that matters here — a host already counting down keeps counting. */
test("an apply that writes nothing leaves an existing countdown alone", async () => {
  const calls = [];
  const api = {
    nftArmed: () => (calls.push("armed"), Promise.resolve({ ok: true, stdout: "armed\n", stderr: "", code: 0 })),
    nftArm: () => (calls.push("arm"), Promise.resolve({ ok: true, stdout: "", stderr: "", code: 0 })),
    nftApply: () => (calls.push("apply"), Promise.resolve({ ok: false, stdout: "", stderr: "syntax error", code: 1 })),
    nftDisarm: () => (calls.push("disarm"), Promise.resolve({ ok: true, stdout: "", stderr: "", code: 0 })),
  };
  const r = await applyWithNet({ ruleset: "nonsense", target: { kind: "ssh", host: "fw1" }, seconds: 60, api });
  assert.equal(r.ok, false);
  assert.ok(!calls.includes("disarm"),
    "it removed the sentinel that was the only thing keeping the other timer alive");
});

/* ── 4. the button that changes one rule could not change one rule ──────────
   addressable() required the model's text to still match the host's, and the
   only caller passes the rule the user has just edited. So it answered with a
   handle right up until there was something to send. */
test("a rule can be pushed by its handle after it has been edited", () => {
  const model = parseNft(LIVE);
  const ch = model.chains[0];
  assert.equal(addressable(model, parseNft(LIVE), ch, 1, "replace"), 3);

  ch.rules[1].verdict = "drop";
  assert.equal(addressable(model, parseNft(LIVE), ch, 1, "replace"), 3,
    "an edited rule became unaddressable, which is every rule worth pushing");
});

test("deleting one still demands that it is the rule you are looking at", () => {
  const model = parseNft(LIVE);
  const ch = model.chains[0];
  ch.rules[1].verdict = "drop";
  assert.equal(addressable(model, parseNft(LIVE), ch, 1, "delete"), null,
    "delete is a claim about the rule as it stands, and it no longer stands");
});

test("and neither is offered when the chain itself has moved", () => {
  const model = parseNft(LIVE);
  const banned = LIVE.replace("\t\ttcp dport 22",
    "\t\tip saddr 203.0.113.9 counter packets 1 bytes 60 drop # handle 9\n\t\ttcp dport 22");
  for (const op of ["replace", "delete"])
    assert.equal(addressable(model, parseNft(banned), model.chains[0], 1, op), null,
      `${op} was offered on a chain something else had added to`);
});

/* ── 5. verify() marked its own preamble as lost ────────────────────────────
   The scoped export writes `table inet filter` and `delete table inet filter`
   above the ruleset to say what it replaces. Neither is content, and neither
   comes back from generate() unless the same scope is asked for again — so
   verifying eFeFlow's own output reported two lost lines per table. */
test("eFeFlow's own output verifies as its own output", () => {
  const src = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 counter accept
	}
}`;
  for (const scope of ["tables", "ruleset"]) {
    const own = generate(parseNft(src), { scope }).join("\n");
    const v = verify(own);
    assert.equal(v.diffs.length, 0,
      `scope ${scope} reported ${JSON.stringify(v.diffs.map((d) => d.src))}`);
    assert.equal(v.ok, v.total);
  }
});

/* A table header is not a preamble line, however short the family is spelled:
   `table filter {` opens a block, `table filter` does not, and dropping the
   first from the comparison would hide whatever happened to its contents.
 *
 * It is compared — six lines here, the header among them — and it agrees.
 * `table filter` *is* `table ip filter`: ip is the family nft assumes when none
 * is written and it prints the one it assumed, so writing it out is nft's own
 * spelling rather than a line we failed to reproduce. Seventy-two of these
 * across three thousand corpus rulesets made it the largest remaining class of
 * difference that meant nothing. */
test("a table that opens a block is compared, and the family it implies agrees", () => {
  const v = verify(`table filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept
	}
}`);
  assert.deepEqual(v.diffs, [], JSON.stringify(v.diffs));
  assert.equal(v.total, 6, "the table header has to be one of the lines counted");
});

/* Only where nft would have assumed it, though. A family that was written
   stays written, and a table named after one is not one. */
test("a family that was written is not rewritten", () => {
  for(const head of ["table inet filter {", "table bridge br0 {", "table netdev raw {"]){
    const v = verify([head, "\tchain c {", "\t\ttcp dport 22 accept", "\t}", "}"].join("\n"));
    assert.deepEqual(v.diffs, [], `${head}: ${JSON.stringify(v.diffs)}`);
  }
});

/* ── 6 & 7. the two numbers under the diff ──────────────────────────────── */

test("only the rules that count are counted", () => {
  const mixed = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" counter packets 5 bytes 300 accept # handle 2
		tcp dport 22 accept # handle 3
	}
}`;
  const p = applyPlan(parseNft(mixed), parseNft(mixed), { tables: OURS });
  assert.equal(p.counting, 1, "`pkts == null` is never true — parseRule gives every rule a zero");
  assert.equal(p.packets, 5);
});

/* A table of ours holding only a set has no chain to be recognised by, and was
   reported as somebody else's — on the same screen that had just named it as
   one of the tables being replaced. */
test("a table in the scope is ours even when no chain names it", () => {
  const model = parseNft(`table inet filter {
	set blocked {
		type ipv4_addr
	}
}`);
  const host = parseNft(`table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 counter packets 4 bytes 240 accept # handle 2
	}
}`);
  const p = applyPlan(model, host, { tables: OURS });
  assert.deepEqual(p.droppedTables, [], "it called our own table not ours");
  assert.equal(p.dropped, 0);
  assert.equal(p.recreated, 1, "the rule is rebuilt with the table, not destroyed with it");
});
