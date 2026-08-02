/* Which rule of the model is which rule of the host.
 *
 * The same question behind live counters, drift and addressing a rule by its
 * handle — asked with rising stakes. Get it wrong for a counter and a number
 * is stale; get it wrong for a handle and you delete a rule you never looked
 * at. So the pairing says how it was arrived at, and only one of the two ways
 * is strong enough to act on. */
import test from "node:test";
import assert from "node:assert/strict";

import { parseNft } from "../src/core/parse.js";
import { pairChain, syncReport, applyCounters, addressable } from "../src/core/sync.js";

/* what `nft -a list ruleset` gives back */
const HOST = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter packets 900 bytes 70000 accept # handle 4
		iif lo counter packets 12 bytes 800 accept # handle 5
		tcp dport 22 counter packets 3 bytes 180 accept # handle 6
	}
}`;

const parse = (s) => parseNft(s);
const chainOf = (p) => p.chains[0];

test("rules read from a host pair by their handle", () => {
  const mine = chainOf(parse(HOST)), theirs = chainOf(parse(HOST));
  const r = pairChain(mine, theirs);
  assert.equal(r.pairs.length, 3);
  assert.ok(r.pairs.every((p) => p.by === "handle" && p.same));
  assert.deepEqual(r.onlyModel, []);
  assert.deepEqual(r.onlyHost, []);
});

/* A handle is the rule's identity, not its position: a rule that moved is
   still the rule it was. */
test("a rule that moved is still paired with itself", () => {
  const mine = chainOf(parse(HOST));
  const [a, b, c] = mine.rules;
  mine.rules = [c, a, b];
  const r = pairChain(mine, chainOf(parse(HOST)));
  assert.equal(r.pairs.length, 3);
  assert.ok(r.pairs.every((p) => p.by === "handle"));
});

test("rules with no handle line up by what they say", () => {
  const mine = chainOf(parse(HOST.replace(/ # handle \d+/g, "")));
  const r = pairChain(mine, chainOf(parse(HOST)));
  assert.equal(r.pairs.length, 3);
  assert.ok(r.pairs.every((p) => p.by === "text"));
});

test("what one has and the other has not is reported as such", () => {
  const mine = chainOf(parse(HOST));
  mine.rules.push({ expr: "tcp dport 443", verdict: "accept", on: true, pkts: 0, bytes: 0 });
  const r = pairChain(mine, chainOf(parse(HOST)));
  assert.equal(r.pairs.length, 3);
  assert.equal(r.onlyModel.length, 1, "a rule written here and not applied yet");

  const theirs = chainOf(parse(HOST));
  theirs.rules.push({ expr: "ip saddr 1.2.3.4", verdict: "drop", on: true,
                      pkts: 0, bytes: 0, handle: 9 });
  const r2 = pairChain(chainOf(parse(HOST)), theirs);
  assert.equal(r2.onlyHost.length, 1, "a rule something else added on the host");
});

/* Same handle, different text: somebody replaced the rule under that handle. */
test("a rule changed under its handle is paired and marked unequal", () => {
  const mine = chainOf(parse(HOST));
  mine.rules[2].expr = "tcp dport 2222";
  const p = pairChain(mine, chainOf(parse(HOST))).pairs.find((x) => x.i === 2);
  assert.equal(p.by, "handle");
  assert.equal(p.same, false);
});

test("the whole report counts what has drifted", () => {
  const model = parse(HOST);
  assert.equal(syncReport(model, parse(HOST)).inSync, true);

  const host = parse(HOST);
  host.chains[0].rules.push({ expr: "ip saddr 1.2.3.4", verdict: "drop", on: true,
                              pkts: 0, bytes: 0, handle: 9 });
  const r = syncReport(parse(HOST), host);
  assert.equal(r.added, 1);
  assert.equal(r.inSync, false);
});

test("a chain the host does not have counts as missing, not as matching", () => {
  const model = parse(HOST);
  model.chains.push({ id: "output", table: "inet filter", hook: "output", prio: 0,
                      type: "filter", policy: "accept", rules: [
                        { expr: "", verdict: "accept", on: true, pkts: 0, bytes: 0 }] });
  const r = syncReport(model, parse(HOST));
  assert.equal(r.missing, 1);
  assert.equal(r.inSync, false);
});

/* Counters are not part of what a ruleset means — the generated source does
   not change — so this is a read, and it puts the numbers where they go. */
test("counters land on the rules they belong to", () => {
  const model = parse(HOST.replace(/packets \d+ bytes \d+/g, "packets 0 bytes 0"));
  assert.equal(model.chains[0].rules[0].pkts, 0);

  const n = applyCounters(model, parse(HOST));
  assert.equal(n, 3);
  assert.deepEqual(model.chains[0].rules.map((r) => r.pkts), [900, 12, 3]);
  assert.deepEqual(model.chains[0].rules.map((r) => r.bytes), [70000, 800, 180]);
});

test("counters follow the rule, not the position", () => {
  const model = parse(HOST.replace(/packets \d+ bytes \d+/g, "packets 0 bytes 0"));
  const [a, b, c] = model.chains[0].rules;
  model.chains[0].rules = [c, a, b];
  applyCounters(model, parse(HOST));
  assert.equal(c.pkts, 3, "the rule that was third on the host is third's counter");
  assert.equal(a.pkts, 900);
});

/* The strict one. A handle is a position in somebody else's kernel. */
test("a rule is addressable only when its chain has not drifted", () => {
  const model = parse(HOST);
  assert.equal(addressable(model, parse(HOST), model.chains[0], 2), 6);

  /* something else added a rule on the host */
  const host = parse(HOST);
  host.chains[0].rules.push({ expr: "ip saddr 1.2.3.4", verdict: "drop", on: true,
                              pkts: 0, bytes: 0, handle: 9 });
  assert.equal(addressable(model, host, model.chains[0], 2), null,
    "the chain moved under us and the handle is no longer a promise");
});

test("a rule with no handle is not addressable, however sure it looks", () => {
  const model = parse(HOST.replace(/ # handle \d+/g, ""));
  assert.equal(addressable(model, parse(HOST), model.chains[0], 2), null);
});

test("a rule edited here is not addressable until it is applied", () => {
  const model = parse(HOST);
  model.chains[0].rules[2].expr = "tcp dport 2222";
  assert.equal(addressable(model, parse(HOST), model.chains[0], 2), null);
});
