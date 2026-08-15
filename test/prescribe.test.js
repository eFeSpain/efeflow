/* The simulator read backwards: "what would make this packet pass, and where".
 *
 * The derivation is the easy half — the trace already names the rule that stops
 * the packet and the path it took. The half that separates a serious tool from
 * a dangerous assistant is the second question the other reviewer pressed on:
 * does the proposed rule, sitting where it goes, let anything else through?
 * prescribe answers it by inserting the rule transiently and re-simulating a
 * spread of witness sources, and these tests pin that behaviour down. */
import test from "node:test";
import assert from "node:assert/strict";

import { MODEL } from "../src/core/model.js";
import { prescribe } from "../src/core/prescribe.js";

/* One base chain of literal rules, hook input, so a packet with dir "in" walks
   it. Restored per test by the next setChain. */
function setChain(rules, policy = "drop", hook = "input") {
  Object.assign(MODEL, {
    tables: [{ name: "inet filter", extra: [] }],
    sets: [], objects: [], prelude: [], preludeAt: [],
    chains: [{
      table: "inet filter", id: hook, hook, type: "filter", prio: 0, policy,
      rules: rules.map(([expr, verdict]) => ({ expr, verdict, on: true, pkts: 0, bytes: 0 })),
    }],
  });
}

const P = (o) => ({
  dir: "in", iif: "wan0", oif: "", saddr: "203.0.113.5", daddr: "198.51.100.10",
  sport: 50000, dport: 443, proto: "tcp", state: "new", flags: ["syn"],
  tracked: true, nat: true, ...o,
});

test("a packet that already passes needs no rule", () => {
  setChain([["tcp dport 443", "accept"]], "drop");
  assert.deepEqual(prescribe(P({ dport: 443 })), { already: true });
});

/* The reviewer's own example: accept one host on 443 through a subnet drop.
   The naive answer (append at the end) is shadowed by the drop; prescribe puts
   the rule in front of it, and — because the rule pins the source — nothing
   else is let in. */
test("a specific rule is placed before the blocker and admits nobody else", () => {
  setChain([
    ["tcp dport 22", "accept"],
    ["ip saddr 10.0.0.0/8", "drop"],
    ["tcp dport 443", "accept"],
  ], "drop");

  const rx = prescribe(P({ saddr: "10.20.30.40", dport: 443 }));
  assert.equal(rx.already, undefined);
  assert.equal(rx.at, 1, "before the drop, not after it");
  assert.match(rx.rule, /ip saddr 10\.20\.30\.40/);
  assert.match(rx.rule, /tcp dport 443/);

  assert.ok(rx.sideEffects, "it probed");
  assert.equal(rx.sideEffects.targetAccepted, true, "the target now passes");
  assert.equal(rx.sideEffects.admits.length, 0,
    `pinning the source lets nobody else in: ${JSON.stringify(rx.sideEffects.admits)}`);
});

/* The dangerous case the check exists for: the target carried no source, so the
   derived rule is `tcp dport 443 accept` — and dropped in front of a blanket
   port drop, it opens 443 to everyone, not just the packet asked about. */
test("a source-broad rule is caught letting other sources in", () => {
  setChain([["tcp dport 443", "drop"]], "accept");

  const rx = prescribe(P({ saddr: "", dport: 443 }));
  assert.equal(rx.already, undefined);
  assert.doesNotMatch(rx.rule, /saddr/, "no source to pin, so the rule is broad");
  assert.equal(rx.sideEffects.targetAccepted, true);
  assert.ok(rx.sideEffects.admits.length > 0,
    "the probe must surface the sources this now admits");
  /* every reported side effect was blocked before and is a concrete source */
  for (const a of rx.sideEffects.admits) {
    assert.ok(a.addr, "names the source");
    assert.notEqual(a.was, "accept", "it was blocked before the rule went in");
  }
});

/* Purity: probing inserts and removes the rule, and must leave the chain as it
   found it — same rules, same length, same objects. */
test("probing leaves the ruleset exactly as it was", () => {
  setChain([["tcp dport 443", "drop"]], "accept");
  const before = MODEL.chains[0].rules.slice();
  const len = MODEL.chains[0].rules.length;

  prescribe(P({ saddr: "", dport: 443 }));

  assert.equal(MODEL.chains[0].rules.length, len, "no rule left behind");
  assert.deepEqual(MODEL.chains[0].rules, before, "same rules, same order");
});

/* The opt-out the UI's insert path uses: it re-derives to apply, and does not
   need the probe run a second time. */
test("{probe:false} skips the re-simulation", () => {
  setChain([["tcp dport 443", "drop"]], "accept");
  const rx = prescribe(P({ saddr: "", dport: 443 }), { probe: false });
  assert.equal(rx.sideEffects, null);
  assert.ok(rx.rule, "still derives the rule");
});
